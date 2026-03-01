using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using MessagePack;
using TordeX.Core.Cryptography;
using TordeX.Core.Models;
using TordeX.Core.Network;
using TordeX.Core.Storage;

namespace TordeX.Core.Services;

/// <summary>
/// Main orchestration service for the tordeX chat system.
/// Coordinates crypto, storage, and networking.
/// </summary>
public sealed class ChatService : IAsyncDisposable
{
    private readonly string _dataDirectory;
    private readonly AppLogger _logger;
    private SecureDatabase? _database;
    private TorManager? _torManager;
    private P2PServer? _p2pServer;
    private IdentityManager? _identity;
    private int _p2pListenPort = 19876;
    private byte[]? _masterKey;
    private UserProfile? _userProfile;
    private bool _disposed;
    private Timer? _selfDestructTimer;
    private Timer? _autoLockTimer;
    private Timer? _peerReconnectTimer;
    private Timer? _heartbeatTimer;
    private CancellationTokenSource? _backgroundCts;
    private DateTime _lastActivityTime = DateTime.UtcNow;
    private string? _cachedFingerprint;

    // Active room keys (room ID -> derived key)
    private readonly ConcurrentDictionary<string, byte[]> _roomKeys = new();

    // Active peer connections per room — keyed by peer fingerprint for O(1) remove
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, PeerConnection>> _roomPeers = new();

    // Blocked users cache
    private readonly ConcurrentDictionary<string, bool> _blockedUsers = new();

    // Known peer addresses per room (for reconnection)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _knownPeerAddresses = new();

    // Deduplication: tracks in-progress outgoing connection attempts (roomId:onionAddress -> byte)
    private readonly ConcurrentDictionary<string, byte> _connectingPeers = new();

    // Prevents concurrent TryReconnectPeersAsync calls from timer overlap
    private readonly SemaphoreSlim _reconnectSemaphore = new(1, 1);

    // Replay protection: two-bucket time-based eviction (total window = 2 × bucket interval = 5 min)
    private HashSet<string> _replayBucketCurrent = new();
    private HashSet<string> _replayBucketPrevious = new();
    private readonly object _replayLock = new();
    private DateTime _lastBucketRotation = DateTime.UtcNow;
    private const int ReplayBucketIntervalSeconds = 150; // 2.5 min per bucket
    private const int ReplayWindowSeconds = 300; // 5-minute total window

    public bool IsInitialized { get; private set; }
    public bool IsLocked { get; private set; }
    public bool IsTorConnected => _torManager?.IsRunning ?? false;
    public UserProfile? CurrentUser => _userProfile;
    public string? UserFingerprint => _cachedFingerprint;

    public event Action<ChatMessage>? OnMessageReceived;
    public event Action<string, bool>? OnPeerStatusChanged;
    public event Action<bool>? OnTorStatusChanged;
    public event Action<int>? OnBootstrapProgressChanged;
    public event Action<string>? OnNotification;
    public event Action? OnAutoLocked;
    #pragma warning disable CS0067
    public event Action<string, string>? OnTypingIndicator; // roomId, senderName — not yet implemented
    #pragma warning restore CS0067
    public event Action<string, string>? OnPeerKeyChanged; // fingerprint, roomId — TOFU key mismatch
    public event Action<string, string>? OnConnectionFailed; // roomId, errorMessage — peer connection failed
    public event Action<ChatRoom>? OnDmAccepted; // Fires when an incoming DM room is auto-created

    public ChatService(string dataDirectory, AppLogger? logger = null)
    {
        _dataDirectory = dataDirectory;
        _logger = logger ?? new AppLogger(dataDirectory);
        Directory.CreateDirectory(dataDirectory);
    }

    // ═══════════════ Authentication ═══════════════

    public bool HasUserProfile()
    {
        var dbExists = File.Exists(Path.Combine(_dataDirectory, "tordeX.db"));
        var saltExists = File.Exists(Path.Combine(_dataDirectory, "salt.bin"));
        return dbExists && saltExists;
    }

    public async Task CreateProfileAsync(string displayName, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(displayName))
            throw new ArgumentException("Display name cannot be empty.", nameof(displayName));
        if (password.Length < 8)
            throw new ArgumentException("Password must be at least 8 characters.", nameof(password));

        var (passwordHash, passwordSalt) = KeyDerivation.DeriveKey(password);
        _masterKey = KeyDerivation.DeriveMasterKey(password, passwordSalt);
        _identity = IdentityManager.Generate();
        _cachedFingerprint = IdentityManager.ComputeFingerprint(_identity.PublicKey);

        await SaveSaltAsync(passwordSalt, ct);

        var dbPath = Path.Combine(_dataDirectory, "tordeX.db");
        _database = new SecureDatabase(dbPath, _logger);
        await _database.InitializeAsync(_masterKey, ct);

        _userProfile = new UserProfile
        {
            Id = Guid.NewGuid().ToString("N"),
            DisplayName = displayName,
            PublicKey = _identity.PublicKey,
            EncryptedPrivateKey = _identity.ExportEncrypted(_masterKey),
            PasswordSalt = passwordSalt,
            PasswordHash = passwordHash,
            CreatedAt = DateTimeOffset.UtcNow,
            LastLoginAt = DateTimeOffset.UtcNow
        };

        await _database.SaveUserProfileAsync(_userProfile, ct);

        var dbInfo = new FileInfo(dbPath);
        if (dbInfo.Length == 0)
        {
            throw new InvalidOperationException(
                "Database file is empty after profile creation. SQLCipher encryption may not be working correctly.");
        }

        StartBackgroundTimers();
        IsInitialized = true;
    }

    public async Task<bool> LoginAsync(string password, CancellationToken ct = default)
    {
        var dbPath = Path.Combine(_dataDirectory, "tordeX.db");
        if (!File.Exists(dbPath))
            return false;

        var saltPath = Path.Combine(_dataDirectory, "salt.bin");
        if (!File.Exists(saltPath))
            throw new FileNotFoundException(
                "Salt file not found. Profile may be corrupted. Delete the data folder and create a new profile.",
                saltPath);

        var passwordSalt = await File.ReadAllBytesAsync(saltPath, ct);
        if (passwordSalt.Length < 16)
            throw new InvalidOperationException("Salt file is corrupted (too short).");

        _masterKey = KeyDerivation.DeriveMasterKey(password, passwordSalt);

        try
        {
            _database = new SecureDatabase(dbPath, _logger);
            await _database.InitializeAsync(_masterKey, ct);

            _userProfile = await _database.GetUserProfileAsync(ct);
            if (_userProfile is null)
            {
                await CleanupFailedLogin();
                return false;
            }

            if (!KeyDerivation.VerifyPassword(password, _userProfile.PasswordHash, _userProfile.PasswordSalt))
            {
                await CleanupFailedLogin();
                return false;
            }

            _identity = IdentityManager.LoadFromEncrypted(_userProfile.EncryptedPrivateKey, _masterKey);
            _cachedFingerprint = IdentityManager.ComputeFingerprint(_identity.PublicKey);

            _userProfile.LastLoginAt = DateTimeOffset.UtcNow;
            await _database.SaveUserProfileAsync(_userProfile, ct);

            // Load blocked users cache
            var blocked = await _database.GetBlockedUsersAsync(ct);
            foreach (var b in blocked) _blockedUsers[b.Fingerprint] = true;

            StartBackgroundTimers();
            IsInitialized = true;
            IsLocked = false;
            return true;
        }
        catch (CryptographicException)
        {
            await CleanupFailedLogin();
            return false;
        }
        catch (Exception)
        {
            await CleanupFailedLogin();
            throw;
        }
    }

    public async Task<bool> ChangePasswordAsync(string currentPassword, string newPassword, CancellationToken ct = default)
    {
        EnsureInitialized();

        if (!KeyDerivation.VerifyPassword(currentPassword, _userProfile!.PasswordHash, _userProfile.PasswordSalt))
            return false;

        if (newPassword.Length < 8)
            throw new ArgumentException("New password must be at least 8 characters.");

        // Re-derive everything with new password
        var (newHash, newSalt) = KeyDerivation.DeriveKey(newPassword);
        var newMasterKey = KeyDerivation.DeriveMasterKey(newPassword, newSalt);

        // Re-encrypt private key with new master key
        var newEncryptedKey = _identity!.ExportEncrypted(newMasterKey);

        // Update profile — preserve ALL fields
        var updatedProfile = new UserProfile
        {
            Id = _userProfile.Id,
            DisplayName = _userProfile.DisplayName,
            PublicKey = _userProfile.PublicKey,
            EncryptedPrivateKey = newEncryptedKey,
            PasswordSalt = newSalt,
            PasswordHash = newHash,
            CreatedAt = _userProfile.CreatedAt,
            LastLoginAt = DateTimeOffset.UtcNow,
            AvatarData = _userProfile.AvatarData,
            Language = _userProfile.Language,
            AutoLockMinutes = _userProfile.AutoLockMinutes,
            NotificationSounds = _userProfile.NotificationSounds,
            ScreenCaptureProtection = _userProfile.ScreenCaptureProtection,
            ShowTimestamps = _userProfile.ShowTimestamps,
            DoubleRatchetEnabled = _userProfile.DoubleRatchetEnabled,
            PostQuantumEnabled = _userProfile.PostQuantumEnabled,
            MultiLayerEncryption = _userProfile.MultiLayerEncryption,
            DeniableEncryption = _userProfile.DeniableEncryption,
            TrafficObfuscation = _userProfile.TrafficObfuscation,
            TimingProtection = _userProfile.TimingProtection,
            RamOnlyMode = _userProfile.RamOnlyMode,
            DnsLeakProtection = _userProfile.DnsLeakProtection,
            DeadManSwitch = _userProfile.DeadManSwitch,
            DeadManSwitchDays = _userProfile.DeadManSwitchDays,
            TamperDetection = _userProfile.TamperDetection,
            IntegrityMonitoring = _userProfile.IntegrityMonitoring,
            CanaryTokens = _userProfile.CanaryTokens,
            AutoMetadataStrip = _userProfile.AutoMetadataStrip,
            TorBridgeLine = _userProfile.TorBridgeLine,
            TorPluggableTransport = _userProfile.TorPluggableTransport,
            PinnedGuardNodes = _userProfile.PinnedGuardNodes,
            MaxLoginAttempts = _userProfile.MaxLoginAttempts,
            LockoutMinutes = _userProfile.LockoutMinutes,
        };

        await _database!.SaveUserProfileAsync(updatedProfile, ct);
        await SaveSaltAsync(newSalt, ct);

        // Re-encrypt database with new master key using PRAGMA rekey
        await _database.RekeyDatabaseAsync(newMasterKey, ct);

        CryptographicOperations.ZeroMemory(_masterKey!);
        _masterKey = newMasterKey;

        _userProfile = updatedProfile;
        return true;
    }

    public void LockApp()
    {
        IsLocked = true;
        OnAutoLocked?.Invoke();
    }

    public Task<bool> UnlockAppAsync(string password, CancellationToken ct = default)
    {
        if (_userProfile is null) return Task.FromResult(false);
        if (KeyDerivation.VerifyPassword(password, _userProfile.PasswordHash, _userProfile.PasswordSalt))
        {
            IsLocked = false;
            _lastActivityTime = DateTime.UtcNow;
            return Task.FromResult(true);
        }
        return Task.FromResult(false);
    }

    public void ResetActivityTimer()
    {
        _lastActivityTime = DateTime.UtcNow;
    }

    private async Task CleanupFailedLogin()
    {
        if (_database is not null)
            await _database.DisposeAsync();
        _database = null;
        if (_masterKey is not null)
            CryptographicOperations.ZeroMemory(_masterKey);
        _masterKey = null;
        _userProfile = null;
        _cachedFingerprint = null;
    }

    private async Task SaveSaltAsync(byte[] salt, CancellationToken ct)
    {
        var saltPath = Path.Combine(_dataDirectory, "salt.bin");
        await File.WriteAllBytesAsync(saltPath, salt, ct);

        if (!File.Exists(saltPath))
            throw new IOException($"Failed to write salt file to {saltPath}");

        var written = await File.ReadAllBytesAsync(saltPath, ct);
        if (written.Length != salt.Length)
            throw new IOException($"Salt file verification failed: expected {salt.Length} bytes, got {written.Length}");
    }

    // ═══════════════ Tor ═══════════════

    public string? OnionAddress => _torManager?.OnionAddress;

    private bool _isTorStarting = false;
    
    public async Task StartTorAsync(CancellationToken ct = default)
    {
        // Prevent duplicate start attempts
        if (_isTorStarting)
        {
            _logger.Info("Tor startup already in progress, ignoring duplicate request", "Tor");
            return;
        }

        if (_torManager?.IsRunning == true)
        {
            _logger.Info("Tor is already running, skipping start", "Tor");
            return;
        }

        _isTorStarting = true;
        _logger.Info("Starting Tor...", "Tor");

        try
        {
            // Step 1: Start P2P server FIRST — we need the listen port for the torrc
            // HiddenServicePort directive. The P2P server runs on localhost and is
            // exposed to the Tor network via the hidden service.
            _p2pListenPort = NetworkUtils.FindAvailablePort(19876);
            _logger.Info($"P2P server will listen on port {_p2pListenPort}", "P2P");

            _p2pServer = new P2PServer(_p2pListenPort, 0); // SOCKS port set after Tor starts
            _p2pServer.PeerConnected += HandleIncomingPeer;
            _p2pServer.AcceptLoopFailed += ex =>
            {
                _logger.Error("P2P accept loop crashed — incoming connections will fail", ex, "P2P");
                OnNotification?.Invoke("P2P server error — restart the app to fix incoming connections.");
            };

            try
            {
                await _p2pServer.StartAsync(ct);
                _logger.Info($"P2P server listening on port {_p2pListenPort}", "P2P");
            }
            catch (Exception ex)
            {
                _logger.Error($"P2P server failed to start on port {_p2pListenPort}", ex, "P2P");
                OnNotification?.Invoke($"P2P server failed to start: {ex.Message}");
                return;
            }

            // Step 2: Start Tor with HiddenServiceDir pointing to our P2P port.
            // TorManager.StartAsync handles everything:
            //   - Generates torrc with HiddenServiceDir + HiddenServicePort
            //   - Starts tor.exe and waits for 100% bootstrap
            //   - Reads .onion address from hostname file
            //   - Monitors HS_DESC events for descriptor upload confirmation
            _torManager = new TorManager(Path.Combine(_dataDirectory, "tor"), _logger);
            _torManager.ConnectionStatusChanged += status =>
            {
                _logger.Info($"Tor connection status: {(status ? "CONNECTED" : "DISCONNECTED")}", "Tor");
                OnTorStatusChanged?.Invoke(status);
            };
            _torManager.BootstrapProgressChanged += pct =>
            {
                OnBootstrapProgressChanged?.Invoke(pct);
            };

            _logger.Info("Initializing Tor manager — waiting for bootstrap + descriptor upload...", "Tor");

            // Outer timeout is 6 minutes (bootstrap up to 3min + descriptor upload up to 2min + margin)
            using var startupCts = new CancellationTokenSource(TimeSpan.FromMinutes(6));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, startupCts.Token);

            await _torManager.StartAsync(_p2pListenPort, linkedCts.Token);

            _logger.Info($"Tor fully ready — SOCKS:{_torManager.SocksPort} Control:{_torManager.ControlPort}, Bootstrap:{_torManager.BootstrapPercent}%, Onion:{_torManager.OnionAddress}", "Tor");

            if (_torManager.IsRunning)
            {
                _logger.Info($"Hidden service maps virtual port {TorManager.HiddenServiceVirtualPort} to local port {_p2pListenPort}", "TorSetup");
                _logger.Info($"Your .onion address: {_torManager.OnionAddress}", "TorSetup");

                // Migration: clear stale own .onion addresses from rooms.
                await CleanStaleRoomOnionAddressesAsync(ct);

                // Hidden service descriptor is confirmed on HSDir — start peer reconnection.
                _logger.Info("Hidden service is live — starting peer reconnection...", "P2P");
                _ = Task.Run(() => TryReconnectPeersAsync(), ct);
            }
            else
            {
                _logger.Warn("Tor is not running after StartAsync — networking disabled", "Tor");
            }
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to start Tor", ex, "Tor");
            throw;
        }
        finally
        {
            _isTorStarting = false;
        }
    }

    public async Task StopTorAsync()
    {
        if (_p2pServer is not null)
        {
            await _p2pServer.StopAsync();
        }
        if (_torManager is not null)
        {
            await _torManager.StopAsync();
        }
    }

    // ═══════════════ P2P Server ═══════════════

    /// <summary>
    /// Clear stale OnionAddress from creator rooms.
    /// Creator rooms stored own .onion in older versions — this causes reconnection to self.
    /// </summary>
    private async Task CleanStaleRoomOnionAddressesAsync(CancellationToken ct)
    {
        if (_database is null || _torManager?.OnionAddress is null) return;

        try
        {
            await _database.ClearRoomOnionAddressAsync(_torManager.OnionAddress, ct);
            _logger.Info("Cleared stale own .onion addresses from creator rooms", "P2P");
        }
        catch (Exception ex)
        {
            _logger.Error("Failed to clean stale room onion addresses", ex, "P2P");
        }
    }

    /// <summary>
    /// Connect to a remote peer's hidden service for a specific room.
    /// Retries with exponential backoff on failure.
    /// </summary>
    public async Task ConnectToRoomPeerAsync(string roomId, string onionAddress, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(onionAddress))
            return;

        onionAddress = onionAddress.Trim();

        // Track known peer address for reconnection
        _knownPeerAddresses.GetOrAdd(roomId, _ => new ConcurrentDictionary<string, byte>()).TryAdd(onionAddress, 0);

        if (_torManager is null || !_torManager.IsRunning || _identity is null || _userProfile is null)
        {
            _logger.Warn($"Cannot connect to peer: Tor={_torManager?.IsRunning}, Identity={_identity is not null}", "P2P");
            return;
        }

        // Don't connect to ourselves
        if (onionAddress == _torManager.OnionAddress)
            return;

        // Check if already connected to this specific onion address (allows multi-peer rooms)
        if (_roomPeers.TryGetValue(roomId, out var existingPeers)
            && existingPeers.Values.Any(p => p.IsConnected && p.PeerOnionAddress == onionAddress))
            return;

        // Prevent duplicate concurrent connection attempts to the same peer
        var connectKey = $"{roomId}:{onionAddress}";
        if (!_connectingPeers.TryAdd(connectKey, 0))
            return;

        try
        {
            // Retry with exponential backoff (5 attempts: 0s, 5s, 15s, 30s, 60s)
            var delays = new[] { 0, 5000, 15000, 30000, 60000 };

            for (int attempt = 0; attempt < delays.Length; attempt++)
            {
                if (ct.IsCancellationRequested) return;

                if (attempt > 0)
                {
                    _logger.Info($"Peer connection retry {attempt + 1}/{delays.Length} in {delays[attempt] / 1000}s...", "P2P");
                    await Task.Delay(delays[attempt], ct);
                }

                // Re-check: Tor might have stopped or peer already connected
                if (_torManager is null || !_torManager.IsRunning) return;
                if (_roomPeers.TryGetValue(roomId, out var recheckPeers)
                    && recheckPeers.Values.Any(p => p.IsConnected && p.PeerOnionAddress == onionAddress))
                    return;

                // Connect to the fixed hidden service virtual port, NOT our local port
                var peer = new PeerConnection(onionAddress, TorManager.HiddenServiceVirtualPort, _torManager.SocksPort);

                try
                {
                    _logger.Info($"Connecting to peer {onionAddress} for room {roomId[..8]}... (attempt {attempt + 1})", "P2P");

                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(60)); // 60s timeout per attempt

                    await peer.ConnectAsync(timeoutCts.Token);
                    await peer.HandshakeAsync(_identity, _userProfile.DisplayName, roomId,
                        _torManager?.OnionAddress, timeoutCts.Token);

                    // TOFU: Verify peer identity against pinned keys
                    if (!await VerifyPeerTofuAsync(roomId, peer, timeoutCts.Token))
                    {
                        _logger.Warn($"TOFU rejection: peer {peer.PeerFingerprint} key mismatch, disconnecting", "Security");
                        await peer.DisposeAsync();
                        return;
                    }

                    WirePeerEvents(peer, roomId);
                    peer.StartReceiving();

                    _roomPeers.GetOrAdd(roomId, _ => new ConcurrentDictionary<string, PeerConnection>())[peer.PeerFingerprint] = peer;

                    // Store peer's onion address for future reconnection
                    if (!string.IsNullOrEmpty(peer.PeerOnionAddress))
                    {
                        _knownPeerAddresses.GetOrAdd(roomId, _ => new ConcurrentDictionary<string, byte>())
                            .TryAdd(peer.PeerOnionAddress, 0);
                    }

                    _logger.Info($"Connected to peer {peer.PeerDisplayName} ({peer.PeerFingerprint}) onion={peer.PeerOnionAddress ?? "n/a"} in room {roomId[..8]}", "P2P");
                    OnPeerStatusChanged?.Invoke(peer.PeerFingerprint, true);
                    return; // Success — stop retrying
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    _logger.Warn($"Peer connection timed out: {onionAddress} (attempt {attempt + 1})", "P2P");
                    await peer.DisposeAsync();
                }
                catch (Exception ex)
                {
                    _logger.Error($"Peer connection failed: {onionAddress} (attempt {attempt + 1})", ex, "P2P");
                    _logger.Error($"Connection details: Target={onionAddress}:{TorManager.HiddenServiceVirtualPort}, SOCKS=127.0.0.1:{_torManager.SocksPort}", null, "P2P");
                    if (ex.InnerException != null)
                    {
                        _logger.Error($"Inner exception: {ex.InnerException.Message}", ex.InnerException, "P2P");
                    }
                    await peer.DisposeAsync();
                }
            }

            _logger.Warn($"All peer connection attempts exhausted for {onionAddress} in room {roomId[..8]}", "P2P");
            OnConnectionFailed?.Invoke(roomId, $"Could not reach peer at {onionAddress[..16]}... — will retry in background.");
        }
        finally
        {
            _connectingPeers.TryRemove(connectKey, out _);
        }
    }

    private void HandleIncomingPeer(PeerConnection peer)
    {
        // Process async on thread pool to not block the accept loop
        var bgToken = _backgroundCts?.Token ?? CancellationToken.None;
        _ = Task.Run(async () =>
        {
            try
            {
                if (_identity is null || _userProfile is null || _disposed) return;

                _logger.Info("Incoming peer connection received", "P2P");

                // Respond to handshake (receive first, then send)
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(bgToken);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));
                var roomId = await peer.RespondToHandshakeAsync(
                    _identity, _userProfile.DisplayName, _torManager?.OnionAddress, timeoutCts.Token);

                // For DM rooms, auto-create/unlock if we recognize the dm- prefix
                if (roomId.StartsWith("dm-", StringComparison.Ordinal) && !_roomKeys.ContainsKey(roomId))
                {
                    try
                    {
                        await AcceptIncomingDmAsync(roomId, peer, bgToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warn($"Failed to accept incoming DM: {ex.Message}", "DM");
                        await peer.DisposeAsync();
                        return;
                    }
                }

                // Verify we have this room and its key
                if (!_roomKeys.ContainsKey(roomId))
                {
                    _logger.Warn($"Incoming peer for unknown/locked room {roomId[..Math.Min(8, roomId.Length)]}, rejecting", "P2P");
                    await peer.DisposeAsync();
                    return;
                }

                // Check if peer is blocked
                if (_blockedUsers.ContainsKey(peer.PeerFingerprint))
                {
                    _logger.Info($"Blocked peer {peer.PeerFingerprint} rejected", "P2P");
                    await peer.DisposeAsync();
                    return;
                }

                // TOFU: Verify peer identity against pinned keys
                if (!await VerifyPeerTofuAsync(roomId, peer, bgToken))
                {
                    _logger.Warn($"TOFU rejection: incoming peer {peer.PeerFingerprint} key mismatch, disconnecting", "Security");
                    await peer.DisposeAsync();
                    return;
                }

                WirePeerEvents(peer, roomId);
                peer.StartReceiving();

                _roomPeers.GetOrAdd(roomId, _ => new ConcurrentDictionary<string, PeerConnection>())[peer.PeerFingerprint] = peer;

                // Store peer's onion address for future reconnection
                if (!string.IsNullOrEmpty(peer.PeerOnionAddress))
                {
                    _knownPeerAddresses.GetOrAdd(roomId, _ => new ConcurrentDictionary<string, byte>())
                        .TryAdd(peer.PeerOnionAddress, 0);
                }

                // Persist peer's onion address to room for reconnection after restart
                if (!string.IsNullOrEmpty(peer.PeerOnionAddress) && _database is not null)
                {
                    try
                    {
                        var room = (await _database.GetRoomsAsync(bgToken))
                            .FirstOrDefault(r => r.Id == roomId);
                        if (room is not null && string.IsNullOrEmpty(room.OnionAddress))
                        {
                            room.OnionAddress = peer.PeerOnionAddress;
                            await _database.SaveRoomAsync(room, bgToken);
                        }
                    }
                    catch (Exception ex) { _logger.Warn($"Failed to persist peer onion address: {ex.Message}", "P2P"); }
                }

                _logger.Info($"Incoming peer accepted: {peer.PeerDisplayName} ({peer.PeerFingerprint}) onion={peer.PeerOnionAddress ?? "n/a"} in room {roomId[..Math.Min(8, roomId.Length)]}", "P2P");
                OnPeerStatusChanged?.Invoke(peer.PeerFingerprint, true);
            }
            catch (Exception ex)
            {
                _logger.Error("Incoming peer handling failed", ex, "P2P");
                try { await peer.DisposeAsync(); } catch { /* best effort */ }
            }
        });
    }

    /// <summary>
    /// Get the number of connected peers for a room.
    /// </summary>
    public int GetRoomPeerCount(string roomId)
    {
        if (_roomPeers.TryGetValue(roomId, out var peers))
            return peers.Values.Count(p => p.IsConnected);
        return 0;
    }

    /// <summary>
    /// Get connected peer display names for a room.
    /// </summary>
    public List<string> GetRoomPeerNames(string roomId)
    {
        if (_roomPeers.TryGetValue(roomId, out var peers))
            return peers.Values.Where(p => p.IsConnected).Select(p => p.PeerDisplayName).ToList();
        return new List<string>();
    }

    private void WirePeerEvents(PeerConnection peer, string roomId)
    {
        peer.MessageReceived += msg => HandleReceivedP2PMessage(msg);
        peer.Disconnected += disconnectedPeer =>
        {
            // O(1) remove by fingerprint — no bag reconstruction needed
            if (_roomPeers.TryGetValue(roomId, out var peers))
                peers.TryRemove(disconnectedPeer.PeerFingerprint, out _);
            OnPeerStatusChanged?.Invoke(disconnectedPeer.PeerFingerprint, false);
        };
    }

    private void HandleReceivedP2PMessage(P2PMessage msg)
    {
        var bgToken = _backgroundCts?.Token ?? CancellationToken.None;
        _ = Task.Run(async () =>
        {
            if (_disposed || bgToken.IsCancellationRequested) return;
            try
            {
                if (msg.Type != P2PMessageType.ChatMessage) return;
                if (!_roomKeys.TryGetValue(msg.RoomId, out var roomKey)) return;
                if (_blockedUsers.ContainsKey(msg.SenderFingerprint)) return;

                // SECURITY FIX: Replay protection — time-bucketed duplicate detection
                if (!TryAddSeenMessage(msg.MessageId))
                {
                    _logger.Warn($"Replay detected: duplicate message ID {msg.MessageId[..Math.Min(8, msg.MessageId.Length)]}", "P2P");
                    return;
                }

                // SECURITY FIX: Timestamp window — reject messages older than 5 minutes
                var msgAge = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - msg.Timestamp;
                if (Math.Abs(msgAge) > ReplayWindowSeconds * 1000)
                {
                    _logger.Warn($"Message outside time window: age={msgAge}ms, sender={msg.SenderFingerprint[..8]}", "P2P");
                    return;
                }

                // SECURITY FIX: CWE-345 — Verify signature over full message context
                var signableContext = BuildSignableContext(msg.RoomId, msg.MessageId, msg.SenderFingerprint, msg.Timestamp, msg.Payload);
                if (!IdentityManager.Verify(signableContext, msg.Signature, msg.SenderPublicKey))
                    return;

                // Decrypt payload with roomId as AAD (prevents cross-room replay)
                var roomIdAad = Encoding.UTF8.GetBytes(msg.RoomId);
                var decryptedPayload = MessageEncryption.Decrypt(msg.Payload, roomKey, roomIdAad);
                var msgData = MessagePackSerializer.Deserialize<ChatMessagePayload>(decryptedPayload);

                var chatMessage = new ChatMessage
                {
                    Id = msgData.Id,
                    RoomId = msg.RoomId,
                    SenderFingerprint = msgData.SenderFingerprint,
                    SenderDisplayName = msgData.SenderDisplayName,
                    Type = (MessageType)msgData.Type,
                    Content = msgData.Content,
                    FileName = msgData.FileName,
                    FileSize = msgData.FileSize,
                    MimeType = msgData.MimeType,
                    Timestamp = DateTimeOffset.FromUnixTimeMilliseconds(msgData.Timestamp),
                    IsOwn = false,
                    ReplyToId = msgData.ReplyToId,
                    ReplyToContent = msgData.ReplyToContent,
                    ReplyToSenderName = msgData.ReplyToSenderName,
                    SelfDestructSeconds = msgData.SelfDestructSeconds,
                    SelfDestructAt = msgData.SelfDestructSeconds.HasValue
                        ? DateTimeOffset.UtcNow.AddSeconds(msgData.SelfDestructSeconds.Value)
                        : null,
                    VoiceDuration = msgData.VoiceDuration,
                    IsDelivered = true,
                };

                // Save to local database
                if (_database is not null)
                    await _database.SaveMessageAsync(msg.RoomId, chatMessage, roomKey);

                // Notify UI
                OnMessageReceived?.Invoke(chatMessage);
                OnNotification?.Invoke($"{chatMessage.SenderDisplayName}: {chatMessage.Content}");
            }
            catch (Exception ex)
            {
                _logger.Error("P2P message handling failed", ex, "P2P");
            }
        });
    }

    // ═══════════════ Rooms ═══════════════

    public async Task<ChatRoom> CreateRoomAsync(string name, string password, string? description = null,
        int maxCapacity = 0, CancellationToken ct = default)
    {
        EnsureInitialized();

        var roomId = SecureRandom.GenerateHex(16);

        // Deterministic salt — both creator and joiner derive same key from same roomId + password
        var saltInput = Encoding.UTF8.GetBytes($"tordeX-room-salt-v1:{roomId}");
        var roomSalt = System.Security.Cryptography.SHA256.HashData(saltInput);
        var roomKey = KeyDerivation.DeriveRoomKey(password, roomSalt);
        var inviteToken = SecureRandom.GenerateHex(16);

        var room = new ChatRoom
        {
            Id = roomId,
            Name = name,
            RoomSalt = roomSalt,
            CreatedAt = DateTimeOffset.UtcNow,
            LastActivityAt = DateTimeOffset.UtcNow,
            Description = description,
            MaxCapacity = maxCapacity,
            InviteToken = inviteToken,
            // Don't store own .onion — use _torManager.OnionAddress dynamically for invite links.
            // Only joiner rooms store the peer's .onion for reconnection.
            OnionAddress = null,
        };

        await _database!.SaveRoomAsync(room, ct);
        _roomKeys[room.Id] = roomKey;

        _logger.Info($"Room created: {name} (ID: {roomId[..8]}..., Onion: {room.OnionAddress ?? "none"})", "Room");
        return room;
    }

    public async Task<ChatRoom> JoinRoomAsync(string roomId, string name, string password, byte[] roomSalt,
        CancellationToken ct = default)
    {
        EnsureInitialized();

        var roomKey = KeyDerivation.DeriveRoomKey(password, roomSalt);

        var room = new ChatRoom
        {
            Id = roomId,
            Name = name,
            RoomSalt = roomSalt,
            CreatedAt = DateTimeOffset.UtcNow,
            LastActivityAt = DateTimeOffset.UtcNow
        };

        await _database!.SaveRoomAsync(room, ct);
        _roomKeys[room.Id] = roomKey;

        return room;
    }

    public async Task<List<ChatRoom>> GetRoomsAsync(CancellationToken ct = default)
    {
        EnsureInitialized();
        return await _database!.GetRoomsAsync(ct);
    }

    public void UnlockRoom(string roomId, string password, byte[] roomSalt)
    {
        var roomKey = KeyDerivation.DeriveRoomKey(password, roomSalt);
        _roomKeys[roomId] = roomKey;
    }

    public async Task DeleteRoomAsync(string roomId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.DeleteRoomAsync(roomId, ct);
        _roomKeys.TryRemove(roomId, out var key);
        if (key is not null) CryptographicOperations.ZeroMemory(key);
    }

    public async Task UpdateRoomAsync(ChatRoom room, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.SaveRoomAsync(room, ct);
    }

    public string GenerateInviteLink(ChatRoom room)
    {
        // Always use the live .onion address — room.OnionAddress may be a peer's address (joiner rooms)
        // or stale (old creator rooms). _torManager.OnionAddress is always our current persistent .onion.
        var onion = _torManager?.OnionAddress ?? "";
        return $"tordex://join/{room.Id}/{room.InviteToken ?? SecureRandom.GenerateHex(16)}/{onion}";
    }

    // ═══════════════ Direct Messages ═══════════════

    /// <summary>
    /// Get the current user's DM token for sharing.
    /// Format: tordex://dm/{onionAddress}/{fingerprint}
    /// </summary>
    public string? GetDmToken()
    {
        var onion = _torManager?.OnionAddress;
        var fp = UserFingerprint;
        if (onion is null || fp is null) return null;
        return $"tordex://dm/{onion}/{fp}";
    }

    /// <summary>
    /// Parse a DM token into onion address and fingerprint.
    /// Returns null if the token is invalid.
    /// </summary>
    public static (string onionAddress, string fingerprint)? ParseDmToken(string token)
    {
        const string prefix = "tordex://dm/";
        if (!token.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return null;

        var remainder = token[prefix.Length..];
        var parts = remainder.Split('/', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return null;

        var onion = parts[0].Trim();
        var fingerprint = parts[1].Trim();

        if (string.IsNullOrEmpty(onion) || string.IsNullOrEmpty(fingerprint))
            return null;

        return (onion, fingerprint);
    }

    /// <summary>
    /// Generate a deterministic DM room ID from two fingerprints.
    /// Sort ensures both peers produce the same ID.
    /// </summary>
    public static string GenerateDmRoomId(string fingerprintA, string fingerprintB)
    {
        var sorted = new[] { fingerprintA, fingerprintB };
        Array.Sort(sorted, StringComparer.Ordinal);
        return $"dm-{sorted[0]}-{sorted[1]}";
    }

    /// <summary>
    /// Create or open a DM conversation with a peer.
    /// If the DM room already exists, returns the existing room.
    /// </summary>
    public async Task<ChatRoom> CreateDirectMessageAsync(string peerOnionAddress, string peerFingerprint, CancellationToken ct = default)
    {
        EnsureInitialized();

        if (peerFingerprint == UserFingerprint)
            throw new InvalidOperationException("Cannot create a DM with yourself.");

        var dmRoomId = GenerateDmRoomId(UserFingerprint!, peerFingerprint);

        // Check if DM room already exists
        var existingRooms = await _database!.GetRoomsAsync(ct);
        var existing = existingRooms.FirstOrDefault(r => r.Id == dmRoomId);
        if (existing is not null)
        {
            // Update onion address if changed
            if (existing.OnionAddress != peerOnionAddress)
            {
                existing.OnionAddress = peerOnionAddress;
                await _database.SaveRoomAsync(existing, ct);
            }

            // Ensure room key is loaded
            if (!_roomKeys.ContainsKey(dmRoomId))
            {
                var dmKey = DeriveDmRoomKey(dmRoomId);
                _roomKeys[dmRoomId] = dmKey;
            }

            return existing;
        }

        // Derive DM room key deterministically from room ID
        var roomKey = DeriveDmRoomKey(dmRoomId);
        var saltInput = Encoding.UTF8.GetBytes($"tordeX-dm-salt-v1:{dmRoomId}");
        var roomSalt = System.Security.Cryptography.SHA256.HashData(saltInput);

        var displayName = peerFingerprint[..9]; // "XXXX-XXXX" short display

        var room = new ChatRoom
        {
            Id = dmRoomId,
            Name = displayName,
            RoomSalt = roomSalt,
            CreatedAt = DateTimeOffset.UtcNow,
            LastActivityAt = DateTimeOffset.UtcNow,
            OnionAddress = peerOnionAddress,
            IsDm = true,
            PeerFingerprint = peerFingerprint,
            MaxCapacity = 2,
        };

        await _database.SaveRoomAsync(room, ct);
        _roomKeys[dmRoomId] = roomKey;

        _logger.Info($"DM room created: {dmRoomId[..16]}... with peer {peerFingerprint[..9]}", "DM");
        return room;
    }

    /// <summary>
    /// Derive a deterministic key for a DM room.
    /// Uses HKDF with the room ID as context — no password needed.
    /// </summary>
    private byte[] DeriveDmRoomKey(string dmRoomId)
    {
        var ikm = Encoding.UTF8.GetBytes($"tordeX-dm-key-v1:{dmRoomId}");
        var salt = System.Security.Cryptography.SHA256.HashData(
            Encoding.UTF8.GetBytes("tordeX-dm-salt-static-v1"));
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm,
            32,
            salt,
            Encoding.UTF8.GetBytes("tordeX-dm-room-key"));
    }

    /// <summary>
    /// Unlock a DM room by deriving the key from the room ID.
    /// No password required for DM rooms.
    /// </summary>
    public void UnlockDmRoom(string dmRoomId)
    {
        if (!_roomKeys.ContainsKey(dmRoomId))
        {
            var key = DeriveDmRoomKey(dmRoomId);
            _roomKeys[dmRoomId] = key;
        }
    }

    /// <summary>
    /// Accept an incoming DM from a peer. Creates the DM room locally if it doesn't exist.
    /// Validates that the room ID matches our fingerprint.
    /// </summary>
    private async Task AcceptIncomingDmAsync(string dmRoomId, PeerConnection peer, CancellationToken ct)
    {
        if (_database is null || _userProfile is null) return;

        // Validate the DM room ID contains our fingerprint
        var myFp = UserFingerprint!;
        if (!dmRoomId.Contains(myFp.Replace("-", ""), StringComparison.Ordinal) &&
            !dmRoomId.Contains(myFp, StringComparison.Ordinal))
        {
            // Check with the raw fingerprint format
            var normalizedId = dmRoomId;
            var parts = normalizedId["dm-".Length..].Split('-');
            // Reconstruct fingerprints: XXXX-XXXX-XXXX-XXXX format
            // DM room ID format: dm-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
            // Contains two sorted fingerprints joined by -
            // We need to check if our fingerprint is one of them
            if (!normalizedId.Contains(myFp, StringComparison.Ordinal))
            {
                _logger.Warn($"Incoming DM room {dmRoomId[..16]}... doesn't match our fingerprint, rejecting", "DM");
                return;
            }
        }

        // Check if room already exists
        var rooms = await _database.GetRoomsAsync(ct);
        var existing = rooms.FirstOrDefault(r => r.Id == dmRoomId);

        if (existing is null)
        {
            // Create new DM room
            var peerFp = peer.PeerFingerprint;
            var saltInput = Encoding.UTF8.GetBytes($"tordeX-dm-salt-v1:{dmRoomId}");
            var roomSalt = System.Security.Cryptography.SHA256.HashData(saltInput);

            var room = new ChatRoom
            {
                Id = dmRoomId,
                Name = peer.PeerDisplayName,
                RoomSalt = roomSalt,
                CreatedAt = DateTimeOffset.UtcNow,
                LastActivityAt = DateTimeOffset.UtcNow,
                OnionAddress = peer.PeerOnionAddress,
                IsDm = true,
                PeerFingerprint = peerFp,
                MaxCapacity = 2,
            };

            await _database.SaveRoomAsync(room, ct);
            _logger.Info($"Accepted incoming DM from {peer.PeerDisplayName} ({peerFp})", "DM");

            // Notify UI so it can refresh the rooms list
            OnDmAccepted?.Invoke(room);
        }
        else if (!string.IsNullOrEmpty(peer.PeerOnionAddress) && existing.OnionAddress != peer.PeerOnionAddress)
        {
            existing.OnionAddress = peer.PeerOnionAddress;
            existing.Name = peer.PeerDisplayName;
            await _database.SaveRoomAsync(existing, ct);
        }

        // Unlock the DM room key
        UnlockDmRoom(dmRoomId);
    }

    // ═══════════════ Messages ═══════════════

    public async Task<ChatMessage> SendTextMessageAsync(string roomId, string text,
        string? replyToId = null, string? replyToContent = null, string? replyToSenderName = null,
        int? selfDestructSeconds = null, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var message = new ChatMessage
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            SenderDisplayName = _userProfile!.DisplayName,
            Type = MessageType.Text,
            Content = text,
            Timestamp = DateTimeOffset.UtcNow,
            IsOwn = true,
            ReplyToId = replyToId,
            ReplyToContent = replyToContent,
            ReplyToSenderName = replyToSenderName,
            SelfDestructSeconds = selfDestructSeconds,
            SelfDestructAt = selfDestructSeconds.HasValue
                ? DateTimeOffset.UtcNow.AddSeconds(selfDestructSeconds.Value)
                : null,
            IsDelivered = true,
        };

        await _database!.SaveMessageAsync(roomId, message, _roomKeys[roomId], ct);
        await BroadcastToRoomAsync(roomId, message, ct);

        return message;
    }

    public async Task<ChatMessage> SendFileMessageAsync(
        string roomId, string fileName, byte[] fileData, string mimeType, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var roomKey = _roomKeys[roomId];

        // SECURITY: Auto-strip EXIF/metadata from images before encrypting.
        // Prevents leaking GPS coordinates, camera model, timestamps, etc.
        if (mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            fileData = MetadataStripperService.StripMetadata(fileData, mimeType);
        }

        var encryptedFile = MessageEncryption.EncryptFile(fileData, roomKey, fileName);
        var fileId = Guid.NewGuid().ToString("N");
        await _database!.SaveEncryptedFileAsync(fileId, fileId, encryptedFile, ct);

        var isImage = mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
        var isVideo = mimeType.StartsWith("video/", StringComparison.OrdinalIgnoreCase);

        var message = new ChatMessage
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            SenderDisplayName = _userProfile!.DisplayName,
            Type = isVideo ? MessageType.Video : (isImage ? MessageType.Image : MessageType.File),
            Content = fileId,
            FileName = fileName,
            FileSize = fileData.Length,
            MimeType = mimeType,
            Timestamp = DateTimeOffset.UtcNow,
            IsOwn = true,
            IsDelivered = true,
        };

        await _database.SaveMessageAsync(roomId, message, roomKey, ct);
        await BroadcastToRoomAsync(roomId, message, ct);

        return message;
    }

    public async Task<ChatMessage> SendVoiceMessageAsync(
        string roomId, byte[] audioData, double durationSeconds, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var roomKey = _roomKeys[roomId];
        var encryptedAudio = MessageEncryption.EncryptFile(audioData, roomKey, "voice.webm");
        var fileId = Guid.NewGuid().ToString("N");
        await _database!.SaveEncryptedFileAsync(fileId, fileId, encryptedAudio, ct);

        var message = new ChatMessage
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            SenderDisplayName = _userProfile!.DisplayName,
            Type = MessageType.Voice,
            Content = fileId,
            FileName = "voice.webm",
            MimeType = "audio/webm",
            FileSize = audioData.Length,
            VoiceDuration = durationSeconds,
            Timestamp = DateTimeOffset.UtcNow,
            IsOwn = true,
            IsDelivered = true,
        };

        await _database.SaveMessageAsync(roomId, message, roomKey, ct);
        await BroadcastToRoomAsync(roomId, message, ct);

        return message;
    }

    public async Task EditMessageAsync(string roomId, string messageId, string newContent, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var roomKey = _roomKeys[roomId];
        var encryptedContent = MessageEncryption.Encrypt(
            Encoding.UTF8.GetBytes(newContent), roomKey);

        await _database!.UpdateMessageContentAsync(messageId, encryptedContent, ct);
    }

    public async Task DeleteMessageAsync(string messageId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.SoftDeleteMessageAsync(messageId, ct);
    }

    public async Task<ChatMessage> ForwardMessageAsync(string targetRoomId, ChatMessage original, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(targetRoomId);

        var forwarded = new ChatMessage
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = targetRoomId,
            SenderFingerprint = UserFingerprint!,
            SenderDisplayName = _userProfile!.DisplayName,
            Type = original.Type,
            Content = $"[Forwarded from {original.SenderDisplayName}]\n{original.Content}",
            FileName = original.FileName,
            FileSize = original.FileSize,
            MimeType = original.MimeType,
            Timestamp = DateTimeOffset.UtcNow,
            IsOwn = true,
            IsDelivered = true,
        };

        await _database!.SaveMessageAsync(targetRoomId, forwarded, _roomKeys[targetRoomId], ct);
        return forwarded;
    }

    public async Task PinMessageAsync(string messageId, string roomId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.PinMessageAsync(messageId, roomId, ct);
    }

    public async Task UnpinMessageAsync(string messageId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.UnpinMessageAsync(messageId, ct);
    }

    public async Task<List<ChatMessage>> GetMessagesAsync(
        string roomId, int limit = 50, int offset = 0, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var messages = await _database!.GetMessagesAsync(roomId, _roomKeys[roomId], limit, offset, ct);

        // Load reactions for all messages in this room
        var allReactions = await _database.GetAllReactionsForRoomAsync(roomId, ct);

        foreach (var msg in messages)
        {
            msg.IsOwn = msg.SenderFingerprint == UserFingerprint;

            if (allReactions.TryGetValue(msg.Id, out var msgReactions))
            {
                msg.Reactions = msgReactions;
            }
        }

        return messages;
    }

    public async Task<List<ChatMessage>> SearchMessagesAsync(string roomId, string query, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var results = await _database!.SearchMessagesAsync(roomId, _roomKeys[roomId], query, ct);
        foreach (var msg in results)
        {
            msg.IsOwn = msg.SenderFingerprint == UserFingerprint;
        }
        return results;
    }

    public async Task<byte[]?> GetFileAsync(string fileId, string roomId, string? fileName = null, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var encrypted = await _database!.GetEncryptedFileAsync(fileId, ct);
        if (encrypted is null) return null;

        return MessageEncryption.DecryptFile(encrypted, _roomKeys[roomId], fileName);
    }

    // ═══════════════ Blocked Users ═══════════════

    public async Task BlockUserAsync(string fingerprint, string? displayName = null, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.BlockUserAsync(fingerprint, displayName, ct);
        _blockedUsers[fingerprint] = true;
    }

    public async Task UnblockUserAsync(string fingerprint, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.UnblockUserAsync(fingerprint, ct);
        _blockedUsers.TryRemove(fingerprint, out _);
    }

    public async Task<List<BlockedUser>> GetBlockedUsersAsync(CancellationToken ct = default)
    {
        EnsureInitialized();
        return await _database!.GetBlockedUsersAsync(ct);
    }

    public bool IsUserBlocked(string fingerprint) => _blockedUsers.ContainsKey(fingerprint);

    // ═══════════════ Reactions ═══════════════

    public async Task AddReactionAsync(string roomId, string messageId, string emoji, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.AddReactionAsync(messageId, emoji, UserFingerprint!, ct);
    }

    public async Task RemoveReactionAsync(string roomId, string messageId, string emoji, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.RemoveReactionAsync(messageId, emoji, UserFingerprint!, ct);
    }

    // ═══════════════ View Once ═══════════════

    public async Task<ChatMessage> SendViewOnceMessageAsync(string roomId, string fileName, byte[] fileData, string mimeType, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var roomKey = _roomKeys[roomId];

        // SECURITY: Auto-strip metadata from view-once images too
        if (mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
            fileData = MetadataStripperService.StripMetadata(fileData, mimeType);

        var encryptedFile = MessageEncryption.EncryptFile(fileData, roomKey, fileName);
        var fileId = Guid.NewGuid().ToString("N");
        await _database!.SaveEncryptedFileAsync(fileId, fileId, encryptedFile, ct);

        var isImage = mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase);

        var message = new ChatMessage
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            SenderDisplayName = _userProfile!.DisplayName,
            Type = isImage ? MessageType.Image : MessageType.File,
            Content = fileId,
            FileName = fileName,
            FileSize = fileData.Length,
            MimeType = mimeType,
            Timestamp = DateTimeOffset.UtcNow,
            IsOwn = true,
            IsDelivered = true,
            IsViewOnce = true,
        };

        await _database.SaveMessageAsync(roomId, message, roomKey, ct);
        await BroadcastToRoomAsync(roomId, message, ct);
        return message;
    }

    public async Task MarkViewOnceOpenedAsync(string messageId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.MarkViewOnceViewedAsync(messageId, ct);
    }

    // ═══════════════ Bookmarks ═══════════════

    public async Task ToggleBookmarkAsync(ChatMessage message, string roomName, CancellationToken ct = default)
    {
        EnsureInitialized();
        var isBookmarked = await _database!.IsBookmarkedAsync(message.Id, ct);
        if (isBookmarked)
        {
            await _database.RemoveBookmarkAsync(message.Id, ct);
        }
        else
        {
            var preview = message.Content.Length > 100 ? message.Content[..100] + "..." : message.Content;
            await _database.AddBookmarkAsync(new Bookmark
            {
                MessageId = message.Id,
                RoomId = message.RoomId,
                RoomName = roomName,
                SenderName = message.SenderDisplayName,
                ContentPreview = preview,
            }, ct);
        }
    }

    public async Task<List<Bookmark>> GetBookmarksAsync(CancellationToken ct = default)
    {
        EnsureInitialized();
        return await _database!.GetBookmarksAsync(ct);
    }

    // ═══════════════ Key Rotation ═══════════════

    public async Task RotateRoomKeyAsync(string roomId, string password, CancellationToken ct = default)
    {
        EnsureInitialized();
        EnsureRoomUnlocked(roomId);

        var oldKey = _roomKeys[roomId];
        var newSalt = SecureRandom.GenerateBytes(32);
        var newKey = KeyDerivation.DeriveRoomKey(password, newSalt);
        var rotationCount = await _database!.GetKeyRotationCountAsync(roomId, ct);

        // SECURITY FIX: CWE-312 — Store SHA-256 hashes, not raw key material
        var record = new KeyRotationRecord
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            OldKeyHash = SHA256.HashData(oldKey),
            NewKeyHash = SHA256.HashData(newKey),
            RotationNumber = rotationCount + 1,
            InitiatorFingerprint = UserFingerprint,
        };

        await _database.SaveKeyRotationAsync(record, ct);
        _roomKeys[roomId] = newKey;

        // Zero old key
        CryptographicOperations.ZeroMemory(oldKey);
    }

    // ═══════════════ Dead Drop ═══════════════

    public async Task CreateDeadDropAsync(string recipientFingerprint, byte[] encryptedPayload, int expiresInHours = 24, CancellationToken ct = default)
    {
        EnsureInitialized();

        var drop = new DeadDrop
        {
            Id = Guid.NewGuid().ToString("N"),
            DropAddress = $"tordex-drop-{SecureRandom.GenerateHex(8)}",
            SenderFingerprint = UserFingerprint!,
            RecipientFingerprint = recipientFingerprint,
            EncryptedPayload = encryptedPayload,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(expiresInHours),
        };

        await _database!.SaveDeadDropAsync(drop, ct);
    }

    public async Task<List<DeadDrop>> CheckDeadDropsAsync(CancellationToken ct = default)
    {
        EnsureInitialized();
        return await _database!.GetDeadDropsForRecipientAsync(UserFingerprint!, ct);
    }

    public async Task PickUpDeadDropAsync(string dropId, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.MarkDeadDropPickedUpAsync(dropId, ct);
    }

    // ═══════════════ Profile ═══════════════

    public async Task UpdateProfileAsync(CancellationToken ct = default)
    {
        EnsureInitialized();
        if (_userProfile is not null)
            await _database!.SaveUserProfileAsync(_userProfile, ct);
    }

    // ═══════════════ Panic Wipe ═══════════════

    public async Task PanicWipeAsync(CancellationToken ct = default)
    {
        // Wipe DB
        if (_database is not null)
        {
            try { await _database.WipeAllDataAsync(ct); } catch { /* best effort */ }
            await _database.DisposeAsync();
            _database = null;
        }

        // Delete files
        var dbPath = Path.Combine(_dataDirectory, "tordeX.db");
        var saltPath = Path.Combine(_dataDirectory, "salt.bin");
        var walPath = dbPath + "-wal";
        var shmPath = dbPath + "-shm";

        foreach (var path in new[] { dbPath, saltPath, walPath, shmPath })
        {
            if (File.Exists(path))
            {
                // Overwrite with random data before deleting (secure wipe)
                var fileSize = new FileInfo(path).Length;
                if (fileSize > 0 && fileSize < 100_000_000) // Don't try to overwrite huge files
                {
                    var random = new byte[fileSize];
                    RandomNumberGenerator.Fill(random);
                    await File.WriteAllBytesAsync(path, random, ct);
                }
                File.Delete(path);
            }
        }

        // Zero all in-memory keys
        foreach (var (_, key) in _roomKeys)
            CryptographicOperations.ZeroMemory(key);
        _roomKeys.Clear();

        if (_masterKey is not null)
            CryptographicOperations.ZeroMemory(_masterKey);
        _masterKey = null;

        _identity?.Dispose();
        _identity = null;
        _userProfile = null;
        _cachedFingerprint = null;
        _blockedUsers.Clear();

        IsInitialized = false;
    }

    // ═══════════════ Settings ═══════════════

    public async Task SaveSettingAsync(string key, string value, CancellationToken ct = default)
    {
        EnsureInitialized();
        await _database!.SetSettingAsync(key, value, ct);
    }

    public async Task<string?> GetSettingAsync(string key, CancellationToken ct = default)
    {
        EnsureInitialized();
        return await _database!.GetSettingAsync(key, ct);
    }

    // ═══════════════ P2P Broadcasting ═══════════════

    private async Task BroadcastToRoomAsync(string roomId, ChatMessage message, CancellationToken ct)
    {
        if (_identity is null || !_roomPeers.TryGetValue(roomId, out var peers))
            return;

        var roomKey = _roomKeys[roomId];

        var chatPayload = new ChatMessagePayload
        {
            Id = message.Id,
            SenderFingerprint = message.SenderFingerprint,
            SenderDisplayName = message.SenderDisplayName,
            Type = (int)message.Type,
            Content = message.Content,
            FileName = message.FileName,
            FileSize = message.FileSize,
            MimeType = message.MimeType,
            Timestamp = message.Timestamp.ToUnixTimeMilliseconds(),
            ReplyToId = message.ReplyToId,
            ReplyToContent = message.ReplyToContent,
            ReplyToSenderName = message.ReplyToSenderName,
            SelfDestructSeconds = message.SelfDestructSeconds,
            VoiceDuration = message.VoiceDuration,
        };
        var payload = MessagePackSerializer.Serialize(chatPayload);

        // SECURITY FIX: CWE-345 — Bind encryption to roomId via AAD
        var roomIdAad = Encoding.UTF8.GetBytes(roomId);
        var encryptedPayload = MessageEncryption.Encrypt(payload, roomKey, roomIdAad);

        var p2pMessage = new P2PMessage
        {
            Type = P2PMessageType.ChatMessage,
            MessageId = message.Id,
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            Payload = encryptedPayload,
            Signature = [], // placeholder — set below after timestamp is known
            SenderPublicKey = _identity.PublicKey
        };

        // SECURITY FIX: CWE-345 — Sign full message context, not just payload
        var signableContext = BuildSignableContext(roomId, message.Id, UserFingerprint!, p2pMessage.Timestamp, encryptedPayload);
        p2pMessage.Signature = _identity.Sign(signableContext);

        // Iterate snapshot of connected peers, dispose any that fail
        foreach (var peer in peers.Values.Where(p => p.IsConnected).ToArray())
        {
            try
            {
                await peer.SendMessageAsync(p2pMessage, ct);
            }
            catch
            {
                try { await peer.DisposeAsync(); } catch { /* best effort */ }
            }
        }
    }

    // ═══════════════ Background Timers ═══════════════

    private void StartBackgroundTimers()
    {
        _backgroundCts = new CancellationTokenSource();

        // Self-destruct cleanup every 10 seconds
        _selfDestructTimer = new Timer(async _ =>
        {
            if (_disposed) return;
            try
            {
                if (_database is not null)
                    await _database.DeleteSelfDestructedMessagesAsync();
            }
            catch (Exception ex) { _logger.Warn($"Self-destruct cleanup failed: {ex.Message}", "Timer"); }
        }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));

        // Auto-lock check every 30 seconds
        _autoLockTimer = new Timer(_ =>
        {
            if (_disposed) return;
            if (_userProfile?.AutoLockMinutes > 0 && !IsLocked)
            {
                var elapsed = DateTime.UtcNow - _lastActivityTime;
                if (elapsed.TotalMinutes >= _userProfile.AutoLockMinutes)
                {
                    LockApp();
                }
            }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));

        // Periodic peer reconnection — first attempt 15s after startup, then every 45s
        _peerReconnectTimer = new Timer(_ =>
        {
            if (_disposed) return;
            _ = TryReconnectPeersAsync();
        }, null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(45));

        // Heartbeat + dead peer cleanup every 30 seconds
        _heartbeatTimer = new Timer(_ =>
        {
            if (_disposed) return;
            _ = SendHeartbeatsAndCleanupAsync();
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Send heartbeat to all connected peers and TryRemove dead ones.
    /// </summary>
    private async Task SendHeartbeatsAndCleanupAsync()
    {
        foreach (var (roomId, peers) in _roomPeers)
        {
            foreach (var (fingerprint, peer) in peers.ToArray())
            {
                if (!peer.IsConnected)
                {
                    peers.TryRemove(fingerprint, out _);
                    try { await peer.DisposeAsync(); } catch { /* best effort */ }
                    continue;
                }

                try
                {
                    var heartbeat = new Models.P2PMessage
                    {
                        Type = Models.P2PMessageType.Heartbeat,
                        MessageId = Guid.NewGuid().ToString("N"),
                        RoomId = roomId,
                        SenderFingerprint = UserFingerprint ?? "",
                        Payload = [],
                        Signature = [],
                        SenderPublicKey = _identity?.PublicKey ?? []
                    };
                    await peer.SendMessageAsync(heartbeat);
                }
                catch
                {
                    // Heartbeat failed — peer is dead
                    _logger.Info($"Heartbeat failed for peer {peer.PeerDisplayName}, removing", "P2P");
                    peers.TryRemove(fingerprint, out _);
                    try { await peer.DisposeAsync(); } catch { /* best effort */ }
                    OnPeerStatusChanged?.Invoke(peer.PeerFingerprint, false);
                }
            }
        }
    }

    /// <summary>
    /// Try to reconnect to known peer addresses that are currently disconnected.
    /// Checks both in-memory cache and database-stored room onion addresses.
    /// Called by background timer and can be invoked from UI for immediate reconnection.
    /// </summary>
    public async Task TryReconnectPeersAsync()
    {
        if (_torManager is null || !_torManager.IsRunning || _identity is null || IsLocked)
            return;

        // Prevent concurrent reconnect calls (timer overlap)
        if (!_reconnectSemaphore.Wait(0))
            return;

        try
        {
            // Also load peer addresses from DB for rooms that have stored onion addresses
            if (_database is not null)
            {
                try
                {
                    var rooms = await _database.GetRoomsAsync();
                    foreach (var room in rooms)
                    {
                        // Auto-unlock DM rooms so they can be reconnected by the timer
                        if (room.IsDm && !_roomKeys.ContainsKey(room.Id))
                        {
                            UnlockDmRoom(room.Id);
                        }

                        if (!string.IsNullOrEmpty(room.OnionAddress) && _roomKeys.ContainsKey(room.Id))
                        {
                            _knownPeerAddresses.GetOrAdd(room.Id, _ => new ConcurrentDictionary<string, byte>())
                                .TryAdd(room.OnionAddress, 0);
                        }
                    }
                }
                catch (Exception ex) { _logger.Warn($"Failed to load room addresses from DB: {ex.Message}", "P2P"); }
            }

            foreach (var (roomId, addresses) in _knownPeerAddresses)
            {
                // Skip rooms that aren't unlocked
                if (!_roomKeys.ContainsKey(roomId))
                    continue;

                foreach (var addr in addresses.Keys.ToArray())
                {
                    if (addr == _torManager.OnionAddress) continue;

                    // Skip if already connected to this specific onion address
                    if (_roomPeers.TryGetValue(roomId, out var peers)
                        && peers.Values.Any(p => p.IsConnected && p.PeerOnionAddress == addr))
                        continue;

                    try
                    {
                        await ConnectToRoomPeerAsync(roomId, addr);
                    }
                    catch (Exception ex) { _logger.Warn($"Peer reconnect failed for {addr}: {ex.Message}", "P2P"); }
                }
            }
        }
        finally
        {
            _reconnectSemaphore.Release();
        }
    }

    // ═══════════════ TOFU Peer Verification ═══════════════

    /// <summary>
    /// Trust-On-First-Use peer identity verification.
    /// Returns true if the peer should be accepted, false if key mismatch detected.
    /// </summary>
    private async Task<bool> VerifyPeerTofuAsync(string roomId, PeerConnection peer, CancellationToken ct)
    {
        if (_database is null) return true; // No DB = can't verify, accept

        var (knownKey, _) = await _database.GetRoomPeerAsync(roomId, peer.PeerFingerprint, ct);

        if (knownKey is not null)
        {
            // Known peer — verify public key matches
            if (!knownKey.AsSpan().SequenceEqual(peer.PeerPublicKey))
            {
                _logger.Warn($"TOFU key mismatch for peer {peer.PeerFingerprint} in room {roomId[..Math.Min(8, roomId.Length)]} — possible impersonation", "Security");
                OnPeerKeyChanged?.Invoke(peer.PeerFingerprint, roomId);
                return false;
            }
        }
        else
        {
            // First contact — trust and pin
            await _database.SaveOrUpdateRoomPeerAsync(roomId, peer.PeerFingerprint, peer.PeerDisplayName, peer.PeerPublicKey, ct);
            _logger.Info($"TOFU: pinned new peer {peer.PeerFingerprint} in room {roomId[..Math.Min(8, roomId.Length)]}", "Security");
        }

        // Update last_seen timestamp
        await _database.SaveOrUpdateRoomPeerAsync(roomId, peer.PeerFingerprint, peer.PeerDisplayName, peer.PeerPublicKey, ct);
        return true;
    }

    // ═══════════════ Signable Context ═══════════════

    /// <summary>
    /// Build canonical byte sequence for signing: roomId + messageId + senderFingerprint + timestamp + payload.
    /// Prevents cross-room replay and metadata tampering.
    /// </summary>
    private static byte[] BuildSignableContext(string roomId, string messageId, string senderFingerprint, long timestamp, byte[] payload)
    {
        var roomIdBytes = Encoding.UTF8.GetBytes(roomId);
        var messageIdBytes = Encoding.UTF8.GetBytes(messageId);
        var senderBytes = Encoding.UTF8.GetBytes(senderFingerprint);
        var timestampBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(timestamp));

        var result = new byte[roomIdBytes.Length + messageIdBytes.Length + senderBytes.Length + timestampBytes.Length + payload.Length];
        var offset = 0;
        Buffer.BlockCopy(roomIdBytes, 0, result, offset, roomIdBytes.Length); offset += roomIdBytes.Length;
        Buffer.BlockCopy(messageIdBytes, 0, result, offset, messageIdBytes.Length); offset += messageIdBytes.Length;
        Buffer.BlockCopy(senderBytes, 0, result, offset, senderBytes.Length); offset += senderBytes.Length;
        Buffer.BlockCopy(timestampBytes, 0, result, offset, timestampBytes.Length); offset += timestampBytes.Length;
        Buffer.BlockCopy(payload, 0, result, offset, payload.Length);
        return result;
    }

    // ═══════════════ Replay Protection ═══════════════

    /// <summary>
    /// Time-bucketed replay detection. Returns false if the message ID was already seen.
    /// Rotates buckets every 2.5 minutes — total replay window = 5 minutes.
    /// </summary>
    private bool TryAddSeenMessage(string messageId)
    {
        lock (_replayLock)
        {
            // Rotate buckets if enough time has elapsed
            var elapsed = (DateTime.UtcNow - _lastBucketRotation).TotalSeconds;
            if (elapsed >= ReplayBucketIntervalSeconds)
            {
                _replayBucketPrevious = _replayBucketCurrent;
                _replayBucketCurrent = new HashSet<string>();
                _lastBucketRotation = DateTime.UtcNow;
            }

            // Check both buckets for duplicate
            if (_replayBucketCurrent.Contains(messageId) || _replayBucketPrevious.Contains(messageId))
                return false;

            _replayBucketCurrent.Add(messageId);
            return true;
        }
    }

    // ═══════════════ Helpers ═══════════════

    /// <summary>
    /// Force-kill the Tor process. Safe to call during app shutdown, even after disposal.
    /// </summary>
    public void ForceKillTor()
    {
        try { _torManager?.ForceKillTorProcess(); } catch { /* best effort */ }
    }

    private void EnsureInitialized()
    {
        if (!IsInitialized || _database is null || _identity is null)
            throw new InvalidOperationException("ChatService not initialized. Login or create profile first.");
    }

    private void EnsureRoomUnlocked(string roomId)
    {
        if (!_roomKeys.ContainsKey(roomId))
            throw new InvalidOperationException($"Room {roomId} is not unlocked. Call UnlockRoom first.");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        // Clear event handlers early to prevent callbacks during disposal (avoids UI deadlocks)
        OnMessageReceived = null;
        OnPeerStatusChanged = null;
        OnTorStatusChanged = null;
        OnBootstrapProgressChanged = null;
        OnNotification = null;
        OnAutoLocked = null;
        OnPeerKeyChanged = null;
        OnConnectionFailed = null;
        OnDmAccepted = null;

        // Cancel all background operations before disposing timers
        try { _backgroundCts?.Cancel(); } catch { /* best effort */ }
        _backgroundCts?.Dispose();
        _backgroundCts = null;

        _selfDestructTimer?.Dispose();
        _autoLockTimer?.Dispose();
        _peerReconnectTimer?.Dispose();
        _heartbeatTimer?.Dispose();

        foreach (var (_, peers) in _roomPeers)
        {
            foreach (var peer in peers.Values)
            {
                try { await peer.DisposeAsync(); } catch { /* best effort */ }
            }
        }
        _roomPeers.Clear();

        foreach (var (_, key) in _roomKeys)
            CryptographicOperations.ZeroMemory(key);
        _roomKeys.Clear();

        if (_p2pServer is not null)
            await _p2pServer.DisposeAsync();

        if (_torManager is not null)
            await _torManager.DisposeAsync();

        _identity?.Dispose();

        if (_database is not null)
            await _database.DisposeAsync();

        if (_masterKey is not null)
            CryptographicOperations.ZeroMemory(_masterKey);

        _reconnectSemaphore.Dispose();

        _logger.Info("ChatService disposed — graceful shutdown", "App");
        _logger.Dispose();
    }
}
