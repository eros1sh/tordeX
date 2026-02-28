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
    private const int P2PListenPort = 19876;
    private byte[]? _masterKey;
    private UserProfile? _userProfile;
    private bool _disposed;
    private Timer? _selfDestructTimer;
    private Timer? _autoLockTimer;
    private DateTime _lastActivityTime = DateTime.UtcNow;

    // Active room keys (room ID -> derived key)
    private readonly ConcurrentDictionary<string, byte[]> _roomKeys = new();

    // Active peer connections per room
    private readonly ConcurrentDictionary<string, List<PeerConnection>> _roomPeers = new();

    // Blocked users cache
    private readonly ConcurrentDictionary<string, bool> _blockedUsers = new();

    public bool IsInitialized { get; private set; }
    public bool IsLocked { get; private set; }
    public bool IsTorConnected => _torManager?.IsRunning ?? false;
    public UserProfile? CurrentUser => _userProfile;
    public string? UserFingerprint => _identity is not null
        ? IdentityManager.ComputeFingerprint(_identity.PublicKey)
        : null;

    #pragma warning disable CS0067
    public event Action<ChatMessage>? OnMessageReceived;
    public event Action<string, bool>? OnPeerStatusChanged;
    public event Action<bool>? OnTorStatusChanged;
    public event Action<string>? OnNotification;
    public event Action? OnAutoLocked;
    public event Action<string, string>? OnTypingIndicator; // roomId, senderName
    #pragma warning restore CS0067

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
        var keyData = _identity!.Sign(Array.Empty<byte>()); // dummy — we need the raw key
        var newEncryptedKey = _identity.ExportEncrypted(newMasterKey);

        // Update profile
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
        };

        await _database!.SaveUserProfileAsync(updatedProfile, ct);
        await SaveSaltAsync(newSalt, ct);

        // Close and reopen DB with new key
        await _database.DisposeAsync();

        CryptographicOperations.ZeroMemory(_masterKey!);
        _masterKey = newMasterKey;

        _database = new SecureDatabase(Path.Combine(_dataDirectory, "tordeX.db"), _logger);
        await _database.InitializeAsync(_masterKey, ct);

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

    public async Task StartTorAsync(CancellationToken ct = default)
    {
        _torManager = new TorManager(Path.Combine(_dataDirectory, "tor"));
        _torManager.ConnectionStatusChanged += status => OnTorStatusChanged?.Invoke(status);
        await _torManager.StartAsync(ct);

        // Start P2P server and create hidden service
        await StartP2PServerAsync(ct);
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

    private async Task StartP2PServerAsync(CancellationToken ct)
    {
        if (_torManager is null || !_torManager.IsRunning)
            return;

        _p2pServer = new P2PServer(P2PListenPort, _torManager.SocksPort);
        _p2pServer.PeerConnected += HandleIncomingPeer;
        await _p2pServer.StartAsync(ct);

        // Create Tor hidden service pointing to our P2P listener
        try
        {
            await _torManager.CreateHiddenServiceAsync(P2PListenPort, ct);
        }
        catch (Exception ex)
        {
            _logger.Error("Hidden service creation failed", ex, "TorSetup");
        }
    }

    /// <summary>
    /// Connect to a remote peer's hidden service for a specific room.
    /// </summary>
    public async Task ConnectToRoomPeerAsync(string roomId, string onionAddress, CancellationToken ct = default)
    {
        if (_torManager is null || !_torManager.IsRunning || _identity is null || _userProfile is null)
            return;

        // Don't connect to ourselves
        if (onionAddress == _torManager.OnionAddress)
            return;

        // Check if already connected to this peer in this room
        if (_roomPeers.TryGetValue(roomId, out var existingPeers))
        {
            if (existingPeers.Any(p => p.IsConnected))
                return;
        }

        var peer = new PeerConnection(onionAddress, P2PListenPort, _torManager.SocksPort);

        try
        {
            await peer.ConnectAsync(ct);
            await peer.HandshakeAsync(_identity, _userProfile.DisplayName, roomId, ct);

            WirePeerEvents(peer, roomId);
            peer.StartReceiving();

            if (!_roomPeers.ContainsKey(roomId))
                _roomPeers[roomId] = new List<PeerConnection>();
            _roomPeers[roomId].Add(peer);

            OnPeerStatusChanged?.Invoke(peer.PeerFingerprint, true);
        }
        catch (Exception ex)
        {
            _logger.Error("Peer connection failed", ex, "P2P");
            await peer.DisposeAsync();
        }
    }

    private void HandleIncomingPeer(PeerConnection peer)
    {
        // Process async on thread pool to not block the accept loop
        _ = Task.Run(async () =>
        {
            try
            {
                if (_identity is null || _userProfile is null) return;

                // Respond to handshake (receive first, then send)
                var roomId = await peer.RespondToHandshakeAsync(
                    _identity, _userProfile.DisplayName);

                // Verify we have this room and its key
                if (!_roomKeys.ContainsKey(roomId))
                {
                    await peer.DisposeAsync();
                    return;
                }

                // Check if peer is blocked
                if (_blockedUsers.ContainsKey(peer.PeerFingerprint))
                {
                    await peer.DisposeAsync();
                    return;
                }

                WirePeerEvents(peer, roomId);
                peer.StartReceiving();

                if (!_roomPeers.ContainsKey(roomId))
                    _roomPeers[roomId] = new List<PeerConnection>();
                _roomPeers[roomId].Add(peer);

                OnPeerStatusChanged?.Invoke(peer.PeerFingerprint, true);
            }
            catch (Exception ex)
            {
                _logger.Error("Incoming peer handling failed", ex, "P2P");
                try { await peer.DisposeAsync(); } catch { /* best effort */ }
            }
        });
    }

    private void WirePeerEvents(PeerConnection peer, string roomId)
    {
        peer.MessageReceived += msg => HandleReceivedP2PMessage(msg);
        peer.Disconnected += disconnectedPeer =>
        {
            if (_roomPeers.TryGetValue(roomId, out var peerList))
                peerList.Remove(disconnectedPeer);
            OnPeerStatusChanged?.Invoke(disconnectedPeer.PeerFingerprint, false);
        };
    }

    private void HandleReceivedP2PMessage(P2PMessage msg)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                if (msg.Type != P2PMessageType.ChatMessage) return;
                if (!_roomKeys.TryGetValue(msg.RoomId, out var roomKey)) return;
                if (_blockedUsers.ContainsKey(msg.SenderFingerprint)) return;

                // Verify signature
                if (!IdentityManager.Verify(msg.Payload, msg.Signature, msg.SenderPublicKey))
                    return;

                // Decrypt payload
                var decryptedPayload = MessageEncryption.Decrypt(msg.Payload, roomKey);
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
            OnionAddress = _torManager?.OnionAddress,
        };

        await _database!.SaveRoomAsync(room, ct);
        _roomKeys[room.Id] = roomKey;

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
        // Format: tordex://join/<roomId>/<inviteToken>/<onionAddress>
        var onion = room.OnionAddress ?? _torManager?.OnionAddress ?? "";
        return $"tordex://join/{room.Id}/{room.InviteToken ?? SecureRandom.GenerateHex(16)}/{onion}";
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

        foreach (var msg in messages)
        {
            msg.IsOwn = msg.SenderFingerprint == UserFingerprint;
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

        var record = new KeyRotationRecord
        {
            Id = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            OldPublicKey = oldKey,
            NewPublicKey = newKey,
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

        var encryptedPayload = MessageEncryption.Encrypt(payload, roomKey);
        var signature = _identity.Sign(encryptedPayload);

        var p2pMessage = new P2PMessage
        {
            Type = P2PMessageType.ChatMessage,
            MessageId = message.Id,
            RoomId = roomId,
            SenderFingerprint = UserFingerprint!,
            Payload = encryptedPayload,
            Signature = signature,
            SenderPublicKey = _identity.PublicKey
        };

        var disconnected = new List<PeerConnection>();

        foreach (var peer in peers.ToArray())
        {
            try
            {
                await peer.SendMessageAsync(p2pMessage, ct);
            }
            catch
            {
                disconnected.Add(peer);
            }
        }

        foreach (var peer in disconnected)
        {
            peers.Remove(peer);
            await peer.DisposeAsync();
        }
    }

    // ═══════════════ Background Timers ═══════════════

    private void StartBackgroundTimers()
    {
        // Self-destruct cleanup every 10 seconds
        _selfDestructTimer = new Timer(async _ =>
        {
            try
            {
                if (_database is not null)
                    await _database.DeleteSelfDestructedMessagesAsync();
            }
            catch { /* best effort */ }
        }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));

        // Auto-lock check every 30 seconds
        _autoLockTimer = new Timer(_ =>
        {
            if (_userProfile?.AutoLockMinutes > 0 && !IsLocked)
            {
                var elapsed = DateTime.UtcNow - _lastActivityTime;
                if (elapsed.TotalMinutes >= _userProfile.AutoLockMinutes)
                {
                    LockApp();
                }
            }
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    // ═══════════════ Helpers ═══════════════

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

        _selfDestructTimer?.Dispose();
        _autoLockTimer?.Dispose();

        foreach (var (_, peers) in _roomPeers)
        {
            foreach (var peer in peers)
                await peer.DisposeAsync();
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

        _logger.Info("ChatService disposed — graceful shutdown", "App");
        _logger.Dispose();
    }
}
