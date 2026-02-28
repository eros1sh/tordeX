using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Configuration for the dead man's switch auto-wipe mechanism.
/// </summary>
/// <param name="Enabled">Whether the dead man's switch is active.</param>
/// <param name="MaxInactiveDays">Number of days of inactivity before the switch triggers.</param>
/// <param name="WipeOnTrigger">Whether to execute the wipe action when triggered.</param>
/// <param name="NotifyBeforeDays">Number of days before trigger to start warning the user.</param>
public sealed record DeadManConfig(
    bool Enabled,
    int MaxInactiveDays = 30,
    bool WipeOnTrigger = true,
    int NotifyBeforeDays = 7);

/// <summary>
/// Dead man's switch service that auto-deletes all user data if no login activity
/// is recorded within a configurable inactivity period. State is persisted to an
/// AES-256-GCM encrypted file keyed to the local machine identity.
/// </summary>
public sealed class DeadManSwitchService
{
    private readonly object _lock = new();
    private DateTimeOffset _lastActivity;
    private readonly TimeProvider _timeProvider;

    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int KeyLength = 32;

    /// <summary>
    /// Initializes a new instance of <see cref="DeadManSwitchService"/> using the system clock.
    /// </summary>
    public DeadManSwitchService()
        : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="DeadManSwitchService"/> with a custom time provider (for testing).
    /// </summary>
    /// <param name="timeProvider">Time provider used for all timestamp operations.</param>
    public DeadManSwitchService(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
        _lastActivity = _timeProvider.GetUtcNow();
    }

    /// <summary>
    /// Records user activity, resetting the inactivity timer.
    /// Call this on every successful login or meaningful user interaction.
    /// </summary>
    public void RecordActivity()
    {
        lock (_lock)
        {
            _lastActivity = _timeProvider.GetUtcNow();
        }
    }

    /// <summary>
    /// Gets the timestamp of the last recorded user activity.
    /// </summary>
    /// <returns>The <see cref="DateTimeOffset"/> of the last activity.</returns>
    public DateTimeOffset GetLastActivity()
    {
        lock (_lock)
        {
            return _lastActivity;
        }
    }

    /// <summary>
    /// Determines whether the dead man's switch has been triggered
    /// (i.e., inactivity has exceeded <see cref="DeadManConfig.MaxInactiveDays"/>).
    /// </summary>
    /// <param name="config">The dead man's switch configuration.</param>
    /// <returns>True if the inactivity threshold has been exceeded and the switch is enabled.</returns>
    public bool IsTriggered(DeadManConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!config.Enabled) return false;

        var now = _timeProvider.GetUtcNow();
        DateTimeOffset lastAct;
        lock (_lock) { lastAct = _lastActivity; }

        var inactiveDays = (now - lastAct).TotalDays;
        return inactiveDays >= config.MaxInactiveDays;
    }

    /// <summary>
    /// Determines whether the warning threshold has been reached
    /// (i.e., inactivity is within <see cref="DeadManConfig.NotifyBeforeDays"/> of triggering).
    /// </summary>
    /// <param name="config">The dead man's switch configuration.</param>
    /// <returns>True if the user should be warned about impending data wipe.</returns>
    public bool ShouldWarn(DeadManConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!config.Enabled) return false;

        var daysRemaining = GetDaysRemaining(config);
        return daysRemaining >= 0 && daysRemaining <= config.NotifyBeforeDays;
    }

    /// <summary>
    /// Calculates the number of days remaining before the dead man's switch triggers.
    /// </summary>
    /// <param name="config">The dead man's switch configuration.</param>
    /// <returns>Days remaining (0 or negative means already triggered).</returns>
    public int GetDaysRemaining(DeadManConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var now = _timeProvider.GetUtcNow();
        DateTimeOffset lastAct;
        lock (_lock) { lastAct = _lastActivity; }

        var elapsed = (now - lastAct).TotalDays;
        return (int)Math.Floor(config.MaxInactiveDays - elapsed);
    }

    /// <summary>
    /// Persists the last activity timestamp to an encrypted state file.
    /// The file is encrypted with AES-256-GCM using a machine-specific key
    /// derived from <see cref="GetMachineKey"/>.
    /// </summary>
    /// <param name="filePath">Absolute path to the state file.</param>
    public void SaveState(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        DateTimeOffset lastAct;
        lock (_lock) { lastAct = _lastActivity; }

        var ticks = BitConverter.GetBytes(lastAct.UtcTicks);
        var offsetMinutes = BitConverter.GetBytes((short)lastAct.Offset.TotalMinutes);

        // Plaintext: [8 bytes ticks][2 bytes offset minutes]
        var plaintext = new byte[10];
        Buffer.BlockCopy(ticks, 0, plaintext, 0, 8);
        Buffer.BlockCopy(offsetMinutes, 0, plaintext, 8, 2);

        var key = GetMachineKey();
        try
        {
            var encrypted = AesGcmEncrypt(key, plaintext);
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllBytes(filePath, encrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Loads the last activity timestamp from an encrypted state file.
    /// If the file does not exist or decryption fails, the current time is used.
    /// </summary>
    /// <param name="filePath">Absolute path to the state file.</param>
    public void LoadState(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
        {
            lock (_lock) { _lastActivity = _timeProvider.GetUtcNow(); }
            return;
        }

        var key = GetMachineKey();
        try
        {
            var encrypted = File.ReadAllBytes(filePath);
            var plaintext = AesGcmDecrypt(key, encrypted);

            try
            {
                if (plaintext.Length < 10)
                {
                    lock (_lock) { _lastActivity = _timeProvider.GetUtcNow(); }
                    return;
                }

                var ticks = BitConverter.ToInt64(plaintext, 0);
                var offsetMinutes = BitConverter.ToInt16(plaintext, 8);
                var offset = TimeSpan.FromMinutes(offsetMinutes);

                lock (_lock)
                {
                    _lastActivity = new DateTimeOffset(ticks, TimeSpan.Zero).ToOffset(offset);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (CryptographicException)
        {
            // Decryption failed (machine changed, tampered file) — reset to now
            lock (_lock) { _lastActivity = _timeProvider.GetUtcNow(); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// Checks whether the dead man's switch has triggered and, if so, executes the wipe action.
    /// </summary>
    /// <param name="config">The dead man's switch configuration.</param>
    /// <param name="wipeAction">Async action to execute when the switch triggers (e.g., <c>PanicWipeAsync</c>).</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task CheckAndExecute(DeadManConfig config, Func<Task> wipeAction)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(wipeAction);

        if (!config.Enabled || !config.WipeOnTrigger)
            return;

        if (IsTriggered(config))
        {
            await wipeAction().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Derives a deterministic 32-byte key from machine-specific identifiers.
    /// Uses SHA-256 of <c>Environment.MachineName + Environment.UserName</c>.
    /// This key is not cryptographically secret but ties the encrypted state to the current machine/user,
    /// preventing state file portability (defense-in-depth).
    /// </summary>
    /// <returns>A 32-byte machine-specific key.</returns>
    public static byte[] GetMachineKey()
    {
        var machineIdentity = $"{Environment.MachineName}:{Environment.UserName}:tordeX-dms-v1";
        var identityBytes = Encoding.UTF8.GetBytes(machineIdentity);
        return SHA256.HashData(identityBytes);
    }

    /// <summary>
    /// Encrypts plaintext with AES-256-GCM.
    /// Output format: [12 nonce][16 tag][ciphertext]
    /// </summary>
    private static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext)
    {
        var nonce = new byte[NonceLength];
        RandomNumberGenerator.Fill(nonce);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[NonceLength + TagLength + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceLength);
        Buffer.BlockCopy(tag, 0, result, NonceLength, TagLength);
        Buffer.BlockCopy(ciphertext, 0, result, NonceLength + TagLength, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Decrypts AES-256-GCM ciphertext.
    /// Input format: [12 nonce][16 tag][ciphertext]
    /// </summary>
    private static byte[] AesGcmDecrypt(byte[] key, byte[] data)
    {
        var minimumLength = NonceLength + TagLength + 1;
        if (data.Length < minimumLength)
            throw new CryptographicException("Encrypted dead-man-switch state data is too short.");

        var nonce = data.AsSpan(0, NonceLength);
        var tag = data.AsSpan(NonceLength, TagLength);
        var ciphertext = data.AsSpan(NonceLength + TagLength);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
