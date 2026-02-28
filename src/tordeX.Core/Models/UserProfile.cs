namespace TordeX.Core.Models;

/// <summary>
/// Local user profile (stored encrypted on disk).
/// </summary>
public sealed class UserProfile
{
    public required string Id { get; init; }
    public required string DisplayName { get; set; }
    public required byte[] PublicKey { get; init; }
    public required byte[] EncryptedPrivateKey { get; init; }
    public required byte[] PasswordSalt { get; init; }
    public required byte[] PasswordHash { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastLoginAt { get; set; } = DateTimeOffset.UtcNow;

    // Profile avatar (PNG/JPG bytes, null = use initials)
    public byte[]? AvatarData { get; set; }

    // Language preference ("en", "tr")
    public string Language { get; set; } = "en";

    // Auto-lock timeout in minutes (0 = disabled)
    public int AutoLockMinutes { get; set; }

    // Notification sounds enabled
    public bool NotificationSounds { get; set; } = true;

    // Screen capture protection enabled
    public bool ScreenCaptureProtection { get; set; }

    // Show message timestamps
    public bool ShowTimestamps { get; set; } = true;

    // ──── Security & Privacy Settings ────

    // Double ratchet forward secrecy
    public bool DoubleRatchetEnabled { get; set; } = true;

    // Post-quantum crypto layer
    public bool PostQuantumEnabled { get; set; }

    // Multi-layer encryption (double AES-256-GCM)
    public bool MultiLayerEncryption { get; set; }

    // Deniable encryption mode
    public bool DeniableEncryption { get; set; }

    // Traffic obfuscation (padding + decoy packets)
    public bool TrafficObfuscation { get; set; } = true;

    // Timing attack protection (random message delays)
    public bool TimingProtection { get; set; } = true;

    // RAM-only mode (no messages written to disk)
    public bool RamOnlyMode { get; set; }

    // DNS leak protection
    public bool DnsLeakProtection { get; set; } = true;

    // Dead man's switch (auto-wipe after inactivity)
    public bool DeadManSwitch { get; set; }
    public int DeadManSwitchDays { get; set; } = 30;

    // Tamper detection (anti-debug)
    public bool TamperDetection { get; set; } = true;

    // Integrity monitoring (file hash verification)
    public bool IntegrityMonitoring { get; set; } = true;

    // Canary tokens in database
    public bool CanaryTokens { get; set; } = true;

    // Auto metadata stripping for all file types
    public bool AutoMetadataStrip { get; set; } = true;

    // Tor bridge/pluggable transport
    public string? TorBridgeLine { get; set; }
    public string? TorPluggableTransport { get; set; }

    // Guard node pinning
    public string? PinnedGuardNodes { get; set; }

    // Brute force protection
    public int MaxLoginAttempts { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;
}
