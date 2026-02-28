using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Configuration for automatic key rotation policies.
/// </summary>
/// <param name="MaxMessages">Maximum messages before rotation is required (default: 100).</param>
/// <param name="MaxLifetimeMinutes">Maximum key lifetime in minutes (default: 60).</param>
/// <param name="Enabled">Whether automatic rotation is enabled.</param>
public sealed record AutoRotationConfig(
    int MaxMessages = 100,
    int MaxLifetimeMinutes = 60,
    bool Enabled = true);

/// <summary>
/// Represents an ephemeral ECDH P-256 key pair with lifecycle metadata.
/// </summary>
public sealed class EphemeralKeyPair : IDisposable
{
    private bool _disposed;
    private ECDiffieHellman? _keyPair;

    /// <summary>Unique identifier for this key pair.</summary>
    public string Id { get; }

    /// <summary>SPKI-encoded public key bytes.</summary>
    public byte[] PublicKey { get; }

    /// <summary>PKCS#8-encoded private key bytes. Zeroed on disposal.</summary>
    public byte[] PrivateKey { get; }

    /// <summary>Timestamp when this key pair was created.</summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>Timestamp when this key pair expires.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Whether this key pair has exceeded its time-to-live.</summary>
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt || _disposed;

    /// <summary>
    /// Gets the underlying <see cref="ECDiffieHellman"/> instance for DH operations.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown if the key pair has been disposed.</exception>
    public ECDiffieHellman KeyPairHandle
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _keyPair!;
        }
    }

    internal EphemeralKeyPair(
        string id,
        byte[] publicKey,
        byte[] privateKey,
        ECDiffieHellman keyPair,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Id = id;
        PublicKey = publicKey;
        PrivateKey = privateKey;
        _keyPair = keyPair;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _keyPair?.Dispose();
        _keyPair = null;
        CryptographicOperations.ZeroMemory(PrivateKey);
        _disposed = true;
    }
}

/// <summary>
/// Manages ephemeral ECDH key pair generation, rotation, and session key derivation.
/// Ephemeral keys have a limited lifetime and message count to provide forward secrecy.
/// </summary>
public static class EphemeralKeyService
{
    private const int KeyLength = 32;

    private static readonly byte[] SessionKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-ephemeral-session-v1");

    /// <summary>
    /// Generates a new ephemeral ECDH P-256 key pair with the specified time-to-live.
    /// </summary>
    /// <param name="ttlMinutes">Key lifetime in minutes. Must be between 1 and 1440 (24 hours).</param>
    /// <returns>A new <see cref="EphemeralKeyPair"/> instance.</returns>
    public static EphemeralKeyPair GenerateEphemeralPair(int ttlMinutes = 60)
    {
        if (ttlMinutes < 1 || ttlMinutes > 1440)
            throw new ArgumentOutOfRangeException(nameof(ttlMinutes), "TTL must be between 1 and 1440 minutes.");

        var keyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = keyPair.PublicKey.ExportSubjectPublicKeyInfo();
        var privateKey = keyPair.ExportPkcs8PrivateKey();
        var now = DateTimeOffset.UtcNow;

        var id = GenerateKeyId();

        return new EphemeralKeyPair(
            id: id,
            publicKey: publicKey,
            privateKey: privateKey,
            keyPair: keyPair,
            createdAt: now,
            expiresAt: now.AddMinutes(ttlMinutes));
    }

    /// <summary>
    /// Rotates the current key pair by generating a fresh one. The caller is responsible
    /// for disposing the old key pair after transitioning.
    /// </summary>
    /// <param name="currentPair">The current key pair to replace. Not disposed by this method.</param>
    /// <returns>A new <see cref="EphemeralKeyPair"/> with the same TTL duration as the original.</returns>
    public static EphemeralKeyPair RotateKey(EphemeralKeyPair currentPair)
    {
        ArgumentNullException.ThrowIfNull(currentPair);

        // Preserve the TTL duration from the original pair
        var ttlMinutes = (int)(currentPair.ExpiresAt - currentPair.CreatedAt).TotalMinutes;
        if (ttlMinutes < 1) ttlMinutes = 60; // Fallback to default if somehow invalid

        return GenerateEphemeralPair(ttlMinutes);
    }

    /// <summary>
    /// Determines whether a key pair should be rotated based on message count
    /// and configured rotation policy.
    /// </summary>
    /// <param name="pair">The key pair to evaluate.</param>
    /// <param name="maxMessages">Maximum number of messages before rotation is needed.</param>
    /// <param name="messageCount">Current number of messages processed with this key.</param>
    /// <returns><c>true</c> if the key should be rotated.</returns>
    public static bool ShouldRotate(EphemeralKeyPair pair, int maxMessages, int messageCount)
    {
        ArgumentNullException.ThrowIfNull(pair);
        if (maxMessages < 1)
            throw new ArgumentOutOfRangeException(nameof(maxMessages), "Max messages must be at least 1.");

        // Rotate if expired, message limit reached, or approaching expiry (within 10%)
        if (pair.IsExpired)
            return true;

        if (messageCount >= maxMessages)
            return true;

        // Proactive rotation: rotate when 90% of lifetime has elapsed
        var totalLifetime = pair.ExpiresAt - pair.CreatedAt;
        var elapsed = DateTimeOffset.UtcNow - pair.CreatedAt;
        if (elapsed >= totalLifetime * 0.9)
            return true;

        return false;
    }

    /// <summary>
    /// Determines whether a key pair should be rotated using an <see cref="AutoRotationConfig"/>.
    /// </summary>
    /// <param name="pair">The key pair to evaluate.</param>
    /// <param name="config">Rotation policy configuration.</param>
    /// <param name="messageCount">Current number of messages processed with this key.</param>
    /// <returns><c>true</c> if rotation is needed and auto-rotation is enabled.</returns>
    public static bool ShouldRotate(EphemeralKeyPair pair, AutoRotationConfig config, int messageCount)
    {
        ArgumentNullException.ThrowIfNull(pair);
        ArgumentNullException.ThrowIfNull(config);

        if (!config.Enabled)
            return false;

        return ShouldRotate(pair, config.MaxMessages, messageCount);
    }

    /// <summary>
    /// Derives a 32-byte session key from a local private key and remote public key
    /// using ECDH key agreement followed by HKDF-SHA256.
    /// </summary>
    /// <param name="localPrivate">Local ECDH private key (PKCS#8-encoded).</param>
    /// <param name="remotePublic">Remote ECDH public key (SPKI-encoded).</param>
    /// <returns>32-byte derived session key.</returns>
    public static byte[] DeriveSessionKey(byte[] localPrivate, byte[] remotePublic)
    {
        ArgumentNullException.ThrowIfNull(localPrivate);
        ArgumentNullException.ThrowIfNull(remotePublic);
        if (localPrivate.Length == 0)
            throw new ArgumentException("Local private key cannot be empty.", nameof(localPrivate));
        if (remotePublic.Length == 0)
            throw new ArgumentException("Remote public key cannot be empty.", nameof(remotePublic));

        using var localKey = ECDiffieHellman.Create();
        localKey.ImportPkcs8PrivateKey(localPrivate, out _);

        using var remoteKey = ECDiffieHellman.Create();
        remoteKey.ImportSubjectPublicKeyInfo(remotePublic, out _);

        var rawSecret = localKey.DeriveKeyFromHash(remoteKey.PublicKey, HashAlgorithmName.SHA256);

        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: rawSecret,
                outputLength: KeyLength,
                info: SessionKeyInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawSecret);
        }
    }

    /// <summary>
    /// Derives a 32-byte session key directly from <see cref="EphemeralKeyPair"/> instances.
    /// </summary>
    /// <param name="localPair">Local ephemeral key pair.</param>
    /// <param name="remotePublicKey">Remote party's SPKI-encoded public key.</param>
    /// <returns>32-byte derived session key.</returns>
    public static byte[] DeriveSessionKey(EphemeralKeyPair localPair, byte[] remotePublicKey)
    {
        ArgumentNullException.ThrowIfNull(localPair);
        ArgumentNullException.ThrowIfNull(remotePublicKey);

        if (localPair.IsExpired)
            throw new InvalidOperationException("Cannot derive session key from an expired key pair.");

        return DeriveSessionKey(localPair.PrivateKey, remotePublicKey);
    }

    /// <summary>
    /// Generates a cryptographically random key identifier.
    /// Format: hex-encoded 16 bytes (32 hex characters).
    /// </summary>
    private static string GenerateKeyId()
    {
        var idBytes = new byte[16];
        RandomNumberGenerator.Fill(idBytes);
        return Convert.ToHexString(idBytes).ToLowerInvariant();
    }
}
