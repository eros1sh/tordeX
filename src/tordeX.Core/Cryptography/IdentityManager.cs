using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TordeX.Core.Cryptography;

/// <summary>
/// Manages the user's cryptographic identity (signing keypair).
/// Used for message authentication and peer verification.
/// </summary>
public sealed class IdentityManager : IDisposable
{
    private ECDsa? _signingKey;
    private bool _disposed;

    /// <summary>
    /// Public key (identity) — can be freely shared.
    /// </summary>
    public byte[] PublicKey { get; }

    /// <summary>
    /// Short fingerprint of the public key for display.
    /// Format: XXXX-XXXX-XXXX-XXXX
    /// </summary>
    public string Fingerprint { get; }

    private IdentityManager(ECDsa signingKey)
    {
        _signingKey = signingKey;
        PublicKey = signingKey.ExportSubjectPublicKeyInfo();
        Fingerprint = ComputeFingerprint(PublicKey);
    }

    /// <summary>
    /// Generate a fresh identity keypair.
    /// </summary>
    public static IdentityManager Generate()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new IdentityManager(key);
    }

    /// <summary>
    /// Load identity from encrypted key data.
    /// </summary>
    public static IdentityManager LoadFromEncrypted(byte[] encryptedKeyData, byte[] masterKey)
    {
        var keyData = MessageEncryption.Decrypt(encryptedKeyData, masterKey);
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(keyData, out _);
        CryptographicOperations.ZeroMemory(keyData);
        return new IdentityManager(key);
    }

    /// <summary>
    /// Export identity as encrypted blob (for secure storage).
    /// </summary>
    public byte[] ExportEncrypted(byte[] masterKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_signingKey is null)
            throw new InvalidOperationException("Signing key disposed.");

        var keyData = _signingKey.ExportPkcs8PrivateKey();
        var encrypted = MessageEncryption.Encrypt(keyData, masterKey);
        CryptographicOperations.ZeroMemory(keyData);
        return encrypted;
    }

    /// <summary>
    /// Sign a message with our private key.
    /// </summary>
    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_signingKey is null)
            throw new InvalidOperationException("Signing key disposed.");

        return _signingKey.SignData(data, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Verify a signature from a peer's public key.
    /// </summary>
    public static bool Verify(byte[] data, byte[] signature, byte[] peerPublicKey)
    {
        using var peerKey = ECDsa.Create();
        peerKey.ImportSubjectPublicKeyInfo(peerPublicKey, out _);
        return peerKey.VerifyData(data, signature, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Compute a human-readable fingerprint from a public key.
    /// Format: XXXX-XXXX-XXXX-XXXX
    /// </summary>
    public static string ComputeFingerprint(byte[] publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        var hex = Convert.ToHexString(hash)[..16].ToUpperInvariant();
        return $"{hex[..4]}-{hex[4..8]}-{hex[8..12]}-{hex[12..16]}";
    }

    public void Dispose()
    {
        if (_disposed) return;
        _signingKey?.Dispose();
        _signingKey = null;
        _disposed = true;
    }
}
