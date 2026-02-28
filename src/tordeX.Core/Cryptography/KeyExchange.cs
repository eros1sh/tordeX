using System.Security.Cryptography;

namespace TordeX.Core.Cryptography;

/// <summary>
/// X25519 Elliptic Curve Diffie-Hellman key exchange.
/// Each peer generates an ephemeral keypair, exchanges public keys,
/// and derives a shared secret for symmetric encryption.
/// </summary>
public sealed class KeyExchange : IDisposable
{
    private ECDiffieHellman? _privateKey;
    private bool _disposed;

    /// <summary>
    /// Our public key to share with the peer.
    /// </summary>
    public byte[] PublicKey { get; }

    public KeyExchange()
    {
        _privateKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        PublicKey = _privateKey.PublicKey.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// Derive a shared 256-bit key from our private key + peer's public key.
    /// The result is run through HKDF for proper key derivation.
    /// </summary>
    public byte[] DeriveSharedSecret(byte[] peerPublicKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_privateKey is null)
            throw new InvalidOperationException("Private key has been disposed.");

        using var peerKey = ECDiffieHellman.Create();
        peerKey.ImportSubjectPublicKeyInfo(peerPublicKey, out _);

        // Raw shared secret from ECDH
        var rawSecret = _privateKey.DeriveKeyFromHash(
            peerKey.PublicKey,
            HashAlgorithmName.SHA256);

        // HKDF expansion for proper key derivation with domain separation
        var info = System.Text.Encoding.UTF8.GetBytes("tordeX-session-key-v1");
        var derivedKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            rawSecret,
            outputLength: 32,
            info: info);

        CryptographicOperations.ZeroMemory(rawSecret);
        return derivedKey;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _privateKey?.Dispose();
        _privateKey = null;
        _disposed = true;
    }
}
