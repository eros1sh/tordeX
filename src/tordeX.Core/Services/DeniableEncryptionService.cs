using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Deniable (OTR-style) encryption service providing cryptographic deniability.
/// <para>
/// Uses HMAC-SHA256 for message authentication instead of digital signatures.
/// Since HMAC is a symmetric operation, either party who shares the MAC key could
/// have generated the tag, making messages cryptographically deniable — a third
/// party cannot prove which participant authored a given message.
/// </para>
/// <para>
/// Encryption uses AES-256-GCM with a shared DH-derived encryption key.
/// The MAC is computed over the ciphertext (Encrypt-then-MAC) using a separate
/// DH-derived MAC key.
/// </para>
/// </summary>
public static class DeniableEncryptionService
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int HmacLength = 32;

    private static readonly byte[] EncryptionKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-deniable-enc-v1");

    private static readonly byte[] MacKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-deniable-mac-v1");

    /// <summary>
    /// Generates a new ECDH P-256 key pair for deniable encryption.
    /// The caller owns the returned instance and must dispose it when no longer needed.
    /// </summary>
    /// <returns>A new <see cref="ECDiffieHellman"/> key pair on the P-256 curve.</returns>
    public static ECDiffieHellman GenerateDeniableKeyPair()
    {
        return ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    }

    /// <summary>
    /// Encrypts plaintext with deniable authentication.
    /// Uses AES-256-GCM for confidentiality and HMAC-SHA256 (Encrypt-then-MAC) for
    /// deniable authentication over the ciphertext.
    /// </summary>
    /// <param name="plaintext">Message to encrypt (must not be empty).</param>
    /// <param name="senderKey">Sender's ECDH private key (PKCS#8-encoded).</param>
    /// <param name="receiverKey">Receiver's ECDH public key (SPKI-encoded).</param>
    /// <returns>
    /// Tuple of (ciphertext, mac) where ciphertext is [12 nonce][16 GCM tag][encrypted data]
    /// and mac is a 32-byte HMAC-SHA256 over the ciphertext.
    /// </returns>
    public static (byte[] Ciphertext, byte[] Mac) DeniableEncrypt(
        byte[] plaintext,
        byte[] senderKey,
        byte[] receiverKey)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentNullException.ThrowIfNull(receiverKey);
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

        var (encryptionKey, macKey) = DeriveSharedKeys(senderKey, receiverKey);

        try
        {
            var ciphertext = AesGcmEncrypt(encryptionKey, plaintext);
            var mac = ComputeHmac(macKey, ciphertext);
            return (ciphertext, mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    /// <summary>
    /// Decrypts a deniably-encrypted message after verifying the HMAC.
    /// </summary>
    /// <param name="ciphertext">The encrypted message.</param>
    /// <param name="mac">The HMAC-SHA256 tag to verify.</param>
    /// <param name="senderKey">Sender's ECDH public key (SPKI-encoded).</param>
    /// <param name="receiverKey">Receiver's ECDH private key (PKCS#8-encoded).</param>
    /// <returns>Decrypted plaintext.</returns>
    /// <exception cref="CryptographicException">Thrown if the MAC verification fails.</exception>
    public static byte[] DeniableDecrypt(
        byte[] ciphertext,
        byte[] mac,
        byte[] senderKey,
        byte[] receiverKey)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentNullException.ThrowIfNull(receiverKey);
        if (mac.Length != HmacLength)
            throw new ArgumentException($"MAC must be exactly {HmacLength} bytes.", nameof(mac));

        // Note: for decryption, the receiver passes their private key as receiverKey
        // and the sender's public key as senderKey. DeriveSharedKeys is symmetric
        // with respect to the DH operation, so both sides derive the same keys.
        var (encryptionKey, macKey) = DeriveSharedKeys(receiverKey, senderKey);

        try
        {
            // Verify MAC before decryption (constant-time comparison)
            var expectedMac = ComputeHmac(macKey, ciphertext);
            if (!CryptographicOperations.FixedTimeEquals(mac, expectedMac))
                throw new CryptographicException("HMAC verification failed. Message may have been tampered with.");

            return AesGcmDecrypt(encryptionKey, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptionKey);
            CryptographicOperations.ZeroMemory(macKey);
        }
    }

    /// <summary>
    /// Derives a shared encryption key and a shared MAC key from the ECDH shared secret.
    /// Both parties derive identical keys because ECDH is commutative.
    /// The two keys are derived with distinct HKDF info strings for domain separation.
    /// </summary>
    /// <param name="localPrivate">Local ECDH private key (PKCS#8-encoded).</param>
    /// <param name="remotePublic">Remote ECDH public key (SPKI-encoded).</param>
    /// <returns>Tuple of (encryptionKey, macKey), each 32 bytes.</returns>
    public static (byte[] EncryptionKey, byte[] MacKey) DeriveSharedKeys(
        byte[] localPrivate,
        byte[] remotePublic)
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
            var encryptionKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: rawSecret,
                outputLength: KeyLength,
                info: EncryptionKeyInfo);

            var macKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: rawSecret,
                outputLength: KeyLength,
                info: MacKeyInfo);

            return (encryptionKey, macKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rawSecret);
        }
    }

    /// <summary>
    /// Computes HMAC-SHA256 over the given data using the provided key.
    /// </summary>
    private static byte[] ComputeHmac(byte[] key, byte[] data)
    {
        return HMACSHA256.HashData(key, data);
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
            throw new CryptographicException("Encrypted data is too short to be valid.");

        var nonce = data.AsSpan(0, NonceLength);
        var tag = data.AsSpan(NonceLength, TagLength);
        var ciphertext = data.AsSpan(NonceLength + TagLength);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
