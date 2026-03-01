using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Cryptography;

/// <summary>
/// Symmetric authenticated encryption using AES-256-GCM.
/// Every message gets a unique nonce (96-bit, random).
/// Format: [nonce:12][ciphertext:N][tag:16]
/// </summary>
public static class MessageEncryption
{
    private const int NonceLength = 12;  // 96-bit nonce (AES-GCM standard)
    private const int TagLength = 16;    // 128-bit authentication tag
    private const int KeyLength = 32;    // 256-bit key

    /// <summary>
    /// Encrypt plaintext with AES-256-GCM.
    /// Returns: nonce || ciphertext || tag
    /// </summary>
    public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        ValidateKey(key);
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

        var nonce = SecureRandom.GenerateBytes(NonceLength);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        // Wire format: [nonce:12][ciphertext:N][tag:16]
        var result = new byte[NonceLength + ciphertext.Length + TagLength];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceLength);
        Buffer.BlockCopy(ciphertext, 0, result, NonceLength, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceLength + ciphertext.Length, TagLength);

        return result;
    }

    /// <summary>
    /// Decrypt ciphertext with AES-256-GCM.
    /// Input format: nonce || ciphertext || tag
    /// </summary>
    public static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[]? associatedData = null)
    {
        ValidateKey(key);

        var minimumLength = NonceLength + 1 + TagLength; // At least 1 byte of ciphertext
        if (encryptedData.Length < minimumLength)
            throw new CryptographicException("Encrypted data is too short to be valid.");

        var nonce = new byte[NonceLength];
        var ciphertextLength = encryptedData.Length - NonceLength - TagLength;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagLength];

        Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceLength);
        Buffer.BlockCopy(encryptedData, NonceLength, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(encryptedData, NonceLength + ciphertextLength, tag, 0, TagLength);

        var plaintext = new byte[ciphertextLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);

        return plaintext;
    }

    /// <summary>
    /// Encrypt a string message. Returns base64-encoded ciphertext.
    /// </summary>
    public static string EncryptString(string message, byte[] key, byte[]? associatedData = null)
    {
        var plaintext = Encoding.UTF8.GetBytes(message);
        try
        {
            var encrypted = Encrypt(plaintext, key, associatedData);
            return Convert.ToBase64String(encrypted);
        }
        finally
        {
            // SECURITY FIX: CWE-316 — zero plaintext bytes after encryption
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Decrypt a base64-encoded ciphertext back to string.
    /// </summary>
    public static string DecryptString(string encryptedBase64, byte[] key, byte[]? associatedData = null)
    {
        var encrypted = Convert.FromBase64String(encryptedBase64);
        var decrypted = Decrypt(encrypted, key, associatedData);
        try
        {
            return Encoding.UTF8.GetString(decrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    /// <summary>
    /// Encrypt a file's contents. Returns encrypted bytes.
    /// </summary>
    public static byte[] EncryptFile(byte[] fileData, byte[] key, string? fileName = null)
    {
        // Use filename as associated data for binding
        var aad = fileName != null ? Encoding.UTF8.GetBytes(fileName) : null;
        return Encrypt(fileData, key, aad);
    }

    /// <summary>
    /// Decrypt file contents.
    /// </summary>
    public static byte[] DecryptFile(byte[] encryptedData, byte[] key, string? fileName = null)
    {
        var aad = fileName != null ? Encoding.UTF8.GetBytes(fileName) : null;
        return Decrypt(encryptedData, key, aad);
    }

    private static void ValidateKey(byte[] key)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be exactly {KeyLength} bytes (256-bit).", nameof(key));
    }
}
