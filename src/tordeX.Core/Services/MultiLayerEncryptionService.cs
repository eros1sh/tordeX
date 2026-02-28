using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Multi-layer encryption service providing defense-in-depth through
/// sequential application of independent AES-256-GCM encryption layers.
/// Each layer uses an independent key and random nonce.
/// <para>
/// Per-layer wire format: [12 nonce][16 tag][ciphertext]
/// </para>
/// </summary>
public static class MultiLayerEncryptionService
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int LayerOverhead = NonceLength + TagLength;

    /// <summary>
    /// Applies two independent AES-256-GCM encryption layers.
    /// Layer 1 encrypts with <paramref name="key1"/>, then layer 2 encrypts
    /// the entire result (including nonce and tag) with <paramref name="key2"/>.
    /// </summary>
    /// <param name="plaintext">Data to encrypt (must not be empty).</param>
    /// <param name="key1">Inner layer key (32 bytes).</param>
    /// <param name="key2">Outer layer key (32 bytes).</param>
    /// <returns>Double-encrypted ciphertext.</returns>
    public static byte[] DoubleEncrypt(byte[] plaintext, byte[] key1, byte[] key2)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);
        ValidateKey(key1, nameof(key1));
        ValidateKey(key2, nameof(key2));
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

        var layer1 = EncryptLayer(plaintext, key1);
        var layer2 = EncryptLayer(layer1, key2);
        return layer2;
    }

    /// <summary>
    /// Decrypts a double-encrypted ciphertext by removing layers in reverse order.
    /// </summary>
    /// <param name="ciphertext">Double-encrypted data.</param>
    /// <param name="key1">Inner layer key (32 bytes).</param>
    /// <param name="key2">Outer layer key (32 bytes).</param>
    /// <returns>Decrypted plaintext.</returns>
    public static byte[] DoubleDecrypt(byte[] ciphertext, byte[] key1, byte[] key2)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);
        ValidateKey(key1, nameof(key1));
        ValidateKey(key2, nameof(key2));

        var layer1 = DecryptLayer(ciphertext, key2);
        var plaintext = DecryptLayer(layer1, key1);
        return plaintext;
    }

    /// <summary>
    /// Applies three independent AES-256-GCM encryption layers.
    /// Encrypts sequentially: key1 (innermost), then key2 (middle), then key3 (outermost).
    /// </summary>
    /// <param name="plaintext">Data to encrypt (must not be empty).</param>
    /// <param name="key1">Innermost layer key (32 bytes).</param>
    /// <param name="key2">Middle layer key (32 bytes).</param>
    /// <param name="key3">Outermost layer key (32 bytes).</param>
    /// <returns>Triple-encrypted ciphertext.</returns>
    public static byte[] TripleEncrypt(byte[] plaintext, byte[] key1, byte[] key2, byte[] key3)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);
        ArgumentNullException.ThrowIfNull(key3);
        ValidateKey(key1, nameof(key1));
        ValidateKey(key2, nameof(key2));
        ValidateKey(key3, nameof(key3));
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

        var layer1 = EncryptLayer(plaintext, key1);
        var layer2 = EncryptLayer(layer1, key2);
        var layer3 = EncryptLayer(layer2, key3);
        return layer3;
    }

    /// <summary>
    /// Decrypts a triple-encrypted ciphertext by removing layers in reverse order.
    /// </summary>
    /// <param name="ciphertext">Triple-encrypted data.</param>
    /// <param name="key1">Innermost layer key (32 bytes).</param>
    /// <param name="key2">Middle layer key (32 bytes).</param>
    /// <param name="key3">Outermost layer key (32 bytes).</param>
    /// <returns>Decrypted plaintext.</returns>
    public static byte[] TripleDecrypt(byte[] ciphertext, byte[] key1, byte[] key2, byte[] key3)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(key1);
        ArgumentNullException.ThrowIfNull(key2);
        ArgumentNullException.ThrowIfNull(key3);
        ValidateKey(key1, nameof(key1));
        ValidateKey(key2, nameof(key2));
        ValidateKey(key3, nameof(key3));

        var layer2 = DecryptLayer(ciphertext, key3);
        var layer1 = DecryptLayer(layer2, key2);
        var plaintext = DecryptLayer(layer1, key1);
        return plaintext;
    }

    /// <summary>
    /// Derives <paramref name="numLayers"/> independent encryption keys from a master key
    /// using HKDF-SHA256 with distinct info strings ("layer-1", "layer-2", ...).
    /// </summary>
    /// <param name="masterKey">Master key (32 bytes) from which layer keys are derived.</param>
    /// <param name="numLayers">Number of layer keys to derive (must be >= 1).</param>
    /// <returns>Array of <paramref name="numLayers"/> independent 32-byte keys.</returns>
    public static byte[][] DeriveLayerKeys(byte[] masterKey, int numLayers)
    {
        ArgumentNullException.ThrowIfNull(masterKey);
        ValidateKey(masterKey, nameof(masterKey));
        if (numLayers < 1)
            throw new ArgumentOutOfRangeException(nameof(numLayers), "Must derive at least 1 layer key.");
        if (numLayers > 16)
            throw new ArgumentOutOfRangeException(nameof(numLayers), "Maximum 16 layer keys supported.");

        var keys = new byte[numLayers][];
        for (int i = 0; i < numLayers; i++)
        {
            var info = Encoding.UTF8.GetBytes($"layer-{i + 1}");
            keys[i] = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: masterKey,
                outputLength: KeyLength,
                info: info);
        }

        return keys;
    }

    /// <summary>
    /// Encrypts a single AES-256-GCM layer.
    /// Output format: [12 nonce][16 tag][ciphertext]
    /// </summary>
    private static byte[] EncryptLayer(byte[] plaintext, byte[] key)
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
    /// Decrypts a single AES-256-GCM layer.
    /// Input format: [12 nonce][16 tag][ciphertext]
    /// </summary>
    private static byte[] DecryptLayer(byte[] data, byte[] key)
    {
        var minimumLength = LayerOverhead + 1;
        if (data.Length < minimumLength)
            throw new CryptographicException("Encrypted layer data is too short to be valid.");

        var nonce = data.AsSpan(0, NonceLength);
        var tag = data.AsSpan(NonceLength, TagLength);
        var ciphertext = data.AsSpan(NonceLength + TagLength);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static void ValidateKey(byte[] key, string paramName)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be exactly {KeyLength} bytes (256-bit).", paramName);
    }
}
