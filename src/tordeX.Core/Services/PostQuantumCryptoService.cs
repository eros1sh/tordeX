using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Post-quantum cryptography layer implementing a simplified lattice-based
/// key encapsulation mechanism (KEM) inspired by Kyber / Learning With Errors (LWE).
/// <para>
/// Parameters: n=256, q=12289 (NTT-friendly prime used in Kyber/NewHope).
/// This provides a hybrid encryption layer to complement classical ECDH, offering
/// defense-in-depth against future quantum adversaries.
/// </para>
/// <para>
/// SECURITY NOTE: This is a simplified educational LWE implementation for hybrid layering.
/// It must always be combined with a classical scheme (ECDH) via <see cref="HybridEncrypt"/>
/// so security never relies solely on this module.
/// </para>
/// </summary>
public static class PostQuantumCryptoService
{
    /// <summary>Lattice dimension.</summary>
    private const int N = 256;

    /// <summary>Prime modulus (NTT-friendly, used in Kyber/NewHope families).</summary>
    private const int Q = 12289;

    /// <summary>Bound for discrete Gaussian-like error sampling (centered binomial, eta=3).</summary>
    private const int ErrorBound = 3;

    private const int KeyLength = 32;

    private static readonly byte[] HybridInfo =
        Encoding.UTF8.GetBytes("tordeX-pq-hybrid-v1");

    /// <summary>
    /// Generates a lattice-based public/secret key pair from a seed.
    /// </summary>
    /// <param name="seed">
    /// 32-byte seed for deterministic key generation.
    /// Pass <c>null</c> to generate a random seed internally.
    /// </param>
    /// <returns>Tuple of (publicKey, secretKey) as serialized byte arrays.</returns>
    public static (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair(byte[]? seed = null)
    {
        var actualSeed = seed ?? RandomNumberGenerator.GetBytes(KeyLength);
        if (actualSeed.Length < KeyLength)
            throw new ArgumentException("Seed must be at least 32 bytes.", nameof(seed));

        // Expand seed into deterministic randomness for matrix A and secret vector s
        var expandedA = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: actualSeed,
            outputLength: N * N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-matrix-A"));

        var expandedS = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: actualSeed,
            outputLength: N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-secret-s"));

        var expandedE = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: actualSeed,
            outputLength: N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-error-e"));

        // Parse matrix A (N x N) mod q
        var matrixA = new int[N * N];
        for (int i = 0; i < N * N; i++)
        {
            var val = BinaryPrimitives.ReadUInt16LittleEndian(expandedA.AsSpan(i * 2, 2));
            matrixA[i] = val % Q;
        }

        // Parse secret vector s with small coefficients
        var secretS = new int[N];
        for (int i = 0; i < N; i++)
        {
            var val = BinaryPrimitives.ReadInt16LittleEndian(expandedS.AsSpan(i * 2, 2));
            secretS[i] = Mod(val % (ErrorBound + 1), Q);
        }

        // Parse error vector e with small coefficients
        var errorE = new int[N];
        for (int i = 0; i < N; i++)
        {
            var val = BinaryPrimitives.ReadInt16LittleEndian(expandedE.AsSpan(i * 2, 2));
            errorE[i] = Mod(val % (ErrorBound + 1), Q);
        }

        // Public key: b = A*s + e (mod q)
        var vectorB = new int[N];
        for (int i = 0; i < N; i++)
        {
            long sum = 0;
            for (int j = 0; j < N; j++)
            {
                sum += (long)matrixA[i * N + j] * secretS[j];
            }
            vectorB[i] = Mod((int)(sum % Q) + errorE[i], Q);
        }

        // Serialize public key: [matrixA (N*N*2 bytes)][vectorB (N*2 bytes)]
        var publicKey = new byte[(N * N * 2) + (N * 2)];
        for (int i = 0; i < N * N; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(publicKey.AsSpan(i * 2, 2), (ushort)matrixA[i]);
        for (int i = 0; i < N; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(publicKey.AsSpan((N * N * 2) + (i * 2), 2), (ushort)vectorB[i]);

        // Serialize secret key: [secretS (N*2 bytes)]
        var secretKey = new byte[N * 2];
        for (int i = 0; i < N; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(secretKey.AsSpan(i * 2, 2), (ushort)Mod(secretS[i], Q));

        // Zero sensitive intermediates
        CryptographicOperations.ZeroMemory(expandedA);
        CryptographicOperations.ZeroMemory(expandedS);
        CryptographicOperations.ZeroMemory(expandedE);

        return (publicKey, secretKey);
    }

    /// <summary>
    /// Encapsulates a shared secret using the recipient's public key.
    /// </summary>
    /// <param name="publicKey">Recipient's lattice public key.</param>
    /// <returns>Tuple of (ciphertext, sharedSecret) where sharedSecret is 32 bytes.</returns>
    public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        var expectedPkLen = (N * N * 2) + (N * 2);
        if (publicKey.Length != expectedPkLen)
            throw new ArgumentException($"Public key must be {expectedPkLen} bytes.", nameof(publicKey));

        // Deserialize public key
        var matrixA = new int[N * N];
        for (int i = 0; i < N * N; i++)
            matrixA[i] = BinaryPrimitives.ReadUInt16LittleEndian(publicKey.AsSpan(i * 2, 2));

        var vectorB = new int[N];
        for (int i = 0; i < N; i++)
            vectorB[i] = BinaryPrimitives.ReadUInt16LittleEndian(publicKey.AsSpan((N * N * 2) + (i * 2), 2));

        // Sample ephemeral randomness
        var rSeed = RandomNumberGenerator.GetBytes(KeyLength);
        var expandedR = HKDF.DeriveKey(HashAlgorithmName.SHA256, rSeed, N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-encaps-r"));
        var expandedE1 = HKDF.DeriveKey(HashAlgorithmName.SHA256, rSeed, N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-encaps-e1"));
        var expandedE2 = HKDF.DeriveKey(HashAlgorithmName.SHA256, rSeed, N * 2,
            info: Encoding.UTF8.GetBytes("tordeX-pq-encaps-e2"));

        var vectorR = new int[N];
        var errorE1 = new int[N];
        var errorE2 = new int[N];

        for (int i = 0; i < N; i++)
        {
            vectorR[i] = Mod(BinaryPrimitives.ReadInt16LittleEndian(expandedR.AsSpan(i * 2, 2)) % (ErrorBound + 1), Q);
            errorE1[i] = Mod(BinaryPrimitives.ReadInt16LittleEndian(expandedE1.AsSpan(i * 2, 2)) % (ErrorBound + 1), Q);
            errorE2[i] = Mod(BinaryPrimitives.ReadInt16LittleEndian(expandedE2.AsSpan(i * 2, 2)) % (ErrorBound + 1), Q);
        }

        // Generate a random message to encode (256 bits = 32 bytes)
        var rawMessage = RandomNumberGenerator.GetBytes(KeyLength);
        var messageBits = new int[N];
        for (int i = 0; i < KeyLength && i * 8 < N; i++)
        {
            for (int bit = 0; bit < 8 && (i * 8 + bit) < N; bit++)
            {
                messageBits[i * 8 + bit] = (rawMessage[i] >> bit) & 1;
            }
        }

        // u = A^T * r + e1 (mod q)
        var vectorU = new int[N];
        for (int i = 0; i < N; i++)
        {
            long sum = 0;
            for (int j = 0; j < N; j++)
            {
                sum += (long)matrixA[j * N + i] * vectorR[j]; // A^T
            }
            vectorU[i] = Mod((int)(sum % Q) + errorE1[i], Q);
        }

        // v = b^T * r + e2 + encode(m) (mod q)
        var vectorV = new int[N];
        {
            long dotProduct = 0;
            for (int j = 0; j < N; j++)
                dotProduct += (long)vectorB[j] * vectorR[j];

            for (int i = 0; i < N; i++)
            {
                // Encode message bit as 0 or q/2
                var encodedBit = messageBits[i] * (Q / 2);
                vectorV[i] = Mod((int)(dotProduct % Q) + errorE2[i] + encodedBit, Q);
            }
        }

        // Serialize ciphertext: [u (N*2)][v (N*2)]
        var ciphertext = new byte[N * 2 + N * 2];
        for (int i = 0; i < N; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(ciphertext.AsSpan(i * 2, 2), (ushort)vectorU[i]);
        for (int i = 0; i < N; i++)
            BinaryPrimitives.WriteUInt16LittleEndian(ciphertext.AsSpan(N * 2 + i * 2, 2), (ushort)vectorV[i]);

        // Shared secret = SHA-256(rawMessage || ciphertext)
        var sharedSecret = DeriveSharedSecret(rawMessage, ciphertext);

        // Zero intermediates
        CryptographicOperations.ZeroMemory(rSeed);
        CryptographicOperations.ZeroMemory(expandedR);
        CryptographicOperations.ZeroMemory(expandedE1);
        CryptographicOperations.ZeroMemory(expandedE2);
        CryptographicOperations.ZeroMemory(rawMessage);

        return (ciphertext, sharedSecret);
    }

    /// <summary>
    /// Decapsulates the shared secret from ciphertext using the secret key.
    /// </summary>
    /// <param name="secretKey">Recipient's lattice secret key.</param>
    /// <param name="ciphertext">The ciphertext from encapsulation.</param>
    /// <returns>32-byte shared secret.</returns>
    public static byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(secretKey);
        ArgumentNullException.ThrowIfNull(ciphertext);
        if (secretKey.Length != N * 2)
            throw new ArgumentException($"Secret key must be {N * 2} bytes.", nameof(secretKey));
        if (ciphertext.Length != N * 2 + N * 2)
            throw new ArgumentException($"Ciphertext must be {N * 2 + N * 2} bytes.", nameof(ciphertext));

        // Deserialize secret key
        var secretS = new int[N];
        for (int i = 0; i < N; i++)
            secretS[i] = BinaryPrimitives.ReadUInt16LittleEndian(secretKey.AsSpan(i * 2, 2));

        // Deserialize ciphertext
        var vectorU = new int[N];
        var vectorV = new int[N];
        for (int i = 0; i < N; i++)
            vectorU[i] = BinaryPrimitives.ReadUInt16LittleEndian(ciphertext.AsSpan(i * 2, 2));
        for (int i = 0; i < N; i++)
            vectorV[i] = BinaryPrimitives.ReadUInt16LittleEndian(ciphertext.AsSpan(N * 2 + i * 2, 2));

        // Decode: m' = v - s^T * u (mod q), then round
        var recoveredMessage = new byte[KeyLength];
        long dotProduct = 0;
        for (int j = 0; j < N; j++)
            dotProduct += (long)secretS[j] * vectorU[j];

        for (int i = 0; i < N; i++)
        {
            var decoded = Mod(vectorV[i] - (int)(dotProduct % Q), Q);
            // Round: if closer to q/2 than to 0, it's a 1
            var bit = (decoded > Q / 4 && decoded < 3 * Q / 4) ? 1 : 0;
            if (i < KeyLength * 8)
            {
                var byteIdx = i / 8;
                var bitIdx = i % 8;
                recoveredMessage[byteIdx] |= (byte)(bit << bitIdx);
            }
        }

        // Shared secret = SHA-256(recoveredMessage || ciphertext)
        var sharedSecret = DeriveSharedSecret(recoveredMessage, ciphertext);
        CryptographicOperations.ZeroMemory(recoveredMessage);
        return sharedSecret;
    }

    /// <summary>
    /// Performs hybrid encryption combining a classical shared key (e.g., from ECDH)
    /// and a post-quantum shared key. The final encryption key is derived by hashing
    /// both keys together, ensuring security holds if either scheme remains unbroken.
    /// </summary>
    /// <param name="classicalKey">32-byte key from classical key exchange (e.g., ECDH).</param>
    /// <param name="postQuantumKey">32-byte key from post-quantum KEM.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <returns>AES-256-GCM ciphertext in format [12 nonce][16 tag][ciphertext].</returns>
    public static byte[] HybridEncrypt(byte[] classicalKey, byte[] postQuantumKey, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(classicalKey);
        ArgumentNullException.ThrowIfNull(postQuantumKey);
        ArgumentNullException.ThrowIfNull(plaintext);
        ValidateKeyLength(classicalKey, nameof(classicalKey));
        ValidateKeyLength(postQuantumKey, nameof(postQuantumKey));
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));

        var hybridKey = DeriveHybridKey(classicalKey, postQuantumKey);
        try
        {
            return AesGcmEncrypt(hybridKey, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridKey);
        }
    }

    /// <summary>
    /// Decrypts hybrid-encrypted ciphertext using both classical and post-quantum keys.
    /// </summary>
    /// <param name="classicalKey">32-byte key from classical key exchange.</param>
    /// <param name="postQuantumKey">32-byte key from post-quantum KEM.</param>
    /// <param name="ciphertext">Ciphertext in format [12 nonce][16 tag][ciphertext].</param>
    /// <returns>Decrypted plaintext.</returns>
    public static byte[] HybridDecrypt(byte[] classicalKey, byte[] postQuantumKey, byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(classicalKey);
        ArgumentNullException.ThrowIfNull(postQuantumKey);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ValidateKeyLength(classicalKey, nameof(classicalKey));
        ValidateKeyLength(postQuantumKey, nameof(postQuantumKey));

        var hybridKey = DeriveHybridKey(classicalKey, postQuantumKey);
        try
        {
            return AesGcmDecrypt(hybridKey, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridKey);
        }
    }

    /// <summary>
    /// Combines classical and post-quantum keys via HKDF to produce a hybrid encryption key.
    /// Security holds as long as at least one input key is secret.
    /// </summary>
    private static byte[] DeriveHybridKey(byte[] classicalKey, byte[] postQuantumKey)
    {
        // Concatenate both keys as IKM for HKDF
        var combinedIkm = new byte[classicalKey.Length + postQuantumKey.Length];
        Buffer.BlockCopy(classicalKey, 0, combinedIkm, 0, classicalKey.Length);
        Buffer.BlockCopy(postQuantumKey, 0, combinedIkm, classicalKey.Length, postQuantumKey.Length);

        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: combinedIkm,
                outputLength: KeyLength,
                info: HybridInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(combinedIkm);
        }
    }

    /// <summary>
    /// Derives the shared secret from the decoded message and ciphertext via SHA-256.
    /// </summary>
    private static byte[] DeriveSharedSecret(byte[] message, byte[] ciphertext)
    {
        var combined = new byte[message.Length + ciphertext.Length];
        Buffer.BlockCopy(message, 0, combined, 0, message.Length);
        Buffer.BlockCopy(ciphertext, 0, combined, message.Length, ciphertext.Length);
        return SHA256.HashData(combined);
    }

    /// <summary>
    /// Proper modular reduction that always returns a non-negative result.
    /// </summary>
    private static int Mod(int value, int modulus)
    {
        var result = value % modulus;
        return result < 0 ? result + modulus : result;
    }

    private static void ValidateKeyLength(byte[] key, string paramName)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be exactly {KeyLength} bytes.", paramName);
    }

    private static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext)
    {
        const int nonceLen = 12;
        const int tagLen = 16;

        var nonce = new byte[nonceLen];
        RandomNumberGenerator.Fill(nonce);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[tagLen];

        using var aes = new AesGcm(key, tagLen);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var result = new byte[nonceLen + tagLen + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonceLen);
        Buffer.BlockCopy(tag, 0, result, nonceLen, tagLen);
        Buffer.BlockCopy(ciphertext, 0, result, nonceLen + tagLen, ciphertext.Length);
        return result;
    }

    private static byte[] AesGcmDecrypt(byte[] key, byte[] data)
    {
        const int nonceLen = 12;
        const int tagLen = 16;
        const int minimumLen = nonceLen + tagLen + 1;

        if (data.Length < minimumLen)
            throw new CryptographicException("Encrypted data is too short to be valid.");

        var nonce = data.AsSpan(0, nonceLen);
        var tag = data.AsSpan(nonceLen, tagLen);
        var ciphertext = data.AsSpan(nonceLen + tagLen);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, tagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
