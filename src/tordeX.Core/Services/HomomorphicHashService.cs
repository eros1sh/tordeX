using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Represents a Merkle proof for verifying that a specific message hash
/// is included in a Merkle tree with a known root.
/// </summary>
/// <param name="Hashes">The sibling hashes along the path from the leaf to the root.</param>
/// <param name="Directions">
/// For each hash in <see cref="Hashes"/>, indicates whether the sibling is on the left (<c>true</c>)
/// or right (<c>false</c>) side when computing the parent hash.
/// </param>
public sealed record MerkleProof(List<byte[]> Hashes, List<bool> Directions);

/// <summary>
/// Homomorphic hashing and Merkle tree service for message integrity verification.
/// <para>
/// Provides SHA-256 and HMAC-SHA256 based hashing with XOR-based additive homomorphism:
/// H(a) XOR H(b) can be verified against H(a||b) properties without requiring
/// the original data, enabling efficient incremental integrity checks.
/// </para>
/// <para>
/// Also provides Merkle tree construction and proof generation/verification
/// for efficient batched message integrity verification.
/// </para>
/// </summary>
public static class HomomorphicHashService
{
    private const int HashLength = 32;

    private static readonly byte[] HomomorphicDomainTag =
        Encoding.UTF8.GetBytes("tordeX-homomorphic-hash-v1");

    /// <summary>
    /// Computes a SHA-256 hash of the input data with domain separation.
    /// </summary>
    /// <param name="data">The data to hash. Must not be null or empty.</param>
    /// <returns>32-byte SHA-256 hash.</returns>
    public static byte[] ComputeHash(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));

        // Domain-separated hash: H(domain || data)
        var input = new byte[HomomorphicDomainTag.Length + data.Length];
        Buffer.BlockCopy(HomomorphicDomainTag, 0, input, 0, HomomorphicDomainTag.Length);
        Buffer.BlockCopy(data, 0, input, HomomorphicDomainTag.Length, data.Length);

        return SHA256.HashData(input);
    }

    /// <summary>
    /// Computes a keyed homomorphic hash using HMAC-SHA256.
    /// The keyed hash supports homomorphic XOR combination: given H_k(a) and H_k(b),
    /// their XOR can be used for incremental integrity verification.
    /// </summary>
    /// <param name="data">The data to hash. Must not be null or empty.</param>
    /// <param name="key">The HMAC key (32 bytes recommended).</param>
    /// <returns>32-byte HMAC-SHA256 hash.</returns>
    public static byte[] ComputeHomomorphicHash(byte[] data, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(key);
        if (data.Length == 0)
            throw new ArgumentException("Data cannot be empty.", nameof(data));
        if (key.Length == 0)
            throw new ArgumentException("Key cannot be empty.", nameof(key));

        // Domain-separated keyed hash: HMAC_k(domain || data)
        var input = new byte[HomomorphicDomainTag.Length + data.Length];
        Buffer.BlockCopy(HomomorphicDomainTag, 0, input, 0, HomomorphicDomainTag.Length);
        Buffer.BlockCopy(data, 0, input, HomomorphicDomainTag.Length, data.Length);

        return HMACSHA256.HashData(key, input);
    }

    /// <summary>
    /// Combines two hashes using XOR, providing additive homomorphism.
    /// This allows incremental integrity verification:
    /// CombineHashes(H(a), H(b)) can be used to verify combined data integrity.
    /// </summary>
    /// <param name="hash1">First 32-byte hash.</param>
    /// <param name="hash2">Second 32-byte hash.</param>
    /// <returns>32-byte XOR combination of the two hashes.</returns>
    public static byte[] CombineHashes(byte[] hash1, byte[] hash2)
    {
        ArgumentNullException.ThrowIfNull(hash1);
        ArgumentNullException.ThrowIfNull(hash2);
        if (hash1.Length != HashLength)
            throw new ArgumentException($"Hash must be exactly {HashLength} bytes.", nameof(hash1));
        if (hash2.Length != HashLength)
            throw new ArgumentException($"Hash must be exactly {HashLength} bytes.", nameof(hash2));

        var result = new byte[HashLength];
        for (int i = 0; i < HashLength; i++)
        {
            result[i] = (byte)(hash1[i] ^ hash2[i]);
        }

        return result;
    }

    /// <summary>
    /// Verifies that the given data produces the expected keyed hash.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="data">The data to verify.</param>
    /// <param name="expectedHash">The expected 32-byte hash.</param>
    /// <param name="key">The HMAC key.</param>
    /// <returns><c>true</c> if the data's keyed hash matches the expected hash.</returns>
    public static bool VerifyIntegrity(byte[] data, byte[] expectedHash, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(expectedHash);
        ArgumentNullException.ThrowIfNull(key);
        if (expectedHash.Length != HashLength)
            throw new ArgumentException($"Expected hash must be exactly {HashLength} bytes.", nameof(expectedHash));

        var computedHash = ComputeHomomorphicHash(data, key);
        return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
    }

    /// <summary>
    /// Constructs a Merkle tree root hash from a list of messages.
    /// Each message is hashed with SHA-256, then paired and hashed upward
    /// to produce a single 32-byte root.
    /// </summary>
    /// <param name="messages">The messages to include in the Merkle tree. Must contain at least one message.</param>
    /// <returns>32-byte Merkle root hash.</returns>
    public static byte[] CreateMerkleRoot(byte[][] messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        if (messages.Length == 0)
            throw new ArgumentException("At least one message is required.", nameof(messages));

        // Hash all leaves
        var currentLevel = new List<byte[]>(messages.Length);
        foreach (var message in messages)
        {
            if (message is null || message.Length == 0)
                throw new ArgumentException("Messages must not be null or empty.", nameof(messages));
            currentLevel.Add(HashLeaf(message));
        }

        // Build tree bottom-up
        while (currentLevel.Count > 1)
        {
            var nextLevel = new List<byte[]>((currentLevel.Count + 1) / 2);

            for (int i = 0; i < currentLevel.Count; i += 2)
            {
                if (i + 1 < currentLevel.Count)
                {
                    nextLevel.Add(HashBranch(currentLevel[i], currentLevel[i + 1]));
                }
                else
                {
                    // Odd element: promote (hash with itself to maintain consistent structure)
                    nextLevel.Add(HashBranch(currentLevel[i], currentLevel[i]));
                }
            }

            currentLevel = nextLevel;
        }

        return currentLevel[0];
    }

    /// <summary>
    /// Generates a Merkle proof for a specific message at the given index.
    /// The proof contains the sibling hashes along the path from the leaf to the root.
    /// </summary>
    /// <param name="messages">All messages in the Merkle tree.</param>
    /// <param name="messageIndex">Zero-based index of the message to prove inclusion for.</param>
    /// <returns>A <see cref="MerkleProof"/> that can verify the message's inclusion.</returns>
    public static MerkleProof GenerateMerkleProof(byte[][] messages, int messageIndex)
    {
        ArgumentNullException.ThrowIfNull(messages);
        if (messages.Length == 0)
            throw new ArgumentException("At least one message is required.", nameof(messages));
        if (messageIndex < 0 || messageIndex >= messages.Length)
            throw new ArgumentOutOfRangeException(nameof(messageIndex), "Message index is out of range.");

        // Hash all leaves
        var currentLevel = new List<byte[]>(messages.Length);
        foreach (var message in messages)
        {
            currentLevel.Add(HashLeaf(message));
        }

        var proofHashes = new List<byte[]>();
        var directions = new List<bool>(); // true = sibling is on the left
        var targetIndex = messageIndex;

        // Build proof by traversing up the tree
        while (currentLevel.Count > 1)
        {
            var nextLevel = new List<byte[]>((currentLevel.Count + 1) / 2);

            for (int i = 0; i < currentLevel.Count; i += 2)
            {
                byte[] left = currentLevel[i];
                byte[] right = (i + 1 < currentLevel.Count) ? currentLevel[i + 1] : currentLevel[i];

                nextLevel.Add(HashBranch(left, right));

                // If this pair contains our target, record the sibling
                if (i == targetIndex || i + 1 == targetIndex)
                {
                    if (targetIndex % 2 == 0)
                    {
                        // Target is on the left; sibling is on the right
                        proofHashes.Add(right);
                        directions.Add(false); // sibling is right
                    }
                    else
                    {
                        // Target is on the right; sibling is on the left
                        proofHashes.Add(left);
                        directions.Add(true); // sibling is left
                    }
                }
            }

            targetIndex /= 2;
            currentLevel = nextLevel;
        }

        return new MerkleProof(proofHashes, directions);
    }

    /// <summary>
    /// Verifies a Merkle proof: checks that the given message hash, combined
    /// with the proof hashes, produces the expected Merkle root.
    /// Uses constant-time comparison for the final root check.
    /// </summary>
    /// <param name="messageHash">SHA-256 hash of the message (leaf hash).</param>
    /// <param name="proof">The Merkle proof containing sibling hashes and directions.</param>
    /// <param name="root">The expected Merkle root hash.</param>
    /// <returns><c>true</c> if the proof is valid and the message is included in the tree.</returns>
    public static bool VerifyMerkleProof(byte[] messageHash, MerkleProof proof, byte[] root)
    {
        ArgumentNullException.ThrowIfNull(messageHash);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(root);
        if (messageHash.Length != HashLength)
            throw new ArgumentException($"Message hash must be exactly {HashLength} bytes.", nameof(messageHash));
        if (root.Length != HashLength)
            throw new ArgumentException($"Root must be exactly {HashLength} bytes.", nameof(root));
        if (proof.Hashes.Count != proof.Directions.Count)
            throw new ArgumentException("Proof hashes and directions must have the same count.", nameof(proof));

        var currentHash = messageHash;

        for (int i = 0; i < proof.Hashes.Count; i++)
        {
            if (proof.Hashes[i].Length != HashLength)
                throw new ArgumentException($"Proof hash at index {i} must be {HashLength} bytes.", nameof(proof));

            if (proof.Directions[i])
            {
                // Sibling is on the left
                currentHash = HashBranch(proof.Hashes[i], currentHash);
            }
            else
            {
                // Sibling is on the right
                currentHash = HashBranch(currentHash, proof.Hashes[i]);
            }
        }

        return CryptographicOperations.FixedTimeEquals(currentHash, root);
    }

    /// <summary>
    /// Hashes a leaf node with a 0x00 prefix for domain separation
    /// between leaf and internal nodes (second preimage resistance).
    /// </summary>
    private static byte[] HashLeaf(byte[] data)
    {
        var prefixed = new byte[1 + data.Length];
        prefixed[0] = 0x00; // Leaf prefix
        Buffer.BlockCopy(data, 0, prefixed, 1, data.Length);
        return SHA256.HashData(prefixed);
    }

    /// <summary>
    /// Hashes an internal branch node with a 0x01 prefix for domain separation.
    /// </summary>
    private static byte[] HashBranch(byte[] left, byte[] right)
    {
        var combined = new byte[1 + left.Length + right.Length];
        combined[0] = 0x01; // Branch prefix
        Buffer.BlockCopy(left, 0, combined, 1, left.Length);
        Buffer.BlockCopy(right, 0, combined, 1 + left.Length, right.Length);
        return SHA256.HashData(combined);
    }
}
