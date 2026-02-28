using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Header transmitted alongside each Double Ratchet ciphertext.
/// Contains the sender's current ratchet public key and message counters.
/// </summary>
/// <param name="PublicKey">Sender's current ECDH ratchet public key (SPKI-encoded).</param>
/// <param name="Counter">Message number within the current sending chain.</param>
/// <param name="PreviousCounter">Length of the previous sending chain (for skipped message handling).</param>
public sealed record RatchetHeader(byte[] PublicKey, int Counter, int PreviousCounter)
{
    /// <summary>
    /// Serializes the header to a byte array for authenticated encryption.
    /// Format: [4 counter][4 previousCounter][pubKey]
    /// </summary>
    public byte[] Serialize()
    {
        var result = new byte[4 + 4 + PublicKey.Length];
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), Counter);
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(4, 4), PreviousCounter);
        Buffer.BlockCopy(PublicKey, 0, result, 8, PublicKey.Length);
        return result;
    }

    /// <summary>
    /// Deserializes a header from raw bytes.
    /// </summary>
    public static RatchetHeader Deserialize(byte[] data)
    {
        if (data.Length < 9)
            throw new CryptographicException("Ratchet header data is too short.");

        var counter = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(0, 4));
        var prevCounter = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(4, 4));
        var pubKey = new byte[data.Length - 8];
        Buffer.BlockCopy(data, 8, pubKey, 0, pubKey.Length);
        return new RatchetHeader(pubKey, counter, prevCounter);
    }
}

/// <summary>
/// Mutable state for the Double Ratchet algorithm.
/// Holds root key, send/receive chain keys, counters, and the local ECDH key pair.
/// </summary>
public sealed class RatchetState : IDisposable
{
    private bool _disposed;

    /// <summary>Root key (32 bytes) used to derive new chain keys on DH ratchet steps.</summary>
    public byte[] RootKey { get; set; }

    /// <summary>Current sending chain key (32 bytes).</summary>
    public byte[] SendChainKey { get; set; }

    /// <summary>Current receiving chain key (32 bytes).</summary>
    public byte[] RecvChainKey { get; set; }

    /// <summary>Number of messages sent in the current sending chain.</summary>
    public int SendCounter { get; set; }

    /// <summary>Number of messages received in the current receiving chain.</summary>
    public int RecvCounter { get; set; }

    /// <summary>Local ECDH key pair used for DH ratchet operations.</summary>
    public ECDiffieHellman? LocalKeyPair { get; set; }

    /// <summary>Remote party's current ECDH public key (SPKI-encoded).</summary>
    public byte[] RemotePublicKey { get; set; }

    /// <summary>Length of the previous sending chain (sent in headers for skipped message handling).</summary>
    public int PreviousSendCounter { get; set; }

    public RatchetState(
        byte[] rootKey,
        byte[] sendChainKey,
        byte[] recvChainKey,
        int sendCounter,
        int recvCounter,
        ECDiffieHellman? localKeyPair,
        byte[] remotePublicKey)
    {
        RootKey = rootKey;
        SendChainKey = sendChainKey;
        RecvChainKey = recvChainKey;
        SendCounter = sendCounter;
        RecvCounter = recvCounter;
        LocalKeyPair = localKeyPair;
        RemotePublicKey = remotePublicKey;
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(RootKey);
        CryptographicOperations.ZeroMemory(SendChainKey);
        CryptographicOperations.ZeroMemory(RecvChainKey);
        LocalKeyPair?.Dispose();
        LocalKeyPair = null;
        _disposed = true;
    }
}

/// <summary>
/// Double Ratchet key management providing forward secrecy and break-in recovery.
/// Implements the Signal Protocol Double Ratchet algorithm using ECDH P-256 for
/// DH ratchet steps and HKDF-SHA256 for symmetric key derivation.
/// </summary>
/// <remarks>
/// Wire format per message: [12 nonce][16 tag][ciphertext]
/// Header is used as associated data in AES-256-GCM to bind it to the ciphertext.
/// </remarks>
public static class DoubleRatchetService
{
    private const int KeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private static readonly byte[] RootKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-double-ratchet-root-v1");

    private static readonly byte[] ChainKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-double-ratchet-chain-v1");

    private static readonly byte[] MessageKeyInfo =
        Encoding.UTF8.GetBytes("tordeX-double-ratchet-msg-v1");

    /// <summary>
    /// Initializes a sender-side ratchet state. Generates a fresh ECDH key pair,
    /// performs DH with the receiver's public key, and derives initial root and chain keys.
    /// </summary>
    /// <param name="remotePublicKey">Receiver's ECDH public key (SPKI-encoded).</param>
    /// <returns>Initialized <see cref="RatchetState"/> ready for sending.</returns>
    public static RatchetState InitializeSender(byte[] remotePublicKey)
    {
        ArgumentNullException.ThrowIfNull(remotePublicKey);
        if (remotePublicKey.Length == 0)
            throw new ArgumentException("Remote public key cannot be empty.", nameof(remotePublicKey));

        var localKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var sharedSecret = PerformDH(localKeyPair, remotePublicKey);

        try
        {
            var (rootKey, chainKey) = DeriveRootAndChainKey(sharedSecret, new byte[KeyLength]);
            return new RatchetState(
                rootKey: rootKey,
                sendChainKey: chainKey,
                recvChainKey: new byte[KeyLength],
                sendCounter: 0,
                recvCounter: 0,
                localKeyPair: localKeyPair,
                remotePublicKey: remotePublicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>
    /// Initializes a receiver-side ratchet state from an existing ECDH key pair
    /// and the sender's public key.
    /// </summary>
    /// <param name="localKeyPair">Receiver's pre-existing ECDH key pair.</param>
    /// <param name="remotePublicKey">Sender's ECDH public key (SPKI-encoded).</param>
    /// <returns>Initialized <see cref="RatchetState"/> ready for receiving.</returns>
    public static RatchetState InitializeReceiver(ECDiffieHellman localKeyPair, byte[] remotePublicKey)
    {
        ArgumentNullException.ThrowIfNull(localKeyPair);
        ArgumentNullException.ThrowIfNull(remotePublicKey);
        if (remotePublicKey.Length == 0)
            throw new ArgumentException("Remote public key cannot be empty.", nameof(remotePublicKey));

        var sharedSecret = PerformDH(localKeyPair, remotePublicKey);

        try
        {
            var (rootKey, chainKey) = DeriveRootAndChainKey(sharedSecret, new byte[KeyLength]);
            return new RatchetState(
                rootKey: rootKey,
                sendChainKey: new byte[KeyLength],
                recvChainKey: chainKey,
                sendCounter: 0,
                recvCounter: 0,
                localKeyPair: localKeyPair,
                remotePublicKey: remotePublicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>
    /// Encrypts a plaintext message, advancing the sending chain.
    /// Returns the ciphertext and a header containing the sender's current public key and counters.
    /// </summary>
    /// <param name="state">Current ratchet state (mutated: send chain key and counter advance).</param>
    /// <param name="plaintext">Message plaintext to encrypt.</param>
    /// <returns>Tuple of (ciphertext, header).</returns>
    public static (byte[] Ciphertext, RatchetHeader Header) RatchetEncrypt(RatchetState state, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext cannot be empty.", nameof(plaintext));
        if (state.LocalKeyPair is null)
            throw new InvalidOperationException("Local key pair is not set on the ratchet state.");

        // Derive message key from send chain key
        var (messageKey, nextChainKey) = DeriveMessageKey(state.SendChainKey);

        try
        {
            // Build header with current public key and counters
            var publicKey = state.LocalKeyPair.PublicKey.ExportSubjectPublicKeyInfo();
            var header = new RatchetHeader(publicKey, state.SendCounter, state.PreviousSendCounter);
            var headerBytes = header.Serialize();

            // Encrypt with AES-256-GCM, using serialized header as associated data
            var ciphertext = AesGcmEncrypt(messageKey, plaintext, headerBytes);

            // Advance chain state
            CryptographicOperations.ZeroMemory(state.SendChainKey);
            state.SendChainKey = nextChainKey;
            state.SendCounter++;

            return (ciphertext, header);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
        }
    }

    /// <summary>
    /// Decrypts a ciphertext message, advancing the receiving chain.
    /// </summary>
    /// <param name="state">Current ratchet state (mutated: recv chain key and counter advance).</param>
    /// <param name="ciphertext">The encrypted message bytes.</param>
    /// <param name="header">The header received alongside the ciphertext.</param>
    /// <returns>Decrypted plaintext.</returns>
    public static byte[] RatchetDecrypt(RatchetState state, byte[] ciphertext, RatchetHeader header)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(header);

        // Derive message key from recv chain key
        var (messageKey, nextChainKey) = DeriveMessageKey(state.RecvChainKey);

        try
        {
            var headerBytes = header.Serialize();
            var plaintext = AesGcmDecrypt(messageKey, ciphertext, headerBytes);

            // Advance chain state
            CryptographicOperations.ZeroMemory(state.RecvChainKey);
            state.RecvChainKey = nextChainKey;
            state.RecvCounter++;

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
        }
    }

    /// <summary>
    /// Performs a DH ratchet step when a new remote public key is received.
    /// Generates a new local ECDH key pair, performs DH twice (once with old key, once with new),
    /// and derives new root, send, and receive chain keys.
    /// </summary>
    /// <param name="state">Current ratchet state (a new state is returned; caller should dispose old).</param>
    /// <param name="newRemotePublicKey">The new remote ECDH public key (SPKI-encoded).</param>
    /// <returns>A fresh <see cref="RatchetState"/> with new keys and reset counters.</returns>
    public static RatchetState PerformDHRatchet(RatchetState state, byte[] newRemotePublicKey)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(newRemotePublicKey);
        if (newRemotePublicKey.Length == 0)
            throw new ArgumentException("Remote public key cannot be empty.", nameof(newRemotePublicKey));
        if (state.LocalKeyPair is null)
            throw new InvalidOperationException("Local key pair is not set on the ratchet state.");

        // DH with current local key and new remote key -> new recv chain key
        var dhOutput1 = PerformDH(state.LocalKeyPair, newRemotePublicKey);
        byte[] newRootKey1;
        byte[] newRecvChainKey;

        try
        {
            (newRootKey1, newRecvChainKey) = DeriveRootAndChainKey(dhOutput1, state.RootKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dhOutput1);
        }

        // Generate new local key pair
        var newLocalKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        // DH with new local key and new remote key -> new send chain key
        var dhOutput2 = PerformDH(newLocalKeyPair, newRemotePublicKey);
        byte[] newRootKey2;
        byte[] newSendChainKey;

        try
        {
            (newRootKey2, newSendChainKey) = DeriveRootAndChainKey(dhOutput2, newRootKey1);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dhOutput2);
            CryptographicOperations.ZeroMemory(newRootKey1);
        }

        return new RatchetState(
            rootKey: newRootKey2,
            sendChainKey: newSendChainKey,
            recvChainKey: newRecvChainKey,
            sendCounter: 0,
            recvCounter: 0,
            localKeyPair: newLocalKeyPair,
            remotePublicKey: newRemotePublicKey)
        {
            PreviousSendCounter = state.SendCounter
        };
    }

    /// <summary>
    /// Performs ECDH key agreement between a local private key and a remote SPKI-encoded public key.
    /// The raw shared secret is returned (caller must zero after use).
    /// </summary>
    private static byte[] PerformDH(ECDiffieHellman localKey, byte[] remotePublicKeySpki)
    {
        using var remoteKey = ECDiffieHellman.Create();
        remoteKey.ImportSubjectPublicKeyInfo(remotePublicKeySpki, out _);
        return localKey.DeriveKeyFromHash(remoteKey.PublicKey, HashAlgorithmName.SHA256);
    }

    /// <summary>
    /// Derives a new root key and chain key from DH output and the current root key using HKDF.
    /// </summary>
    private static (byte[] RootKey, byte[] ChainKey) DeriveRootAndChainKey(byte[] dhOutput, byte[] currentRootKey)
    {
        // Root key derivation: HKDF with current root key as salt, DH output as IKM
        var rootKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: dhOutput,
            outputLength: KeyLength,
            salt: currentRootKey,
            info: RootKeyInfo);

        var chainKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: dhOutput,
            outputLength: KeyLength,
            salt: currentRootKey,
            info: ChainKeyInfo);

        return (rootKey, chainKey);
    }

    /// <summary>
    /// Derives a message encryption key and the next chain key from the current chain key.
    /// This is the symmetric ratchet step.
    /// </summary>
    private static (byte[] MessageKey, byte[] NextChainKey) DeriveMessageKey(byte[] chainKey)
    {
        var messageKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: chainKey,
            outputLength: KeyLength,
            info: MessageKeyInfo);

        var nextChainKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: chainKey,
            outputLength: KeyLength,
            info: ChainKeyInfo);

        return (messageKey, nextChainKey);
    }

    /// <summary>
    /// Encrypts plaintext with AES-256-GCM.
    /// Output format: [12 nonce][16 tag][ciphertext]
    /// </summary>
    private static byte[] AesGcmEncrypt(byte[] key, byte[] plaintext, byte[]? associatedData = null)
    {
        var nonce = new byte[NonceLength];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

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
    private static byte[] AesGcmDecrypt(byte[] key, byte[] data, byte[]? associatedData = null)
    {
        var minimumLength = NonceLength + TagLength + 1;
        if (data.Length < minimumLength)
            throw new CryptographicException("Encrypted data is too short to be valid.");

        var nonce = data.AsSpan(0, NonceLength);
        var tag = data.AsSpan(NonceLength, TagLength);
        var ciphertext = data.AsSpan(NonceLength + TagLength);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}
