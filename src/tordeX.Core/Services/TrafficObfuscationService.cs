using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TordeX.Core.Services;

/// <summary>
/// Traffic padding and obfuscation service.
/// Prevents traffic analysis by normalizing message sizes, adding random padding,
/// generating decoy packets, and obfuscating timing patterns.
/// </summary>
public static class TrafficObfuscationService
{
    /// <summary>
    /// Header prepended to decoy packets for identification.
    /// </summary>
    /// <param name="PacketType">Packet type marker (0xFF = decoy).</param>
    /// <param name="Timestamp">Unix timestamp in milliseconds.</param>
    /// <param name="RandomId">8-byte random identifier.</param>
    public sealed record DecoyPacketHeader(byte PacketType, long Timestamp, byte[] RandomId)
    {
        /// <summary>Decoy packet type marker constant.</summary>
        public const byte DecoyMarker = 0xFF;

        /// <summary>Total header size in bytes: 1 (type) + 8 (timestamp) + 8 (randomId) = 17.</summary>
        public const int HeaderSize = 17;
    }

    // ═══════════════ PKCS7-Style Block Padding ═══════════════

    /// <summary>
    /// Pads message data to a fixed block size using PKCS7-style padding.
    /// The last byte(s) indicate the number of padding bytes added (1..blockSize).
    /// </summary>
    /// <param name="data">The original message bytes.</param>
    /// <param name="blockSize">The target block size (default 512). Must be 1..256.</param>
    /// <returns>Padded byte array whose length is a multiple of blockSize.</returns>
    public static byte[] PadMessage(byte[] data, int blockSize = 512)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (blockSize < 1 || blockSize > 65536)
            throw new ArgumentOutOfRangeException(nameof(blockSize), "Block size must be between 1 and 65536.");

        // PKCS7: pad amount is 1..blockSize so even a perfectly aligned message gets a full block
        int paddingNeeded = blockSize - (data.Length % blockSize);
        if (paddingNeeded == 0)
            paddingNeeded = blockSize;

        // For blockSize > 255, we use 2-byte padding length at end
        var padded = new byte[data.Length + paddingNeeded];
        data.CopyTo(padded, 0);

        // Fill padding bytes: for blockSize <= 255, each byte = paddingNeeded (classic PKCS7)
        // For blockSize > 255, fill with random + last 2 bytes = big-endian length
        if (blockSize <= 255)
        {
            var paddingByte = (byte)paddingNeeded;
            padded.AsSpan(data.Length, paddingNeeded).Fill(paddingByte);
        }
        else
        {
            // Fill padding region with random bytes for obfuscation
            RandomNumberGenerator.Fill(padded.AsSpan(data.Length, paddingNeeded - 2));
            BinaryPrimitives.WriteUInt16BigEndian(padded.AsSpan(padded.Length - 2), (ushort)paddingNeeded);
        }

        return padded;
    }

    /// <summary>
    /// Removes PKCS7-style padding from a padded message.
    /// </summary>
    /// <param name="paddedData">The padded byte array.</param>
    /// <returns>Original unpadded data.</returns>
    /// <exception cref="CryptographicException">Thrown when padding is invalid.</exception>
    public static byte[] UnpadMessage(byte[] paddedData)
    {
        ArgumentNullException.ThrowIfNull(paddedData);
        if (paddedData.Length == 0)
            throw new CryptographicException("Cannot unpad empty data.");

        // Determine padding length
        // Heuristic: if last byte value <= 255 and all trailing bytes are the same, it's classic PKCS7
        // Otherwise check 2-byte trailer
        int paddingLength = paddedData[^1];

        if (paddingLength >= 1 && paddingLength <= 255 && paddingLength <= paddedData.Length)
        {
            // Verify all padding bytes match (classic PKCS7 for blockSize <= 255)
            bool validPkcs7 = true;
            for (int i = paddedData.Length - paddingLength; i < paddedData.Length; i++)
            {
                if (paddedData[i] != paddingLength)
                {
                    validPkcs7 = false;
                    break;
                }
            }

            if (validPkcs7)
            {
                return paddedData.AsSpan(0, paddedData.Length - paddingLength).ToArray();
            }
        }

        // Extended mode: last 2 bytes are big-endian padding length
        if (paddedData.Length >= 2)
        {
            int extendedPadding = BinaryPrimitives.ReadUInt16BigEndian(paddedData.AsSpan(paddedData.Length - 2));
            if (extendedPadding >= 2 && extendedPadding <= paddedData.Length)
            {
                return paddedData.AsSpan(0, paddedData.Length - extendedPadding).ToArray();
            }
        }

        throw new CryptographicException("Invalid padding.");
    }

    // ═══════════════ Random Padding ═══════════════

    /// <summary>
    /// Adds a random amount of random bytes to the message.
    /// Format: [4 bytes original length (big-endian)][original data][random bytes].
    /// Total random padding is between minExtra and maxExtra bytes.
    /// </summary>
    /// <param name="data">Original message data.</param>
    /// <param name="minExtra">Minimum random bytes to add (default 64).</param>
    /// <param name="maxExtra">Maximum random bytes to add (default 256).</param>
    /// <returns>Padded data with length prefix and random trailing bytes.</returns>
    public static byte[] AddRandomPadding(byte[] data, int minExtra = 64, int maxExtra = 256)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (minExtra < 0)
            throw new ArgumentOutOfRangeException(nameof(minExtra), "Minimum extra must be non-negative.");
        if (maxExtra < minExtra)
            throw new ArgumentOutOfRangeException(nameof(maxExtra), "Maximum extra must be >= minimum extra.");

        int extraBytes = RandomNumberGenerator.GetInt32(minExtra, maxExtra + 1);
        var result = new byte[4 + data.Length + extraBytes];

        // Write original data length as 4-byte big-endian prefix
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), data.Length);

        // Copy original data
        data.CopyTo(result, 4);

        // Fill trailing space with random bytes
        RandomNumberGenerator.Fill(result.AsSpan(4 + data.Length));

        return result;
    }

    /// <summary>
    /// Removes random padding by reading the length prefix and extracting original data.
    /// </summary>
    /// <param name="data">Padded data produced by <see cref="AddRandomPadding"/>.</param>
    /// <returns>Original unpadded data.</returns>
    public static byte[] RemoveRandomPadding(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length < 4)
            throw new CryptographicException("Data too short to contain length prefix.");

        int originalLength = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(0, 4));
        if (originalLength < 0 || originalLength > data.Length - 4)
            throw new CryptographicException("Invalid length prefix — possible tampering detected.");

        return data.AsSpan(4, originalLength).ToArray();
    }

    // ═══════════════ Decoy Packets ═══════════════

    /// <summary>
    /// Generates a decoy packet that resembles a real encrypted packet.
    /// Starts with a valid-looking header (type=0xFF, timestamp, random ID) followed by random data.
    /// </summary>
    /// <param name="size">Total packet size in bytes (minimum 17 for header).</param>
    /// <returns>A decoy packet byte array.</returns>
    public static byte[] GenerateDecoyPacket(int size)
    {
        if (size < DecoyPacketHeader.HeaderSize)
            throw new ArgumentOutOfRangeException(nameof(size),
                $"Decoy packet must be at least {DecoyPacketHeader.HeaderSize} bytes.");

        var packet = new byte[size];

        // Fill entire packet with random data first
        RandomNumberGenerator.Fill(packet);

        // Write header
        packet[0] = DecoyPacketHeader.DecoyMarker;
        BinaryPrimitives.WriteInt64BigEndian(
            packet.AsSpan(1, 8),
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        // Bytes 9..16 are already random (RandomId)

        return packet;
    }

    /// <summary>
    /// Checks if a packet is a decoy by examining the header marker byte.
    /// </summary>
    /// <param name="data">Packet data to inspect.</param>
    /// <returns>True if the packet has a decoy marker.</returns>
    public static bool IsDecoyPacket(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return data.Length >= DecoyPacketHeader.HeaderSize && data[0] == DecoyPacketHeader.DecoyMarker;
    }

    // ═══════════════ Fixed-Size Packets ═══════════════

    /// <summary>
    /// Pads data to a fixed size. Format: [4 bytes actual length (big-endian)][actual data][random padding].
    /// Always produces output of exactly fixedSize bytes.
    /// </summary>
    /// <param name="data">Original data.</param>
    /// <param name="fixedSize">Fixed output size (default 4096). Must be >= data.Length + 4.</param>
    /// <returns>Fixed-size byte array.</returns>
    public static byte[] PadToFixedSize(byte[] data, int fixedSize = 4096)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (fixedSize < 4)
            throw new ArgumentOutOfRangeException(nameof(fixedSize), "Fixed size must be at least 4 bytes.");
        if (data.Length + 4 > fixedSize)
            throw new InvalidOperationException(
                $"Data ({data.Length} bytes) + 4-byte header exceeds fixed size ({fixedSize} bytes). " +
                $"Max payload: {fixedSize - 4} bytes.");

        var result = new byte[fixedSize];

        // Write actual data length
        BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(0, 4), data.Length);

        // Copy actual data
        data.CopyTo(result, 4);

        // Fill remaining space with random bytes (prevents content-length analysis)
        if (4 + data.Length < fixedSize)
        {
            RandomNumberGenerator.Fill(result.AsSpan(4 + data.Length));
        }

        return result;
    }

    /// <summary>
    /// Extracts original data from a fixed-size padded packet.
    /// </summary>
    /// <param name="data">Fixed-size packet produced by <see cref="PadToFixedSize"/>.</param>
    /// <returns>Original unpadded data.</returns>
    public static byte[] UnpadFromFixedSize(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length < 4)
            throw new CryptographicException("Fixed-size packet too short to contain length header.");

        int actualLength = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(0, 4));
        if (actualLength < 0 || actualLength > data.Length - 4)
            throw new CryptographicException("Invalid length in fixed-size packet — possible tampering.");

        return data.AsSpan(4, actualLength).ToArray();
    }

    // ═══════════════ Timing Obfuscation ═══════════════

    /// <summary>
    /// Adds random jitter delays to a sequence of messages to obscure timing patterns.
    /// Returns a list of (message, suggestedDelayMs) pairs.
    /// </summary>
    /// <param name="messages">The messages to schedule.</param>
    /// <param name="minDelayMs">Minimum inter-message delay in milliseconds.</param>
    /// <param name="maxDelayMs">Maximum inter-message delay in milliseconds.</param>
    /// <returns>List of tuples containing each message and its suggested delay before sending.</returns>
    public static List<(byte[] Message, int DelayMs)> ObfuscateTimingPattern(
        IReadOnlyList<byte[]> messages,
        int minDelayMs = 50,
        int maxDelayMs = 2000)
    {
        ArgumentNullException.ThrowIfNull(messages);
        if (minDelayMs < 0)
            throw new ArgumentOutOfRangeException(nameof(minDelayMs));
        if (maxDelayMs < minDelayMs)
            throw new ArgumentOutOfRangeException(nameof(maxDelayMs));

        var result = new List<(byte[] Message, int DelayMs)>(messages.Count);
        foreach (var msg in messages)
        {
            int delay = RandomNumberGenerator.GetInt32(minDelayMs, maxDelayMs + 1);
            result.Add((msg, delay));
        }
        return result;
    }

    /// <summary>
    /// Calculates the optimal block size for padding based on average message size.
    /// Returns the nearest power of 2 >= average message size.
    /// </summary>
    /// <param name="avgMessageSize">Average message size in bytes.</param>
    /// <returns>Optimal block size (power of 2).</returns>
    public static int CalculateOptimalBlockSize(int avgMessageSize)
    {
        if (avgMessageSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(avgMessageSize), "Average message size must be positive.");

        // Find nearest power of 2 >= avgMessageSize, minimum 64
        int size = 64;
        while (size < avgMessageSize && size < 65536)
        {
            size <<= 1;
        }
        return size;
    }
}
