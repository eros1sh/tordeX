using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// LSB (Least Significant Bit) steganography service.
/// Hides encrypted messages inside PNG/BMP image pixel data.
/// Format: [4 bytes length][encrypted message bytes] encoded in LSBs of RGB channels.
/// </summary>
public static class SteganographyService
{
    private const int HeaderSize = 32; // bits for payload length

    /// <summary>
    /// Embeds an encrypted message into raw RGBA pixel data.
    /// Each byte of the message is stored across 8 pixel color channel LSBs.
    /// </summary>
    /// <param name="pixelData">Raw RGBA pixel buffer (will be modified in-place).</param>
    /// <param name="message">The plaintext message to hide.</param>
    /// <param name="key">AES-256 key for encrypting the message before embedding.</param>
    /// <returns>The modified pixel data with hidden message.</returns>
    public static byte[] Embed(byte[] pixelData, string message, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(pixelData);
        ArgumentException.ThrowIfNullOrEmpty(message);

        // Encrypt the message first
        var plainBytes = Encoding.UTF8.GetBytes(message);
        var encrypted = EncryptPayload(plainBytes, key);

        // Check capacity: each byte needs 8 bits = 8 color channels
        // RGBA = 4 channels per pixel, so each pixel stores 4 bits
        var totalBitsNeeded = HeaderSize + (encrypted.Length * 8);
        var availableBits = pixelData.Length; // Each byte in pixelData is one channel

        if (totalBitsNeeded > availableBits)
            throw new InvalidOperationException(
                $"Image too small. Need {totalBitsNeeded} bits but only {availableBits} available. " +
                $"Max message size for this image: ~{(availableBits - HeaderSize) / 8} bytes.");

        var result = new byte[pixelData.Length];
        Array.Copy(pixelData, result, pixelData.Length);

        int bitIndex = 0;

        // Write 32-bit header (payload length)
        WriteBits(result, ref bitIndex, encrypted.Length, HeaderSize);

        // Write encrypted payload
        foreach (var b in encrypted)
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                int value = (b >> bit) & 1;
                result[bitIndex] = (byte)((result[bitIndex] & 0xFE) | value);
                bitIndex++;
            }
        }

        return result;
    }

    /// <summary>
    /// Extracts a hidden message from raw RGBA pixel data.
    /// </summary>
    /// <param name="pixelData">Raw RGBA pixel buffer potentially containing a hidden message.</param>
    /// <param name="key">AES-256 key for decrypting the extracted message.</param>
    /// <returns>The decrypted hidden message, or null if extraction fails.</returns>
    public static string? Extract(byte[] pixelData, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(pixelData);

        if (pixelData.Length < HeaderSize)
            return null;

        try
        {
            int bitIndex = 0;

            // Read 32-bit header (payload length)
            int payloadLength = ReadBits(pixelData, ref bitIndex, HeaderSize);

            if (payloadLength <= 0 || payloadLength > (pixelData.Length - HeaderSize) / 8)
                return null;

            // Read encrypted payload
            var encrypted = new byte[payloadLength];
            for (int i = 0; i < payloadLength; i++)
            {
                byte b = 0;
                for (int bit = 7; bit >= 0; bit--)
                {
                    b |= (byte)((pixelData[bitIndex] & 1) << bit);
                    bitIndex++;
                }
                encrypted[i] = b;
            }

            // Decrypt
            var decrypted = DecryptPayload(encrypted, key);
            return Encoding.UTF8.GetString(decrypted);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Calculate maximum message size (in characters) for given pixel data size.
    /// </summary>
    public static int GetMaxMessageSize(int pixelDataLength)
    {
        var availableBits = pixelDataLength - HeaderSize;
        if (availableBits <= 0) return 0;
        // AES-GCM adds 12 (nonce) + 16 (tag) = 28 bytes overhead
        return Math.Max(0, (availableBits / 8) - 28);
    }

    private static void WriteBits(byte[] data, ref int bitIndex, int value, int numBits)
    {
        for (int i = numBits - 1; i >= 0; i--)
        {
            int bit = (value >> i) & 1;
            data[bitIndex] = (byte)((data[bitIndex] & 0xFE) | bit);
            bitIndex++;
        }
    }

    private static int ReadBits(byte[] data, ref int bitIndex, int numBits)
    {
        int value = 0;
        for (int i = numBits - 1; i >= 0; i--)
        {
            value |= (data[bitIndex] & 1) << i;
            bitIndex++;
        }
        return value;
    }

    private static byte[] EncryptPayload(byte[] data, byte[] key)
    {
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        var ciphertext = new byte[data.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, data, ciphertext, tag);

        // Format: [12 nonce][16 tag][ciphertext]
        var result = new byte[12 + 16 + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, 12);
        ciphertext.CopyTo(result, 28);
        return result;
    }

    private static byte[] DecryptPayload(byte[] encrypted, byte[] key)
    {
        if (encrypted.Length < 28)
            throw new CryptographicException("Invalid steganography payload.");

        var nonce = encrypted.AsSpan(0, 12);
        var tag = encrypted.AsSpan(12, 16);
        var ciphertext = encrypted.AsSpan(28);
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}
