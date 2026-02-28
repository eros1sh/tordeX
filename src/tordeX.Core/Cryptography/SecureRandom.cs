using System.Security.Cryptography;

namespace TordeX.Core.Cryptography;

/// <summary>
/// Cryptographically secure random number generation using OS entropy sources.
/// Uses CryptGenRandom (Windows) / /dev/urandom (Linux) via .NET's RNG.
/// </summary>
public static class SecureRandom
{
    public static byte[] GenerateBytes(int count)
    {
        if (count <= 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Byte count must be positive.");

        var buffer = new byte[count];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    public static string GenerateHex(int byteCount)
    {
        var bytes = GenerateBytes(byteCount);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string GenerateBase64(int byteCount)
    {
        var bytes = GenerateBytes(byteCount);
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Generate a random integer in [0, exclusiveMax).
    /// Rejection sampling to avoid modulo bias.
    /// </summary>
    public static int GenerateInt(int exclusiveMax)
    {
        if (exclusiveMax <= 0)
            throw new ArgumentOutOfRangeException(nameof(exclusiveMax));

        return RandomNumberGenerator.GetInt32(exclusiveMax);
    }
}
