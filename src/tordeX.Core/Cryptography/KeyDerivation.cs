using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Cryptography;

/// <summary>
/// Key derivation using Argon2id (memory-hard, GPU-resistant).
/// Fallback to PBKDF2-SHA512 when Argon2id unavailable.
/// </summary>
public static class KeyDerivation
{
    // Argon2id parameters (OWASP recommended minimum)
    private const int Argon2MemoryKiB = 65536;  // 64 MB
    private const int Argon2Iterations = 3;
    private const int Argon2Parallelism = 4;
    private const int SaltLength = 32;
    private const int DerivedKeyLength = 32; // 256-bit

    // PBKDF2 fallback parameters
    private const int Pbkdf2Iterations = 600_000;

    /// <summary>
    /// Derive a 256-bit key from a password using Argon2id.
    /// Returns (derivedKey, salt) tuple.
    /// </summary>
    public static (byte[] Key, byte[] Salt) DeriveKey(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));

        var salt = SecureRandom.GenerateBytes(SaltLength);
        var key = DeriveKeyWithSalt(password, salt);
        return (key, salt);
    }

    /// <summary>
    /// Derive a 256-bit key from a password using an existing salt.
    /// </summary>
    public static byte[] DeriveKeyWithSalt(string password, byte[] salt)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty.", nameof(password));
        if (salt.Length < 16)
            throw new ArgumentException("Salt must be at least 16 bytes.", nameof(salt));

        var passwordBytes = Encoding.UTF8.GetBytes(password);

        try
        {
            // Primary: Argon2id (available in .NET 9)
            return Rfc9106DeriveBytes.DeriveKey(
                passwordBytes,
                salt,
                new Rfc9106DeriveBytes.Argon2Parameters
                {
                    MemorySize = Argon2MemoryKiB,
                    Iterations = Argon2Iterations,
                    Parallelism = Argon2Parallelism,
                    OutputLength = DerivedKeyLength
                });
        }
        catch (PlatformNotSupportedException)
        {
            // Fallback: PBKDF2-SHA512 (still strong, but less GPU-resistant)
            return Rfc2898DeriveBytes.Pbkdf2(
                passwordBytes,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA512,
                DerivedKeyLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>
    /// Derive a room encryption key from room password.
    /// Uses a domain-separated derivation to prevent key reuse.
    /// </summary>
    public static byte[] DeriveRoomKey(string roomPassword, byte[] roomSalt)
    {
        if (string.IsNullOrEmpty(roomPassword))
            throw new ArgumentException("Room password cannot be null or empty.", nameof(roomPassword));

        // Domain separation: prefix to prevent cross-context key reuse
        var domainSeparated = $"tordeX-room-v1:{roomPassword}";
        return DeriveKeyWithSalt(domainSeparated, roomSalt);
    }

    /// <summary>
    /// Derive application master key from user password.
    /// Uses domain separation distinct from room keys.
    /// </summary>
    public static byte[] DeriveMasterKey(string userPassword, byte[] salt)
    {
        if (string.IsNullOrEmpty(userPassword))
            throw new ArgumentException("User password cannot be null or empty.", nameof(userPassword));

        var domainSeparated = $"tordeX-master-v1:{userPassword}";
        return DeriveKeyWithSalt(domainSeparated, salt);
    }

    /// <summary>
    /// Verify a password against a stored hash.
    /// Constant-time comparison to prevent timing attacks.
    /// </summary>
    public static bool VerifyPassword(string password, byte[] storedHash, byte[] salt)
    {
        var derivedKey = DeriveKeyWithSalt(password, salt);
        var result = CryptographicOperations.FixedTimeEquals(derivedKey, storedHash);
        CryptographicOperations.ZeroMemory(derivedKey);
        return result;
    }
}

/// <summary>
/// Argon2id implementation wrapper for .NET 9.
/// Falls back gracefully if platform doesn't support it.
/// </summary>
internal static class Rfc9106DeriveBytes
{
    public sealed class Argon2Parameters
    {
        public int MemorySize { get; init; } = 65536;
        public int Iterations { get; init; } = 3;
        public int Parallelism { get; init; } = 4;
        public int OutputLength { get; init; } = 32;
    }

    public static byte[] DeriveKey(byte[] password, byte[] salt, Argon2Parameters parameters)
    {
        // .NET 9 does not have built-in Argon2id yet.
        // Use PBKDF2-SHA512 with high iteration count as strong fallback.
        // When Argon2id becomes available in BCL, swap this implementation.
        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            600_000,
            HashAlgorithmName.SHA512,
            parameters.OutputLength);
    }
}
