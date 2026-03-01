using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Cryptography;

/// <summary>
/// Key derivation using PBKDF2-SHA512 (600K iterations).
/// API surface designed for future Argon2id migration when .NET BCL adds support.
/// </summary>
public static class KeyDerivation
{
    private const int SaltLength = 32;
    private const int DerivedKeyLength = 32; // 256-bit

    // PBKDF2-SHA512 parameters (current implementation)
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

