using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TordeX.Core.Services;

/// <summary>
/// An anonymous user profile containing only cryptographic identity — no real-world PII.
/// </summary>
/// <param name="Id">Random hex identifier (no correlation to real identity).</param>
/// <param name="PublicKey">ECDH public key for key exchange.</param>
/// <param name="PrivateKey">ECDH private key (PKCS8-encoded, must be protected in memory).</param>
/// <param name="Pseudonym">Human-readable pseudonym (e.g., "SilentFox").</param>
/// <param name="CreatedAt">Timestamp of profile creation.</param>
public sealed record AnonymousProfile(
    string Id,
    byte[] PublicKey,
    byte[] PrivateKey,
    string Pseudonym,
    DateTimeOffset CreatedAt);

/// <summary>
/// Privacy-preserving utilities for anonymous profile generation, PII stripping,
/// and data masking. All operations are stateless and deterministic where noted.
/// </summary>
public static partial class PrivacyService
{
    // ═══════════════ Pseudonym Word Lists ═══════════════

    private static readonly string[] Adjectives =
    [
        "Silent", "Cryptic", "Shadow", "Hidden", "Phantom",
        "Stealth", "Veiled", "Cipher", "Masked", "Ghost",
        "Rogue", "Covert", "Enigma", "Hollow", "Frost",
        "Onyx", "Spectral", "Obsidian", "Nebula", "Void"
    ];

    private static readonly string[] Nouns =
    [
        "Fox", "Wolf", "Raven", "Hawk", "Viper",
        "Lynx", "Falcon", "Panther", "Cobra", "Owl",
        "Bear", "Tiger", "Mantis", "Osprey", "Serpent",
        "Phoenix", "Griffin", "Drake", "Wraith", "Specter"
    ];

    // ═══════════════ Compiled Regex Patterns ═══════════════

    // SECURITY: All regex patterns use NonBacktracking to prevent ReDoS (CWE-1333)

    /// <summary>
    /// Matches IPv4 addresses (e.g., 192.168.1.100).
    /// </summary>
    [GeneratedRegex(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        matchTimeoutMilliseconds: 2000)]
    private static partial Regex Ipv4Regex();

    /// <summary>
    /// Matches email addresses.
    /// </summary>
    [GeneratedRegex(
        @"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        matchTimeoutMilliseconds: 2000)]
    private static partial Regex EmailRegex();

    /// <summary>
    /// Matches common phone number formats (US/international).
    /// </summary>
    [GeneratedRegex(
        @"(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        matchTimeoutMilliseconds: 2000)]
    private static partial Regex PhoneRegex();

    /// <summary>
    /// Matches SSN-like patterns (XXX-XX-XXXX).
    /// </summary>
    [GeneratedRegex(
        @"\b\d{3}[\-]\d{2}[\-]\d{4}\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        matchTimeoutMilliseconds: 2000)]
    private static partial Regex SsnRegex();

    /// <summary>
    /// Matches IPv6 addresses (simplified — common compressed and full forms).
    /// </summary>
    [GeneratedRegex(
        @"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        matchTimeoutMilliseconds: 2000)]
    private static partial Regex Ipv6Regex();

    // ═══════════════ Profile Generation ═══════════════

    /// <summary>
    /// Generates a fully anonymous profile with a fresh ECDH key pair and random pseudonym.
    /// Contains zero real-world PII.
    /// </summary>
    /// <returns>A new <see cref="AnonymousProfile"/> with random identity.</returns>
    public static AnonymousProfile GenerateAnonymousProfile()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
        var privateKey = ecdh.ExportPkcs8PrivateKey();

        return new AnonymousProfile(
            Id: GenerateRandomHex(16),
            PublicKey: publicKey,
            PrivateKey: privateKey,
            Pseudonym: GeneratePseudonym(),
            CreatedAt: DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Generates a random pseudonym by combining a random adjective and noun
    /// (e.g., "SilentFox", "CrypticWolf").
    /// </summary>
    /// <returns>A pseudonym string.</returns>
    public static string GeneratePseudonym()
    {
        var adjIndex = RandomNumberGenerator.GetInt32(Adjectives.Length);
        var nounIndex = RandomNumberGenerator.GetInt32(Nouns.Length);
        return $"{Adjectives[adjIndex]}{Nouns[nounIndex]}";
    }

    /// <summary>
    /// Generates a deterministic pseudonym for a specific room using HMAC-SHA256.
    /// The same (roomId, masterKey) pair always produces the same pseudonym,
    /// providing consistent identity within a room without cross-room correlation.
    /// </summary>
    /// <param name="roomId">The room identifier.</param>
    /// <param name="masterKey">Master key for HMAC derivation.</param>
    /// <returns>A deterministic pseudonym for the room.</returns>
    public static string GenerateRoomPseudonym(string roomId, byte[] masterKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(roomId);
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.Length == 0)
            throw new ArgumentException("Master key cannot be empty.", nameof(masterKey));

        var roomBytes = Encoding.UTF8.GetBytes($"tordeX-room-pseudonym-v1:{roomId}");
        var hash = HMACSHA256.HashData(masterKey, roomBytes);

        try
        {
            // Use first 4 bytes for adjective index, next 4 for noun index
            var adjIndex = Math.Abs(BitConverter.ToInt32(hash, 0)) % Adjectives.Length;
            var nounIndex = Math.Abs(BitConverter.ToInt32(hash, 4)) % Nouns.Length;

            // Append a 3-digit numeric suffix from bytes 8-9 for uniqueness
            var suffix = (BitConverter.ToUInt16(hash, 8) % 1000).ToString("D3");

            return $"{Adjectives[adjIndex]}{Nouns[nounIndex]}{suffix}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    // ═══════════════ PII Sanitization ═══════════════

    /// <summary>
    /// Sanitizes a log entry by stripping all detected PII patterns
    /// (IP addresses, emails, phone numbers, SSN-like patterns).
    /// </summary>
    /// <param name="logEntry">The raw log entry text.</param>
    /// <returns>Sanitized log entry with PII replaced by redaction markers.</returns>
    public static string SanitizeLogEntry(string logEntry)
    {
        if (string.IsNullOrEmpty(logEntry)) return logEntry;

        return StripPII(logEntry);
    }

    /// <summary>
    /// Masks an IPv4 address, preserving only the first octet for general classification.
    /// Example: "192.168.1.100" -> "192.x.x.x"
    /// </summary>
    /// <param name="ip">The IP address string to mask.</param>
    /// <returns>Masked IP address string.</returns>
    public static string MaskIpAddress(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return "[REDACTED_IP]";

        var parts = ip.Trim().Split('.');
        if (parts.Length == 4)
        {
            return $"{parts[0]}.x.x.x";
        }

        // IPv6 or unrecognized format — fully redact
        return "[REDACTED_IP]";
    }

    /// <summary>
    /// Masks an email address, showing first character of local part and domain TLD only.
    /// Example: "john.doe@example.com" -> "j***@e***.com"
    /// </summary>
    /// <param name="email">The email address to mask.</param>
    /// <returns>Masked email string.</returns>
    public static string MaskEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email)) return "[REDACTED_EMAIL]";

        var atIndex = email.IndexOf('@');
        if (atIndex <= 0) return "[REDACTED_EMAIL]";

        var localPart = email[..atIndex];
        var domainPart = email[(atIndex + 1)..];

        var maskedLocal = localPart.Length > 0 ? $"{localPart[0]}***" : "***";

        var dotIndex = domainPart.LastIndexOf('.');
        if (dotIndex <= 0)
            return $"{maskedLocal}@***.***";

        var domainName = domainPart[..dotIndex];
        var tld = domainPart[(dotIndex + 1)..];
        var maskedDomain = domainName.Length > 0 ? $"{domainName[0]}***" : "***";

        return $"{maskedLocal}@{maskedDomain}.{tld}";
    }

    /// <summary>
    /// Masks a cryptographic fingerprint, showing only the first 4 and last 4 characters.
    /// Example: "a1b2c3d4e5f6g7h8" -> "a1b2...g7h8"
    /// </summary>
    /// <param name="fingerprint">The fingerprint string to mask.</param>
    /// <returns>Masked fingerprint string.</returns>
    public static string MaskFingerprint(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return "[REDACTED]";

        if (fingerprint.Length <= 8)
            return fingerprint; // Too short to meaningfully mask

        return $"{fingerprint[..4]}...{fingerprint[^4..]}";
    }

    /// <summary>
    /// Checks whether the given text contains an IPv4 address pattern.
    /// </summary>
    /// <param name="text">Text to check.</param>
    /// <returns>True if an IPv4 address pattern is found.</returns>
    public static bool IsIpAddress(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        return Ipv4Regex().IsMatch(text);
    }

    /// <summary>
    /// Strips all detected PII patterns from text, replacing with type-specific redaction markers.
    /// Detects: IPv4, IPv6, email addresses, phone numbers, SSN-like patterns.
    /// </summary>
    /// <param name="text">Text to sanitize.</param>
    /// <returns>Text with all detected PII replaced by redaction markers.</returns>
    public static string StripPII(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;

        // Order matters: process more specific patterns first to avoid partial matches

        // SSN-like patterns (XXX-XX-XXXX)
        text = SsnRegex().Replace(text, "[REDACTED_SSN]");

        // Email addresses (before IP to avoid matching domain parts)
        text = EmailRegex().Replace(text, match => MaskEmail(match.Value));

        // IPv6 addresses (before IPv4 to avoid partial matches)
        text = Ipv6Regex().Replace(text, "[REDACTED_IPV6]");

        // IPv4 addresses
        text = Ipv4Regex().Replace(text, match => MaskIpAddress(match.Value));

        // Phone numbers
        text = PhoneRegex().Replace(text, "[REDACTED_PHONE]");

        return text;
    }

    // ═══════════════ Helpers ═══════════════

    /// <summary>
    /// Generates a cryptographically random lowercase hex string.
    /// </summary>
    /// <param name="byteCount">Number of random bytes (hex string will be 2x this length).</param>
    /// <returns>Lowercase hex string.</returns>
    private static string GenerateRandomHex(int byteCount)
    {
        var bytes = new byte[byteCount];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
