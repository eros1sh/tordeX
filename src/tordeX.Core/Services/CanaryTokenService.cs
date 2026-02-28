using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TordeX.Core.Services;

/// <summary>
/// Hidden database markers (canary tokens) to detect unauthorized access or data breaches.
/// Canaries are planted as hidden rows in database tables. If they are modified or removed,
/// it indicates the database has been accessed or tampered with by an unauthorized party.
/// </summary>
public static class CanaryTokenService
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>
    /// Represents a canary token placed in the database to detect unauthorized access.
    /// </summary>
    /// <param name="Id">Unique identifier for the canary token.</param>
    /// <param name="TokenHash">SHA-256 hash of the canary's secret value.</param>
    /// <param name="PlacedAt">When the canary was originally planted.</param>
    /// <param name="Location">Description of where the canary is placed (e.g., "users/row_42").</param>
    /// <param name="LastVerified">When the canary was last successfully verified.</param>
    /// <param name="IsTriggered">Whether tampering has been detected for this canary.</param>
    public sealed record CanaryToken(
        string Id,
        string TokenHash,
        DateTimeOffset PlacedAt,
        string Location,
        DateTimeOffset? LastVerified = null,
        bool IsTriggered = false);

    /// <summary>
    /// Report produced by <see cref="DetectTampering"/> comparing original and current canary states.
    /// </summary>
    /// <param name="IsClean">True if no tampering was detected.</param>
    /// <param name="MissingTokens">IDs of canary tokens that have been removed.</param>
    /// <param name="ModifiedTokens">IDs of canary tokens whose hashes have changed.</param>
    /// <param name="Timestamp">When this report was generated.</param>
    public sealed record TamperReport(
        bool IsClean,
        List<string> MissingTokens,
        List<string> ModifiedTokens,
        DateTimeOffset Timestamp);

    /// <summary>
    /// Generates a new canary token with a cryptographically random 32-byte secret.
    /// The returned token contains the SHA-256 hash of the secret (the secret itself is not stored).
    /// </summary>
    /// <returns>A new <see cref="CanaryToken"/> ready to be placed in a database table.</returns>
    public static CanaryToken GenerateToken()
    {
        Span<byte> secret = stackalloc byte[32];
        RandomNumberGenerator.Fill(secret);

        var hash = ComputeSha256Hex(secret);

        return new CanaryToken(
            Id: Guid.NewGuid().ToString("N"),
            TokenHash: hash,
            PlacedAt: DateTimeOffset.UtcNow,
            Location: string.Empty);
    }

    /// <summary>
    /// Generates a parameterized SQL INSERT statement for placing a canary in the canary_tokens table.
    /// The caller must bind the parameter values separately to prevent SQL injection.
    /// </summary>
    /// <param name="tokenHash">SHA-256 hash of the canary's secret value.</param>
    /// <param name="location">Description of the canary's placement location.</param>
    /// <returns>A parameterized SQL INSERT statement.</returns>
    public static string PlaceCanary(string tokenHash, string location)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenHash);
        ArgumentException.ThrowIfNullOrWhiteSpace(location);

        // SECURITY: Returns parameterized SQL — callers MUST bind @id, @token_hash, @location, @placed_at
        return """
            INSERT INTO canary_tokens (id, token_hash, location, placed_at, is_triggered)
            VALUES (@id, @token_hash, @location, @placed_at, 0);
            """;
    }

    /// <summary>
    /// Performs a constant-time comparison of two token hashes to prevent timing attacks.
    /// </summary>
    /// <param name="tokenHash">The hash value to verify.</param>
    /// <param name="storedHash">The stored reference hash to compare against.</param>
    /// <returns>True if the hashes match; false otherwise.</returns>
    public static bool VerifyCanary(string tokenHash, string storedHash)
    {
        if (string.IsNullOrEmpty(tokenHash) || string.IsNullOrEmpty(storedHash))
            return false;

        var tokenBytes = Encoding.UTF8.GetBytes(tokenHash);
        var storedBytes = Encoding.UTF8.GetBytes(storedHash);

        // SECURITY FIX: CWE-208 — constant-time comparison prevents timing side-channel attacks
        return CryptographicOperations.FixedTimeEquals(tokenBytes, storedBytes);
    }

    /// <summary>
    /// Checks a collection of canary tokens and returns those that have been triggered
    /// (indicating tampering or unauthorized access).
    /// </summary>
    /// <param name="canaries">The canary tokens to check.</param>
    /// <returns>List of canary tokens where <see cref="CanaryToken.IsTriggered"/> is true.</returns>
    public static List<CanaryToken> CheckAllCanaries(IEnumerable<CanaryToken> canaries)
    {
        ArgumentNullException.ThrowIfNull(canaries);

        return canaries.Where(c => c.IsTriggered).ToList();
    }

    /// <summary>
    /// Returns the SQL DDL statement to create the canary_tokens table.
    /// </summary>
    /// <returns>SQL CREATE TABLE statement for SQLite.</returns>
    public static string CreateCanaryTable()
    {
        return """
            CREATE TABLE IF NOT EXISTS canary_tokens (
                id            TEXT PRIMARY KEY NOT NULL,
                token_hash    TEXT NOT NULL,
                location      TEXT NOT NULL,
                placed_at     TEXT NOT NULL,
                last_verified TEXT,
                is_triggered  INTEGER NOT NULL DEFAULT 0
            );
            """;
    }

    /// <summary>
    /// Generates a hidden canary row for insertion into an arbitrary table.
    /// The row uses a well-known canary prefix in the ID to identify it, plus the token hash
    /// is stored as a column value. Returns both the parameterized INSERT SQL and the token.
    /// </summary>
    /// <param name="tableName">The table name to insert the canary row into. Must be alphanumeric/underscores only.</param>
    /// <returns>A tuple of (parameterized INSERT SQL, generated CanaryToken).</returns>
    /// <exception cref="ArgumentException">If the table name contains invalid characters.</exception>
    public static (string InsertSql, CanaryToken Token) GenerateCanaryRow(string tableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tableName);

        // SECURITY FIX: CWE-89 — validate table name to prevent SQL injection via identifier
        if (!IsValidIdentifier(tableName))
            throw new ArgumentException(
                "Table name must contain only alphanumeric characters and underscores.",
                nameof(tableName));

        var token = GenerateToken();
        var tokenWithLocation = token with { Location = $"{tableName}/canary" };

        // Table name is validated above; parameterized values for data columns
        var sql = $"""
            INSERT INTO {tableName} (id, canary_hash, created_at)
            VALUES (@id, @canary_hash, @created_at);
            """;

        return (sql, tokenWithLocation);
    }

    /// <summary>
    /// Returns a parameterized SQL SELECT query to verify a specific canary token by ID.
    /// </summary>
    /// <param name="tokenId">The canary token ID to look up.</param>
    /// <returns>A parameterized SQL SELECT statement. Caller must bind @token_id.</returns>
    public static string GetVerificationQuery(string tokenId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenId);

        // SECURITY: Parameterized query — caller must bind @token_id
        return """
            SELECT id, token_hash, location, placed_at, last_verified, is_triggered
            FROM canary_tokens
            WHERE id = @token_id;
            """;
    }

    /// <summary>
    /// Compares original canary tokens against their current state to detect tampering.
    /// Missing or modified tokens indicate unauthorized database access.
    /// </summary>
    /// <param name="originalTokens">The original set of canary tokens as they were placed.</param>
    /// <param name="currentTokens">The current state of canary tokens retrieved from the database.</param>
    /// <returns>A <see cref="TamperReport"/> detailing any detected tampering.</returns>
    public static TamperReport DetectTampering(
        IReadOnlyList<CanaryToken> originalTokens,
        IReadOnlyList<CanaryToken> currentTokens)
    {
        ArgumentNullException.ThrowIfNull(originalTokens);
        ArgumentNullException.ThrowIfNull(currentTokens);

        var currentById = new Dictionary<string, CanaryToken>(currentTokens.Count);
        foreach (var token in currentTokens)
        {
            currentById[token.Id] = token;
        }

        var missingTokens = new List<string>();
        var modifiedTokens = new List<string>();

        foreach (var original in originalTokens)
        {
            if (!currentById.TryGetValue(original.Id, out var current))
            {
                missingTokens.Add(original.Id);
                continue;
            }

            // Constant-time comparison to avoid timing leaks
            if (!VerifyCanary(original.TokenHash, current.TokenHash))
            {
                modifiedTokens.Add(original.Id);
            }
        }

        var isClean = missingTokens.Count == 0 && modifiedTokens.Count == 0;

        return new TamperReport(
            IsClean: isClean,
            MissingTokens: missingTokens,
            ModifiedTokens: modifiedTokens,
            Timestamp: DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Serializes a list of canary tokens to a JSON string.
    /// </summary>
    /// <param name="tokens">The tokens to serialize.</param>
    /// <returns>A JSON string representation of the tokens.</returns>
    public static string SerializeTokens(IReadOnlyList<CanaryToken> tokens)
    {
        ArgumentNullException.ThrowIfNull(tokens);

        return JsonSerializer.Serialize(tokens, s_jsonOptions);
    }

    /// <summary>
    /// Deserializes a JSON string back into a list of canary tokens.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>A list of <see cref="CanaryToken"/> instances.</returns>
    /// <exception cref="JsonException">If the JSON is malformed or invalid.</exception>
    public static List<CanaryToken> DeserializeTokens(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);

        // SECURITY: Limit deserialization input size to prevent DoS via large payloads
        const int maxJsonLength = 1_048_576; // 1 MB
        if (json.Length > maxJsonLength)
            throw new InvalidOperationException(
                $"JSON payload exceeds maximum allowed size of {maxJsonLength} bytes.");

        return JsonSerializer.Deserialize<List<CanaryToken>>(json, s_jsonOptions)
               ?? [];
    }

    /// <summary>
    /// Validates that a SQL identifier (table/column name) contains only safe characters.
    /// </summary>
    private static bool IsValidIdentifier(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 128)
            return false;

        foreach (var ch in name)
        {
            if (!char.IsLetterOrDigit(ch) && ch != '_')
                return false;
        }

        // Must start with letter or underscore
        return char.IsLetter(name[0]) || name[0] == '_';
    }

    /// <summary>
    /// Computes a lowercase hex-encoded SHA-256 hash of the given data.
    /// </summary>
    private static string ComputeSha256Hex(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
