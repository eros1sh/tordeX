using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Represents a single share from Shamir's Secret Sharing scheme.
/// </summary>
/// <param name="Index">The share's x-coordinate (1-based, in GF(256)).</param>
/// <param name="Data">The share's y-values (one byte per byte of the original secret).</param>
public sealed record Share(byte Index, byte[] Data);

/// <summary>
/// Shamir's Secret Sharing over GF(256) (Galois Field with 256 elements).
/// Splits a secret into <c>n</c> shares such that any <c>k</c> (threshold) shares
/// can reconstruct the original secret, but fewer than <c>k</c> shares reveal
/// no information about it (information-theoretic security).
/// <para>
/// Uses the irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D) for GF(256)
/// multiplication via log/antilog tables. Each byte of the secret is processed
/// independently through a random polynomial of degree k-1.
/// </para>
/// </summary>
public static class ShamirSecretService
{
    /// <summary>
    /// Irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x^2 + 1 = 0x11D.
    /// </summary>
    private const int IrreduciblePolynomial = 0x11D;

    /// <summary>Generator element for the multiplicative group of GF(256) under polynomial 0x11D.</summary>
    private const int Generator = 0x02;

    /// <summary>Maximum number of shares (limited by GF(256) non-zero elements).</summary>
    private const int MaxShares = 255;

    /// <summary>Logarithm table for GF(256). LogTable[a] = log_g(a).</summary>
    private static readonly byte[] LogTable = new byte[256];

    /// <summary>Anti-logarithm (exponentiation) table. ExpTable[i] = g^i.</summary>
    private static readonly byte[] ExpTable = new byte[256];

    static ShamirSecretService()
    {
        BuildGaloisFieldTables();
    }

    /// <summary>
    /// Splits a secret byte array into <paramref name="totalShares"/> shares
    /// with a reconstruction threshold of <paramref name="threshold"/>.
    /// </summary>
    /// <param name="secret">The secret to split. Must not be empty.</param>
    /// <param name="totalShares">Total number of shares to generate (2-255).</param>
    /// <param name="threshold">Minimum shares required for reconstruction (2-totalShares).</param>
    /// <returns>Array of <see cref="Share"/> objects.</returns>
    public static Share[] Split(byte[] secret, int totalShares, int threshold)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("Secret cannot be empty.", nameof(secret));
        if (totalShares < 2 || totalShares > MaxShares)
            throw new ArgumentOutOfRangeException(nameof(totalShares), $"Total shares must be between 2 and {MaxShares}.");
        if (threshold < 2 || threshold > totalShares)
            throw new ArgumentOutOfRangeException(nameof(threshold), "Threshold must be between 2 and totalShares.");

        var shares = new Share[totalShares];
        for (int i = 0; i < totalShares; i++)
        {
            shares[i] = new Share((byte)(i + 1), new byte[secret.Length]);
        }

        // Process each byte of the secret independently
        for (int byteIdx = 0; byteIdx < secret.Length; byteIdx++)
        {
            var shareValues = SplitByte(secret[byteIdx], totalShares, threshold);
            for (int i = 0; i < totalShares; i++)
            {
                shares[i].Data[byteIdx] = shareValues[i];
            }
        }

        return shares;
    }

    /// <summary>
    /// Reconstructs the original secret from a set of shares.
    /// Requires at least <paramref name="threshold"/> valid shares.
    /// </summary>
    /// <param name="shares">The shares to combine (minimum threshold count).</param>
    /// <param name="threshold">The threshold that was used during splitting.</param>
    /// <returns>The reconstructed secret bytes.</returns>
    public static byte[] Combine(Share[] shares, int threshold)
    {
        ArgumentNullException.ThrowIfNull(shares);
        if (shares.Length < threshold)
            throw new ArgumentException($"Need at least {threshold} shares to reconstruct, got {shares.Length}.", nameof(shares));
        if (threshold < 2)
            throw new ArgumentOutOfRangeException(nameof(threshold), "Threshold must be at least 2.");

        // Validate all shares have the same data length
        var dataLength = shares[0].Data.Length;
        for (int i = 1; i < shares.Length; i++)
        {
            if (shares[i].Data.Length != dataLength)
                throw new ArgumentException("All shares must have the same data length.", nameof(shares));
        }

        // Verify no duplicate indices
        var seenIndices = new HashSet<byte>();
        foreach (var share in shares)
        {
            if (!seenIndices.Add(share.Index))
                throw new ArgumentException($"Duplicate share index detected: {share.Index}.", nameof(shares));
        }

        // Use only the first 'threshold' shares
        var usedShares = shares.AsSpan(0, threshold);
        var secret = new byte[dataLength];

        for (int byteIdx = 0; byteIdx < dataLength; byteIdx++)
        {
            var points = new (byte X, byte Y)[threshold];
            for (int i = 0; i < threshold; i++)
            {
                points[i] = (usedShares[i].Index, usedShares[i].Data[byteIdx]);
            }

            secret[byteIdx] = CombineByte(points);
        }

        return secret;
    }

    /// <summary>
    /// Splits a single secret byte into share values using a random polynomial of degree (threshold-1).
    /// </summary>
    /// <param name="secretByte">The secret byte to split.</param>
    /// <param name="totalShares">Number of shares to generate.</param>
    /// <param name="threshold">Reconstruction threshold.</param>
    /// <returns>Array of share values (y-coordinates for x=1..totalShares).</returns>
    public static byte[] SplitByte(byte secretByte, int totalShares, int threshold)
    {
        // Generate random polynomial coefficients: a[0] = secretByte, a[1..k-1] = random
        var coefficients = new byte[threshold];
        coefficients[0] = secretByte;

        // Fill random coefficients for a[1..k-1]
        var randomBytes = RandomNumberGenerator.GetBytes(threshold - 1);
        Buffer.BlockCopy(randomBytes, 0, coefficients, 1, threshold - 1);

        // Evaluate polynomial at x = 1, 2, ..., totalShares
        var shareValues = new byte[totalShares];
        for (int i = 0; i < totalShares; i++)
        {
            byte x = (byte)(i + 1);
            shareValues[i] = EvaluatePolynomial(coefficients, x);
        }

        return shareValues;
    }

    /// <summary>
    /// Reconstructs a single secret byte from share points using Lagrange interpolation at x=0.
    /// </summary>
    /// <param name="points">Array of (x, y) share points.</param>
    /// <returns>The reconstructed secret byte.</returns>
    public static byte CombineByte((byte X, byte Y)[] points)
    {
        ArgumentNullException.ThrowIfNull(points);
        if (points.Length < 2)
            throw new ArgumentException("At least 2 points are required.", nameof(points));

        // Lagrange interpolation at x=0
        byte result = 0;

        for (int i = 0; i < points.Length; i++)
        {
            byte numerator = 1;
            byte denominator = 1;

            for (int j = 0; j < points.Length; j++)
            {
                if (i == j) continue;

                // numerator *= (0 - x_j) = x_j in GF(256) since -a = a
                numerator = GfMul(numerator, points[j].X);

                // denominator *= (x_i - x_j)
                denominator = GfMul(denominator, GfAdd(points[i].X, points[j].X));
            }

            // Lagrange basis: L_i(0) = numerator / denominator
            var lagrangeBasis = GfDiv(numerator, denominator);

            // Accumulate: result += y_i * L_i(0)
            result = GfAdd(result, GfMul(points[i].Y, lagrangeBasis));
        }

        return result;
    }

    /// <summary>
    /// Splits a master password into <paramref name="n"/> hex-encoded recovery shares
    /// with a reconstruction threshold of <paramref name="k"/>.
    /// </summary>
    /// <param name="masterPassword">The master password bytes to split.</param>
    /// <param name="n">Total number of recovery shares.</param>
    /// <param name="k">Minimum shares required for recovery.</param>
    /// <returns>List of hex-encoded share strings. Format: "II:HHHH..." where II is the share index.</returns>
    public static List<string> GenerateRecoveryShares(byte[] masterPassword, int n, int k)
    {
        ArgumentNullException.ThrowIfNull(masterPassword);
        if (masterPassword.Length == 0)
            throw new ArgumentException("Master password cannot be empty.", nameof(masterPassword));

        var shares = Split(masterPassword, n, k);
        var result = new List<string>(n);

        foreach (var share in shares)
        {
            // Format: "index:hexdata"
            var hex = Convert.ToHexString(share.Data).ToLowerInvariant();
            result.Add($"{share.Index:x2}:{hex}");
        }

        return result;
    }

    /// <summary>
    /// Recovers master password bytes from hex-encoded recovery share strings.
    /// </summary>
    /// <param name="shareStrings">Hex-encoded share strings in "II:HHHH..." format.</param>
    /// <returns>The reconstructed master password bytes.</returns>
    public static byte[] RecoverFromShares(List<string> shareStrings)
    {
        ArgumentNullException.ThrowIfNull(shareStrings);
        if (shareStrings.Count < 2)
            throw new ArgumentException("At least 2 shares are required for recovery.", nameof(shareStrings));

        var shares = new Share[shareStrings.Count];
        for (int i = 0; i < shareStrings.Count; i++)
        {
            var parts = shareStrings[i].Split(':');
            if (parts.Length != 2)
                throw new ArgumentException($"Invalid share format at index {i}. Expected 'index:hexdata'.", nameof(shareStrings));

            var index = Convert.ToByte(parts[0], 16);
            var data = Convert.FromHexString(parts[1]);
            shares[i] = new Share(index, data);
        }

        // Threshold = number of shares provided (caller must provide exactly threshold shares)
        return Combine(shares, shares.Length);
    }

    // ═══════════════════════════════════════════════════════════
    // GF(256) Arithmetic
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Addition in GF(256) is XOR.
    /// </summary>
    private static byte GfAdd(byte a, byte b) => (byte)(a ^ b);

    /// <summary>
    /// Multiplication in GF(256) using log/antilog tables.
    /// </summary>
    private static byte GfMul(byte a, byte b)
    {
        if (a == 0 || b == 0) return 0;
        var logSum = (LogTable[a] + LogTable[b]) % 255;
        return ExpTable[logSum];
    }

    /// <summary>
    /// Division in GF(256): a / b = a * b^(-1).
    /// </summary>
    private static byte GfDiv(byte a, byte b)
    {
        if (b == 0)
            throw new DivideByZeroException("Division by zero in GF(256).");
        if (a == 0) return 0;
        var logDiff = (LogTable[a] - LogTable[b] + 255) % 255;
        return ExpTable[logDiff];
    }

    /// <summary>
    /// Evaluates a polynomial at point x in GF(256) using Horner's method.
    /// coefficients[0] is the constant term (secret), coefficients[k-1] is the highest degree.
    /// </summary>
    private static byte EvaluatePolynomial(byte[] coefficients, byte x)
    {
        // Horner's method: evaluate from highest degree to lowest
        byte result = 0;
        for (int i = coefficients.Length - 1; i >= 0; i--)
        {
            result = GfAdd(GfMul(result, x), coefficients[i]);
        }
        return result;
    }

    /// <summary>
    /// Builds the log and antilog (exp) tables for GF(256) with the
    /// irreducible polynomial 0x11D and generator 0x02.
    /// ExpTable[i] = g^i, LogTable[g^i] = i.
    /// </summary>
    private static void BuildGaloisFieldTables()
    {
        int value = 1;
        for (int i = 0; i < 255; i++)
        {
            ExpTable[i] = (byte)value;
            LogTable[value] = (byte)i;

            // Multiply by generator (0x02) in GF(256): left shift by 1 with reduction
            value <<= 1;
            if ((value & 0x100) != 0)
            {
                value ^= IrreduciblePolynomial;
            }
        }

        // LogTable[0] is undefined (log of 0 doesn't exist) — handled by GfMul returning 0
    }
}
