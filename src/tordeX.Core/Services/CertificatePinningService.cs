using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TordeX.Core.Services;

/// <summary>
/// Certificate and public key pinning service.
/// Provides defense against MITM attacks by validating server certificates
/// against a pre-configured set of pinned certificate fingerprints and public key hashes.
/// Thread-safe via <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
public static partial class CertificatePinningService
{
    /// <summary>
    /// A pinned certificate entry.
    /// </summary>
    /// <param name="SubjectName">The certificate subject (CN or full subject).</param>
    /// <param name="Sha256Fingerprint">SHA-256 hash of the entire DER-encoded certificate (hex, lowercase).</param>
    /// <param name="PublicKeySha256">SHA-256 hash of the SubjectPublicKeyInfo (hex, lowercase).</param>
    /// <param name="ExpiresAt">When this pin expires and should be refreshed.</param>
    public sealed record PinnedCert(
        string SubjectName,
        string Sha256Fingerprint,
        string PublicKeySha256,
        DateTimeOffset ExpiresAt);

    /// <summary>
    /// Result of certificate validation against the pin store.
    /// </summary>
    /// <param name="IsValid">True if the certificate passed all validation checks.</param>
    /// <param name="IsPinned">True if the certificate matched a pin in the store.</param>
    /// <param name="Reason">Human-readable reason for the validation result.</param>
    public sealed record CertValidationResult(bool IsValid, bool IsPinned, string Reason);

    /// <summary>
    /// Thread-safe pin store. Keyed by subject name (case-insensitive).
    /// </summary>
    public sealed class PinStore
    {
        private readonly ConcurrentDictionary<string, PinnedCert> _pins = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Gets the number of pins in the store.</summary>
        public int Count => _pins.Count;

        /// <summary>Gets all pinned certificates.</summary>
        public IReadOnlyCollection<PinnedCert> Pins => _pins.Values.ToArray();

        internal bool TryGet(string subjectName, out PinnedCert? pin) =>
            _pins.TryGetValue(subjectName, out pin);

        internal void Set(string subjectName, PinnedCert pin) =>
            _pins[subjectName] = pin;

        internal bool Remove(string subjectName) =>
            _pins.TryRemove(subjectName, out _);

        internal void Clear() => _pins.Clear();
    }

    // JSON serialization context for NativeAOT compatibility
    [JsonSerializable(typeof(List<PinnedCertDto>))]
    [JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    private sealed partial class PinJsonContext : JsonSerializerContext;

    /// <summary>
    /// DTO for JSON serialization of pinned certificates.
    /// </summary>
    private sealed record PinnedCertDto(
        string SubjectName,
        string Sha256Fingerprint,
        string PublicKeySha256,
        string ExpiresAt);

    // ═══════════════ Pin Management ═══════════════

    /// <summary>
    /// Adds or updates a certificate pin in the store.
    /// </summary>
    /// <param name="store">The pin store.</param>
    /// <param name="subjectName">Certificate subject name (used as key).</param>
    /// <param name="sha256Fingerprint">SHA-256 hex fingerprint of the DER-encoded certificate.</param>
    /// <param name="publicKeyHash">SHA-256 hex hash of the SubjectPublicKeyInfo.</param>
    /// <param name="expiresAt">Optional pin expiry. Defaults to 1 year from now.</param>
    public static void AddPin(
        PinStore store,
        string subjectName,
        string sha256Fingerprint,
        string publicKeyHash,
        DateTimeOffset? expiresAt = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(subjectName);
        ArgumentException.ThrowIfNullOrEmpty(sha256Fingerprint);
        ArgumentException.ThrowIfNullOrEmpty(publicKeyHash);

        var pin = new PinnedCert(
            SubjectName: subjectName.Trim(),
            Sha256Fingerprint: NormalizeHex(sha256Fingerprint),
            PublicKeySha256: NormalizeHex(publicKeyHash),
            ExpiresAt: expiresAt ?? DateTimeOffset.UtcNow.AddYears(1));

        store.Set(subjectName, pin);
    }

    /// <summary>
    /// Removes a certificate pin from the store.
    /// </summary>
    /// <param name="store">The pin store.</param>
    /// <param name="subjectName">Certificate subject name to remove.</param>
    public static void RemovePin(PinStore store, string subjectName)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(subjectName);
        store.Remove(subjectName);
    }

    // ═══════════════ Certificate Validation ═══════════════

    /// <summary>
    /// Validates a certificate against the pin store.
    /// Checks both the certificate fingerprint and the public key hash.
    /// </summary>
    /// <param name="store">The pin store to validate against.</param>
    /// <param name="cert">The X.509 certificate to validate.</param>
    /// <returns>Validation result indicating whether the cert matches a pin.</returns>
    public static CertValidationResult ValidateCertificate(PinStore store, X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(cert);

        var subject = cert.Subject;
        var certFingerprint = ComputeCertFingerprint(cert);
        var certPubKeyHash = ComputePublicKeyHash(cert);

        // Try to find a matching pin by subject name
        if (!store.TryGet(subject, out var pin) || pin is null)
        {
            // Also try the simple CN extraction
            var cn = ExtractCommonName(subject);
            if (cn is null || !store.TryGet(cn, out pin) || pin is null)
            {
                return new CertValidationResult(
                    IsValid: false,
                    IsPinned: false,
                    Reason: $"No pin found for subject '{subject}'.");
            }
        }

        // Check pin expiry
        if (pin.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return new CertValidationResult(
                IsValid: false,
                IsPinned: true,
                Reason: $"Pin for '{pin.SubjectName}' has expired (expired {pin.ExpiresAt:O}).");
        }

        // Validate certificate fingerprint (full cert hash)
        bool fingerprintMatch = string.Equals(
            certFingerprint, pin.Sha256Fingerprint, StringComparison.OrdinalIgnoreCase);

        // Validate public key hash (SPKI hash — survives cert renewal)
        bool pubKeyMatch = string.Equals(
            certPubKeyHash, pin.PublicKeySha256, StringComparison.OrdinalIgnoreCase);

        if (fingerprintMatch && pubKeyMatch)
        {
            return new CertValidationResult(
                IsValid: true,
                IsPinned: true,
                Reason: "Certificate matches pinned fingerprint and public key hash.");
        }

        if (pubKeyMatch && !fingerprintMatch)
        {
            // Public key matches but cert fingerprint differs — cert was likely renewed
            return new CertValidationResult(
                IsValid: true,
                IsPinned: true,
                Reason: "Public key matches pin. Certificate fingerprint differs (likely renewed).");
        }

        return new CertValidationResult(
            IsValid: false,
            IsPinned: true,
            Reason: $"SECURITY: Certificate does not match pin. " +
                    $"Expected fingerprint: {pin.Sha256Fingerprint[..16]}..., " +
                    $"got: {certFingerprint[..16]}...");
    }

    // ═══════════════ Fingerprint/Hash Computation ═══════════════

    /// <summary>
    /// Computes the SHA-256 fingerprint of a DER-encoded X.509 certificate.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>Lowercase hex SHA-256 hash string.</returns>
    public static string ComputeCertFingerprint(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);
        var derBytes = cert.RawData;
        var hash = SHA256.HashData(derBytes);
        return Convert.ToHexStringLower(hash);
    }

    /// <summary>
    /// Computes the SHA-256 hash of the certificate's SubjectPublicKeyInfo (SPKI).
    /// This hash is stable across certificate renewals when the same key pair is used.
    /// </summary>
    /// <param name="cert">The certificate.</param>
    /// <returns>Lowercase hex SHA-256 hash string of the SPKI.</returns>
    public static string ComputePublicKeyHash(X509Certificate2 cert)
    {
        ArgumentNullException.ThrowIfNull(cert);

        // Export the SubjectPublicKeyInfo from the certificate's public key
        var publicKey = cert.PublicKey;
        var spkiBytes = publicKey.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spkiBytes);
        return Convert.ToHexStringLower(hash);
    }

    // ═══════════════ Serialization ═══════════════

    /// <summary>
    /// Exports the pin store to a JSON string for backup/persistence.
    /// </summary>
    /// <param name="store">The pin store to export.</param>
    /// <returns>JSON string representation of all pins.</returns>
    public static string ExportPins(PinStore store)
    {
        ArgumentNullException.ThrowIfNull(store);

        var dtos = store.Pins.Select(p => new PinnedCertDto(
            p.SubjectName,
            p.Sha256Fingerprint,
            p.PublicKeySha256,
            p.ExpiresAt.ToString("O")
        )).ToList();

        return JsonSerializer.Serialize(dtos, PinJsonContext.Default.ListPinnedCertDto);
    }

    /// <summary>
    /// Imports pins from a JSON string into the pin store.
    /// Existing pins with the same subject name are overwritten.
    /// </summary>
    /// <param name="store">The pin store to import into.</param>
    /// <param name="json">JSON string produced by <see cref="ExportPins"/>.</param>
    /// <returns>Number of pins successfully imported.</returns>
    public static int ImportPins(PinStore store, string json)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentException.ThrowIfNullOrEmpty(json);

        List<PinnedCertDto>? dtos;
        try
        {
            dtos = JsonSerializer.Deserialize(json, PinJsonContext.Default.ListPinnedCertDto);
        }
        catch (JsonException)
        {
            return 0;
        }

        if (dtos is null)
            return 0;

        int count = 0;
        foreach (var dto in dtos)
        {
            if (string.IsNullOrEmpty(dto.SubjectName) ||
                string.IsNullOrEmpty(dto.Sha256Fingerprint) ||
                string.IsNullOrEmpty(dto.PublicKeySha256))
                continue;

            if (!DateTimeOffset.TryParse(dto.ExpiresAt, out var expiresAt))
                expiresAt = DateTimeOffset.UtcNow.AddYears(1);

            var pin = new PinnedCert(
                dto.SubjectName,
                NormalizeHex(dto.Sha256Fingerprint),
                NormalizeHex(dto.PublicKeySha256),
                expiresAt);

            store.Set(dto.SubjectName, pin);
            count++;
        }

        return count;
    }

    // ═══════════════ HttpClientHandler Factory ═══════════════

    /// <summary>
    /// Creates an <see cref="HttpClientHandler"/> that performs certificate pinning validation
    /// using the provided pin store. Rejects connections to servers whose certificates
    /// do not match a pin.
    /// </summary>
    /// <param name="store">The pin store containing expected certificate pins.</param>
    /// <returns>Configured <see cref="HttpClientHandler"/>.</returns>
    public static HttpClientHandler CreateHttpClientHandler(PinStore store)
    {
        ArgumentNullException.ThrowIfNull(store);

        var handler = new HttpClientHandler
        {
            // SECURITY: Custom validation callback for certificate pinning
            ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, chain, sslPolicyErrors) =>
            {
                // Must have a certificate
                if (cert is null)
                    return false;

                // Standard TLS validation must pass first (chain trust, expiry, revocation)
                if (sslPolicyErrors != SslPolicyErrors.None)
                    return false;

                using var x509 = new X509Certificate2(cert);
                var result = ValidateCertificate(store, x509);

                // If not pinned (no entry in store), we can choose policy:
                // For tordeX, we fail-closed — only allow pinned certificates
                return result.IsValid && result.IsPinned;
            }
        };

        return handler;
    }

    // ═══════════════ Certificate Expiry Check ═══════════════

    /// <summary>
    /// Checks if a certificate is expiring within the given threshold.
    /// </summary>
    /// <param name="cert">The certificate to check.</param>
    /// <param name="daysThreshold">Number of days before expiry to trigger warning (default 30).</param>
    /// <returns>True if the certificate expires within the threshold.</returns>
    public static bool IsCertificateExpiringSoon(X509Certificate2 cert, int daysThreshold = 30)
    {
        ArgumentNullException.ThrowIfNull(cert);
        if (daysThreshold < 0)
            throw new ArgumentOutOfRangeException(nameof(daysThreshold), "Days threshold must be non-negative.");

        var expiryDate = cert.NotAfter.ToUniversalTime();
        var threshold = DateTime.UtcNow.AddDays(daysThreshold);
        return expiryDate <= threshold;
    }

    // ═══════════════ Private Helpers ═══════════════

    /// <summary>
    /// Normalizes a hex string: lowercase, no separators.
    /// </summary>
    private static string NormalizeHex(string hex)
    {
        var sb = new StringBuilder(hex.Length);
        foreach (var c in hex)
        {
            if (char.IsAsciiHexDigit(c))
                sb.Append(char.ToLowerInvariant(c));
            // Skip colons, dashes, spaces
        }
        return sb.ToString();
    }

    /// <summary>
    /// Extracts the Common Name (CN) from a certificate subject string.
    /// </summary>
    private static string? ExtractCommonName(string subject)
    {
        if (string.IsNullOrEmpty(subject))
            return null;

        // Subject format: "CN=example.com, O=Example Inc, ..."
        foreach (var part in subject.Split(',', StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return part[3..].Trim();
            }
        }

        return null;
    }
}
