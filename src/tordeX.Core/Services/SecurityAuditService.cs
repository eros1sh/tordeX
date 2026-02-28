using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TordeX.Core.Services;

/// <summary>
/// Security event types tracked by the audit system.
/// </summary>
public enum SecurityEventType
{
    /// <summary>Successful authentication.</summary>
    LoginSuccess,

    /// <summary>Failed authentication attempt.</summary>
    LoginFailure,

    /// <summary>User password was changed.</summary>
    PasswordChanged,

    /// <summary>Data wipe operation was executed.</summary>
    DataWiped,

    /// <summary>Cryptographic keys were rotated.</summary>
    KeyRotated,

    /// <summary>Brute-force attack pattern detected.</summary>
    BruteForceDetected,

    /// <summary>Application tampering detected.</summary>
    TamperDetected,

    /// <summary>A canary token was triggered (database breach indicator).</summary>
    CanaryTriggered,

    /// <summary>File integrity violation detected.</summary>
    IntegrityViolation,

    /// <summary>Debugger attachment detected.</summary>
    DebuggerDetected,

    /// <summary>TLS certificate mismatch detected.</summary>
    CertificateMismatch,

    /// <summary>Unauthorized access attempt.</summary>
    UnauthorizedAccess,

    /// <summary>Application settings were modified.</summary>
    SettingsChanged,

    /// <summary>New user profile was created.</summary>
    ProfileCreated,

    /// <summary>Chat room was created.</summary>
    RoomCreated,

    /// <summary>Chat room was deleted.</summary>
    RoomDeleted,

    /// <summary>Message was deleted.</summary>
    MessageDeleted,

    /// <summary>File was accessed.</summary>
    FileAccessed,

    /// <summary>Data export was requested.</summary>
    ExportRequested,

    /// <summary>Emergency data wipe was triggered.</summary>
    EmergencyWipe
}

/// <summary>
/// Severity levels for security events.
/// </summary>
public enum EventSeverity
{
    /// <summary>Informational event — normal operation.</summary>
    Info,

    /// <summary>Warning — something unusual that merits attention.</summary>
    Warning,

    /// <summary>Critical — requires immediate investigation.</summary>
    Critical,

    /// <summary>Emergency — active attack or data breach in progress.</summary>
    Emergency
}

/// <summary>
/// Centralized security event logging and audit trail service.
/// Provides thread-safe, tamper-evident logging of all security-relevant events
/// with PII masking, severity filtering, and export capabilities.
/// This service is NOT static because it manages mutable log state.
/// </summary>
public sealed class SecurityAuditService
{
    private const int MaxCapacity = 10_000;

    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    // SECURITY FIX: CWE-1333 — use NonBacktracking to prevent ReDoS attacks on PII masking patterns
    private static readonly Regex s_emailRegex = new(
        @"[\w.+-]+@[\w-]+\.[\w.]+",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    private static readonly Regex s_ipRegex = new(
        @"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    private static readonly Regex s_phoneRegex = new(
        @"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    private readonly ConcurrentQueue<SecurityEvent> _events = new();
    private readonly Lock _lock = new();
    private int _eventCount;

    /// <summary>
    /// Represents a single security event in the audit log.
    /// </summary>
    /// <param name="Id">Unique event identifier (GUID).</param>
    /// <param name="EventType">Category of the security event.</param>
    /// <param name="Description">Human-readable description of what occurred.</param>
    /// <param name="Severity">Severity level of the event.</param>
    /// <param name="Timestamp">When the event occurred (UTC).</param>
    /// <param name="SourceIp">Source IP address (masked for privacy).</param>
    /// <param name="UserId">User identifier (masked for privacy).</param>
    /// <param name="Details">Additional structured details about the event.</param>
    public sealed record SecurityEvent(
        string Id,
        SecurityEventType EventType,
        string Description,
        EventSeverity Severity,
        DateTimeOffset Timestamp,
        string? SourceIp,
        string? UserId,
        Dictionary<string, string>? Details);

    /// <summary>
    /// Summary statistics of the security audit log.
    /// </summary>
    /// <param name="TotalEvents">Total number of events in the log.</param>
    /// <param name="CriticalCount">Number of Critical or Emergency severity events.</param>
    /// <param name="LastLoginAttempt">Timestamp of the most recent login attempt (success or failure).</param>
    /// <param name="FailedLogins24h">Number of failed login attempts in the last 24 hours.</param>
    /// <param name="TamperEvents">Number of tamper detection events.</param>
    /// <param name="LastWipeEvent">Timestamp of the most recent data wipe event.</param>
    public sealed record SecuritySummary(
        int TotalEvents,
        int CriticalCount,
        DateTimeOffset? LastLoginAttempt,
        int FailedLogins24h,
        int TamperEvents,
        DateTimeOffset? LastWipeEvent);

    /// <summary>
    /// Logs a security event to the audit trail.
    /// Thread-safe. Automatically masks PII in the description and details.
    /// Evicts oldest events when the log exceeds <see cref="MaxCapacity"/>.
    /// </summary>
    /// <param name="eventType">The type of security event.</param>
    /// <param name="description">Human-readable description.</param>
    /// <param name="severity">Severity level.</param>
    /// <param name="details">Optional additional details (keys and values will be PII-masked).</param>
    public void LogEvent(
        SecurityEventType eventType,
        string description,
        EventSeverity severity,
        Dictionary<string, string>? details = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        // Mask PII in description and details
        var maskedDescription = MaskPii(description);

        Dictionary<string, string>? maskedDetails = null;
        if (details is { Count: > 0 })
        {
            maskedDetails = new Dictionary<string, string>(details.Count);
            foreach (var kvp in details)
            {
                maskedDetails[kvp.Key] = MaskPii(kvp.Value);
            }
        }

        var securityEvent = new SecurityEvent(
            Id: Guid.NewGuid().ToString("D"),
            EventType: eventType,
            Description: maskedDescription,
            Severity: severity,
            Timestamp: DateTimeOffset.UtcNow,
            SourceIp: null,
            UserId: null,
            Details: maskedDetails);

        _events.Enqueue(securityEvent);

        // Evict oldest events if over capacity
        var currentCount = Interlocked.Increment(ref _eventCount);
        while (currentCount > MaxCapacity && _events.TryDequeue(out _))
        {
            currentCount = Interlocked.Decrement(ref _eventCount);
        }
    }

    /// <summary>
    /// Logs a security event with source IP and user ID (both will be automatically masked).
    /// </summary>
    /// <param name="eventType">The type of security event.</param>
    /// <param name="description">Human-readable description.</param>
    /// <param name="severity">Severity level.</param>
    /// <param name="sourceIp">Source IP address (will be partially masked).</param>
    /// <param name="userId">User identifier (will be partially masked).</param>
    /// <param name="details">Optional additional details.</param>
    public void LogEvent(
        SecurityEventType eventType,
        string description,
        EventSeverity severity,
        string? sourceIp,
        string? userId,
        Dictionary<string, string>? details = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        var maskedDescription = MaskPii(description);
        var maskedIp = sourceIp is not null ? MaskIpAddress(sourceIp) : null;
        var maskedUserId = userId is not null ? MaskUserId(userId) : null;

        Dictionary<string, string>? maskedDetails = null;
        if (details is { Count: > 0 })
        {
            maskedDetails = new Dictionary<string, string>(details.Count);
            foreach (var kvp in details)
            {
                maskedDetails[kvp.Key] = MaskPii(kvp.Value);
            }
        }

        var securityEvent = new SecurityEvent(
            Id: Guid.NewGuid().ToString("D"),
            EventType: eventType,
            Description: maskedDescription,
            Severity: severity,
            Timestamp: DateTimeOffset.UtcNow,
            SourceIp: maskedIp,
            UserId: maskedUserId,
            Details: maskedDetails);

        _events.Enqueue(securityEvent);

        var currentCount = Interlocked.Increment(ref _eventCount);
        while (currentCount > MaxCapacity && _events.TryDequeue(out _))
        {
            currentCount = Interlocked.Decrement(ref _eventCount);
        }
    }

    /// <summary>
    /// Retrieves security events matching the specified filters.
    /// All filter parameters are optional — omitted filters match everything.
    /// </summary>
    /// <param name="startDate">Include events on or after this date.</param>
    /// <param name="endDate">Include events on or before this date.</param>
    /// <param name="eventType">Filter by specific event type.</param>
    /// <param name="severity">Filter by minimum severity level.</param>
    /// <returns>List of matching events, ordered by timestamp descending.</returns>
    public List<SecurityEvent> GetEvents(
        DateTimeOffset? startDate = null,
        DateTimeOffset? endDate = null,
        SecurityEventType? eventType = null,
        EventSeverity? severity = null)
    {
        IEnumerable<SecurityEvent> query = _events;

        if (startDate.HasValue)
            query = query.Where(e => e.Timestamp >= startDate.Value);

        if (endDate.HasValue)
            query = query.Where(e => e.Timestamp <= endDate.Value);

        if (eventType.HasValue)
            query = query.Where(e => e.EventType == eventType.Value);

        if (severity.HasValue)
            query = query.Where(e => e.Severity >= severity.Value);

        return query.OrderByDescending(e => e.Timestamp).ToList();
    }

    /// <summary>
    /// Retrieves the most recent security events.
    /// </summary>
    /// <param name="count">Maximum number of events to return (default 50, max 1000).</param>
    /// <returns>List of the most recent events, ordered by timestamp descending.</returns>
    public List<SecurityEvent> GetRecentEvents(int count = 50)
    {
        if (count is < 1 or > 1000)
            count = Math.Clamp(count, 1, 1000);

        return _events
            .OrderByDescending(e => e.Timestamp)
            .Take(count)
            .ToList();
    }

    /// <summary>
    /// Exports the entire audit log as a serialized string.
    /// </summary>
    /// <param name="format">Export format. Currently only "json" is supported.</param>
    /// <returns>Serialized audit log string.</returns>
    /// <exception cref="ArgumentException">If an unsupported format is specified.</exception>
    public string ExportAuditLog(string format = "json")
    {
        if (!string.Equals(format, "json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Unsupported export format: {format}. Only 'json' is supported.", nameof(format));

        var events = _events.OrderBy(e => e.Timestamp).ToList();
        return JsonSerializer.Serialize(events, s_jsonOptions);
    }

    /// <summary>
    /// Clears all events from the audit log.
    /// This is a destructive operation — use with caution.
    /// </summary>
    public void ClearLog()
    {
        lock (_lock)
        {
            while (_events.TryDequeue(out _))
            {
                // Drain the queue
            }

            Interlocked.Exchange(ref _eventCount, 0);
        }
    }

    /// <summary>
    /// Returns the count of events, optionally filtered by event type.
    /// </summary>
    /// <param name="eventType">Optional event type filter. If null, returns total count.</param>
    /// <returns>Number of matching events.</returns>
    public int GetEventCount(SecurityEventType? eventType = null)
    {
        if (!eventType.HasValue)
            return _eventCount;

        return _events.Count(e => e.EventType == eventType.Value);
    }

    /// <summary>
    /// Generates a summary of security-relevant statistics from the audit log.
    /// </summary>
    /// <returns>A <see cref="SecuritySummary"/> with aggregated metrics.</returns>
    public SecuritySummary GetSecuritySummary()
    {
        var snapshot = _events.ToArray();
        var now = DateTimeOffset.UtcNow;
        var twentyFourHoursAgo = now.AddHours(-24);

        var totalEvents = snapshot.Length;

        var criticalCount = snapshot.Count(e =>
            e.Severity is EventSeverity.Critical or EventSeverity.Emergency);

        var lastLogin = snapshot
            .Where(e => e.EventType is SecurityEventType.LoginSuccess or SecurityEventType.LoginFailure)
            .OrderByDescending(e => e.Timestamp)
            .Select(e => (DateTimeOffset?)e.Timestamp)
            .FirstOrDefault();

        var failedLogins24h = snapshot.Count(e =>
            e.EventType == SecurityEventType.LoginFailure
            && e.Timestamp >= twentyFourHoursAgo);

        var tamperEvents = snapshot.Count(e =>
            e.EventType is SecurityEventType.TamperDetected
                or SecurityEventType.IntegrityViolation
                or SecurityEventType.CanaryTriggered
                or SecurityEventType.DebuggerDetected);

        var lastWipe = snapshot
            .Where(e => e.EventType is SecurityEventType.DataWiped or SecurityEventType.EmergencyWipe)
            .OrderByDescending(e => e.Timestamp)
            .Select(e => (DateTimeOffset?)e.Timestamp)
            .FirstOrDefault();

        return new SecuritySummary(
            TotalEvents: totalEvents,
            CriticalCount: criticalCount,
            LastLoginAttempt: lastLogin,
            FailedLogins24h: failedLogins24h,
            TamperEvents: tamperEvents,
            LastWipeEvent: lastWipe);
    }

    /// <summary>
    /// Computes a SHA-256 hash of the serialized audit log for tamper evidence.
    /// This hash can be stored separately and compared later to verify log integrity.
    /// </summary>
    /// <returns>Lowercase hex-encoded SHA-256 hash of the serialized log.</returns>
    public string ComputeLogHash()
    {
        var events = _events.OrderBy(e => e.Timestamp).ToList();
        var json = JsonSerializer.Serialize(events, s_jsonOptions);
        var bytes = Encoding.UTF8.GetBytes(json);

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ═══════════════════════════════════════════════════════════
    // PII Masking
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Masks personally identifiable information in a string.
    /// Handles email addresses, IP addresses, and phone numbers.
    /// </summary>
    private static string MaskPii(string input)
    {
        if (string.IsNullOrEmpty(input))
            return input;

        var result = input;

        // Mask email: user@domain.com → u***@domain.com
        result = s_emailRegex.Replace(result, match =>
        {
            var email = match.Value;
            var atIndex = email.IndexOf('@');
            if (atIndex <= 0) return email;
            return $"{email[0]}***{email[atIndex..]}";
        });

        // Mask IP: 192.168.1.100 → 192.168.***.***
        result = s_ipRegex.Replace(result, match =>
        {
            if (match.Groups.Count < 5) return match.Value;
            return $"{match.Groups[1].Value}.{match.Groups[2].Value}.***.***";
        });

        // Mask phone: 555-123-4567 → ***-***-4567
        result = s_phoneRegex.Replace(result, match =>
        {
            var phone = match.Value;
            if (phone.Length < 4) return phone;
            return $"***-***-{phone[^4..]}";
        });

        return result;
    }

    /// <summary>
    /// Masks an IP address for privacy: 192.168.1.100 → 192.168.***.***
    /// </summary>
    private static string MaskIpAddress(string ip)
    {
        if (string.IsNullOrEmpty(ip))
            return ip;

        return s_ipRegex.Replace(ip, match =>
        {
            if (match.Groups.Count < 5) return match.Value;
            return $"{match.Groups[1].Value}.{match.Groups[2].Value}.***.***";
        });
    }

    /// <summary>
    /// Masks a user ID for privacy: "john_doe_123" → "joh***123"
    /// </summary>
    private static string MaskUserId(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return userId;

        if (userId.Length <= 6)
            return $"{userId[0]}***";

        return $"{userId[..3]}***{userId[^3..]}";
    }
}
