using System.Collections.Concurrent;

namespace TordeX.Core.Services;

/// <summary>
/// Result of a brute-force attempt check indicating whether the attempt is allowed,
/// how long to wait, and how many attempts remain before lockout.
/// </summary>
/// <param name="Allowed">Whether the authentication attempt is permitted.</param>
/// <param name="WaitSeconds">Seconds the caller must wait before retrying (0 if allowed).</param>
/// <param name="AttemptsRemaining">Number of attempts remaining before lockout.</param>
/// <param name="LockedUntil">Absolute time the identifier is locked until, or null if not locked.</param>
public sealed record AttemptResult(
    bool Allowed,
    int WaitSeconds,
    int AttemptsRemaining,
    DateTimeOffset? LockedUntil);

/// <summary>
/// Rate limiting service for password/authentication attempts with exponential backoff.
/// Provides per-identifier tracking, automatic lockout after max failures, and
/// exponential back-off delays to mitigate brute-force and credential-stuffing attacks.
/// Thread-safe via <see cref="ConcurrentDictionary{TKey,TValue}"/>.
/// </summary>
public sealed class BruteForceProtectionService
{
    /// <summary>Maximum number of failed attempts before lockout.</summary>
    private const int MaxAttempts = 5;

    /// <summary>Duration of lockout in minutes after max failures are reached.</summary>
    private const int LockoutMinutes = 15;

    /// <summary>Multiplier applied to compute exponential backoff delays.</summary>
    private const double BackoffMultiplier = 2.0;

    /// <summary>Duration after which idle records are eligible for cleanup.</summary>
    private static readonly TimeSpan RecordExpiryDuration = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<string, AttemptRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Internal record tracking per-identifier failure state.
    /// </summary>
    private sealed class AttemptRecord
    {
        private readonly object _lock = new();
        public int FailCount { get; private set; }
        public DateTimeOffset LastFailure { get; private set; }
        public DateTimeOffset? LockedUntil { get; private set; }

        /// <summary>
        /// Records a failed attempt, optionally triggering lockout.
        /// Returns the updated fail count.
        /// </summary>
        public int IncrementFailure(DateTimeOffset now)
        {
            lock (_lock)
            {
                FailCount++;
                LastFailure = now;

                if (FailCount >= MaxAttempts)
                {
                    LockedUntil = now.AddMinutes(LockoutMinutes);
                }

                return FailCount;
            }
        }

        /// <summary>
        /// Resets all failure tracking (called on successful authentication).
        /// </summary>
        public void Reset()
        {
            lock (_lock)
            {
                FailCount = 0;
                LastFailure = default;
                LockedUntil = null;
            }
        }

        /// <summary>
        /// Creates a snapshot of the current state under lock.
        /// </summary>
        public (int FailCount, DateTimeOffset LastFailure, DateTimeOffset? LockedUntil) Snapshot()
        {
            lock (_lock)
            {
                return (FailCount, LastFailure, LockedUntil);
            }
        }
    }

    /// <summary>
    /// Initializes a new instance of <see cref="BruteForceProtectionService"/> using the system clock.
    /// </summary>
    public BruteForceProtectionService()
        : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Initializes a new instance of <see cref="BruteForceProtectionService"/> with a custom time provider (for testing).
    /// </summary>
    /// <param name="timeProvider">Time provider used for all timestamp operations.</param>
    public BruteForceProtectionService(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    /// <summary>
    /// Checks whether an authentication attempt is allowed for the given identifier.
    /// Does NOT record a failure; call <see cref="RecordFailure"/> separately on actual failure.
    /// </summary>
    /// <param name="identifier">Unique identifier (username, IP, etc.).</param>
    /// <returns>An <see cref="AttemptResult"/> describing the current state.</returns>
    public AttemptResult CheckAttempt(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var now = _timeProvider.GetUtcNow();

        if (!_records.TryGetValue(identifier, out var record))
        {
            return new AttemptResult(
                Allowed: true,
                WaitSeconds: 0,
                AttemptsRemaining: MaxAttempts,
                LockedUntil: null);
        }

        var (failCount, lastFailure, lockedUntil) = record.Snapshot();

        // Check hard lockout
        if (lockedUntil.HasValue && now < lockedUntil.Value)
        {
            var remaining = (int)Math.Ceiling((lockedUntil.Value - now).TotalSeconds);
            return new AttemptResult(
                Allowed: false,
                WaitSeconds: remaining,
                AttemptsRemaining: 0,
                LockedUntil: lockedUntil);
        }

        // If lockout has expired, allow (will be cleaned up or reset on success)
        if (lockedUntil.HasValue && now >= lockedUntil.Value)
        {
            record.Reset();
            return new AttemptResult(
                Allowed: true,
                WaitSeconds: 0,
                AttemptsRemaining: MaxAttempts,
                LockedUntil: null);
        }

        // Check exponential backoff delay: 1st fail=0s, 2nd=2s, 3rd=4s, 4th=8s, 5th=lockout
        if (failCount > 0 && failCount < MaxAttempts)
        {
            var backoffSeconds = ComputeBackoffSeconds(failCount);
            var backoffExpiry = lastFailure.AddSeconds(backoffSeconds);

            if (now < backoffExpiry)
            {
                var waitSeconds = (int)Math.Ceiling((backoffExpiry - now).TotalSeconds);
                return new AttemptResult(
                    Allowed: false,
                    WaitSeconds: waitSeconds,
                    AttemptsRemaining: MaxAttempts - failCount,
                    LockedUntil: null);
            }
        }

        return new AttemptResult(
            Allowed: true,
            WaitSeconds: 0,
            AttemptsRemaining: MaxAttempts - failCount,
            LockedUntil: null);
    }

    /// <summary>
    /// Records a failed authentication attempt for the given identifier.
    /// Increments the failure counter and may trigger lockout or backoff.
    /// </summary>
    /// <param name="identifier">Unique identifier (username, IP, etc.).</param>
    public void RecordFailure(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var now = _timeProvider.GetUtcNow();
        var record = _records.GetOrAdd(identifier, _ => new AttemptRecord());
        record.IncrementFailure(now);
    }

    /// <summary>
    /// Records a successful authentication, resetting all failure tracking for the identifier.
    /// </summary>
    /// <param name="identifier">Unique identifier (username, IP, etc.).</param>
    public void RecordSuccess(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        if (_records.TryGetValue(identifier, out var record))
        {
            record.Reset();
        }

        // Remove the record entirely to free memory
        _records.TryRemove(identifier, out _);
    }

    /// <summary>
    /// Checks whether the given identifier is currently locked out.
    /// </summary>
    /// <param name="identifier">Unique identifier (username, IP, etc.).</param>
    /// <returns>True if the identifier is currently in a lockout period.</returns>
    public bool IsLocked(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        if (!_records.TryGetValue(identifier, out var record))
            return false;

        var (_, _, lockedUntil) = record.Snapshot();
        if (!lockedUntil.HasValue)
            return false;

        return _timeProvider.GetUtcNow() < lockedUntil.Value;
    }

    /// <summary>
    /// Gets the remaining lockout time for the given identifier.
    /// </summary>
    /// <param name="identifier">Unique identifier (username, IP, etc.).</param>
    /// <returns>Remaining lockout duration, or null if not locked.</returns>
    public TimeSpan? GetRemainingLockoutTime(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        if (!_records.TryGetValue(identifier, out var record))
            return null;

        var (_, _, lockedUntil) = record.Snapshot();
        if (!lockedUntil.HasValue)
            return null;

        var now = _timeProvider.GetUtcNow();
        if (now >= lockedUntil.Value)
            return null;

        return lockedUntil.Value - now;
    }

    /// <summary>
    /// Removes all records older than 1 hour (no recent failure and lockout expired).
    /// Call periodically to prevent unbounded memory growth.
    /// </summary>
    /// <returns>Number of expired records removed.</returns>
    public int ClearExpiredRecords()
    {
        var now = _timeProvider.GetUtcNow();
        var cutoff = now - RecordExpiryDuration;
        var removed = 0;

        foreach (var kvp in _records)
        {
            var (failCount, lastFailure, lockedUntil) = kvp.Value.Snapshot();

            // Remove if last failure is older than expiry and not currently locked
            var isExpired = lastFailure != default && lastFailure < cutoff;
            var isLockExpired = !lockedUntil.HasValue || now >= lockedUntil.Value;

            if (isExpired && isLockExpired)
            {
                if (_records.TryRemove(kvp.Key, out _))
                    removed++;
            }
            else if (failCount == 0 && !lockedUntil.HasValue)
            {
                // Clean up reset/empty records
                if (_records.TryRemove(kvp.Key, out _))
                    removed++;
            }
        }

        return removed;
    }

    /// <summary>
    /// Computes exponential backoff delay in seconds for a given failure count.
    /// Pattern: fail 1 = 0s, fail 2 = 2s, fail 3 = 4s, fail 4 = 8s, fail 5 = lockout.
    /// </summary>
    private static double ComputeBackoffSeconds(int failCount)
    {
        if (failCount <= 1) return 0;

        // 2^(failCount-2) * BackoffMultiplier gives: fail2=2, fail3=4, fail4=8
        return Math.Pow(2, failCount - 2) * BackoffMultiplier;
    }
}
