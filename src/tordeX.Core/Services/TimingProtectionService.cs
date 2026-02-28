using System.Security.Cryptography;

namespace TordeX.Core.Services;

/// <summary>
/// Timing attack protection service.
/// Prevents traffic correlation and timing analysis by introducing controlled randomness
/// into message send timing, batching messages, and providing constant-time comparison.
/// </summary>
public static class TimingProtectionService
{
    /// <summary>
    /// Timing obfuscation configuration.
    /// </summary>
    /// <param name="MinDelayMs">Minimum delay between messages in milliseconds.</param>
    /// <param name="MaxDelayMs">Maximum delay between messages in milliseconds.</param>
    /// <param name="UseExponentialDistribution">If true, delays follow exponential distribution; otherwise uniform.</param>
    /// <param name="JitterPercent">Percentage of jitter to apply to delays (0-100).</param>
    /// <param name="BatchingEnabled">If true, messages are collected and sent in batches.</param>
    /// <param name="BatchIntervalMs">Interval between batch sends in milliseconds.</param>
    public sealed record TimingConfig(
        int MinDelayMs = 50,
        int MaxDelayMs = 2000,
        bool UseExponentialDistribution = true,
        int JitterPercent = 30,
        bool BatchingEnabled = false,
        int BatchIntervalMs = 5000);

    /// <summary>
    /// A scheduled message with its planned send time.
    /// </summary>
    /// <param name="Message">The message payload bytes.</param>
    /// <param name="ScheduledSendTime">The scheduled send time with timezone offset.</param>
    public sealed record MessageSchedule(byte[] Message, DateTimeOffset ScheduledSendTime);

    // ═══════════════ Random Delay Generation ═══════════════

    /// <summary>
    /// Generates a random delay in milliseconds according to the timing configuration.
    /// Uses exponential distribution (models inter-arrival times of natural traffic)
    /// or uniform distribution based on config.
    /// </summary>
    /// <param name="config">Timing configuration.</param>
    /// <returns>Delay in milliseconds, clamped to [MinDelayMs, MaxDelayMs].</returns>
    public static int GetRandomDelay(TimingConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (config.MinDelayMs < 0)
            throw new ArgumentOutOfRangeException(nameof(config), "MinDelayMs must be non-negative.");
        if (config.MaxDelayMs < config.MinDelayMs)
            throw new ArgumentOutOfRangeException(nameof(config), "MaxDelayMs must be >= MinDelayMs.");

        int delay;
        if (config.UseExponentialDistribution)
        {
            // Mean of the exponential distribution centered between min and max
            double mean = (config.MinDelayMs + config.MaxDelayMs) / 2.0;
            delay = GetExponentialDelay((int)mean);
        }
        else
        {
            // Uniform distribution
            delay = CryptoRandomInt(config.MinDelayMs, config.MaxDelayMs + 1);
        }

        // Clamp to configured bounds
        return Math.Clamp(delay, config.MinDelayMs, config.MaxDelayMs);
    }

    /// <summary>
    /// Applies random jitter to a base delay value.
    /// Jitter is a random percentage deviation from the base delay.
    /// </summary>
    /// <param name="baseDelayMs">The base delay in milliseconds.</param>
    /// <param name="jitterPercent">Jitter as a percentage (0-100). Default 30.</param>
    /// <returns>Delay with applied jitter, minimum 0.</returns>
    public static int ApplyJitter(int baseDelayMs, int jitterPercent = 30)
    {
        if (baseDelayMs < 0)
            throw new ArgumentOutOfRangeException(nameof(baseDelayMs), "Base delay must be non-negative.");
        if (jitterPercent < 0 || jitterPercent > 100)
            throw new ArgumentOutOfRangeException(nameof(jitterPercent), "Jitter percent must be between 0 and 100.");

        if (jitterPercent == 0 || baseDelayMs == 0)
            return baseDelayMs;

        // Calculate jitter range: +/- jitterPercent% of baseDelay
        double maxJitter = baseDelayMs * (jitterPercent / 100.0);
        int jitterRange = (int)(maxJitter * 2);

        if (jitterRange == 0)
            return baseDelayMs;

        // Random value in [-maxJitter, +maxJitter]
        int jitter = CryptoRandomInt(0, jitterRange + 1) - (int)maxJitter;

        return Math.Max(0, baseDelayMs + jitter);
    }

    // ═══════════════ Message Batching ═══════════════

    /// <summary>
    /// Creates a batch schedule for sending messages at controlled intervals.
    /// Messages are distributed across the batch interval with random delays to prevent
    /// traffic pattern analysis.
    /// </summary>
    /// <param name="messages">The messages to batch.</param>
    /// <param name="config">Timing configuration.</param>
    /// <returns>List of scheduled messages with their planned send times.</returns>
    public static List<MessageSchedule> CreateMessageBatch(IReadOnlyList<byte[]> messages, TimingConfig config)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(config);

        if (messages.Count == 0)
            return [];

        var schedules = new List<MessageSchedule>(messages.Count);
        var now = DateTimeOffset.UtcNow;

        if (config.BatchingEnabled && messages.Count > 1)
        {
            // Distribute messages evenly across the batch interval with jitter
            double interval = (double)config.BatchIntervalMs / messages.Count;

            for (int i = 0; i < messages.Count; i++)
            {
                int baseOffset = (int)(interval * i);
                int jitteredOffset = ApplyJitter(baseOffset, config.JitterPercent);
                var sendTime = now.AddMilliseconds(jitteredOffset);
                schedules.Add(new MessageSchedule(messages[i], sendTime));
            }
        }
        else
        {
            // Non-batched: each message gets its own random delay
            var cumulativeDelay = 0;
            foreach (var message in messages)
            {
                int delay = GetRandomDelay(config);
                cumulativeDelay += delay;
                var sendTime = now.AddMilliseconds(cumulativeDelay);
                schedules.Add(new MessageSchedule(message, sendTime));
            }
        }

        // Sort by scheduled time
        schedules.Sort((a, b) => a.ScheduledSendTime.CompareTo(b.ScheduledSendTime));
        return schedules;
    }

    // ═══════════════ Decoy Traffic ═══════════════

    /// <summary>
    /// Randomly determines whether a decoy message should be sent.
    /// Used to generate cover traffic that makes real messages harder to distinguish.
    /// </summary>
    /// <param name="decoyProbability">Probability of sending a decoy (0.0 to 1.0). Default 0.1 (10%).</param>
    /// <returns>True if a decoy should be sent.</returns>
    public static bool ShouldSendDecoy(double decoyProbability = 0.1)
    {
        if (decoyProbability < 0.0 || decoyProbability > 1.0)
            throw new ArgumentOutOfRangeException(nameof(decoyProbability),
                "Decoy probability must be between 0.0 and 1.0.");

        if (decoyProbability == 0.0) return false;
        if (decoyProbability == 1.0) return true;

        // Generate a random double in [0, 1) using crypto-safe randomness
        // 4 bytes → uint → divide by uint.MaxValue+1 for uniform [0,1)
        Span<byte> buffer = stackalloc byte[4];
        RandomNumberGenerator.Fill(buffer);
        double randomValue = BitConverter.ToUInt32(buffer) / (double)(uint.MaxValue + 1UL);

        return randomValue < decoyProbability;
    }

    /// <summary>
    /// Samples a delay from an exponential distribution with the given mean.
    /// Models natural inter-arrival times: P(X ≤ x) = 1 - e^(-x/mean).
    /// Formula: -ln(U) * mean, where U ~ Uniform(0,1).
    /// </summary>
    /// <param name="meanMs">Mean delay in milliseconds. Must be positive.</param>
    /// <returns>Sampled delay in milliseconds (at least 1).</returns>
    public static int GetExponentialDelay(int meanMs)
    {
        if (meanMs <= 0)
            throw new ArgumentOutOfRangeException(nameof(meanMs), "Mean must be positive.");

        // Generate uniform random in (0, 1] — avoid 0 to prevent -ln(0) = infinity
        Span<byte> buffer = stackalloc byte[8];
        double u;
        do
        {
            RandomNumberGenerator.Fill(buffer);
            u = (BitConverter.ToUInt64(buffer) >> 11) * (1.0 / (1UL << 53)); // [0, 1)
        }
        while (u == 0.0); // Reject exactly 0

        double sample = -Math.Log(u) * meanMs;

        // Clamp to int range, minimum 1ms
        return (int)Math.Clamp(sample, 1, int.MaxValue);
    }

    /// <summary>
    /// Redistributes a list of send times to appear more uniform.
    /// This defeats traffic analysis that looks for bursty patterns.
    /// Preserves the overall time span but smooths out clustering.
    /// </summary>
    /// <param name="sendTimes">Original send times.</param>
    /// <returns>Redistributed send times spanning the same total duration.</returns>
    public static List<DateTimeOffset> NormalizeTrafficPattern(List<DateTimeOffset> sendTimes)
    {
        ArgumentNullException.ThrowIfNull(sendTimes);

        if (sendTimes.Count <= 1)
            return new List<DateTimeOffset>(sendTimes);

        var sorted = sendTimes.OrderBy(t => t).ToList();
        var start = sorted[0];
        var end = sorted[^1];
        var totalSpan = end - start;

        if (totalSpan.TotalMilliseconds <= 0)
        {
            // All messages at the same time — spread them out with small jitter
            var result = new List<DateTimeOffset>(sorted.Count);
            for (int i = 0; i < sorted.Count; i++)
            {
                int jitter = ApplyJitter(100 * i, 20);
                result.Add(start.AddMilliseconds(jitter));
            }
            return result;
        }

        // Redistribute evenly across the span with small jitter
        var normalized = new List<DateTimeOffset>(sorted.Count);
        double interval = totalSpan.TotalMilliseconds / (sorted.Count - 1);

        for (int i = 0; i < sorted.Count; i++)
        {
            double baseOffsetMs = interval * i;
            int jitteredOffset = ApplyJitter((int)baseOffsetMs, 10); // Small jitter to avoid perfect uniformity
            normalized.Add(start.AddMilliseconds(jitteredOffset));
        }

        return normalized;
    }

    /// <summary>
    /// Performs a constant-time comparison of two byte arrays.
    /// Prevents timing side-channel attacks by always comparing all bytes
    /// regardless of where differences occur.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>True if both arrays have identical contents and length.</returns>
    public static bool ConstantTimeCompare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        // Use CryptographicOperations for timing-safe comparison (BCL built-in)
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    // ═══════════════ Private Helpers ═══════════════

    /// <summary>
    /// Generates a cryptographically secure random integer in [minInclusive, maxExclusive).
    /// </summary>
    private static int CryptoRandomInt(int minInclusive, int maxExclusive)
    {
        if (minInclusive >= maxExclusive)
            return minInclusive;
        return RandomNumberGenerator.GetInt32(minInclusive, maxExclusive);
    }
}
