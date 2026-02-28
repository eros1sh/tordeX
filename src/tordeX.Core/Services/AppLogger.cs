using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Thread-safe file-based application logger.
/// Writes structured log entries to a rotating log file in the data directory.
/// </summary>
public sealed class AppLogger : IDisposable
{
    private readonly string _logDir;
    private readonly ConcurrentQueue<string> _buffer = new();
    private readonly Timer _flushTimer;
    private readonly Lock _writeLock = new();
    private bool _disposed;

    private const int MaxLogFileSizeBytes = 5 * 1024 * 1024; // 5 MB
    private const int MaxLogFiles = 3;

    public AppLogger(string dataDir)
    {
        _logDir = Path.Combine(dataDir, "logs");
        Directory.CreateDirectory(_logDir);

        // Flush every 2 seconds
        _flushTimer = new Timer(_ => Flush(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }

    public void Info(string message, string? source = null)
        => Enqueue("INFO", message, source);

    public void Warn(string message, string? source = null)
        => Enqueue("WARN", message, source);

    public void Error(string message, Exception? ex = null, string? source = null)
    {
        var entry = ex is null
            ? message
            : $"{message} | {ex.GetType().Name}: {ex.Message}";

        Enqueue("ERROR", entry, source);

        if (ex?.InnerException is not null)
        {
            Enqueue("ERROR", $"  Inner: {ex.InnerException.GetType().Name}: {ex.InnerException.Message}", source);
        }

        if (ex?.StackTrace is not null)
        {
            // Only log first 3 frames to keep log concise
            var frames = ex.StackTrace.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var limited = frames.Length > 3 ? frames[..3] : frames;
            foreach (var frame in limited)
            {
                Enqueue("TRACE", frame.Trim(), source);
            }
        }
    }

    public void DbError(string operation, Exception ex, string? sql = null)
    {
        var msg = new StringBuilder();
        msg.Append($"DB {operation} failed");
        if (sql is not null)
            msg.Append($" | SQL: {sql[..Math.Min(sql.Length, 100)]}");
        msg.Append($" | {ex.GetType().Name}: {ex.Message}");

        if (ex is Microsoft.Data.Sqlite.SqliteException sqlEx)
        {
            msg.Append($" | ErrorCode: {sqlEx.SqliteErrorCode}");
            msg.Append($" | ExtendedCode: {sqlEx.SqliteExtendedErrorCode}");
        }

        Enqueue("DB_ERR", msg.ToString(), "SecureDatabase");

        if (ex.StackTrace is not null)
        {
            var frames = ex.StackTrace.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var limited = frames.Length > 3 ? frames[..3] : frames;
            foreach (var frame in limited)
            {
                Enqueue("TRACE", frame.Trim(), "SecureDatabase");
            }
        }
    }

    private void Enqueue(string level, string message, string? source)
    {
        var timestamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
        var src = source is not null ? $"[{source}]" : "";
        _buffer.Enqueue($"{timestamp} [{level,-6}] {src} {message}");
    }

    public void Flush()
    {
        if (_buffer.IsEmpty || _disposed) return;

        var lines = new List<string>();
        while (_buffer.TryDequeue(out var line))
        {
            lines.Add(line);
        }

        if (lines.Count == 0) return;

        lock (_writeLock)
        {
            try
            {
                var logFile = Path.Combine(_logDir, "tordex.log");
                RotateIfNeeded(logFile);
                File.AppendAllLines(logFile, lines, Encoding.UTF8);
            }
            catch
            {
                // Best-effort logging — never crash the app
            }
        }
    }

    private void RotateIfNeeded(string logFile)
    {
        if (!File.Exists(logFile)) return;

        var info = new FileInfo(logFile);
        if (info.Length < MaxLogFileSizeBytes) return;

        // Rotate: delete oldest, shift others
        for (var i = MaxLogFiles - 1; i >= 1; i--)
        {
            var older = Path.Combine(_logDir, $"tordex.{i}.log");
            var newer = Path.Combine(_logDir, $"tordex.{i - 1}.log");
            if (i == MaxLogFiles - 1 && File.Exists(older))
                File.Delete(older);
            if (File.Exists(newer))
                File.Move(newer, older, overwrite: true);
        }

        File.Move(logFile, Path.Combine(_logDir, "tordex.0.log"), overwrite: true);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _flushTimer.Dispose();
        Flush(); // Final flush
    }
}
