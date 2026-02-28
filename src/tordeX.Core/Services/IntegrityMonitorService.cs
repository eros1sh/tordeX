using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TordeX.Core.Services;

/// <summary>
/// Application file integrity verification service.
/// Computes SHA-256 hashes of files, builds manifests, and detects unauthorized modifications.
/// Used to verify that application binaries and configuration files have not been tampered with.
/// </summary>
public static class IntegrityMonitorService
{
    private static readonly JsonSerializerOptions s_jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    /// <summary>
    /// Represents the integrity state of a single file at a point in time.
    /// </summary>
    /// <param name="FilePath">Absolute path to the file.</param>
    /// <param name="Sha256Hash">Lowercase hex-encoded SHA-256 hash of file contents.</param>
    /// <param name="FileSize">File size in bytes at time of recording.</param>
    /// <param name="LastModified">File's last write time at time of recording.</param>
    /// <param name="VerifiedAt">When this integrity record was created or last verified.</param>
    public sealed record FileIntegrityRecord(
        string FilePath,
        string Sha256Hash,
        long FileSize,
        DateTimeOffset LastModified,
        DateTimeOffset VerifiedAt);

    /// <summary>
    /// Report produced by <see cref="VerifyIntegrity"/> comparing a manifest against the file system.
    /// </summary>
    /// <param name="IsClean">True if all files match their recorded hashes with no unexpected changes.</param>
    /// <param name="VerifiedFiles">Number of files that passed verification.</param>
    /// <param name="ModifiedFiles">Paths of files whose hash no longer matches the manifest.</param>
    /// <param name="MissingFiles">Paths of files in the manifest that no longer exist on disk.</param>
    /// <param name="NewFiles">Paths of files found on disk that are not in the manifest.</param>
    /// <param name="Timestamp">When this report was generated.</param>
    public sealed record IntegrityReport(
        bool IsClean,
        int VerifiedFiles,
        List<string> ModifiedFiles,
        List<string> MissingFiles,
        List<string> NewFiles,
        DateTimeOffset Timestamp);

    /// <summary>
    /// Computes the SHA-256 hash of a file.
    /// </summary>
    /// <param name="filePath">Absolute path to the file to hash.</param>
    /// <returns>Lowercase hex-encoded SHA-256 hash string.</returns>
    /// <exception cref="FileNotFoundException">If the file does not exist.</exception>
    public static string ComputeFileHash(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found for integrity hashing.", filePath);

        using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 81920,
            FileOptions.SequentialScan);

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(stream, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Builds an integrity manifest by hashing all files matching a pattern in a directory.
    /// </summary>
    /// <param name="dirPath">Directory to scan.</param>
    /// <param name="pattern">File search pattern (e.g., "*.dll", "*.exe", "*").</param>
    /// <returns>List of <see cref="FileIntegrityRecord"/> for all matching files.</returns>
    public static List<FileIntegrityRecord> ComputeDirectoryManifest(string dirPath, string pattern = "*")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dirPath);

        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException($"Directory not found: {dirPath}");

        var now = DateTimeOffset.UtcNow;
        var records = new List<FileIntegrityRecord>();

        var files = Directory.EnumerateFiles(dirPath, pattern, SearchOption.AllDirectories);

        foreach (var filePath in files)
        {
            try
            {
                var info = new FileInfo(filePath);
                var hash = ComputeFileHash(filePath);

                records.Add(new FileIntegrityRecord(
                    FilePath: Path.GetFullPath(filePath),
                    Sha256Hash: hash,
                    FileSize: info.Length,
                    LastModified: new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
                    VerifiedAt: now));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Skip files we cannot read (locked, permission denied)
                // In a production system, these would be logged via SecurityAuditService
            }
        }

        return records;
    }

    /// <summary>
    /// Saves an integrity manifest to disk as a JSON file.
    /// </summary>
    /// <param name="records">The integrity records to save.</param>
    /// <param name="manifestPath">Path where the manifest JSON file will be written.</param>
    public static void SaveManifest(IReadOnlyList<FileIntegrityRecord> records, string manifestPath)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);

        var json = JsonSerializer.Serialize(records, s_jsonOptions);

        // Atomic write: write to temp file first, then move to target
        var tempPath = manifestPath + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json, Encoding.UTF8);
            File.Move(tempPath, manifestPath, overwrite: true);
        }
        finally
        {
            // Clean up temp file if move failed
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); }
                catch { /* Best effort cleanup */ }
            }
        }
    }

    /// <summary>
    /// Loads an integrity manifest from a JSON file.
    /// </summary>
    /// <param name="manifestPath">Path to the manifest JSON file.</param>
    /// <returns>List of <see cref="FileIntegrityRecord"/> from the manifest.</returns>
    /// <exception cref="FileNotFoundException">If the manifest file does not exist.</exception>
    public static List<FileIntegrityRecord> LoadManifest(string manifestPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);

        if (!File.Exists(manifestPath))
            throw new FileNotFoundException("Manifest file not found.", manifestPath);

        var json = File.ReadAllText(manifestPath, Encoding.UTF8);

        // SECURITY: Limit deserialization size to prevent DoS
        const int maxSize = 10_485_760; // 10 MB
        if (json.Length > maxSize)
            throw new InvalidOperationException(
                $"Manifest file exceeds maximum allowed size of {maxSize} bytes.");

        return JsonSerializer.Deserialize<List<FileIntegrityRecord>>(json, s_jsonOptions)
               ?? [];
    }

    /// <summary>
    /// Verifies the integrity of all files listed in a manifest.
    /// Checks for modified, missing, and new files in the same directories.
    /// </summary>
    /// <param name="manifestPath">Path to the manifest JSON file to verify against.</param>
    /// <returns>An <see cref="IntegrityReport"/> detailing the verification results.</returns>
    public static IntegrityReport VerifyIntegrity(string manifestPath)
    {
        var records = LoadManifest(manifestPath);
        var modifiedFiles = new List<string>();
        var missingFiles = new List<string>();
        var verifiedCount = 0;

        foreach (var record in records)
        {
            if (!File.Exists(record.FilePath))
            {
                missingFiles.Add(record.FilePath);
                continue;
            }

            if (VerifyFile(record))
            {
                verifiedCount++;
            }
            else
            {
                modifiedFiles.Add(record.FilePath);
            }
        }

        // Detect new files: scan all directories from the manifest and find files not in it
        var newFiles = DetectNewFiles(records);

        var isClean = modifiedFiles.Count == 0 && missingFiles.Count == 0 && newFiles.Count == 0;

        return new IntegrityReport(
            IsClean: isClean,
            VerifiedFiles: verifiedCount,
            ModifiedFiles: modifiedFiles,
            MissingFiles: missingFiles,
            NewFiles: newFiles,
            Timestamp: DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Verifies a single file against its recorded integrity state.
    /// </summary>
    /// <param name="record">The integrity record to verify against.</param>
    /// <returns>True if the file exists and its SHA-256 hash matches the record.</returns>
    public static bool VerifyFile(FileIntegrityRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (!File.Exists(record.FilePath))
            return false;

        try
        {
            var currentHash = ComputeFileHash(record.FilePath);
            return string.Equals(currentHash, record.Sha256Hash, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Computes the SHA-256 hash of the currently running executable.
    /// </summary>
    /// <returns>Lowercase hex-encoded SHA-256 hash of the main executable.</returns>
    public static string GetExecutableHash()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
            throw new InvalidOperationException("Unable to determine the current executable path.");

        return ComputeFileHash(exePath);
    }

    /// <summary>
    /// Creates an <see cref="IntegrityWatcher"/> that monitors a directory for file changes.
    /// </summary>
    /// <param name="dirPath">Directory to monitor.</param>
    /// <param name="onChange">Callback invoked when a file modification is detected.</param>
    /// <returns>An <see cref="IntegrityWatcher"/> (IDisposable) that monitors the directory.</returns>
    public static IntegrityWatcher MonitorForChanges(string dirPath, Action<FileSystemEventArgs> onChange)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dirPath);
        ArgumentNullException.ThrowIfNull(onChange);

        if (!Directory.Exists(dirPath))
            throw new DirectoryNotFoundException($"Directory not found: {dirPath}");

        return new IntegrityWatcher(dirPath, onChange);
    }

    /// <summary>
    /// Computes a SHA-256 hash of the entire manifest for tamper detection.
    /// This can be stored separately (e.g., in encrypted preferences) to verify the manifest itself.
    /// </summary>
    /// <param name="records">The integrity records to hash.</param>
    /// <returns>Lowercase hex-encoded SHA-256 hash of the serialized manifest.</returns>
    public static string ComputeManifestHash(IReadOnlyList<FileIntegrityRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);

        // Deterministic serialization: sort by file path to ensure consistent hashing
        var sorted = records.OrderBy(r => r.FilePath, StringComparer.OrdinalIgnoreCase).ToList();
        var json = JsonSerializer.Serialize(sorted, s_jsonOptions);
        var bytes = Encoding.UTF8.GetBytes(json);

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Detects files that exist on disk in manifest directories but are not listed in the manifest.
    /// </summary>
    private static List<string> DetectNewFiles(IReadOnlyList<FileIntegrityRecord> records)
    {
        if (records.Count == 0)
            return [];

        var knownPaths = new HashSet<string>(
            records.Select(r => Path.GetFullPath(r.FilePath)),
            StringComparer.OrdinalIgnoreCase);

        var directories = records
            .Select(r => Path.GetDirectoryName(r.FilePath))
            .Where(d => d is not null)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var newFiles = new List<string>();
        foreach (var dir in directories)
        {
            if (dir is null || !Directory.Exists(dir))
                continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    var fullPath = Path.GetFullPath(file);
                    if (!knownPaths.Contains(fullPath))
                    {
                        newFiles.Add(fullPath);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Skip inaccessible directories
            }
        }

        return newFiles;
    }
}

/// <summary>
/// Wraps <see cref="FileSystemWatcher"/> to monitor a directory for file modifications.
/// Fires the registered callback when files are created, changed, renamed, or deleted.
/// Thread-safe and disposable.
/// </summary>
public sealed class IntegrityWatcher : IDisposable
{
    private readonly FileSystemWatcher _watcher;
    private readonly Action<FileSystemEventArgs> _onChange;
    private volatile bool _disposed;

    /// <summary>
    /// Creates a new integrity watcher for the specified directory.
    /// </summary>
    /// <param name="directoryPath">Directory to monitor.</param>
    /// <param name="onChange">Callback invoked on file system changes.</param>
    internal IntegrityWatcher(string directoryPath, Action<FileSystemEventArgs> onChange)
    {
        _onChange = onChange;

        _watcher = new FileSystemWatcher(directoryPath)
        {
            NotifyFilter = NotifyFilters.FileName
                           | NotifyFilters.LastWrite
                           | NotifyFilters.Size
                           | NotifyFilters.CreationTime,
            IncludeSubdirectories = true,
            EnableRaisingEvents = true
        };

        _watcher.Changed += OnFileEvent;
        _watcher.Created += OnFileEvent;
        _watcher.Deleted += OnFileEvent;
        _watcher.Renamed += OnRenamedEvent;
        _watcher.Error += OnError;
    }

    /// <summary>
    /// Gets or sets whether the watcher is actively monitoring.
    /// </summary>
    public bool IsMonitoring
    {
        get => !_disposed && _watcher.EnableRaisingEvents;
        set
        {
            if (!_disposed)
                _watcher.EnableRaisingEvents = value;
        }
    }

    /// <summary>
    /// Event raised when the watcher encounters an internal error (e.g., buffer overflow).
    /// </summary>
    public event EventHandler<ErrorEventArgs>? WatcherError;

    private void OnFileEvent(object sender, FileSystemEventArgs e)
    {
        if (_disposed) return;

        try
        {
            _onChange(e);
        }
        catch
        {
            // Swallow callback exceptions to prevent crashing the watcher thread
        }
    }

    private void OnRenamedEvent(object sender, RenamedEventArgs e)
    {
        if (_disposed) return;

        try
        {
            _onChange(e);
        }
        catch
        {
            // Swallow callback exceptions
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        WatcherError?.Invoke(this, e);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _watcher.EnableRaisingEvents = false;
        _watcher.Changed -= OnFileEvent;
        _watcher.Created -= OnFileEvent;
        _watcher.Deleted -= OnFileEvent;
        _watcher.Renamed -= OnRenamedEvent;
        _watcher.Error -= OnError;
        _watcher.Dispose();
    }
}
