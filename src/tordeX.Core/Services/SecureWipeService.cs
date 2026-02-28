using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace TordeX.Core.Services;

/// <summary>
/// Secure file and memory deletion service implementing DoD 5220.22-M compliant
/// multi-pass overwrite, SQLite artifact cleanup, and anti-forensics utilities.
/// All file operations overwrite data before deletion to prevent recovery.
/// </summary>
public static class SecureWipeService
{
    /// <summary>
    /// Securely deletes a file using the DoD 5220.22-M 3-pass overwrite pattern:
    /// Pass 1: all zeros (0x00), Pass 2: all ones (0xFF), Pass 3: cryptographic random.
    /// The file is then deleted from the filesystem.
    /// </summary>
    /// <param name="filePath">Absolute path to the file to securely delete.</param>
    /// <param name="passes">Number of overwrite pass sets (default 3 = 9 total passes).</param>
    /// <returns>True if the file was successfully overwritten and deleted; false if the file did not exist.</returns>
    public static bool SecureDeleteFile(string filePath, int passes = 3)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (passes < 1) passes = 1;

        if (!File.Exists(filePath))
            return false;

        try
        {
            var fileInfo = new FileInfo(filePath);
            var length = fileInfo.Length;

            if (length == 0)
            {
                File.Delete(filePath);
                return true;
            }

            // Perform DoD 5220.22-M passes
            for (int pass = 0; pass < passes; pass++)
            {
                DoD5220Pattern(filePath, length);
            }

            // Remove read-only attribute if set
            var attributes = File.GetAttributes(filePath);
            if ((attributes & FileAttributes.ReadOnly) != 0)
            {
                File.SetAttributes(filePath, attributes & ~FileAttributes.ReadOnly);
            }

            File.Delete(filePath);
            return true;
        }
        catch (IOException)
        {
            // File may be locked — attempt simple delete as fallback
            try { File.Delete(filePath); } catch { /* best effort */ }
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Securely deletes all files in a directory and its subdirectories.
    /// Each file is overwritten before deletion. Empty directories are removed after.
    /// </summary>
    /// <param name="dirPath">Absolute path to the directory.</param>
    /// <param name="passes">Number of DoD 5220.22-M pass sets per file.</param>
    /// <returns>Number of files successfully deleted.</returns>
    public static int SecureDeleteDirectory(string dirPath, int passes = 3)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dirPath);
        if (passes < 1) passes = 1;

        if (!Directory.Exists(dirPath))
            return 0;

        var filesDeleted = 0;

        try
        {
            // Process all files recursively (depth-first)
            foreach (var file in Directory.EnumerateFiles(dirPath, "*", SearchOption.AllDirectories))
            {
                if (SecureDeleteFile(file, passes))
                    filesDeleted++;
            }

            // Remove empty directories bottom-up
            foreach (var dir in Directory.EnumerateDirectories(dirPath, "*", SearchOption.AllDirectories)
                         .OrderByDescending(d => d.Length))
            {
                try
                {
                    if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                        Directory.Delete(dir);
                }
                catch { /* best effort */ }
            }

            // Delete the root directory itself if empty
            try
            {
                if (Directory.Exists(dirPath) && !Directory.EnumerateFileSystemEntries(dirPath).Any())
                    Directory.Delete(dirPath);
            }
            catch { /* best effort */ }
        }
        catch (UnauthorizedAccessException) { /* partial cleanup is acceptable */ }

        return filesDeleted;
    }

    /// <summary>
    /// Overwrites an entire file with a repeating byte pattern.
    /// </summary>
    /// <param name="filePath">Absolute path to the file.</param>
    /// <param name="pattern">The byte value to fill the file with.</param>
    /// <param name="length">The length to write (typically the original file size).</param>
    public static void OverwriteWithPattern(string filePath, byte pattern, long length)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (length <= 0) return;

        const int bufferSize = 65536; // 64 KB buffer
        var buffer = new byte[Math.Min(bufferSize, length)];
        Array.Fill(buffer, pattern);

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);
            fs.Position = 0;

            var remaining = length;
            while (remaining > 0)
            {
                var toWrite = (int)Math.Min(remaining, buffer.Length);
                fs.Write(buffer, 0, toWrite);
                remaining -= toWrite;
            }

            fs.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>
    /// Cleans up SQLite artifact files (WAL, journal, shared memory) associated with a database.
    /// These files may contain plaintext data even when the main database is encrypted.
    /// </summary>
    /// <param name="dbPath">Absolute path to the main SQLite database file.</param>
    public static void CleanSqliteArtifacts(string dbPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dbPath);

        var artifacts = new[]
        {
            dbPath + "-wal",
            dbPath + "-journal",
            dbPath + "-shm"
        };

        foreach (var artifact in artifacts)
        {
            if (File.Exists(artifact))
            {
                SecureDeleteFile(artifact, passes: 3);
            }
        }
    }

    /// <summary>
    /// Finds and securely deletes temporary files in the specified data directory.
    /// Targets common temp file patterns: *.tmp, *.temp, *~, *.bak, *.log.
    /// </summary>
    /// <param name="dataDir">Absolute path to the data directory to clean.</param>
    /// <returns>Number of temporary files securely deleted.</returns>
    public static int CleanTempFiles(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);

        if (!Directory.Exists(dataDir))
            return 0;

        var tempPatterns = new[] { "*.tmp", "*.temp", "*.bak", "*.log", "*~" };
        var deleted = 0;

        foreach (var pattern in tempPatterns)
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(dataDir, pattern, SearchOption.AllDirectories))
                {
                    if (SecureDeleteFile(file, passes: 1))
                        deleted++;
                }
            }
            catch (UnauthorizedAccessException) { /* skip inaccessible files */ }
            catch (IOException) { /* skip locked files */ }
        }

        return deleted;
    }

    /// <summary>
    /// Fills free disk space on the volume containing <paramref name="path"/> with random data,
    /// then deletes the fill file. This is a simplified anti-forensics measure to overwrite
    /// deleted file remnants in free space.
    /// </summary>
    /// <param name="path">Any path on the target volume (used to determine the drive).</param>
    /// <param name="chunkSizeMB">Size of write chunks in megabytes (default 10).</param>
    /// <remarks>
    /// This operation can be very slow and I/O intensive. Use with caution.
    /// The operation is best-effort and will stop when the disk is full.
    /// </remarks>
    public static void WipeFreeDiskSpace(string path, int chunkSizeMB = 10)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (chunkSizeMB < 1) chunkSizeMB = 1;
        if (chunkSizeMB > 100) chunkSizeMB = 100; // Cap to prevent excessive memory use

        var directory = Path.GetDirectoryName(path) ?? path;
        if (!Directory.Exists(directory))
            return;

        var fillFilePath = Path.Combine(directory, $".tordex_wipe_{Guid.NewGuid():N}.tmp");
        var chunkSize = chunkSizeMB * 1024 * 1024;
        var chunk = new byte[chunkSize];

        try
        {
            using var fs = new FileStream(fillFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
            File.SetAttributes(fillFilePath, FileAttributes.Hidden | FileAttributes.Temporary);

            while (true)
            {
                RandomNumberGenerator.Fill(chunk);
                try
                {
                    fs.Write(chunk);
                    fs.Flush(flushToDisk: true);
                }
                catch (IOException)
                {
                    // Disk full — mission accomplished
                    break;
                }
            }
        }
        catch (IOException) { /* disk full or write error — expected */ }
        finally
        {
            CryptographicOperations.ZeroMemory(chunk);

            // Delete the fill file
            try
            {
                if (File.Exists(fillFilePath))
                    File.Delete(fillFilePath);
            }
            catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Securely zeros a memory span using <see cref="CryptographicOperations.ZeroMemory"/>,
    /// which is guaranteed not to be optimized away by the JIT.
    /// </summary>
    /// <param name="data">The memory span to zero.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void SecureZeroMemory(Span<byte> data)
    {
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>
    /// Attempts to overwrite a managed string's character buffer in place.
    /// Pins the string and overwrites each character with '\0'.
    /// Then sets the reference to null.
    /// </summary>
    /// <param name="str">Reference to the string to shred. Set to null after shredding.</param>
    /// <remarks>
    /// Managed strings are immutable and may be interned. This is a best-effort measure;
    /// the GC may have already copied the string data. For truly sensitive data,
    /// use <see cref="MemoryProtectionService.ProtectedBuffer"/> or byte arrays instead.
    /// </remarks>
    public static unsafe void ShredString(ref string? str)
    {
        if (str is null) return;

        var pinned = GCHandle.Alloc(str, GCHandleType.Pinned);
        try
        {
            var ptr = (char*)pinned.AddrOfPinnedObject();
            for (int i = 0; i < str.Length; i++)
            {
                ptr[i] = '\0';
            }
        }
        finally
        {
            pinned.Free();
        }

        str = null;
    }

    /// <summary>
    /// Generates a cryptographically secure random byte array.
    /// </summary>
    /// <param name="length">Number of random bytes to generate.</param>
    /// <returns>A byte array filled with cryptographic random data.</returns>
    public static byte[] GetSecureRandom(int length)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");

        var buffer = new byte[length];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    /// <summary>
    /// Performs the DoD 5220.22-M 3-pass overwrite on a file:
    /// Pass 1: Write all zeros (0x00).
    /// Pass 2: Write all ones (0xFF).
    /// Pass 3: Write cryptographic random data.
    /// Each pass flushes to disk before the next begins.
    /// </summary>
    /// <param name="filePath">Absolute path to the file to overwrite.</param>
    /// <param name="length">Length of data to write (original file size).</param>
    private static void DoD5220Pattern(string filePath, long length)
    {
        const int bufferSize = 65536; // 64 KB

        // Pass 1: All zeros
        OverwriteWithPattern(filePath, 0x00, length);

        // Pass 2: All ones
        OverwriteWithPattern(filePath, 0xFF, length);

        // Pass 3: Random data
        var randomBuffer = new byte[Math.Min(bufferSize, length)];
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None);
            fs.Position = 0;

            var remaining = length;
            while (remaining > 0)
            {
                var toWrite = (int)Math.Min(remaining, randomBuffer.Length);
                RandomNumberGenerator.Fill(randomBuffer.AsSpan(0, toWrite));
                fs.Write(randomBuffer, 0, toWrite);
                remaining -= toWrite;
            }

            fs.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(randomBuffer);
        }
    }
}
