using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace TordeX.Core.Services;

/// <summary>
/// Provides in-memory data protection using Windows DPAPI (Data Protection API)
/// via direct P/Invoke to Crypt32.dll. Encrypts and decrypts sensitive byte arrays
/// in RAM to mitigate cold-boot and memory-dump attacks.
/// </summary>
[SupportedOSPlatform("windows")]
public static class MemoryProtectionService
{
    // ═══════════════ DPAPI P/Invoke ═══════════════

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    // dwFlags for CryptProtectData / CryptUnprotectData
    private const uint CRYPTPROTECT_UI_FORBIDDEN = 0x1;

    [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(
        ref DATA_BLOB pDataIn,
        string? szDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn,
        IntPtr ppszDataDescr,
        ref DATA_BLOB pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll", SetLastError = false)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    /// <summary>
    /// Application-specific entropy bytes binding protected data to the tordeX application context.
    /// </summary>
    private static readonly byte[] EntropyBytes = "tordeX-memory-protection-v1"u8.ToArray();

    /// <summary>
    /// Encrypts data in memory using DPAPI (CurrentUser scope).
    /// The protected data can only be unprotected by the same Windows user account on the same machine.
    /// </summary>
    /// <param name="data">Plaintext data to protect.</param>
    /// <returns>DPAPI-encrypted byte array.</returns>
    public static byte[] ProtectInMemory(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.Length == 0) return [];

        return DpapiProtect(data, EntropyBytes);
    }

    /// <summary>
    /// Decrypts DPAPI-protected data back to plaintext.
    /// </summary>
    /// <param name="protectedData">DPAPI-encrypted byte array from <see cref="ProtectInMemory"/>.</param>
    /// <returns>Decrypted plaintext byte array. Caller must zero this after use.</returns>
    public static byte[] UnprotectInMemory(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        if (protectedData.Length == 0) return [];

        return DpapiUnprotect(protectedData, EntropyBytes);
    }

    /// <summary>
    /// Creates a new <see cref="ProtectedBuffer"/> that stores data encrypted in RAM.
    /// The buffer is initialized with zeros and can be populated via <see cref="ProtectedBuffer.UseUnprotected"/>.
    /// </summary>
    /// <param name="size">Size of the plaintext buffer in bytes.</param>
    /// <returns>A new <see cref="ProtectedBuffer"/> instance. Caller must dispose when done.</returns>
    public static ProtectedBuffer CreateProtectedBuffer(int size)
    {
        if (size <= 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Buffer size must be positive.");

        return new ProtectedBuffer(size);
    }

    /// <summary>
    /// Converts a plaintext string to a DPAPI-protected buffer.
    /// The string is encoded as UTF-8, encrypted, and the intermediate bytes are securely zeroed.
    /// </summary>
    /// <param name="value">The plaintext string to protect.</param>
    /// <returns>A <see cref="ProtectedBuffer"/> containing the encrypted UTF-8 bytes.</returns>
    public static ProtectedBuffer ToSecureBytes(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            var buffer = new ProtectedBuffer(bytes);
            return buffer;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Zeros out a byte array using <see cref="CryptographicOperations.ZeroMemory"/>,
    /// which is guaranteed not to be optimized away.
    /// </summary>
    /// <param name="data">The byte array to wipe.</param>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void WipeArray(byte[] data)
    {
        if (data is null) return;
        CryptographicOperations.ZeroMemory(data);
    }

    /// <summary>
    /// Clears a string reference. Managed strings cannot be reliably wiped from memory
    /// due to immutability and possible interning, so this nulls the reference as a best effort.
    /// For truly sensitive data, use <see cref="ProtectedBuffer"/> or byte arrays.
    /// </summary>
    /// <param name="str">Reference to the string to clear. Set to null after call.</param>
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void WipeString(ref string? str)
    {
        str = null;
    }

    /// <summary>
    /// Checks whether DPAPI-based memory protection is available on the current platform.
    /// Returns true on Windows when Crypt32.dll is functional, false otherwise.
    /// </summary>
    /// <returns>True if DPAPI protection is available and working.</returns>
    public static bool IsProtectionAvailable()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            // Probe with a small test to verify DPAPI is functional
            var testData = new byte[] { 0x42 };
            var encrypted = DpapiProtect(testData, null);
            var decrypted = DpapiUnprotect(encrypted, null);
            return decrypted.Length == 1 && decrypted[0] == 0x42;
        }
        catch
        {
            return false;
        }
    }

    // ═══════════════ DPAPI Core ═══════════════

    /// <summary>
    /// Encrypts data using Windows DPAPI (CryptProtectData) with CurrentUser scope.
    /// </summary>
    private static byte[] DpapiProtect(byte[] plaintext, byte[]? entropy)
    {
        var dataIn = new DATA_BLOB();
        var dataOut = new DATA_BLOB();
        var entropyBlob = new DATA_BLOB();

        var dataHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
        GCHandle entropyHandle = default;

        try
        {
            dataIn.cbData = plaintext.Length;
            dataIn.pbData = dataHandle.AddrOfPinnedObject();

            if (entropy is { Length: > 0 })
            {
                entropyHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
                entropyBlob.cbData = entropy.Length;
                entropyBlob.pbData = entropyHandle.AddrOfPinnedObject();
            }

            var success = CryptProtectData(
                ref dataIn,
                null,
                ref entropyBlob,
                IntPtr.Zero,
                IntPtr.Zero,
                CRYPTPROTECT_UI_FORBIDDEN,
                out dataOut);

            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                throw new CryptographicException($"DPAPI CryptProtectData failed with error code {error}.");
            }

            var result = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
            return result;
        }
        finally
        {
            if (dataOut.pbData != IntPtr.Zero)
                LocalFree(dataOut.pbData);

            dataHandle.Free();
            if (entropyHandle.IsAllocated)
                entropyHandle.Free();
        }
    }

    /// <summary>
    /// Decrypts data using Windows DPAPI (CryptUnprotectData) with CurrentUser scope.
    /// </summary>
    private static byte[] DpapiUnprotect(byte[] protectedData, byte[]? entropy)
    {
        var dataIn = new DATA_BLOB();
        var dataOut = new DATA_BLOB();
        var entropyBlob = new DATA_BLOB();

        var dataHandle = GCHandle.Alloc(protectedData, GCHandleType.Pinned);
        GCHandle entropyHandle = default;

        try
        {
            dataIn.cbData = protectedData.Length;
            dataIn.pbData = dataHandle.AddrOfPinnedObject();

            if (entropy is { Length: > 0 })
            {
                entropyHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
                entropyBlob.cbData = entropy.Length;
                entropyBlob.pbData = entropyHandle.AddrOfPinnedObject();
            }

            var success = CryptUnprotectData(
                ref dataIn,
                IntPtr.Zero,
                ref entropyBlob,
                IntPtr.Zero,
                IntPtr.Zero,
                CRYPTPROTECT_UI_FORBIDDEN,
                out dataOut);

            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                throw new CryptographicException($"DPAPI CryptUnprotectData failed with error code {error}.");
            }

            var result = new byte[dataOut.cbData];
            Marshal.Copy(dataOut.pbData, result, 0, dataOut.cbData);
            return result;
        }
        finally
        {
            if (dataOut.pbData != IntPtr.Zero)
                LocalFree(dataOut.pbData);

            dataHandle.Free();
            if (entropyHandle.IsAllocated)
                entropyHandle.Free();
        }
    }
}

/// <summary>
/// An <see cref="IDisposable"/> wrapper that holds sensitive data encrypted via DPAPI
/// at all times except during explicit <see cref="UseUnprotected(Action{byte[]})"/> calls.
/// Data is only decrypted into a temporary buffer, used, and immediately re-encrypted and zeroed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ProtectedBuffer : IDisposable
{
    private byte[]? _protectedData;
    private readonly int _plainSize;
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="ProtectedBuffer"/> with a zero-filled buffer of the given size.
    /// </summary>
    /// <param name="size">Size of the plaintext buffer in bytes.</param>
    internal ProtectedBuffer(int size)
    {
        if (size <= 0)
            throw new ArgumentOutOfRangeException(nameof(size), "Buffer size must be positive.");

        _plainSize = size;
        var zeros = new byte[size];
        try
        {
            _protectedData = MemoryProtectionService.ProtectInMemory(zeros);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zeros);
        }
    }

    /// <summary>
    /// Initializes a new <see cref="ProtectedBuffer"/> from existing plaintext data.
    /// The provided data is encrypted immediately; the caller is responsible for zeroing the original.
    /// </summary>
    /// <param name="plaintext">Plaintext data to protect. This array is NOT zeroed by this constructor.</param>
    internal ProtectedBuffer(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length == 0)
            throw new ArgumentException("Plaintext data cannot be empty.", nameof(plaintext));

        _plainSize = plaintext.Length;
        _protectedData = MemoryProtectionService.ProtectInMemory(plaintext);
    }

    /// <summary>
    /// Gets the size of the unprotected data in bytes.
    /// </summary>
    public int Size => _plainSize;

    /// <summary>
    /// Temporarily decrypts the data, invokes the provided action, then re-encrypts and zeros the buffer.
    /// The decrypted data exists in memory only for the duration of the action.
    /// </summary>
    /// <param name="action">Action to execute with the temporarily decrypted data.</param>
    /// <exception cref="ObjectDisposedException">Thrown if the buffer has been disposed.</exception>
    public void UseUnprotected(Action<byte[]> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        ObjectDisposedException.ThrowIf(_disposed, this);

        byte[]? decrypted = null;

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_protectedData is null)
                throw new InvalidOperationException("Protected data is in an invalid state.");

            decrypted = MemoryProtectionService.UnprotectInMemory(_protectedData);
        }

        try
        {
            action(decrypted);
        }
        finally
        {
            // Re-encrypt with fresh DPAPI output (new key material per call)
            lock (_lock)
            {
                if (!_disposed)
                {
                    var oldProtected = _protectedData;
                    _protectedData = MemoryProtectionService.ProtectInMemory(decrypted);

                    // Zero old protected data blob
                    if (oldProtected is not null)
                        CryptographicOperations.ZeroMemory(oldProtected);
                }
            }

            // Always zero the decrypted buffer
            CryptographicOperations.ZeroMemory(decrypted);
        }
    }

    /// <summary>
    /// Temporarily decrypts the data, invokes the provided function, then re-encrypts and zeros the buffer.
    /// Returns the function result.
    /// </summary>
    /// <typeparam name="T">Return type of the function.</typeparam>
    /// <param name="func">Function to execute with the temporarily decrypted data.</param>
    /// <returns>The result of the function.</returns>
    public T UseUnprotected<T>(Func<byte[], T> func)
    {
        ArgumentNullException.ThrowIfNull(func);
        ObjectDisposedException.ThrowIf(_disposed, this);

        T result = default!;
        UseUnprotected(data => { result = func(data); });
        return result;
    }

    /// <summary>
    /// Disposes the buffer, securely zeroing both the protected and any residual data.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;

            if (_protectedData is not null)
            {
                CryptographicOperations.ZeroMemory(_protectedData);
                _protectedData = null;
            }
        }
    }
}
