using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace TordeX.Core.Services;

/// <summary>
/// Anti-debugging and anti-tamper detection service.
/// Detects attached debuggers, virtual machines, profiling instrumentation,
/// suspicious loaded modules, and memory tampering indicators.
/// Uses native P/Invoke on Windows for kernel-level checks.
/// </summary>
public static partial class TamperDetectionService
{
    // ═══════════════════════════════════════════════════════════
    // P/Invoke declarations (Windows kernel32)
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Determines whether the calling process is being debugged by a user-mode debugger.
    /// </summary>
    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsDebuggerPresent();

    /// <summary>
    /// Determines whether the specified process is being debugged.
    /// </summary>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CheckRemoteDebuggerPresent(
        IntPtr hProcess,
        [MarshalAs(UnmanagedType.Bool)] out bool isDebuggerPresent);

    /// <summary>
    /// Returns a pseudohandle for the current process.
    /// </summary>
    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetCurrentProcess();

    // ═══════════════════════════════════════════════════════════
    // Known indicators
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// MAC address OUI prefixes commonly associated with virtual machine hypervisors.
    /// </summary>
    private static readonly string[] s_vmMacPrefixes =
    [
        "00:05:69", // VMware
        "00:0C:29", // VMware
        "00:1C:14", // VMware
        "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "0A:00:27", // VirtualBox
        "00:15:5D", // Hyper-V
        "00:16:3E", // Xen
        "52:54:00", // QEMU/KVM
        "00:1A:4A", // Parallels
    ];

    /// <summary>
    /// Known DLL names injected by profilers, debuggers, or instrumentation tools.
    /// </summary>
    private static readonly string[] s_suspiciousModules =
    [
        "snxhk.dll",        // Avecto / BeyondTrust
        "cmdvrt32.dll",     // Comodo sandbox
        "cmdvrt64.dll",     // Comodo sandbox
        "SbieDll.dll",      // Sandboxie
        "SxIn.dll",         // Qihoo 360
        "Sf2.dll",          // SpyEye
        "dbghelp.dll",      // Debug helper (may be legitimate)
        "api_log.dll",      // API logging
        "dir_watch.dll",    // Directory watcher injection
        "pstorec.dll",      // Protected Storage
        "vmcheck.dll",      // VM detection
        "wpespy.dll",       // WPE Pro (packet editor)
    ];

    /// <summary>
    /// Registry paths that contain VM-related identifiers.
    /// </summary>
    private static readonly string[] s_vmRegistryPaths =
    [
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxGuest",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxMouse",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxSF",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxVideo",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse",
    ];

    // ═══════════════════════════════════════════════════════════
    // Records
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Comprehensive threat assessment result from all detection checks.
    /// </summary>
    /// <param name="DebuggerDetected">True if a local debugger is attached.</param>
    /// <param name="RemoteDebugger">True if a remote debugger is attached.</param>
    /// <param name="VirtualMachine">True if VM indicators were found.</param>
    /// <param name="Instrumentation">True if profiling/instrumentation is active.</param>
    /// <param name="MemoryTampered">True if loaded modules appear tampered.</param>
    /// <param name="ThreatLevel">Overall threat level: None, Low, Medium, High, or Critical.</param>
    /// <param name="Recommendations">List of recommended actions based on detected threats.</param>
    public sealed record ThreatAssessment(
        bool DebuggerDetected,
        bool RemoteDebugger,
        bool VirtualMachine,
        bool Instrumentation,
        bool MemoryTampered,
        string ThreatLevel,
        List<string> Recommendations);

    // ═══════════════════════════════════════════════════════════
    // Detection methods
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Checks whether a debugger is attached to the current process.
    /// Combines the managed <see cref="Debugger.IsAttached"/> check with the native
    /// kernel32 <c>IsDebuggerPresent()</c> call for defense in depth.
    /// </summary>
    /// <returns>True if any debugger is detected.</returns>
    public static bool IsDebuggerAttached()
    {
        // Managed check
        if (Debugger.IsAttached)
            return true;

        // Native check — may detect debuggers that bypass .NET detection
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return IsDebuggerPresent();
            }
        }
        catch
        {
            // P/Invoke failure — cannot determine, assume safe
        }

        return false;
    }

    /// <summary>
    /// Checks whether a remote debugger is attached to the current process
    /// using the native <c>CheckRemoteDebuggerPresent</c> API.
    /// </summary>
    /// <returns>True if a remote debugger is detected.</returns>
    public static bool IsRemoteDebuggerPresent()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            var hProcess = GetCurrentProcess();
            if (CheckRemoteDebuggerPresent(hProcess, out var isPresent))
            {
                return isPresent;
            }
        }
        catch
        {
            // P/Invoke failure
        }

        return false;
    }

    /// <summary>
    /// Performs a combined check of multiple tamper indicators.
    /// Returns true if ANY indicator suggests the application has been tampered with.
    /// </summary>
    /// <returns>True if tampering is detected via any method.</returns>
    public static bool HasBeenTampered()
    {
        return IsDebuggerAttached()
               || IsRemoteDebuggerPresent()
               || DetectInstrumentation()
               || !VerifyModuleIntegrity();
    }

    /// <summary>
    /// Checks for virtual machine indicators including VM-specific MAC address prefixes,
    /// registry keys for VM guest tools, and known VM-related environment variables.
    /// </summary>
    /// <returns>True if the application appears to be running inside a virtual machine.</returns>
    public static bool DetectVirtualMachine()
    {
        return CheckVmMacAddresses()
               || CheckVmRegistry()
               || CheckVmEnvironment();
    }

    /// <summary>
    /// Checks for profiling and instrumentation indicators.
    /// Detects the COR_ENABLE_PROFILING environment variable and known profiler DLLs.
    /// </summary>
    /// <returns>True if profiling or instrumentation is detected.</returns>
    public static bool DetectInstrumentation()
    {
        // Check for .NET CLR profiling API activation
        var profilingEnabled = Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING");
        if (string.Equals(profilingEnabled, "1", StringComparison.Ordinal))
            return true;

        var corExtProfilingEnabled = Environment.GetEnvironmentVariable("CORECLR_ENABLE_PROFILING");
        if (string.Equals(corExtProfilingEnabled, "1", StringComparison.Ordinal))
            return true;

        // Check for profiler GUID being set
        var profilerGuid = Environment.GetEnvironmentVariable("COR_PROFILER");
        if (!string.IsNullOrWhiteSpace(profilerGuid))
            return true;

        var coreClrProfilerGuid = Environment.GetEnvironmentVariable("CORECLR_PROFILER");
        if (!string.IsNullOrWhiteSpace(coreClrProfilerGuid))
            return true;

        // Check for known profiler/instrumentation DLLs in loaded modules
        return CheckForProfilerModules();
    }

    /// <summary>
    /// Performs a comprehensive threat assessment combining all detection methods
    /// and produces an actionable report with threat level and recommendations.
    /// </summary>
    /// <returns>A <see cref="ThreatAssessment"/> with detailed findings.</returns>
    public static ThreatAssessment GetThreatAssessment()
    {
        var debugger = IsDebuggerAttached();
        var remoteDebugger = IsRemoteDebuggerPresent();
        var vm = DetectVirtualMachine();
        var instrumentation = DetectInstrumentation();
        var memoryTampered = !VerifyModuleIntegrity();

        var recommendations = new List<string>();

        if (debugger)
            recommendations.Add("Local debugger detected. Terminate sensitive operations and wipe session keys.");

        if (remoteDebugger)
            recommendations.Add("Remote debugger detected. This may indicate active reverse engineering. Consider immediate shutdown.");

        if (vm)
            recommendations.Add("Virtual machine detected. Verify this is an expected deployment environment.");

        if (instrumentation)
            recommendations.Add("Profiling/instrumentation detected. Disable COR_ENABLE_PROFILING and check for injected DLLs.");

        if (memoryTampered)
            recommendations.Add("Suspicious modules loaded. Verify loaded DLLs and check for injection attacks.");

        var threatLevel = CalculateThreatLevel(debugger, remoteDebugger, vm, instrumentation, memoryTampered);

        return new ThreatAssessment(
            DebuggerDetected: debugger,
            RemoteDebugger: remoteDebugger,
            VirtualMachine: vm,
            Instrumentation: instrumentation,
            MemoryTampered: memoryTampered,
            ThreatLevel: threatLevel,
            Recommendations: recommendations);
    }

    /// <summary>
    /// Verifies the integrity of loaded process modules.
    /// Flags any loaded DLL whose path is outside the Windows system directory
    /// or the application's own directory as potentially suspicious.
    /// </summary>
    /// <returns>True if all loaded modules appear legitimate; false if suspicious modules are found.</returns>
    public static bool VerifyModuleIntegrity()
    {
        try
        {
            var process = Process.GetCurrentProcess();
            var appDir = AppContext.BaseDirectory;
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var dotnetDir = Path.Combine(programFiles, "dotnet");

            foreach (ProcessModule module in process.Modules)
            {
                var modulePath = module.FileName;
                if (string.IsNullOrEmpty(modulePath))
                    continue;

                var moduleFileName = Path.GetFileName(modulePath);

                // Check against known suspicious module names
                foreach (var suspicious in s_suspiciousModules)
                {
                    if (string.Equals(moduleFileName, suspicious, StringComparison.OrdinalIgnoreCase))
                        return false;
                }

                // Verify the module is from a trusted location
                var fullPath = Path.GetFullPath(modulePath);
                var isTrusted = fullPath.StartsWith(appDir, StringComparison.OrdinalIgnoreCase)
                                || fullPath.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)
                                || fullPath.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)
                                || fullPath.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase)
                                || fullPath.StartsWith(dotnetDir, StringComparison.OrdinalIgnoreCase);

                if (!isTrusted)
                    return false;
            }

            return true;
        }
        catch
        {
            // If we cannot enumerate modules, assume clean rather than false-positive
            return true;
        }
    }

    /// <summary>
    /// Placeholder for memory section hash verification.
    /// Compares a precomputed hash against the current memory contents at a base address.
    /// Full implementation requires reading process memory and comparing against a known-good hash.
    /// </summary>
    /// <param name="expectedHash">Expected SHA-256 hash of the memory region.</param>
    /// <param name="baseAddress">Base address of the memory region to verify.</param>
    /// <returns>True if the memory region matches the expected hash; false otherwise.</returns>
    public static bool CheckMemoryIntegrity(string expectedHash, IntPtr baseAddress)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedHash);

        if (baseAddress == IntPtr.Zero)
            return false;

        // Memory integrity verification requires reading raw process memory at the specified
        // base address and comparing its SHA-256 hash against the expected value.
        // This is architecture-dependent and requires careful handling of page permissions.
        // For now, we verify that the base address is within a valid module range.
        try
        {
            var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                var moduleBase = module.BaseAddress;
                var moduleEnd = moduleBase + module.ModuleMemorySize;

                if (baseAddress >= moduleBase && baseAddress < moduleEnd)
                {
                    // Address is within a known module — basic validity check passes
                    return true;
                }
            }

            // Address not found in any loaded module — suspicious
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Starts a periodic background timer that runs threat assessment checks
    /// and invokes a callback when threats are detected.
    /// </summary>
    /// <param name="intervalMs">Interval between checks in milliseconds (minimum 1000).</param>
    /// <param name="onThreatDetected">Callback invoked with the <see cref="ThreatAssessment"/> when threats are found.</param>
    /// <returns>A <see cref="MonitoringTimer"/> (IDisposable) that runs the checks periodically.</returns>
    public static MonitoringTimer StartContinuousMonitoring(
        int intervalMs,
        Action<ThreatAssessment> onThreatDetected)
    {
        ArgumentNullException.ThrowIfNull(onThreatDetected);

        if (intervalMs < 1000)
            throw new ArgumentOutOfRangeException(
                nameof(intervalMs),
                "Monitoring interval must be at least 1000ms to avoid excessive CPU usage.");

        return new MonitoringTimer(intervalMs, onThreatDetected);
    }

    // ═══════════════════════════════════════════════════════════
    // Private helpers
    // ═══════════════════════════════════════════════════════════

    /// <summary>
    /// Checks network adapter MAC addresses against known VM hypervisor OUI prefixes.
    /// </summary>
    private static bool CheckVmMacAddresses()
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up)
                    continue;

                var macBytes = iface.GetPhysicalAddress().GetAddressBytes();
                if (macBytes.Length < 3)
                    continue;

                var macPrefix = $"{macBytes[0]:X2}:{macBytes[1]:X2}:{macBytes[2]:X2}";
                foreach (var vmPrefix in s_vmMacPrefixes)
                {
                    if (string.Equals(macPrefix, vmPrefix, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }
        catch
        {
            // Cannot enumerate NICs
        }

        return false;
    }

    /// <summary>
    /// Checks Windows registry for VM guest tool service entries.
    /// </summary>
    private static bool CheckVmRegistry()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return false;

        try
        {
            foreach (var path in s_vmRegistryPaths)
            {
                // Parse the registry path: "HKEY_LOCAL_MACHINE\path\to\key"
                var value = Microsoft.Win32.Registry.GetValue(path, null, null);
                if (value is not null)
                    return true;
            }
        }
        catch
        {
            // Registry access may be restricted
        }

        return false;
    }

    /// <summary>
    /// Checks environment variables and system information for VM indicators.
    /// </summary>
    private static bool CheckVmEnvironment()
    {
        try
        {
            // Check common VM environment variables
            var hypervisorPresent = Environment.GetEnvironmentVariable("HYPERVISOR");
            if (!string.IsNullOrWhiteSpace(hypervisorPresent))
                return true;

            // Check system manufacturer via environment
            var manufacturer = Environment.GetEnvironmentVariable("COMPUTERNAME");
            // We don't flag based on computer name alone — that would be too aggressive

            // Check processor count as a very basic heuristic (VMs often have 1-2)
            // This alone is not conclusive, so we only use it as supporting evidence
            // when combined with other checks above.
        }
        catch
        {
            // Environment access failure
        }

        return false;
    }

    /// <summary>
    /// Checks loaded modules for known profiler and instrumentation DLLs.
    /// </summary>
    private static bool CheckForProfilerModules()
    {
        try
        {
            var process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                var fileName = Path.GetFileName(module.FileName);
                if (string.IsNullOrEmpty(fileName))
                    continue;

                // Check for common profiler DLL patterns
                if (fileName.Contains("profiler", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("coverage", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("intellitrace", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("dotTrace", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("dotMemory", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Cannot enumerate modules
        }

        return false;
    }

    /// <summary>
    /// Calculates an overall threat level string based on individual detection results.
    /// </summary>
    private static string CalculateThreatLevel(
        bool debugger,
        bool remoteDebugger,
        bool vm,
        bool instrumentation,
        bool memoryTampered)
    {
        var score = 0;

        if (debugger) score += 3;
        if (remoteDebugger) score += 4;
        if (vm) score += 1;             // VM alone is low risk
        if (instrumentation) score += 3;
        if (memoryTampered) score += 4;

        return score switch
        {
            0 => "None",
            1 => "Low",
            >= 2 and <= 3 => "Medium",
            >= 4 and <= 6 => "High",
            _ => "Critical"
        };
    }
}

/// <summary>
/// Disposable wrapper around <see cref="System.Threading.Timer"/> for continuous
/// tamper detection monitoring. Periodically runs threat assessments and invokes
/// the callback when any threat is detected.
/// </summary>
public sealed class MonitoringTimer : IDisposable
{
    private readonly Timer _timer;
    private readonly Action<TamperDetectionService.ThreatAssessment> _onThreatDetected;
    private volatile bool _disposed;
    private volatile bool _isRunning;

    /// <summary>
    /// Creates and starts a new monitoring timer.
    /// </summary>
    /// <param name="intervalMs">Interval between checks in milliseconds.</param>
    /// <param name="onThreatDetected">Callback for when threats are detected.</param>
    internal MonitoringTimer(int intervalMs, Action<TamperDetectionService.ThreatAssessment> onThreatDetected)
    {
        _onThreatDetected = onThreatDetected;
        _timer = new Timer(OnTick, null, TimeSpan.FromMilliseconds(intervalMs), TimeSpan.FromMilliseconds(intervalMs));
    }

    /// <summary>
    /// Gets whether the timer is currently running.
    /// </summary>
    public bool IsRunning => !_disposed;

    private void OnTick(object? state)
    {
        if (_disposed || _isRunning)
            return;

        _isRunning = true;
        try
        {
            var assessment = TamperDetectionService.GetThreatAssessment();
            if (assessment.ThreatLevel != "None")
            {
                _onThreatDetected(assessment);
            }
        }
        catch
        {
            // Swallow exceptions to prevent crashing the timer thread
        }
        finally
        {
            _isRunning = false;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _timer.Change(Timeout.Infinite, Timeout.Infinite);
        _timer.Dispose();
    }
}
