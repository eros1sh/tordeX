using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using TordeX.Core.Cryptography;
using TordeX.Core.Services;

namespace TordeX.Core.Network;

/// <summary>
/// Manages embedded Tor process lifecycle directly (no TorSharp dependency).
/// Provides SOCKS5 proxy for all P2P connections.
/// Uses filesystem-based HiddenServiceDir for reliable hidden service creation
/// and monitors HS_DESC events via control port for descriptor upload confirmation.
/// </summary>
public sealed class TorManager : IAsyncDisposable
{
    private Process? _torProcess;
    private readonly string _dataDirectory;
    private readonly AppLogger _logger;
    private string? _controlPassword;
    private string? _hashedControlPassword;
    private bool _disposed;
    private bool _isRunning;

    // Hidden service configuration
    private int _localP2PPort;
    private string? _hiddenServiceDir;

    // Bootstrap tracking — set when Tor outputs "Bootstrapped 100%"
    private readonly TaskCompletionSource<bool> _bootstrapTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _bootstrapPercent;

    public int SocksPort { get; private set; }
    public int ControlPort { get; private set; }
    public bool IsRunning => _isRunning;
    public bool HasHiddenService => OnionAddress is not null;
    public int BootstrapPercent => _bootstrapPercent;

    /// <summary>
    /// Fixed virtual port for the hidden service.
    /// All peers connect to this port on the .onion address regardless of local port.
    /// </summary>
    public const int HiddenServiceVirtualPort = 19876;

    public string? OnionAddress { get; private set; }

    /// <summary>
    /// Event fired when Tor connection status changes.
    /// </summary>
    public event Action<bool>? ConnectionStatusChanged;

    /// <summary>
    /// Event fired when bootstrap progress changes (0-100).
    /// </summary>
    public event Action<int>? BootstrapProgressChanged;

    public TorManager(string dataDirectory, AppLogger logger)
    {
        _dataDirectory = dataDirectory;
        _logger = logger;
    }

    /// <summary>
    /// Start Tor process with a filesystem-based hidden service.
    /// The HiddenServiceDir is configured in torrc BEFORE Tor starts,
    /// which is the most reliable method for hidden service creation.
    /// Waits for Tor to fully bootstrap (100%) and confirms descriptor
    /// upload to HSDir via control port HS_DESC events.
    /// </summary>
    /// <param name="localP2PPort">Local TCP port where P2P server is already listening.</param>
    /// <param name="ct">Cancellation token.</param>
    public async Task StartAsync(int localP2PPort, CancellationToken ct = default)
    {
        if (_isRunning)
        {
            _logger?.Info("Tor is already running, skipping start", "Tor");
            return;
        }

        _localP2PPort = localP2PPort;

        _controlPassword = SecureRandom.GenerateHex(16);
        _logger?.Info($"Generated control password: {_controlPassword[..8]}...", "Tor");

        // Use dynamic ports to avoid conflicts when multiple instances run
        SocksPort = NetworkUtils.FindAvailablePort(9050);
        ControlPort = NetworkUtils.FindAvailablePort(SocksPort + 1);
        _logger?.Info($"Selected ports - SOCKS:{SocksPort} Control:{ControlPort}", "Tor");

        // Kill any stale Tor processes from previous crashes
        _logger?.Info("Killing stale Tor processes...", "Tor");
        KillStaleTorProcesses();

        // Find Tor executable
        var torExePath = FindTorExecutable();
        if (torExePath is null)
        {
            throw new FileNotFoundException(
                "Tor executable not found. Please ensure tor.exe is alongside tordeX.exe or install Tor Browser.");
        }

        _logger?.Info($"Using Tor executable: {torExePath}", "Tor");

        // Hash the control password using tor --hash-password
        _hashedControlPassword = await HashControlPasswordAsync(torExePath, _controlPassword, ct);
        if (_hashedControlPassword is null)
        {
            throw new InvalidOperationException("Failed to hash Tor control password. tor.exe may be corrupted or incompatible.");
        }
        _logger?.Info("Control password hashed successfully", "Tor");

        // Prepare data directory
        var torDataDir = Path.Combine(_dataDirectory, "data");
        Directory.CreateDirectory(torDataDir);

        // Prepare hidden service directory
        _hiddenServiceDir = Path.Combine(_dataDirectory, "hidden_service");
        Directory.CreateDirectory(_hiddenServiceDir);
        _logger?.Info($"Hidden service directory: {_hiddenServiceDir}", "Tor");

        // Generate torrc config (includes HiddenServiceDir)
        var torrcPath = Path.Combine(_dataDirectory, "torrc");
        await WriteTorrcAsync(torrcPath, torDataDir, ct);
        _logger?.Info($"Generated torrc at: {torrcPath}", "Tor");

        // Start Tor process
        _logger?.Info("Starting Tor process...", "Tor");
        var psi = new ProcessStartInfo
        {
            FileName = torExePath,
            Arguments = $"-f \"{torrcPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(torExePath)!
        };

        _torProcess = new Process { StartInfo = psi, EnableRaisingEvents = true };

        // Capture Tor stdout — parse bootstrap progress
        _torProcess.OutputDataReceived += OnTorOutput;
        _torProcess.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
                _logger?.Warn($"[tor-err] {e.Data}", "Tor");
        };

        if (!_torProcess.Start())
        {
            throw new InvalidOperationException("Failed to start tor.exe process.");
        }

        _torProcess.BeginOutputReadLine();
        _torProcess.BeginErrorReadLine();

        _logger?.Info($"Tor process started with PID: {_torProcess.Id}", "Tor");

        // Wait for Tor to fully bootstrap (100%) — up to 3 minutes
        _logger?.Info("Waiting for Tor to bootstrap to 100%...", "Tor");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(3));

        try
        {
            await _bootstrapTcs.Task.WaitAsync(timeoutCts.Token);
            _logger?.Info("Tor bootstrap completed — 100%", "Tor");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Timeout but user didn't cancel — check if process is alive
            if (_torProcess is not null && !_torProcess.HasExited)
            {
                _logger?.Warn($"Tor bootstrap timeout at {_bootstrapPercent}% — continuing optimistically", "Tor");
            }
            else
            {
                throw new InvalidOperationException(
                    $"Tor process exited before bootstrap completed (exit code: {_torProcess?.ExitCode})");
            }
        }

        // Verify process is still alive
        if (_torProcess is null || _torProcess.HasExited)
        {
            throw new InvalidOperationException(
                $"Tor process died during bootstrap (exit code: {_torProcess?.ExitCode})");
        }

        // Read .onion address from the hostname file created by Tor
        OnionAddress = await ReadHostnameFileAsync(ct);
        _logger?.Info($"Hidden service address: {OnionAddress}", "Tor");

        // Wait for descriptor upload confirmation via control port HS_DESC events.
        // This is CRITICAL — without this, other Tor instances cannot find our hidden service.
        // The old self-test approach was flawed: connecting to our OWN .onion through our OWN
        // Tor instance always succeeds because Tor shortcuts the connection locally,
        // bypassing HSDir entirely. HS_DESC UPLOADED event gives definitive proof.
        await WaitForDescriptorUploadAsync(ct);

        _isRunning = true;
        ConnectionStatusChanged?.Invoke(true);

        // Register cleanup handler
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    /// <summary>
    /// Parse Tor stdout for bootstrap progress.
    /// Sets _bootstrapTcs when 100% is reached.
    /// </summary>
    private void OnTorOutput(object sender, DataReceivedEventArgs e)
    {
        if (string.IsNullOrEmpty(e.Data)) return;

        _logger?.Info($"[tor] {e.Data}", "Tor");

        // Parse: "Bootstrapped 75% (enough_dirinfo): Loaded enough directory info to build circuits"
        var data = e.Data;
        var idx = data.IndexOf("Bootstrapped ", StringComparison.Ordinal);
        if (idx >= 0)
        {
            var after = data.AsSpan(idx + "Bootstrapped ".Length);
            var pctEnd = after.IndexOf('%');
            if (pctEnd > 0 && int.TryParse(after[..pctEnd], out var pct))
            {
                _bootstrapPercent = pct;
                BootstrapProgressChanged?.Invoke(pct);
                _logger?.Info($"Bootstrap progress: {pct}%", "Tor");

                if (pct >= 100)
                {
                    _bootstrapTcs.TrySetResult(true);
                }
            }
        }
    }

    private void OnProcessExit(object? sender, EventArgs e) => ForceKillTorProcess();

    /// <summary>
    /// Read the hidden service .onion address from the hostname file.
    /// Tor creates this file in the HiddenServiceDir during initialization.
    /// Retries for up to 30 seconds (file may not exist until Tor processes the config).
    /// </summary>
    private async Task<string> ReadHostnameFileAsync(CancellationToken ct)
    {
        var hostnameFile = Path.Combine(_hiddenServiceDir!, "hostname");

        for (int i = 0; i < 30; i++)
        {
            if (ct.IsCancellationRequested) break;

            if (File.Exists(hostnameFile))
            {
                var hostname = (await File.ReadAllTextAsync(hostnameFile, ct)).Trim();
                if (!string.IsNullOrEmpty(hostname))
                {
                    _logger?.Info($"Read hostname from file on attempt {i + 1}: {hostname}", "Tor");
                    return hostname;
                }
            }

            await Task.Delay(1000, ct);
        }

        throw new InvalidOperationException(
            "Tor did not create hostname file for hidden service. Check torrc configuration and Tor logs.");
    }

    /// <summary>
    /// Wait for hidden service descriptor upload confirmation via control port HS_DESC events.
    /// Subscribes to HS_DESC asynchronous events and waits for an UPLOADED event,
    /// which confirms at least one HSDir node has our descriptor — making us globally reachable.
    /// </summary>
    private async Task WaitForDescriptorUploadAsync(CancellationToken ct)
    {
        _logger?.Info("Connecting to control port to monitor HS_DESC events...", "Tor");

        var controlReady = await WaitForControlPortAsync(ct);
        if (!controlReady)
        {
            _logger?.Warn("Control port not ready — waiting flat 60s for descriptor propagation", "Tor");
            await Task.Delay(60_000, ct);
            return;
        }

        TcpClient? controlClient = null;
        try
        {
            controlClient = new TcpClient();
            await controlClient.ConnectAsync("127.0.0.1", ControlPort, ct);
            var stream = controlClient.GetStream();
            stream.ReadTimeout = 150_000; // 2.5 minutes
            using var reader = new StreamReader(stream, Encoding.ASCII);
            using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

            // Authenticate
            await writer.WriteLineAsync($"AUTHENTICATE \"{_controlPassword}\"");
            var authResp = await reader.ReadLineAsync(ct);
            if (authResp is null || !authResp.StartsWith("250"))
            {
                _logger?.Warn($"Control auth failed: {authResp} — waiting flat 60s", "Tor");
                await Task.Delay(60_000, ct);
                return;
            }
            _logger?.Info("Control port authenticated", "Tor");

            // Subscribe to HS_DESC events
            await writer.WriteLineAsync("SETEVENTS HS_DESC");
            var eventResp = await reader.ReadLineAsync(ct);
            if (eventResp is null || !eventResp.StartsWith("250"))
            {
                _logger?.Warn($"SETEVENTS HS_DESC failed: {eventResp} — waiting flat 60s", "Tor");
                await Task.Delay(60_000, ct);
                return;
            }
            _logger?.Info("Subscribed to HS_DESC events — waiting for descriptor upload...", "Tor");

            // Wait for HS_DESC UPLOADED event (up to 2 minutes)
            using var uploadCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            uploadCts.CancelAfter(TimeSpan.FromMinutes(2));

            int uploadCount = 0;
            const int requiredUploads = 1; // At least 1 HSDir confirmation

            while (!uploadCts.IsCancellationRequested)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(uploadCts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (line is null) break;

                _logger?.Info($"[control-event] {line}", "Tor");

                // 650 HS_DESC UPLOADED <onion> <auth_type> <hsdir_id_digest>
                if (line.Contains("HS_DESC UPLOADED", StringComparison.OrdinalIgnoreCase))
                {
                    uploadCount++;
                    _logger?.Info($"Descriptor UPLOADED to HSDir ({uploadCount} confirmation(s))", "Tor");

                    if (uploadCount >= requiredUploads)
                    {
                        _logger?.Info("Hidden service descriptor confirmed on HSDir — globally reachable!", "Tor");

                        // Unsubscribe from events
                        try
                        {
                            await writer.WriteLineAsync("SETEVENTS");
                        }
                        catch { /* best effort */ }

                        return;
                    }
                }

                // Log failures but keep waiting for a success
                if (line.Contains("HS_DESC FAILED", StringComparison.OrdinalIgnoreCase))
                {
                    _logger?.Warn($"Descriptor upload FAILED to one HSDir: {line}", "Tor");
                }
            }

            if (uploadCount > 0)
            {
                _logger?.Info($"Descriptor uploaded to {uploadCount} HSDir node(s) before timeout", "Tor");
            }
            else
            {
                _logger?.Warn("No HS_DESC UPLOADED event received within 2 minutes — peers may not be able to reach us immediately", "Tor");
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            _logger?.Warn("Descriptor upload wait timed out — proceeding anyway", "Tor");
        }
        catch (Exception ex)
        {
            _logger?.Warn($"HS_DESC monitoring failed: {ex.Message} — waiting flat 30s for propagation", "Tor");
            try { await Task.Delay(30_000, ct); } catch { /* cancelled */ }
        }
        finally
        {
            controlClient?.Dispose();
        }
    }

    /// <summary>
    /// Hash control password using tor --hash-password command.
    /// </summary>
    private async Task<string?> HashControlPasswordAsync(string torExePath, string password, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = torExePath,
                Arguments = $"--hash-password \"{password}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(torExePath)!
            };

            using var proc = Process.Start(psi);
            if (proc is null) return null;

            var output = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            // The hash line starts with "16:"
            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("16:"))
                    return trimmed;
            }

            _logger?.Warn($"tor --hash-password output: {output}", "Tor");
            return null;
        }
        catch (Exception ex)
        {
            _logger?.Error("Failed to hash control password", ex, "Tor");
            return null;
        }
    }

    /// <summary>
    /// Generate torrc configuration file with filesystem-based HiddenServiceDir.
    /// This is more reliable than ADD_ONION because:
    /// 1. Tor manages the full HS lifecycle from startup
    /// 2. Descriptor publication starts as soon as circuits are available
    /// 3. Keys persist automatically in the directory
    /// </summary>
    private async Task WriteTorrcAsync(string torrcPath, string dataDir, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"SocksPort {SocksPort}");
        sb.AppendLine($"ControlPort {ControlPort}");
        sb.AppendLine($"HashedControlPassword {_hashedControlPassword}");
        sb.AppendLine($"DataDirectory {dataDir.Replace('\\', '/')}");

        // Filesystem-based Hidden Service — most reliable approach.
        // Tor creates keys, publishes descriptor, manages lifecycle automatically.
        sb.AppendLine($"HiddenServiceDir {_hiddenServiceDir!.Replace('\\', '/')}");
        sb.AppendLine($"HiddenServicePort {HiddenServiceVirtualPort} 127.0.0.1:{_localP2PPort}");

        // GeoIP files if they exist alongside tor.exe
        var torExePath = FindTorExecutable();
        if (torExePath is not null)
        {
            var torDir = Path.GetDirectoryName(torExePath)!;
            var geoip = Path.Combine(torDir, "geoip");
            var geoip6 = Path.Combine(torDir, "geoip6");
            if (File.Exists(geoip))
                sb.AppendLine($"GeoIPFile {geoip.Replace('\\', '/')}");
            if (File.Exists(geoip6))
                sb.AppendLine($"GeoIPv6File {geoip6.Replace('\\', '/')}");
        }

        sb.AppendLine("DisableNetwork 0");
        sb.AppendLine("Log notice stdout");
        sb.AppendLine("SafeLogging 1");

        await File.WriteAllTextAsync(torrcPath, sb.ToString(), ct);
    }

    /// <summary>
    /// Find Tor executable in order of priority:
    /// 1. Embedded binary alongside the application EXE
    /// 2. System Tor (in PATH)
    /// 3. Tor Browser (common install locations)
    /// 4. Previously placed in data directory
    /// </summary>
    private string? FindTorExecutable()
    {
        // 1. Check embedded binaries in app directory first (most reliable for distribution)
        var embeddedPaths = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "tor.exe"),
            Path.Combine(AppContext.BaseDirectory, "tor", "tor.exe"),
            Path.Combine(AppContext.BaseDirectory, "Resources", "tor", "tor.exe"),
            Path.Combine(Directory.GetCurrentDirectory(), "tor.exe"),
            Path.Combine(Directory.GetCurrentDirectory(), "tor", "tor.exe"),
        };

        foreach (var path in embeddedPaths)
        {
            if (File.Exists(path))
            {
                _logger?.Info($"Found embedded Tor at: {path}", "Tor");
                return path;
            }
        }

        // 2. Check PATH for tor.exe
        var pathTor = FindInPath("tor.exe");
        if (pathTor is not null)
        {
            _logger?.Info("Found Tor in system PATH", "Tor");
            return pathTor;
        }

        // 3. Check Tor Browser common locations
        var torBrowserPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
            @"C:\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            @"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            @"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
        };

        foreach (var path in torBrowserPaths)
        {
            if (File.Exists(path))
            {
                _logger?.Info($"Found Tor Browser at: {path}", "Tor");
                return path;
            }
        }

        // 4. Check data directory
        var dataPath = Path.Combine(_dataDirectory, "tor.exe");
        if (File.Exists(dataPath))
        {
            _logger?.Info($"Found Tor in data directory: {dataPath}", "Tor");
            return dataPath;
        }

        _logger?.Warn("Tor executable not found in any location", "Tor");
        return null;
    }

    /// <summary>
    /// Find executable in system PATH.
    /// </summary>
    private static string? FindInPath(string executable)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path)) return null;

        var paths = path.Split(Path.PathSeparator);
        foreach (var dir in paths)
        {
            var fullPath = Path.Combine(dir, executable);
            if (File.Exists(fullPath))
                return fullPath;
        }
        return null;
    }

    /// <summary>
    /// Force-kill the Tor process. Safe to call multiple times, even after disposal.
    /// </summary>
    public void ForceKillTorProcess()
    {
        // Kill tracked process
        if (_torProcess is not null)
        {
            try
            {
                if (!_torProcess.HasExited)
                {
                    _torProcess.Kill(entireProcessTree: true);
                    _torProcess.WaitForExit(3000);
                }
            }
            catch { /* already exited or access denied */ }
        }

        // Fallback: kill all stale tor processes from our directory
        KillStaleTorProcesses();
    }

    /// <summary>
    /// Kill stale Tor processes left from previous crashes.
    /// </summary>
    private void KillStaleTorProcesses()
    {
        try
        {
            foreach (var proc in Process.GetProcessesByName("tor"))
            {
                try
                {
                    var procPath = proc.MainModule?.FileName;
                    if (procPath is not null)
                    {
                        var appDir = AppContext.BaseDirectory;
                        if (procPath.StartsWith(appDir, StringComparison.OrdinalIgnoreCase) ||
                            procPath.StartsWith(_dataDirectory, StringComparison.OrdinalIgnoreCase))
                        {
                            proc.Kill();
                            proc.WaitForExit(5000);
                        }
                    }
                }
                catch { /* access denied or already exited */ }
            }
        }
        catch { /* best effort */ }
    }

    /// <summary>
    /// Wait for control port to accept connections.
    /// </summary>
    private async Task<bool> WaitForControlPortAsync(CancellationToken ct)
    {
        for (int i = 0; i < 30; i++)
        {
            try
            {
                using var testClient = new TcpClient();
                await testClient.ConnectAsync("127.0.0.1", ControlPort, ct);
                return true;
            }
            catch
            {
                await Task.Delay(1000, ct);
            }
        }
        return false;
    }

    /// <summary>
    /// Get a SOCKS5-configured HttpClient for Tor routing.
    /// </summary>
    public HttpClient CreateTorHttpClient()
    {
        if (!_isRunning)
            throw new InvalidOperationException("Tor is not running. Call StartAsync first.");

        var proxy = new System.Net.WebProxy($"socks5://127.0.0.1:{SocksPort}");
        var handler = new HttpClientHandler
        {
            Proxy = proxy,
            UseProxy = true
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(60)
        };
    }

    /// <summary>
    /// Get a configured SOCKS5 proxy endpoint for raw TCP connections.
    /// </summary>
    public System.Net.DnsEndPoint GetSocksEndpoint()
    {
        return new System.Net.DnsEndPoint("127.0.0.1", SocksPort);
    }

    /// <summary>
    /// Stop Tor process gracefully.
    /// </summary>
    public async Task StopAsync()
    {
        if (!_isRunning) return;

        _isRunning = false;
        OnionAddress = null;

        // Try graceful shutdown via control port first
        if (_controlPassword is not null)
        {
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", ControlPort);
                var stream = client.GetStream();
                using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };
                await writer.WriteLineAsync($"AUTHENTICATE \"{_controlPassword}\"");
                await Task.Delay(100);
                await writer.WriteLineAsync("SIGNAL SHUTDOWN");
                await Task.Delay(500);
            }
            catch { /* best effort */ }
        }

        ForceKillTorProcess();
        ConnectionStatusChanged?.Invoke(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;

        if (_isRunning)
        {
            await StopAsync();
        }

        _torProcess?.Dispose();
        _torProcess = null;

        ForceKillTorProcess();
    }
}
