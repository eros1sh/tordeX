using System.Net.Sockets;
using System.Text;
using Knapcode.TorSharp;

namespace TordeX.Core.Network;

/// <summary>
/// Manages embedded Tor process lifecycle.
/// Provides SOCKS5 proxy for all P2P connections.
/// Creates ephemeral hidden services via Tor control port.
/// </summary>
public sealed class TorManager : IAsyncDisposable
{
    private TorSharpProxy? _proxy;
    private readonly string _dataDirectory;
    private string? _controlPassword;
    private bool _disposed;
    private bool _isRunning;

    public int SocksPort { get; private set; } = 9050;
    public int ControlPort { get; private set; } = 9051;
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Onion address of our hidden service (set after CreateHiddenServiceAsync).
    /// </summary>
    public string? OnionAddress { get; private set; }

    /// <summary>
    /// Event fired when Tor connection status changes.
    /// </summary>
    public event Action<bool>? ConnectionStatusChanged;

    public TorManager(string dataDirectory)
    {
        _dataDirectory = dataDirectory;
    }

    /// <summary>
    /// Start embedded Tor proxy.
    /// Downloads Tor binaries if not present.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_isRunning) return;

        _controlPassword = Cryptography.SecureRandom.GenerateHex(16);

        var settings = new TorSharpSettings
        {
            ZippedToolsDirectory = Path.Combine(_dataDirectory, "tor-zipped"),
            ExtractedToolsDirectory = Path.Combine(_dataDirectory, "tor-extracted"),
            ToolRunnerType = ToolRunnerType.Simple, // No console window — runs silently in background
            PrivoxySettings = { Disable = true }, // We only need Tor SOCKS, not Privoxy
            TorSettings =
            {
                SocksPort = SocksPort,
                ControlPort = ControlPort,
                ControlPassword = _controlPassword
            }
        };

        // Download Tor binaries if needed
        try
        {
            using var httpClient = new HttpClient();
            var fetcher = new TorSharpToolFetcher(settings, httpClient);
            var updates = await fetcher.CheckForUpdatesAsync();

            if (updates.HasUpdate)
            {
                await fetcher.FetchAsync(updates);
            }
        }
        catch (Exception ex)
        {
            // If download fails, try to use existing binaries
            System.Diagnostics.Debug.WriteLine($"Tor download failed, trying existing: {ex.Message}");
        }

        _proxy = new TorSharpProxy(settings);
        await _proxy.ConfigureAndStartAsync();
        _isRunning = true;
        ConnectionStatusChanged?.Invoke(true);
    }

    /// <summary>
    /// Create an ephemeral Tor hidden service via control port ADD_ONION.
    /// The hidden service maps the given port to 127.0.0.1:localPort.
    /// </summary>
    public async Task CreateHiddenServiceAsync(int localPort, CancellationToken ct = default)
    {
        if (!_isRunning || _controlPassword is null)
            throw new InvalidOperationException("Tor is not running.");

        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", ControlPort, ct);
        var stream = client.GetStream();
        stream.ReadTimeout = 10_000;
        stream.WriteTimeout = 10_000;

        using var reader = new StreamReader(stream, Encoding.ASCII);
        using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

        // Authenticate with control port
        await writer.WriteLineAsync($"AUTHENTICATE \"{_controlPassword}\"");
        var authResponse = await reader.ReadLineAsync(ct);
        if (authResponse is null || !authResponse.StartsWith("250"))
            throw new InvalidOperationException($"Tor control auth failed: {authResponse}");

        // Create ephemeral hidden service
        // ADD_ONION creates an in-memory hidden service that disappears when Tor stops
        await writer.WriteLineAsync($"ADD_ONION NEW:BEST Port={localPort},127.0.0.1:{localPort}");

        // Parse multi-line response
        string? serviceId = null;
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            if (line.StartsWith("250-ServiceID="))
                serviceId = line["250-ServiceID=".Length..].Trim();
            if (line.StartsWith("250 "))
                break;
        }

        if (serviceId is null)
            throw new InvalidOperationException("Failed to create Tor hidden service.");

        OnionAddress = $"{serviceId}.onion";
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
    /// Stop Tor proxy gracefully.
    /// </summary>
    public async Task StopAsync()
    {
        if (!_isRunning || _proxy is null) return;

        _proxy.Stop();
        _isRunning = false;
        OnionAddress = null;
        ConnectionStatusChanged?.Invoke(false);
        await Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_isRunning)
        {
            await StopAsync();
        }

        _proxy?.Dispose();
        _proxy = null;
    }
}
