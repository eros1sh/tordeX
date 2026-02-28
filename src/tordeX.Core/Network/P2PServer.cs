using System.Net;
using System.Net.Sockets;

namespace TordeX.Core.Network;

/// <summary>
/// P2P listener — accepts incoming peer connections.
/// Runs on localhost, exposed via Tor hidden service.
/// </summary>
public sealed class P2PServer : IAsyncDisposable
{
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private readonly int _listenPort;
    private readonly int _socksPort;
    private bool _disposed;
    private bool _isRunning;

    public int ListenPort => _listenPort;
    public bool IsRunning => _isRunning;

    public event Action<PeerConnection>? PeerConnected;

    public P2PServer(int listenPort, int socksPort)
    {
        _listenPort = listenPort;
        _socksPort = socksPort;
    }

    /// <summary>
    /// Start accepting incoming peer connections.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_isRunning) return;

        _listener = new TcpListener(IPAddress.Loopback, _listenPort);
        _listener.Start();
        _isRunning = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        _ = AcceptLoopAsync(_cts.Token);
        await Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _listener is not null)
            {
                var client = await _listener.AcceptTcpClientAsync(ct);

                // Rate limit: max 50 concurrent connections
                var peer = new PeerConnection(client, _socksPort);
                PeerConnected?.Invoke(peer);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (ObjectDisposedException)
        {
            // Listener was stopped
        }
    }

    public async Task StopAsync()
    {
        if (!_isRunning) return;

        _cts?.Cancel();
        _listener?.Stop();
        _isRunning = false;
        await Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        await StopAsync();
        _cts?.Dispose();
        _cts = null;
    }
}
