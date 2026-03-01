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
    private Task? _acceptTask;
    private readonly int _listenPort;
    private readonly int _socksPort;
    private bool _disposed;
    private bool _isRunning;

    // Rate limiting: max concurrent connection handshakes
    private const int MaxConcurrentConnections = 50;
    private readonly SemaphoreSlim _connectionSemaphore = new(MaxConcurrentConnections, MaxConcurrentConnections);

    public int ListenPort => _listenPort;
    public bool IsRunning => _isRunning;

    public event Action<PeerConnection>? PeerConnected;

    /// <summary>
    /// Fired when the accept loop encounters a fatal error after startup.
    /// </summary>
    public event Action<Exception>? AcceptLoopFailed;

    public P2PServer(int listenPort, int socksPort)
    {
        _listenPort = listenPort;
        _socksPort = socksPort;
    }

    /// <summary>
    /// Start accepting incoming peer connections.
    /// </summary>
    public Task StartAsync(CancellationToken ct = default)
    {
        if (_isRunning) return Task.CompletedTask;

        // Listen on all interfaces to accept connections from Tor (which connects via 127.0.0.1)
        // but also allow external connections if they somehow route through Tor
        _listener = new TcpListener(IPAddress.Any, _listenPort);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start();
        _isRunning = true;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        // Store task reference for error observation — fire callback on failure
        _acceptTask = AcceptLoopAsync(_cts.Token);
        _acceptTask.ContinueWith(t =>
        {
            if (t.IsFaulted && t.Exception is not null)
            {
                _isRunning = false;
                AcceptLoopFailed?.Invoke(t.Exception.InnerException ?? t.Exception);
            }
        }, TaskContinuationOptions.OnlyOnFaulted);

        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _listener is not null)
            {
                var client = await _listener.AcceptTcpClientAsync(ct);

                // Rate limit: reject connections when at capacity
                if (!_connectionSemaphore.Wait(0))
                {
                    // At max capacity — reject immediately
                    client.Dispose();
                    continue;
                }

                var peer = new PeerConnection(client, _socksPort);

                // Release semaphore when peer disconnects
                peer.Disconnected += _ =>
                {
                    try { _connectionSemaphore.Release(); }
                    catch (ObjectDisposedException) { /* server already disposed */ }
                };

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
        catch (SocketException ex)
        {
            // Socket-level failure in accept loop — propagate via event
            _isRunning = false;
            AcceptLoopFailed?.Invoke(ex);
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
        _connectionSemaphore.Dispose();
    }
}
