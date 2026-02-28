using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using MessagePack;
using TordeX.Core.Cryptography;
using TordeX.Core.Models;

namespace TordeX.Core.Network;

/// <summary>
/// Represents a single P2P connection to a remote peer.
/// All traffic is routed through Tor SOCKS5 proxy.
/// </summary>
public sealed class PeerConnection : IAsyncDisposable
{
    private TcpClient? _client;
    private NetworkStream? _stream;
    private readonly string _peerAddress;
    private readonly int _peerPort;
    private readonly int _socksPort;
    private bool _disposed;
    private CancellationTokenSource? _cts;

    public string PeerFingerprint { get; private set; } = string.Empty;
    public string PeerDisplayName { get; private set; } = string.Empty;
    public byte[] PeerPublicKey { get; private set; } = [];
    public bool IsConnected { get; private set; }
    public byte[] SessionKey { get; private set; } = [];

    public event Action<P2PMessage>? MessageReceived;
    public event Action<PeerConnection>? Disconnected;

    public PeerConnection(string peerAddress, int peerPort, int socksPort)
    {
        _peerAddress = peerAddress;
        _peerPort = peerPort;
        _socksPort = socksPort;
    }

    /// <summary>
    /// For incoming connections (already connected TcpClient).
    /// </summary>
    public PeerConnection(TcpClient client, int socksPort)
    {
        _client = client;
        _stream = client.GetStream();
        _peerAddress = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();
        _peerPort = ((IPEndPoint)client.Client.RemoteEndPoint!).Port;
        _socksPort = socksPort;
        IsConnected = true;
    }

    /// <summary>
    /// Connect to peer through Tor SOCKS5 proxy.
    /// </summary>
    public async Task ConnectAsync(CancellationToken ct = default)
    {
        if (IsConnected) return;

        _client = new TcpClient();

        // Connect through SOCKS5 proxy (Tor)
        await ConnectViaSocks5Async(_peerAddress, _peerPort, ct);

        _stream = _client.GetStream();
        IsConnected = true;
    }

    /// <summary>
    /// Perform key exchange handshake with peer.
    /// </summary>
    public async Task HandshakeAsync(IdentityManager identity, string displayName, string roomId, CancellationToken ct = default)
    {
        if (!IsConnected || _stream is null)
            throw new InvalidOperationException("Not connected.");

        using var keyExchange = new KeyExchange();

        // Send our handshake
        var handshakePayload = new HandshakePayload
        {
            ProtocolVersion = "tordeX/1.0",
            PublicKey = identity.PublicKey,
            EphemeralPublicKey = keyExchange.PublicKey,
            DisplayName = displayName,
            RoomId = roomId
        };

        var payloadBytes = MessagePackSerializer.Serialize(handshakePayload);
        var signature = identity.Sign(payloadBytes);

        var handshakeMsg = new P2PMessage
        {
            Type = P2PMessageType.Handshake,
            MessageId = Guid.NewGuid().ToString("N"),
            RoomId = roomId,
            SenderFingerprint = IdentityManager.ComputeFingerprint(identity.PublicKey),
            Payload = payloadBytes,
            Signature = signature,
            SenderPublicKey = identity.PublicKey
        };

        await SendRawAsync(handshakeMsg, ct);

        // Receive peer's handshake
        var peerMsg = await ReceiveRawAsync(ct);
        if (peerMsg is null || peerMsg.Type != P2PMessageType.Handshake)
            throw new InvalidOperationException("Invalid handshake response.");

        // Verify peer's signature
        if (!IdentityManager.Verify(peerMsg.Payload, peerMsg.Signature, peerMsg.SenderPublicKey))
            throw new InvalidOperationException("Handshake signature verification failed.");

        var peerHandshake = MessagePackSerializer.Deserialize<HandshakePayload>(peerMsg.Payload);

        PeerPublicKey = peerHandshake.PublicKey;
        PeerFingerprint = IdentityManager.ComputeFingerprint(PeerPublicKey);
        PeerDisplayName = peerHandshake.DisplayName;

        // Derive shared session key
        SessionKey = keyExchange.DeriveSharedSecret(peerHandshake.EphemeralPublicKey);
    }

    /// <summary>
    /// Send an encrypted P2P message.
    /// </summary>
    public async Task SendMessageAsync(P2PMessage message, CancellationToken ct = default)
    {
        if (!IsConnected || _stream is null)
            throw new InvalidOperationException("Not connected.");

        await SendRawAsync(message, ct);
    }

    /// <summary>
    /// Start listening for incoming messages.
    /// </summary>
    public void StartReceiving()
    {
        _cts = new CancellationTokenSource();
        _ = ReceiveLoopAsync(_cts.Token);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && IsConnected)
            {
                var msg = await ReceiveRawAsync(ct);
                if (msg is null)
                {
                    IsConnected = false;
                    Disconnected?.Invoke(this);
                    break;
                }

                if (msg.Type == P2PMessageType.Heartbeat)
                    continue;

                MessageReceived?.Invoke(msg);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception)
        {
            IsConnected = false;
            Disconnected?.Invoke(this);
        }
    }

    private async Task SendRawAsync(P2PMessage message, CancellationToken ct)
    {
        if (_stream is null) return;

        var data = MessagePackSerializer.Serialize(message);

        // Length-prefixed framing: [4-byte big-endian length][payload]
        var lengthPrefix = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(data.Length));
        await _stream.WriteAsync(lengthPrefix, ct);
        await _stream.WriteAsync(data, ct);
        await _stream.FlushAsync(ct);
    }

    private async Task<P2PMessage?> ReceiveRawAsync(CancellationToken ct)
    {
        if (_stream is null) return null;

        // Read length prefix
        var lengthBuffer = new byte[4];
        var bytesRead = await ReadExactAsync(_stream, lengthBuffer, 4, ct);
        if (bytesRead < 4) return null;

        var length = System.Net.IPAddress.NetworkToHostOrder(BitConverter.ToInt32(lengthBuffer, 0));

        // Protect against oversized messages (max 10 MB)
        if (length <= 0 || length > 10 * 1024 * 1024)
            throw new InvalidOperationException($"Invalid message length: {length}");

        var buffer = new byte[length];
        bytesRead = await ReadExactAsync(_stream, buffer, length, ct);
        if (bytesRead < length) return null;

        return MessagePackSerializer.Deserialize<P2PMessage>(buffer);
    }

    private static async Task<int> ReadExactAsync(NetworkStream stream, byte[] buffer, int count, CancellationToken ct)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, count - totalRead), ct);
            if (read == 0) return totalRead; // Connection closed
            totalRead += read;
        }
        return totalRead;
    }

    /// <summary>
    /// SOCKS5 proxy connection through Tor.
    /// </summary>
    private async Task ConnectViaSocks5Async(string targetHost, int targetPort, CancellationToken ct)
    {
        if (_client is null) throw new InvalidOperationException("TcpClient not created.");

        // Connect to Tor SOCKS5 proxy
        await _client.ConnectAsync("127.0.0.1", _socksPort, ct);
        var stream = _client.GetStream();

        // SOCKS5 greeting: version + auth methods
        var greeting = new byte[] { 0x05, 0x01, 0x00 }; // Version 5, 1 method, No auth
        await stream.WriteAsync(greeting, ct);

        // Read response
        var response = new byte[2];
        await ReadExactAsync(stream, response, 2, ct);
        if (response[0] != 0x05 || response[1] != 0x00)
            throw new InvalidOperationException("SOCKS5 proxy auth failed.");

        // Connection request
        var hostBytes = System.Text.Encoding.ASCII.GetBytes(targetHost);
        var request = new byte[4 + 1 + hostBytes.Length + 2];
        request[0] = 0x05; // Version
        request[1] = 0x01; // Connect
        request[2] = 0x00; // Reserved
        request[3] = 0x03; // Domain name
        request[4] = (byte)hostBytes.Length;
        Buffer.BlockCopy(hostBytes, 0, request, 5, hostBytes.Length);

        // Port in big-endian
        request[^2] = (byte)(targetPort >> 8);
        request[^1] = (byte)(targetPort & 0xFF);

        await stream.WriteAsync(request, ct);

        // Read connection response (at least 10 bytes)
        var connResponse = new byte[10];
        await ReadExactAsync(stream, connResponse, 10, ct);

        if (connResponse[1] != 0x00)
            throw new InvalidOperationException($"SOCKS5 connection failed with code: {connResponse[1]}");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        IsConnected = false;

        if (_stream is not null)
        {
            await _stream.DisposeAsync();
            _stream = null;
        }

        _client?.Dispose();
        _client = null;

        CryptographicOperations.ZeroMemory(SessionKey);
    }
}
