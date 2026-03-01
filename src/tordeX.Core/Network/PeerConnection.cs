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

    private bool _handshakeComplete;

    public string PeerFingerprint { get; private set; } = string.Empty;
    public string PeerDisplayName { get; private set; } = string.Empty;
    public byte[] PeerPublicKey { get; private set; } = [];
    public string? PeerOnionAddress { get; private set; }
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
    public async Task HandshakeAsync(IdentityManager identity, string displayName, string roomId,
        string? ourOnionAddress = null, CancellationToken ct = default)
    {
        if (!IsConnected || _stream is null)
            throw new InvalidOperationException("Not connected.");

        using var keyExchange = new KeyExchange();

        // Send our handshake (includes our .onion for bidirectional discovery)
        var handshakePayload = new HandshakePayload
        {
            ProtocolVersion = "tordeX/1.0",
            PublicKey = identity.PublicKey,
            EphemeralPublicKey = keyExchange.PublicKey,
            DisplayName = displayName,
            RoomId = roomId,
            OnionAddress = ourOnionAddress
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
        PeerOnionAddress = peerHandshake.OnionAddress;

        // Derive shared session key
        SessionKey = keyExchange.DeriveSharedSecret(peerHandshake.EphemeralPublicKey);
        _handshakeComplete = true;
    }

    /// <summary>
    /// Respond to an incoming handshake (for the listener side).
    /// Receives the peer's handshake first, then sends ours.
    /// Returns the room ID from the peer's handshake.
    /// </summary>
    public async Task<string> RespondToHandshakeAsync(IdentityManager identity, string displayName,
        string? ourOnionAddress = null, CancellationToken ct = default)
    {
        if (!IsConnected || _stream is null)
            throw new InvalidOperationException("Not connected.");

        // Receive peer's handshake first (they initiated)
        var peerMsg = await ReceiveRawAsync(ct);
        if (peerMsg is null || peerMsg.Type != P2PMessageType.Handshake)
            throw new InvalidOperationException("Invalid handshake from peer.");

        if (!IdentityManager.Verify(peerMsg.Payload, peerMsg.Signature, peerMsg.SenderPublicKey))
            throw new InvalidOperationException("Handshake signature verification failed.");

        var peerHandshake = MessagePackSerializer.Deserialize<HandshakePayload>(peerMsg.Payload);

        using var keyExchange = new KeyExchange();

        // Send our handshake response (includes our .onion for bidirectional discovery)
        var responsePayload = new HandshakePayload
        {
            ProtocolVersion = "tordeX/1.0",
            PublicKey = identity.PublicKey,
            EphemeralPublicKey = keyExchange.PublicKey,
            DisplayName = displayName,
            RoomId = peerHandshake.RoomId,
            OnionAddress = ourOnionAddress
        };

        var payloadBytes = MessagePackSerializer.Serialize(responsePayload);
        var signature = identity.Sign(payloadBytes);

        var responseMsg = new P2PMessage
        {
            Type = P2PMessageType.Handshake,
            MessageId = Guid.NewGuid().ToString("N"),
            RoomId = peerHandshake.RoomId,
            SenderFingerprint = IdentityManager.ComputeFingerprint(identity.PublicKey),
            Payload = payloadBytes,
            Signature = signature,
            SenderPublicKey = identity.PublicKey
        };

        await SendRawAsync(responseMsg, ct);

        // Set peer info
        PeerPublicKey = peerHandshake.PublicKey;
        PeerFingerprint = IdentityManager.ComputeFingerprint(PeerPublicKey);
        PeerDisplayName = peerHandshake.DisplayName;
        PeerOnionAddress = peerHandshake.OnionAddress;

        // Derive shared session key
        SessionKey = keyExchange.DeriveSharedSecret(peerHandshake.EphemeralPublicKey);
        _handshakeComplete = true;

        return peerHandshake.RoomId;
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

        // SECURITY FIX: CWE-319 — Encrypt transport with session key after handshake
        if (_handshakeComplete && SessionKey.Length > 0)
        {
            data = Cryptography.MessageEncryption.Encrypt(data, SessionKey);
        }

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

        // Protect against oversized messages (max 10 MB + encryption overhead)
        if (length <= 0 || length > 10 * 1024 * 1024 + 28)
            throw new InvalidOperationException($"Invalid message length: {length}");

        var buffer = new byte[length];
        bytesRead = await ReadExactAsync(_stream, buffer, length, ct);
        if (bytesRead < length) return null;

        // SECURITY FIX: CWE-319 — Decrypt transport with session key after handshake
        if (_handshakeComplete && SessionKey.Length > 0)
        {
            buffer = Cryptography.MessageEncryption.Decrypt(buffer, SessionKey);
        }

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
        // IMPORTANT: Use 127.0.0.1 explicitly (not localhost) to ensure IPv4
        try
        {
            await _client.ConnectAsync("127.0.0.1", _socksPort, ct);
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException($"Failed to connect to Tor SOCKS proxy at 127.0.0.1:{_socksPort}. Is Tor running? Error: {ex.Message}", ex);
        }
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

        // Read SOCKS5 connection response header (4 bytes: VER, REP, RSV, ATYP)
        var headerBuf = new byte[4];
        await ReadExactAsync(stream, headerBuf, 4, ct);

        if (headerBuf[1] != 0x00)
            throw new InvalidOperationException($"SOCKS5 connection failed with code: {headerBuf[1]}");

        // Read remaining bytes based on address type (ATYP)
        // SOCKS5 response: [VER, REP, RSV, ATYP, ADDR..., PORT(2 bytes)]
        int remainingBytes = headerBuf[3] switch
        {
            0x01 => 4 + 2,  // IPv4: 4 bytes addr + 2 bytes port
            0x04 => 16 + 2, // IPv6: 16 bytes addr + 2 bytes port
            0x03 => -1,     // Domain: need to read length byte first
            _ => throw new InvalidOperationException($"Unknown SOCKS5 address type: {headerBuf[3]}")
        };

        if (headerBuf[3] == 0x03)
        {
            // Domain type: read length byte first
            var lenBuf = new byte[1];
            await ReadExactAsync(stream, lenBuf, 1, ct);
            int domainLen = lenBuf[0];
            
            // Read domain + 2 bytes port
            var domainBuf = new byte[domainLen + 2];
            await ReadExactAsync(stream, domainBuf, domainLen + 2, ct);
            // domainBuf[0..domainLen] = domain, domainBuf[domainLen..domainLen+2] = port
        }
        else
        {
            // IPv4 or IPv6: read fixed-size address + port
            var addrBuf = new byte[remainingBytes];
            await ReadExactAsync(stream, addrBuf, remainingBytes, ct);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;

        var wasConnected = IsConnected;
        IsConnected = false;

        if (_stream is not null)
        {
            await _stream.DisposeAsync();
            _stream = null;
        }

        _client?.Dispose();
        _client = null;

        CryptographicOperations.ZeroMemory(SessionKey);

        // Fire Disconnected so P2PServer releases its semaphore slot
        if (wasConnected)
        {
            try { Disconnected?.Invoke(this); } catch { /* best effort */ }
        }
    }
}
