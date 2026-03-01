using MessagePack;

namespace TordeX.Core.Models;

/// <summary>
/// P2P protocol message types.
/// </summary>
public enum P2PMessageType : byte
{
    Handshake = 0x01,
    HandshakeAck = 0x02,
    ChatMessage = 0x10,
    FileChunk = 0x11,
    FileComplete = 0x12,
    PeerAnnounce = 0x20,
    PeerDiscover = 0x21,
    Heartbeat = 0x30,
    RoomJoin = 0x40,
    RoomLeave = 0x41,

    // New protocol messages
    MessageEdit = 0x50,
    MessageDelete = 0x51,
    MessagePin = 0x52,
    TypingIndicator = 0x60,
    ReadReceipt = 0x61,
    BlockUser = 0x70,

    // Extended features
    Reaction = 0x80,
    ViewOnceOpened = 0x81,
    VoipOffer = 0x90,
    VoipAnswer = 0x91,
    VoipIceCandidate = 0x92,
    VoipHangup = 0x93,
    ScreenShareStart = 0xA0,
    ScreenShareStop = 0xA1,
    KeyRotation = 0xB0,
    DeadDrop = 0xC0
}

/// <summary>
/// Wire-format message for P2P transport.
/// Serialized with MessagePack for compact binary encoding.
/// </summary>
[MessagePackObject]
public sealed class P2PMessage
{
    [Key(0)]
    public P2PMessageType Type { get; set; }

    [Key(1)]
    public required string MessageId { get; set; }

    [Key(2)]
    public required string RoomId { get; set; }

    [Key(3)]
    public required string SenderFingerprint { get; set; }

    [Key(4)]
    public required byte[] Payload { get; set; }

    [Key(5)]
    public required byte[] Signature { get; set; }

    [Key(6)]
    public required byte[] SenderPublicKey { get; set; }

    [Key(7)]
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>
/// Chat message payload for P2P transport.
/// Serialized inside the encrypted P2PMessage.Payload.
/// </summary>
[MessagePackObject]
public sealed class ChatMessagePayload
{
    [Key(0)] public string Id { get; set; } = string.Empty;
    [Key(1)] public string SenderFingerprint { get; set; } = string.Empty;
    [Key(2)] public string SenderDisplayName { get; set; } = string.Empty;
    [Key(3)] public int Type { get; set; }
    [Key(4)] public string Content { get; set; } = string.Empty;
    [Key(5)] public string? FileName { get; set; }
    [Key(6)] public long? FileSize { get; set; }
    [Key(7)] public string? MimeType { get; set; }
    [Key(8)] public long Timestamp { get; set; }
    [Key(9)] public string? ReplyToId { get; set; }
    [Key(10)] public string? ReplyToContent { get; set; }
    [Key(11)] public string? ReplyToSenderName { get; set; }
    [Key(12)] public int? SelfDestructSeconds { get; set; }
    [Key(13)] public double? VoiceDuration { get; set; }
}

/// <summary>
/// Handshake payload: exchanged during peer connection setup.
/// </summary>
[MessagePackObject]
public sealed class HandshakePayload
{
    [Key(0)]
    public required string ProtocolVersion { get; set; }

    [Key(1)]
    public required byte[] PublicKey { get; set; }

    [Key(2)]
    public required byte[] EphemeralPublicKey { get; set; }

    [Key(3)]
    public required string DisplayName { get; set; }

    [Key(4)]
    public required string RoomId { get; set; }

    /// <summary>
    /// Peer's .onion address for bidirectional discovery.
    /// Allows both sides to reconnect to each other.
    /// </summary>
    [Key(5)]
    public string? OnionAddress { get; set; }
}
