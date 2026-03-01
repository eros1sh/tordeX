namespace TordeX.Core.Models;

/// <summary>
/// Represents a chat room. Access is controlled by room password.
/// Room key is derived from password — no password, no access.
/// </summary>
public sealed class ChatRoom
{
    public required string Id { get; init; }
    public required string Name { get; set; }
    public required byte[] RoomSalt { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastActivityAt { get; set; } = DateTimeOffset.UtcNow;
    public int UnreadCount { get; set; }

    // Room description
    public string? Description { get; set; }

    // Room capacity (0 = unlimited)
    public int MaxCapacity { get; set; }

    // Invite token for shareable invite links
    public string? InviteToken { get; set; }

    // Onion address for P2P hosting
    public string? OnionAddress { get; set; }

    // Direct Message fields
    public bool IsDm { get; set; }
    public string? PeerFingerprint { get; set; }

    /// <summary>
    /// Known peers in this room (public key fingerprints).
    /// </summary>
    public List<RoomPeer> Peers { get; set; } = [];
}

public sealed class RoomPeer
{
    public required string Fingerprint { get; init; }
    public required string DisplayName { get; set; }
    public required byte[] PublicKey { get; init; }
    public DateTimeOffset LastSeenAt { get; set; } = DateTimeOffset.UtcNow;
    public bool IsOnline { get; set; }
    public bool IsTyping { get; set; }
}
