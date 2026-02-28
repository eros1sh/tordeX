namespace TordeX.Core.Models;

public enum MessageType
{
    Text = 0,
    Image = 1,
    File = 2,
    System = 3,
    Voice = 4,
    Video = 5
}

/// <summary>
/// Decrypted chat message (only exists in memory after decryption).
/// </summary>
public sealed class ChatMessage
{
    public required string Id { get; init; }
    public required string RoomId { get; init; }
    public required string SenderFingerprint { get; init; }
    public required string SenderDisplayName { get; init; }
    public required MessageType Type { get; set; }
    public required string Content { get; set; }
    public string? FileName { get; set; }
    public long? FileSize { get; set; }
    public string? MimeType { get; set; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public bool IsOwn { get; set; }

    // Reply support
    public string? ReplyToId { get; set; }
    public string? ReplyToContent { get; set; }
    public string? ReplyToSenderName { get; set; }

    // Edit support
    public DateTimeOffset? EditedAt { get; set; }

    // Delete support (soft delete)
    public bool IsDeleted { get; set; }

    // Self-destruct
    public int? SelfDestructSeconds { get; set; }
    public DateTimeOffset? SelfDestructAt { get; set; }

    // Pin support
    public bool IsPinned { get; set; }

    // Read receipt
    public bool IsDelivered { get; set; }
    public bool IsRead { get; set; }

    // Voice message duration (seconds)
    public double? VoiceDuration { get; set; }

    // View-once (disappears after first view)
    public bool IsViewOnce { get; set; }
    public DateTimeOffset? ViewedAt { get; set; }

    // Reactions (emoji -> list of sender fingerprints)
    public Dictionary<string, List<string>> Reactions { get; set; } = [];

    // Bookmarked locally
    public bool IsBookmarked { get; set; }
}

/// <summary>
/// Encrypted message as stored/transmitted.
/// Wire format for P2P transport.
/// </summary>
public sealed class EncryptedEnvelope
{
    public required string Id { get; init; }
    public required string RoomId { get; init; }
    public required string SenderFingerprint { get; init; }
    public required byte[] EncryptedPayload { get; init; }
    public required byte[] Signature { get; init; }
    public required byte[] SenderPublicKey { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}
