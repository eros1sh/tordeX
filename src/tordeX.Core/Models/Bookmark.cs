namespace TordeX.Core.Models;

/// <summary>
/// A locally saved message bookmark.
/// </summary>
public sealed class Bookmark
{
    public required string MessageId { get; init; }
    public required string RoomId { get; init; }
    public required string RoomName { get; init; }
    public required string SenderName { get; init; }
    public required string ContentPreview { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}
