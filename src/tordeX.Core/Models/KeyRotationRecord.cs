namespace TordeX.Core.Models;

/// <summary>
/// Tracks key rotation events for forward secrecy.
/// Each rotation generates new ephemeral keys for a room.
/// </summary>
public sealed class KeyRotationRecord
{
    public required string Id { get; init; }
    public required string RoomId { get; init; }
    public required byte[] OldPublicKey { get; init; }
    public required byte[] NewPublicKey { get; init; }
    public required int RotationNumber { get; init; }
    public DateTimeOffset RotatedAt { get; init; } = DateTimeOffset.UtcNow;
    public string? InitiatorFingerprint { get; init; }
}
