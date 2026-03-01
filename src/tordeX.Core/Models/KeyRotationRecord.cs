namespace TordeX.Core.Models;

/// <summary>
/// Tracks key rotation events for forward secrecy.
/// Stores SHA-256 hashes of keys instead of raw key material.
/// </summary>
public sealed class KeyRotationRecord
{
    public required string Id { get; init; }
    public required string RoomId { get; init; }

    /// <summary>SHA-256 hash of the old room key (never store raw key material).</summary>
    public required byte[] OldKeyHash { get; init; }

    /// <summary>SHA-256 hash of the new room key (never store raw key material).</summary>
    public required byte[] NewKeyHash { get; init; }

    public required int RotationNumber { get; init; }
    public DateTimeOffset RotatedAt { get; init; } = DateTimeOffset.UtcNow;
    public string? InitiatorFingerprint { get; init; }
}
