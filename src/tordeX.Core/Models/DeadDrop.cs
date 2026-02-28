namespace TordeX.Core.Models;

/// <summary>
/// A dead drop message — async message exchange via hidden service.
/// The sender leaves an encrypted message at a "drop point" (onion address).
/// The receiver picks it up later without needing to be online simultaneously.
/// </summary>
public sealed class DeadDrop
{
    public required string Id { get; init; }
    public required string DropAddress { get; init; }  // onion address or identifier
    public required string SenderFingerprint { get; init; }
    public required string RecipientFingerprint { get; init; }
    public required byte[] EncryptedPayload { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ExpiresAt { get; init; }
    public bool IsPickedUp { get; set; }
    public DateTimeOffset? PickedUpAt { get; set; }
}
