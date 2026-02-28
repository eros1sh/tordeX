namespace TordeX.Core.Models;

/// <summary>
/// A blocked user identified by their cryptographic fingerprint.
/// </summary>
public sealed class BlockedUser
{
    public required string Fingerprint { get; init; }
    public string? DisplayName { get; set; }
    public DateTimeOffset BlockedAt { get; init; } = DateTimeOffset.UtcNow;
}
