namespace TordeX.Core.Models;

/// <summary>
/// Represents a Tor circuit with its relay hops.
/// </summary>
public sealed class TorCircuitInfo
{
    public required string CircuitId { get; init; }
    public required List<TorRelay> Relays { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public bool IsActive { get; set; } = true;
}

public sealed class TorRelay
{
    public required string Nickname { get; init; }
    public required string IpAddress { get; init; }
    public required string Country { get; init; }
    public required string CountryCode { get; init; }
    public required string Fingerprint { get; init; }
    public int Bandwidth { get; init; }
    public bool IsGuard { get; init; }
    public bool IsExit { get; init; }
}
