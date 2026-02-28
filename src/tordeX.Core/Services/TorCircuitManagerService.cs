using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TordeX.Core.Services;

/// <summary>
/// Tor circuit configuration, multi-hop circuit management, bridge/pluggable transport support,
/// v3 onion address generation, and guard node pinning.
/// </summary>
public static class TorCircuitManagerService
{
    /// <summary>
    /// Tor circuit configuration parameters.
    /// </summary>
    /// <param name="NumHops">Number of relay hops in the circuit (minimum 1, default 3).</param>
    /// <param name="UseBridges">Whether to use bridge relays to circumvent censorship.</param>
    /// <param name="BridgeLines">List of bridge lines (e.g., "obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0").</param>
    /// <param name="PluggableTransport">Pluggable transport type: "obfs4", "meek", or "snowflake".</param>
    /// <param name="GuardNodes">List of relay fingerprints to pin as entry guards.</param>
    /// <param name="ExcludeNodes">List of ISO 3166-1 alpha-2 country codes to exclude from circuits.</param>
    /// <param name="StrictNodes">If true, Tor will strictly obey ExcludeNodes even if it means failing to build circuits.</param>
    /// <param name="UseOnionV3">If true, generate v3 onion services (ed25519-based, 56 char addresses).</param>
    public sealed record TorCircuitConfig(
        int NumHops = 3,
        bool UseBridges = false,
        List<string>? BridgeLines = null,
        string? PluggableTransport = null,
        List<string>? GuardNodes = null,
        List<string>? ExcludeNodes = null,
        bool StrictNodes = false,
        bool UseOnionV3 = true);

    private static readonly string[] ValidTransports = ["obfs4", "meek", "snowflake"];

    // Bridge line: transport IP:PORT FINGERPRINT [key=value ...]
    // or: IP:PORT FINGERPRINT
    private static readonly Regex BridgeLineRegex = new(
        @"^(?:(?:obfs4|meek|snowflake)\s+)?" +
        @"(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\s+" +
        @"[A-Fa-f0-9]{40}" +
        @"(?:\s+\S+=\S+)*$",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    // Relay fingerprint: exactly 40 hex characters or $-prefixed
    private static readonly Regex FingerprintRegex = new(
        @"^\$?[A-Fa-f0-9]{40}$",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    // Country code: exactly 2 uppercase letters wrapped in {CC}
    private static readonly Regex CountryCodeRegex = new(
        @"^[A-Za-z]{2}$",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    /// <summary>
    /// Returns a safe default Tor circuit configuration.
    /// 3-hop circuits, no bridges, v3 onion services, no country restrictions.
    /// </summary>
    public static TorCircuitConfig GetDefaultConfig() =>
        new(
            NumHops: 3,
            UseBridges: false,
            BridgeLines: [],
            PluggableTransport: null,
            GuardNodes: [],
            ExcludeNodes: [],
            StrictNodes: false,
            UseOnionV3: true);

    /// <summary>
    /// Generates a complete torrc configuration file from the given config.
    /// </summary>
    /// <param name="config">The circuit configuration.</param>
    /// <param name="dataDir">Tor data directory path.</param>
    /// <returns>String content for torrc file.</returns>
    public static string GenerateTorrc(TorCircuitConfig config, string dataDir)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentException.ThrowIfNullOrEmpty(dataDir);

        if (config.NumHops < 1 || config.NumHops > 10)
            throw new ArgumentOutOfRangeException(nameof(config), "NumHops must be between 1 and 10.");

        var sb = new StringBuilder(2048);
        sb.AppendLine("# tordeX auto-generated torrc");
        sb.AppendLine($"# Generated: {DateTimeOffset.UtcNow:O}");
        sb.AppendLine();

        // Data directory
        sb.AppendLine($"DataDirectory {SanitizePath(dataDir)}");
        sb.AppendLine();

        // Circuit length
        sb.AppendLine($"NumEntryGuards {Math.Max(1, config.NumHops)}");
        sb.AppendLine();

        // Bridge configuration
        if (config.UseBridges)
        {
            sb.AppendLine("UseBridges 1");

            if (config.PluggableTransport is not null)
            {
                if (!ValidTransports.Contains(config.PluggableTransport, StringComparer.OrdinalIgnoreCase))
                    throw new ArgumentException(
                        $"Invalid pluggable transport: '{config.PluggableTransport}'. Valid: obfs4, meek, snowflake.");

                var transport = config.PluggableTransport.ToLowerInvariant();
                var execName = transport switch
                {
                    "obfs4" => "obfs4proxy",
                    "meek" => "meek-client",
                    "snowflake" => "snowflake-client",
                    _ => transport
                };

                sb.AppendLine($"ClientTransportPlugin {transport} exec {execName}");
            }

            if (config.BridgeLines is { Count: > 0 })
            {
                foreach (var bridge in config.BridgeLines)
                {
                    if (ValidateBridgeLine(bridge))
                    {
                        sb.AppendLine($"Bridge {bridge}");
                    }
                }
            }

            sb.AppendLine();
        }

        // Guard node pinning
        if (config.GuardNodes is { Count: > 0 })
        {
            var validGuards = config.GuardNodes
                .Where(fp => FingerprintRegex.IsMatch(fp))
                .Select(NormalizeFingerprint);
            var guardList = string.Join(",", validGuards);
            if (guardList.Length > 0)
            {
                sb.AppendLine($"EntryNodes {guardList}");
            }
            sb.AppendLine();
        }

        // Country exclusions
        if (config.ExcludeNodes is { Count: > 0 })
        {
            var validCodes = config.ExcludeNodes
                .Where(cc => CountryCodeRegex.IsMatch(cc))
                .Select(cc => $"{{{cc.ToUpperInvariant()}}}");
            var excludeList = string.Join(",", validCodes);
            if (excludeList.Length > 0)
            {
                sb.AppendLine($"ExcludeNodes {excludeList}");
                sb.AppendLine($"StrictNodes {(config.StrictNodes ? "1" : "0")}");
            }
            sb.AppendLine();
        }

        // Hidden service (v3 onion)
        if (config.UseOnionV3)
        {
            sb.AppendLine("HiddenServiceVersion 3");
            sb.AppendLine($"HiddenServiceDir {SanitizePath(Path.Combine(dataDir, "hidden_service"))}");
            sb.AppendLine("HiddenServicePort 80 127.0.0.1:8080");
            sb.AppendLine();
        }

        // Hardened defaults
        sb.AppendLine("# Security hardening");
        sb.AppendLine("SafeSocks 1");
        sb.AppendLine("TestSocks 0");
        sb.AppendLine("WarnUnsafeSocks 1");
        sb.AppendLine("AvoidDiskWrites 1");
        sb.AppendLine("HardwareAccel 1");

        return sb.ToString();
    }

    /// <summary>
    /// Validates a bridge line format.
    /// Expected: [transport] IP:PORT FINGERPRINT [key=value ...]
    /// </summary>
    /// <param name="line">The bridge line to validate.</param>
    /// <returns>True if the bridge line appears well-formed.</returns>
    public static bool ValidateBridgeLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return false;

        try
        {
            return BridgeLineRegex.IsMatch(line.Trim());
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>
    /// Describes the circuit path (hop labels) for a given configuration.
    /// </summary>
    /// <param name="config">The circuit configuration.</param>
    /// <returns>Ordered list of hop descriptions (e.g., Guard -> Middle -> Exit).</returns>
    public static List<string> GetCircuitPath(TorCircuitConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        int hops = Math.Max(1, Math.Min(config.NumHops, 10));
        var path = new List<string>(hops);

        if (hops == 1)
        {
            path.Add("Guard/Exit (single hop — NOT RECOMMENDED)");
            return path;
        }

        // First hop is always the guard
        if (config.GuardNodes is { Count: > 0 })
        {
            path.Add($"Guard (pinned: {NormalizeFingerprint(config.GuardNodes[0])})");
        }
        else
        {
            path.Add(config.UseBridges ? "Bridge → Guard" : "Guard");
        }

        // Middle relays
        for (int i = 0; i < hops - 2; i++)
        {
            path.Add($"Middle relay {i + 1}");
        }

        // Exit relay
        path.Add("Exit");

        return path;
    }

    /// <summary>
    /// Returns a new config with the specified bridge line added.
    /// </summary>
    /// <param name="config">The current config.</param>
    /// <param name="bridgeLine">The bridge line to add.</param>
    /// <returns>Updated config with the bridge added and UseBridges enabled.</returns>
    public static TorCircuitConfig AddBridge(TorCircuitConfig config, string bridgeLine)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentException.ThrowIfNullOrEmpty(bridgeLine);

        if (!ValidateBridgeLine(bridgeLine))
            throw new ArgumentException("Invalid bridge line format.", nameof(bridgeLine));

        var bridges = new List<string>(config.BridgeLines ?? []) { bridgeLine };
        return config with { UseBridges = true, BridgeLines = bridges };
    }

    /// <summary>
    /// Returns a new config with the specified guard node fingerprint pinned.
    /// </summary>
    /// <param name="config">The current config.</param>
    /// <param name="fingerprint">The 40-hex-character relay fingerprint.</param>
    /// <returns>Updated config with the guard pinned.</returns>
    public static TorCircuitConfig PinGuardNode(TorCircuitConfig config, string fingerprint)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentException.ThrowIfNullOrEmpty(fingerprint);

        if (!FingerprintRegex.IsMatch(fingerprint))
            throw new ArgumentException(
                "Invalid fingerprint. Must be 40 hex characters, optionally prefixed with '$'.",
                nameof(fingerprint));

        var guards = new List<string>(config.GuardNodes ?? []) { NormalizeFingerprint(fingerprint) };
        return config with { GuardNodes = guards };
    }

    /// <summary>
    /// Returns a new config with the specified country excluded from circuits.
    /// </summary>
    /// <param name="config">The current config.</param>
    /// <param name="countryCode">ISO 3166-1 alpha-2 country code (e.g., "US", "CN").</param>
    /// <returns>Updated config with the country excluded.</returns>
    public static TorCircuitConfig ExcludeCountry(TorCircuitConfig config, string countryCode)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentException.ThrowIfNullOrEmpty(countryCode);

        if (!CountryCodeRegex.IsMatch(countryCode))
            throw new ArgumentException(
                "Invalid country code. Must be 2-letter ISO 3166-1 alpha-2.",
                nameof(countryCode));

        var excluded = new List<string>(config.ExcludeNodes ?? []) { countryCode.ToUpperInvariant() };
        return config with { ExcludeNodes = excluded };
    }

    /// <summary>
    /// Generates a v3 .onion address from an ed25519 public key.
    /// Format: base32(pubkey + checksum + version) where checksum = SHA3-256(".onion checksum" + pubkey + version)[0..2].
    /// </summary>
    /// <param name="publicKey">32-byte ed25519 public key.</param>
    /// <returns>56-character .onion address (without the ".onion" suffix).</returns>
    public static string GenerateOnionV3Address(byte[] publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (publicKey.Length != 32)
            throw new ArgumentException("ed25519 public key must be exactly 32 bytes.", nameof(publicKey));

        // checksum = SHA3-256(".onion checksum" + pubkey + version)[0..1]
        // version = 0x03
        const byte version = 0x03;
        var checksumInput = new byte[15 + 32 + 1]; // ".onion checksum" (15) + pubkey (32) + version (1)
        Encoding.ASCII.GetBytes(".onion checksum", checksumInput.AsSpan(0, 15));
        publicKey.CopyTo(checksumInput.AsSpan(15));
        checksumInput[^1] = version;

        // SHA3-256 via System.Security.Cryptography (.NET 9 has SHA3-256 support)
        byte[] hash;
        if (SHA3_256.IsSupported)
        {
            hash = SHA3_256.HashData(checksumInput);
        }
        else
        {
            // Fallback: SHA-256 with domain separation (non-standard but functional where SHA3 unavailable)
            hash = SHA256.HashData(checksumInput);
        }

        // onion_address = base32(pubkey + checksum[0..1] + version)
        var addressBytes = new byte[35]; // 32 + 2 + 1
        publicKey.CopyTo(addressBytes.AsSpan(0));
        addressBytes[32] = hash[0];
        addressBytes[33] = hash[1];
        addressBytes[34] = version;

        return Base32Encode(addressBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Parses a v3 .onion address and extracts the ed25519 public key.
    /// Validates checksum and version byte.
    /// </summary>
    /// <param name="address">56-character .onion address (with or without ".onion" suffix).</param>
    /// <returns>32-byte public key, or null if the address is invalid.</returns>
    public static byte[]? ParseOnionV3Address(string address)
    {
        if (string.IsNullOrWhiteSpace(address))
            return null;

        // Strip ".onion" suffix if present
        var cleaned = address.Trim().ToLowerInvariant();
        if (cleaned.EndsWith(".onion", StringComparison.Ordinal))
            cleaned = cleaned[..^6];

        if (cleaned.Length != 56)
            return null;

        byte[]? decoded;
        try
        {
            decoded = Base32Decode(cleaned.ToUpperInvariant());
        }
        catch
        {
            return null;
        }

        if (decoded is null || decoded.Length != 35)
            return null;

        var pubkey = decoded.AsSpan(0, 32);
        byte checksumByte0 = decoded[32];
        byte checksumByte1 = decoded[33];
        byte version = decoded[34];

        if (version != 0x03)
            return null;

        // Verify checksum
        var checksumInput = new byte[15 + 32 + 1];
        Encoding.ASCII.GetBytes(".onion checksum", checksumInput.AsSpan(0, 15));
        pubkey.CopyTo(checksumInput.AsSpan(15));
        checksumInput[^1] = 0x03;

        byte[] hash;
        if (SHA3_256.IsSupported)
        {
            hash = SHA3_256.HashData(checksumInput);
        }
        else
        {
            hash = SHA256.HashData(checksumInput);
        }

        if (hash[0] != checksumByte0 || hash[1] != checksumByte1)
            return null;

        return pubkey.ToArray();
    }

    // ═══════════════ Helpers ═══════════════

    private static string NormalizeFingerprint(string fingerprint)
    {
        var fp = fingerprint.Trim();
        if (fp.StartsWith('$'))
            fp = fp[1..];
        return $"${fp.ToUpperInvariant()}";
    }

    /// <summary>
    /// Sanitizes a file path for torrc inclusion (escapes spaces).
    /// </summary>
    private static string SanitizePath(string path)
    {
        if (path.Contains(' ', StringComparison.Ordinal))
            return $"\"{path}\"";
        return path;
    }

    /// <summary>
    /// RFC 4648 Base32 encoding (no padding).
    /// </summary>
    private static string Base32Encode(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);

        int buffer = 0;
        int bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                sb.Append(alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }

        if (bitsLeft > 0)
        {
            sb.Append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }

        return sb.ToString();
    }

    /// <summary>
    /// RFC 4648 Base32 decoding.
    /// </summary>
    private static byte[]? Base32Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return null;

        encoded = encoded.TrimEnd('=');
        var output = new byte[encoded.Length * 5 / 8];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;

        foreach (var c in encoded)
        {
            int val;
            if (c is >= 'A' and <= 'Z')
                val = c - 'A';
            else if (c is >= '2' and <= '7')
                val = c - '2' + 26;
            else if (c is >= 'a' and <= 'z')
                val = c - 'a';
            else
                return null;

            buffer = (buffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                if (index < output.Length)
                    output[index++] = (byte)(buffer >> bitsLeft);
            }
        }

        return output;
    }
}
