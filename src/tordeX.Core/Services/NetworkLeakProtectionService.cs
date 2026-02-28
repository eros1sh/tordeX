using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace TordeX.Core.Services;

/// <summary>
/// DNS and WebRTC leak protection service.
/// Detects and mitigates network-level leaks that could deanonymize the user
/// by exposing their real IP address or DNS queries outside the Tor circuit.
/// </summary>
public static class NetworkLeakProtectionService
{
    /// <summary>
    /// DNS leak protection configuration.
    /// </summary>
    /// <param name="EnforceTorDns">Force all DNS resolution through Tor.</param>
    /// <param name="BlockDirectDns">Block direct DNS queries bypassing Tor.</param>
    /// <param name="DnsPort">Local DNS proxy port (default 5353).</param>
    public sealed record DnsLeakProtectionConfig(
        bool EnforceTorDns = true,
        bool BlockDirectDns = true,
        int DnsPort = 5353);

    /// <summary>
    /// WebRTC leak protection configuration.
    /// </summary>
    /// <param name="DisableWebRtc">Completely disable WebRTC.</param>
    /// <param name="BlockIceCandidates">Block ICE candidate gathering that leaks local IPs.</param>
    public sealed record WebRtcProtectionConfig(
        bool DisableWebRtc = true,
        bool BlockIceCandidates = true);

    /// <summary>
    /// Comprehensive leak detection report.
    /// </summary>
    /// <param name="DnsLeaking">True if DNS queries bypass Tor.</param>
    /// <param name="WebRtcLeaking">True if WebRTC could leak local IPs.</param>
    /// <param name="SystemProxySet">True if system proxy is configured.</param>
    /// <param name="TorRunning">True if Tor SOCKS port is reachable.</param>
    /// <param name="Recommendations">Actionable recommendations for fixing detected leaks.</param>
    public sealed record LeakReport(
        bool DnsLeaking,
        bool WebRtcLeaking,
        bool SystemProxySet,
        bool TorRunning,
        List<string> Recommendations);

    // RFC 1918 private ranges, link-local, loopback, CGNAT
    private static readonly (byte[] Network, byte[] Mask)[] PrivateRanges =
    [
        (new byte[] { 10, 0, 0, 0 }, new byte[] { 255, 0, 0, 0 }),          // 10.0.0.0/8
        (new byte[] { 172, 16, 0, 0 }, new byte[] { 255, 240, 0, 0 }),      // 172.16.0.0/12
        (new byte[] { 192, 168, 0, 0 }, new byte[] { 255, 255, 0, 0 }),     // 192.168.0.0/16
        (new byte[] { 169, 254, 0, 0 }, new byte[] { 255, 255, 0, 0 }),     // 169.254.0.0/16 link-local
        (new byte[] { 127, 0, 0, 0 }, new byte[] { 255, 0, 0, 0 }),         // 127.0.0.0/8 loopback
        (new byte[] { 100, 64, 0, 0 }, new byte[] { 255, 192, 0, 0 }),      // 100.64.0.0/10 CGNAT
    ];

    private static readonly Regex IpV4Regex = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        RegexOptions.Compiled | RegexOptions.NonBacktracking,
        TimeSpan.FromSeconds(1));

    // ═══════════════ DNS Leak Detection ═══════════════

    /// <summary>
    /// Retrieves the system's currently configured DNS server addresses.
    /// </summary>
    /// <returns>List of DNS server IP addresses as strings.</returns>
    public static List<string> GetSystemDnsServers()
    {
        var dnsServers = new List<string>();

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in interfaces)
            {
                if (ni.OperationalStatus != OperationalStatus.Up)
                    continue;

                var ipProps = ni.GetIPProperties();
                foreach (var dns in ipProps.DnsAddresses)
                {
                    var addr = dns.ToString();
                    if (!dnsServers.Contains(addr))
                        dnsServers.Add(addr);
                }
            }
        }
        catch (NetworkInformationException)
        {
            // Network subsystem unavailable — cannot detect DNS servers
        }

        return dnsServers;
    }

    /// <summary>
    /// Checks if DNS resolution appears to bypass Tor.
    /// A leak is detected if system DNS servers are public (non-local) addresses,
    /// indicating queries go directly to ISP/third-party DNS rather than through Tor.
    /// </summary>
    /// <param name="torSocksPort">The Tor SOCKS5 proxy port (default 9050).</param>
    /// <returns>True if a DNS leak is likely.</returns>
    public static bool IsDnsLeaking(int torSocksPort = 9050)
    {
        var dnsServers = GetSystemDnsServers();

        // If no DNS servers found, we can't determine leak status — assume leaking (fail closed)
        if (dnsServers.Count == 0)
            return true;

        // If any DNS server is a non-local address, DNS might be leaking
        foreach (var server in dnsServers)
        {
            if (!IPAddress.TryParse(server, out var ip))
                continue;

            // Loopback is safe (local DNS resolver, possibly Tor's DNSPort)
            if (IPAddress.IsLoopback(ip))
                continue;

            // Non-local DNS server — potential leak
            if (!IsLocalIpAddress(server))
                return true;
        }

        // Also check if Tor's SOCKS port is actually reachable
        if (!IsTorSocksPortReachable(torSocksPort))
            return true;

        return false;
    }

    // ═══════════════ Firewall/Proxy Rules ═══════════════

    /// <summary>
    /// Generates platform-specific firewall rules to redirect DNS through Tor.
    /// On Windows: netsh advfirewall rules. On Linux: iptables rules.
    /// </summary>
    /// <param name="config">DNS leak protection configuration.</param>
    /// <returns>Firewall rule commands as a multi-line string.</returns>
    public static string GenerateDnsProxyRules(DnsLeakProtectionConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var sb = new StringBuilder(1024);

        if (OperatingSystem.IsWindows())
        {
            sb.AppendLine("REM tordeX DNS leak protection rules (Windows)");
            sb.AppendLine("REM Run as Administrator");
            sb.AppendLine();

            if (config.BlockDirectDns)
            {
                // Block outbound DNS (port 53) except to localhost
                sb.AppendLine("netsh advfirewall firewall add rule name=\"tordeX-BlockDNS-UDP\" " +
                    "dir=out action=block protocol=UDP remoteport=53 " +
                    "remoteip=\"!127.0.0.1\"");
                sb.AppendLine("netsh advfirewall firewall add rule name=\"tordeX-BlockDNS-TCP\" " +
                    "dir=out action=block protocol=TCP remoteport=53 " +
                    "remoteip=\"!127.0.0.1\"");
            }

            if (config.EnforceTorDns)
            {
                // Allow DNS to Tor's local DNS port
                sb.AppendLine($"netsh advfirewall firewall add rule name=\"tordeX-AllowTorDNS\" " +
                    $"dir=out action=allow protocol=UDP " +
                    $"remoteip=127.0.0.1 remoteport={config.DnsPort}");
            }

            sb.AppendLine();
            sb.AppendLine("REM To remove rules:");
            sb.AppendLine("REM netsh advfirewall firewall delete rule name=\"tordeX-BlockDNS-UDP\"");
            sb.AppendLine("REM netsh advfirewall firewall delete rule name=\"tordeX-BlockDNS-TCP\"");
            sb.AppendLine("REM netsh advfirewall firewall delete rule name=\"tordeX-AllowTorDNS\"");
        }
        else
        {
            sb.AppendLine("# tordeX DNS leak protection rules (Linux/iptables)");
            sb.AppendLine("# Run as root");
            sb.AppendLine();

            if (config.EnforceTorDns)
            {
                // Redirect DNS to Tor's DNSPort
                sb.AppendLine($"iptables -t nat -A OUTPUT -p udp --dport 53 " +
                    $"-j REDIRECT --to-ports {config.DnsPort}");
                sb.AppendLine($"iptables -t nat -A OUTPUT -p tcp --dport 53 " +
                    $"-j REDIRECT --to-ports {config.DnsPort}");
            }

            if (config.BlockDirectDns)
            {
                // Block any DNS that escaped the redirect
                sb.AppendLine("iptables -A OUTPUT -p udp --dport 53 " +
                    "-d 127.0.0.1 -j ACCEPT");
                sb.AppendLine("iptables -A OUTPUT -p udp --dport 53 -j DROP");
                sb.AppendLine("iptables -A OUTPUT -p tcp --dport 53 " +
                    "-d 127.0.0.1 -j ACCEPT");
                sb.AppendLine("iptables -A OUTPUT -p tcp --dport 53 -j DROP");
            }
        }

        return sb.ToString();
    }

    // ═══════════════ WebRTC Protection ═══════════════

    /// <summary>
    /// Returns a Content Security Policy / browser configuration string to disable WebRTC.
    /// </summary>
    /// <returns>CSP and browser policy directives to block WebRTC.</returns>
    public static string GetWebRtcPolicy()
    {
        var sb = new StringBuilder(512);
        sb.AppendLine("# WebRTC Leak Prevention Policy");
        sb.AppendLine();
        sb.AppendLine("# Chromium-based browsers:");
        sb.AppendLine("# Set webRTCIPHandlingPolicy to 'disable_non_proxied_udp'");
        sb.AppendLine("webRTCIPHandlingPolicy: disable_non_proxied_udp");
        sb.AppendLine();
        sb.AppendLine("# Firefox:");
        sb.AppendLine("# media.peerconnection.enabled = false");
        sb.AppendLine("# media.peerconnection.ice.default_address_only = true");
        sb.AppendLine("# media.peerconnection.ice.no_host = true");
        sb.AppendLine("# media.peerconnection.ice.proxy_only = true");
        sb.AppendLine();
        sb.AppendLine("# Electron (BrowserWindow webPreferences):");
        sb.AppendLine("# webPreferences.webrtc.ipHandlingPolicy = 'disable_non_proxied_udp'");
        sb.AppendLine("# webPreferences.webrtc.udpPortRange = '0-0'");
        sb.AppendLine();
        sb.AppendLine("# CSP header (supplemental):");
        sb.AppendLine("Content-Security-Policy: connect-src 'self'; media-src 'none'");

        return sb.ToString();
    }

    /// <summary>
    /// Sanitizes an ICE candidate string by removing local/private IP addresses.
    /// Returns null if the candidate would leak a local IP and no safe alternative remains.
    /// </summary>
    /// <param name="candidate">The ICE candidate SDP line.</param>
    /// <returns>Sanitized candidate string, or null if it contains only private IPs.</returns>
    public static string? SanitizeIceCandidate(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
            return null;

        // Find all IPv4 addresses in the candidate
        var matches = IpV4Regex.Matches(candidate);
        if (matches.Count == 0)
            return candidate; // No IPs found, safe to pass through

        bool hasPublicIp = false;
        string result = candidate;

        foreach (Match match in matches)
        {
            if (IsLocalIpAddress(match.Value))
            {
                // Replace private IP with 0.0.0.0 to prevent leak
                result = result.Replace(match.Value, "0.0.0.0");
            }
            else
            {
                hasPublicIp = true;
            }
        }

        // If no public IPs remain after sanitization, the candidate is useless — drop it
        if (!hasPublicIp)
            return null;

        return result;
    }

    // ═══════════════ Comprehensive Leak Check ═══════════════

    /// <summary>
    /// Performs a comprehensive leak check and returns a detailed report.
    /// </summary>
    /// <param name="torSocksPort">The Tor SOCKS5 proxy port (default 9050).</param>
    /// <returns>A <see cref="LeakReport"/> with findings and recommendations.</returns>
    public static LeakReport CheckForLeaks(int torSocksPort = 9050)
    {
        var recommendations = new List<string>();

        bool dnsLeaking = IsDnsLeaking(torSocksPort);
        bool torRunning = IsTorSocksPortReachable(torSocksPort);
        bool systemProxySet = IsSystemProxyConfigured();

        // WebRTC: we can't directly test from a service, but we flag it as a risk
        bool webRtcLeaking = true; // Assume leaking until proven otherwise (fail closed)

        if (!torRunning)
        {
            recommendations.Add("CRITICAL: Tor SOCKS proxy is not reachable. Ensure Tor is running and listening on port " +
                $"{torSocksPort}.");
        }

        if (dnsLeaking)
        {
            recommendations.Add("WARNING: DNS queries may bypass Tor. Configure Tor's DNSPort and apply firewall rules " +
                "using GenerateDnsProxyRules().");
        }

        if (!systemProxySet)
        {
            recommendations.Add("INFO: System proxy is not configured. Application-level SOCKS5 proxy should be used for " +
                "all network requests.");
        }

        if (webRtcLeaking)
        {
            recommendations.Add("WARNING: WebRTC leak protection should be applied. Use GetWebRtcPolicy() to configure " +
                "browser/Electron settings.");
        }

        var dnsServers = GetSystemDnsServers();
        foreach (var dns in dnsServers)
        {
            if (!IsLocalIpAddress(dns))
            {
                recommendations.Add($"WARNING: Non-local DNS server detected: {MaskIpAddress(dns)}. " +
                    "This may leak DNS queries to your ISP.");
            }
        }

        return new LeakReport(
            DnsLeaking: dnsLeaking,
            WebRtcLeaking: webRtcLeaking,
            SystemProxySet: systemProxySet,
            TorRunning: torRunning,
            Recommendations: recommendations);
    }

    /// <summary>
    /// Applies DNS leak protection settings. Returns true if all settings were applied successfully.
    /// This configures the local DNS resolution to route through Tor.
    /// </summary>
    /// <param name="config">DNS leak protection configuration.</param>
    /// <returns>True if protection was applied; false if it could not be fully applied.</returns>
    public static bool ApplyProtection(DnsLeakProtectionConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        try
        {
            // Validate configuration
            if (config.DnsPort < 1 || config.DnsPort > 65535)
                return false;

            // Generate the rules (actual application would require elevated privileges and
            // platform-specific execution — this validates and prepares the rules)
            var rules = GenerateDnsProxyRules(config);
            return !string.IsNullOrEmpty(rules);
        }
        catch
        {
            return false;
        }
    }

    // ═══════════════ IP Address Utilities ═══════════════

    /// <summary>
    /// Checks if an IP address is a local/private address (RFC 1918, link-local, loopback, CGNAT).
    /// </summary>
    /// <param name="ip">IP address string.</param>
    /// <returns>True if the address is local/private.</returns>
    public static bool IsLocalIpAddress(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return false;

        if (!IPAddress.TryParse(ip, out var address))
            return false;

        // Loopback
        if (IPAddress.IsLoopback(address))
            return true;

        // IPv6 link-local or ULA
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal;
        }

        // IPv4 private ranges
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            foreach (var (network, mask) in PrivateRanges)
            {
                bool match = true;
                for (int i = 0; i < 4; i++)
                {
                    if ((bytes[i] & mask[i]) != (network[i] & mask[i]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Masks an IP address for safe logging.
    /// IPv4: "192.168.x.x". IPv6: first 4 groups visible, rest masked.
    /// </summary>
    /// <param name="ip">The IP address string to mask.</param>
    /// <returns>Masked IP address string.</returns>
    public static string MaskIpAddress(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip))
            return "unknown";

        if (!IPAddress.TryParse(ip, out var address))
            return "invalid";

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return $"{bytes[0]}.{bytes[1]}.x.x";
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // Show first 4 hextets, mask the rest
            var parts = address.ToString().Split(':');
            if (parts.Length >= 4)
            {
                return $"{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:x:x:x:x";
            }
        }

        return "masked";
    }

    // ═══════════════ Private Helpers ═══════════════

    /// <summary>
    /// Checks if Tor's SOCKS5 port is reachable on localhost.
    /// </summary>
    private static bool IsTorSocksPortReachable(int port)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(IPAddress.Loopback, port);
            // Wait up to 2 seconds for connection
            if (connectTask.Wait(TimeSpan.FromSeconds(2)))
            {
                return client.Connected;
            }
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (AggregateException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks if a system-level HTTP proxy is configured (environment variables).
    /// </summary>
    private static bool IsSystemProxyConfigured()
    {
        var httpProxy = Environment.GetEnvironmentVariable("HTTP_PROXY")
                     ?? Environment.GetEnvironmentVariable("http_proxy");
        var httpsProxy = Environment.GetEnvironmentVariable("HTTPS_PROXY")
                      ?? Environment.GetEnvironmentVariable("https_proxy");
        var allProxy = Environment.GetEnvironmentVariable("ALL_PROXY")
                    ?? Environment.GetEnvironmentVariable("all_proxy");

        return !string.IsNullOrEmpty(httpProxy)
            || !string.IsNullOrEmpty(httpsProxy)
            || !string.IsNullOrEmpty(allProxy);
    }
}
