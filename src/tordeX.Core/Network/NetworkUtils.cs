using System.Net;
using System.Net.Sockets;

namespace TordeX.Core.Network;

/// <summary>
/// Shared network utility methods.
/// </summary>
internal static class NetworkUtils
{
    /// <summary>
    /// Find an available TCP port starting from the preferred port.
    /// Scans up to 100 ports above preferred, then falls back to OS-assigned.
    /// </summary>
    public static int FindAvailablePort(int preferred)
    {
        for (int port = preferred; port < preferred + 100; port++)
        {
            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, port);
                listener.Start();
                listener.Stop();
                return port;
            }
            catch (SocketException) { }
        }

        using var fallback = new TcpListener(IPAddress.Loopback, 0);
        fallback.Start();
        var assignedPort = ((IPEndPoint)fallback.LocalEndpoint).Port;
        fallback.Stop();
        return assignedPort;
    }
}
