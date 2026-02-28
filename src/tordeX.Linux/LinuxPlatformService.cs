using TordeX.Core.Services;

namespace TordeX.Linux;

/// <summary>
/// Linux/Photino implementation of IPlatformService.
/// Screen capture protection is not available on Linux.
/// </summary>
public sealed class LinuxPlatformService : IPlatformService
{
    public void SetScreenCaptureProtection(bool enabled)
    {
        // Not supported on Linux — no-op
    }

    public void RequestShutdown()
    {
        Environment.Exit(0);
    }
}
