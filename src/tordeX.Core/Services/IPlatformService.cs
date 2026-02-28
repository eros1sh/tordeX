namespace TordeX.Core.Services;

/// <summary>
/// Abstracts platform-specific operations so the shared UI layer
/// can trigger host-level actions without referencing WPF or Photino directly.
/// </summary>
public interface IPlatformService
{
    /// <summary>
    /// Enables or disables screen capture protection (Windows-only: WDA_EXCLUDEFROMCAPTURE).
    /// No-op on platforms that don't support it.
    /// </summary>
    void SetScreenCaptureProtection(bool enabled);

    /// <summary>
    /// Requests the application to shut down gracefully.
    /// </summary>
    void RequestShutdown();
}
