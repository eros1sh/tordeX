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

    public Task CopyToClipboardAsync(string text)
    {
        // Use xclip or xsel on Linux
        try
        {
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "xclip",
                    Arguments = "-selection clipboard",
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                }
            };
            process.Start();
            process.StandardInput.Write(text);
            process.StandardInput.Close();
            process.WaitForExit(2000);
        }
        catch
        {
            // xclip not available — silently fail
        }
        return Task.CompletedTask;
    }
}
