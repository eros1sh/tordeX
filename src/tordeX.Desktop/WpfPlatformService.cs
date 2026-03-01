using System.Windows;
using TordeX.Core.Services;

namespace TordeX.Desktop;

/// <summary>
/// WPF implementation of IPlatformService.
/// Provides screen capture protection via Win32 and WPF shutdown.
/// </summary>
public sealed class WpfPlatformService : IPlatformService
{
    public void SetScreenCaptureProtection(bool enabled)
    {
        if (Application.Current?.MainWindow is MainWindow mainWindow)
        {
            mainWindow.SetScreenCaptureProtection(enabled);
        }
    }

    public void RequestShutdown()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Application.Current.Shutdown();
        });
    }

    public Task CopyToClipboardAsync(string text)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Clipboard.SetText(text);
        });
        return Task.CompletedTask;
    }
}
