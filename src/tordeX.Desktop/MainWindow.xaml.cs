using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.AspNetCore.Components.WebView.Wpf;
using Microsoft.Extensions.DependencyInjection;
using TordeX.Core.Services;

namespace TordeX.Desktop;

public partial class MainWindow : Window
{
    private readonly ChatService _chatService;
    private bool _isExiting;
    private bool _screenCaptureProtected;

    // Win32 API for screen capture protection
    private const uint WDA_NONE = 0x00000000;
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

    public MainWindow()
    {
        InitializeComponent();

        _chatService = App.Services.GetRequiredService<ChatService>();

        // Wire up Blazor WebView — Services first, then RootComponents
        BlazorWebView.Services = App.Services;
        BlazorWebView.RootComponents.Add(
            new RootComponent
            {
                Selector = "#app",
                ComponentType = typeof(Pages.Main)
            });

        _chatService.OnNotification += ShowNotification;
    }

    /// <summary>
    /// Enables or disables screen capture protection (WDA_EXCLUDEFROMCAPTURE).
    /// Window appears black in screenshots and screen recordings.
    /// </summary>
    public void SetScreenCaptureProtection(bool enabled)
    {
        if (_screenCaptureProtected == enabled) return;

        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero) return;

        SetWindowDisplayAffinity(hwnd, enabled ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
        _screenCaptureProtected = enabled;
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (!_isExiting)
        {
            _isExiting = true;
            _chatService.OnNotification -= ShowNotification;
        }
    }

    private void ShowNotification(string message)
    {
        Dispatcher.Invoke(() =>
        {
            if (WindowState == WindowState.Minimized || !IsActive)
            {
                // Play notification sound if enabled
                if (_chatService.CurrentUser?.NotificationSounds != false)
                {
                    System.Media.SystemSounds.Asterisk.Play();
                }

                try
                {
                    new Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder()
                        .AddText("tordeX")
                        .AddText("New encrypted message received.")
                        .Show();
                }
                catch
                {
                    // Toast notification may not be available
                }
            }
        });
    }
}
