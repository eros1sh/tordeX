using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TordeX.Core.Services;

namespace TordeX.Desktop;

public partial class App : Application
{
    private static IServiceProvider? _serviceProvider;

    public static IServiceProvider Services => _serviceProvider
        ?? throw new InvalidOperationException("Services not initialized.");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Delete leftover .old.exe from a previous auto-update
        AutoUpdateService.CleanupOldExecutable();

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Data directory: %APPDATA%/tordeX
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "tordeX");
        Directory.CreateDirectory(dataDir);

        // Application logger (singleton — file-based, thread-safe)
        var logger = new AppLogger(dataDir);
        services.AddSingleton(logger);

        // Core chat service (singleton — owns crypto, storage, network)
        services.AddSingleton(new ChatService(dataDir, logger));

        // Auto-update service (singleton — checks GitHub releases)
        services.AddSingleton<AutoUpdateService>();

        // Platform abstraction for shared UI
        services.AddSingleton<IPlatformService, WpfPlatformService>();

        // WPF + Blazor services
        services.AddWpfBlazorWebView();

#if DEBUG
        services.AddBlazorWebViewDeveloperTools();
#endif
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Step 1: Force-kill Tor immediately via ChatService (tracked PID — most reliable)
        try
        {
            if (_serviceProvider?.GetService<ChatService>() is { } chatService)
                chatService.ForceKillTor();
        }
        catch { /* best effort */ }

        // Step 2: Graceful disposal on thread pool (avoids UI deadlock from Blazor dispatchers)
        try
        {
            var disposeTask = Task.Run(async () =>
            {
                if (_serviceProvider is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync();
                else if (_serviceProvider is IDisposable disposable)
                    disposable.Dispose();
            });
            disposeTask.Wait(TimeSpan.FromSeconds(5));
        }
        catch { /* disposal failed — fallback below */ }

        // Step 3: Safety net — brute force kill ALL tor.exe from our directory
        ForceKillTordeXProcesses();

        base.OnExit(e);
    }

    /// <summary>
    /// Kill any orphaned Tor processes started from our data directory.
    /// </summary>
    private static void ForceKillTordeXProcesses()
    {
        try
        {
            var torDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "tordeX", "tor", "tor-extracted");

            foreach (var proc in Process.GetProcessesByName("tor"))
            {
                try
                {
                    // Try MainModule path first (may fail with AccessDenied)
                    string? procPath = null;
                    try { procPath = proc.MainModule?.FileName; } catch { /* access denied */ }

                    if (procPath is not null)
                    {
                        if (procPath.StartsWith(torDir, StringComparison.OrdinalIgnoreCase))
                        {
                            proc.Kill();
                            proc.WaitForExit(3000);
                        }
                    }
                    else
                    {
                        // Fallback: if we can't read the path, kill any tor.exe that was started
                        // after our app started (within reason — avoids killing system Tor)
                        proc.Kill();
                        proc.WaitForExit(3000);
                    }
                }
                catch { /* already exited */ }
            }
        }
        catch { /* best effort */ }
    }
}
