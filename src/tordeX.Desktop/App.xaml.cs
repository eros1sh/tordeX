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

        // Core chat service (singleton — owns crypto, storage, network)
        services.AddSingleton(new ChatService(dataDir));

        // Auto-update service (singleton — checks GitHub releases)
        services.AddSingleton<AutoUpdateService>();

        // WPF + Blazor services
        services.AddWpfBlazorWebView();

#if DEBUG
        services.AddBlazorWebViewDeveloperTools();
#endif
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        // Graceful shutdown: dispose ChatService (zeroes keys, closes DB, stops Tor)
        if (_serviceProvider is IAsyncDisposable asyncDisposable)
        {
            await asyncDisposable.DisposeAsync();
        }
        else if (_serviceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }

        base.OnExit(e);
    }
}
