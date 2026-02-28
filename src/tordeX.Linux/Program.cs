using Microsoft.Extensions.DependencyInjection;
using Photino.Blazor;
using TordeX.Core.Services;

namespace TordeX.Linux;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Data directory: ~/.local/share/tordeX (XDG standard on Linux)
        var dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "tordeX");
        Directory.CreateDirectory(dataDir);

        AutoUpdateService.CleanupOldExecutable();

        var appBuilder = PhotinoBlazorAppBuilder.CreateDefault(args);

        var logger = new AppLogger(dataDir);
        appBuilder.Services.AddSingleton(logger);
        appBuilder.Services.AddSingleton(new ChatService(dataDir, logger));
        appBuilder.Services.AddSingleton<AutoUpdateService>();
        appBuilder.Services.AddSingleton<IPlatformService, LinuxPlatformService>();

        appBuilder.RootComponents.Add<TordeX.UI.Pages.Main>("app");

        var app = appBuilder.Build();

        app.MainWindow
            .SetTitle("tordeX")
            .SetUseOsDefaultSize(false)
            .SetSize(1100, 700)
            .SetMinSize(800, 500);

        AppDomain.CurrentDomain.UnhandledException += (_, error) =>
        {
            if (app.Services.GetService(typeof(ChatService)) is ChatService chat)
            {
                chat.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        };

        app.Run();

        // Graceful shutdown
        if (app.Services.GetService(typeof(ChatService)) is ChatService chatService)
        {
            chatService.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
