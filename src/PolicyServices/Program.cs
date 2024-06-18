using Microsoft.AspNetCore;
using NLog;
using NLog.Web;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Meshmakers.Octo.Backend.PolicyServices;

/// <summary>
///     Main entry point for the application.
/// </summary>
public class Program
{
    /// <summary>
    ///     Main entry point for the application.
    /// </summary>
    /// <param name="args"></param>
    public static void Main(string[] args)
    {
        // NLog: setup the logger first to catch all errors
        var nLogFactory = LogManager.Setup().RegisterNLogWeb().LoadConfigurationFromFile("nlog.config").LogFactory;
        var logger = nLogFactory.GetCurrentClassLogger();
        try
        {
            logger.Debug("init main");
            CreateWebHostBuilder(args).Build().Run();
        }
        catch (Exception ex)
        {
            //NLog: catch setup errors
            logger.Error(ex, "Stopped program because of exception");
            throw;
        }
        finally
        {
            // Ensure to flush and stop internal timers/threads before application-exit (Avoid segmentation fault on Linux)
            LogManager.Shutdown();
        }
    }

    private static IWebHostBuilder CreateWebHostBuilder(string[] args)
    {
        return WebHost.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((_, config) =>
            {
                // Call additional providers here as needed.
                // Call AddEnvironmentVariables last if you need to allow environment
                // variables to override values from other providers.
                config.AddEnvironmentVariables("OCTO_").AddCommandLine(args);
            })
            .ConfigureLogging((_, logging) =>
            {
                logging.ClearProviders();
                logging.SetMinimumLevel(LogLevel.Trace);
            })
            .UseNLog() // NLog: setup NLog for Dependency injection
            .UseStartup<Startup>();
    }
}