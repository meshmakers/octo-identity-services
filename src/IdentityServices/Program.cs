#pragma warning disable 1591
using System;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NLog;
using NLog.Web;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace Meshmakers.Octo.Backend.IdentityServices;

public class Program
{
    private static string GetNLogConfigFileName()
    {
#if DEBUG
        return "nlog.Debug.config";
#else
            return "nlog.Release.config";
#endif
    }

    public static void Main(string[] args)
    {
        // NLog: setup the logger first to catch all errors
        var nlogFactory = NLogBuilder.ConfigureNLog(GetNLogConfigFileName());
        var logger = nlogFactory.GetCurrentClassLogger();
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

    public static IWebHostBuilder CreateWebHostBuilder(string[] args)
    {
        return WebHost.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration((hostingContext, config) =>
            {
                // Call additional providers here as needed.
                // Call AddEnvironmentVariables last if you need to allow environment
                // variables to override values from other providers.
                config.AddEnvironmentVariables("OCTO_").AddCommandLine(args);
                config.AddUserSecrets(typeof(Program).Assembly, true);
            })
            .ConfigureLogging((hostingContext, logging) =>
            {
                logging.ClearProviders();
                logging.SetMinimumLevel(LogLevel.Trace);
            })
            .UseNLog() // NLog: setup NLog for Dependency injection
            .UseStartup<Startup>();
    }
}
