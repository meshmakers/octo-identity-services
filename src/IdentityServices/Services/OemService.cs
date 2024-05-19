namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class OemService : IOemService
{
    public OemService(IWebHostEnvironment environmentService)
    {
        var oemFolder = Path.Combine(environmentService.WebRootPath, "oem");

        Favicon = File.Exists(Path.Combine(oemFolder, "favicon.ico")) ? "/oem/favicon.ico" : "/assets/favicon.ico";
        Favicon32x32 = File.Exists(Path.Combine(oemFolder, "favicon-32x32.png")) ? "/oem/favicon-32x32.png" : "/assets/favicon-32x32.png";
        StyleBundle = File.Exists(Path.Combine(oemFolder, "bundle.css")) ? "/oem/bundle.css" : "/js/bundle.css";
        JsBundle = File.Exists(Path.Combine(oemFolder, "bundle.js")) ? "/oem/bundle.js" : "/js/bundle.js";
    }

    public string Favicon { get; }

    public string Favicon32x32 { get; }

    public string StyleBundle { get; }

    public string JsBundle { get; }
}

public static class OemServiceCollectionExtensions
{
    public static void AddOemServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<OemOptions>(options => configuration.GetSection("Oem").Bind(options));
        services.AddSingleton<IOemService, OemService>();
    }
}