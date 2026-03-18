using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Common.Shared;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

// ReSharper disable once ClassNeverInstantiated.Global
internal class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IOptions<OctoIdentityServicesOptions> _octoIdentityOptions;
    private readonly IWebHostEnvironment _environment;

    public ConfigureJwtBearerOptions(IOptions<OctoIdentityServicesOptions> octoIdentityOptions, IWebHostEnvironment environment)
    {
        _octoIdentityOptions = octoIdentityOptions;
        _environment = environment;
    }


    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        options.Authority = _octoIdentityOptions.Value.AuthorityUrl.EnsureEndsWith("/");

        // Disable inbound claim mapping so JWT claim types (sub, name, preferred_username,
        // tenant_id, etc.) are preserved as-is instead of being remapped to long XML namespaces.
        // This is required for controllers that read IdentityModel JwtClaimTypes from the token.
        options.MapInboundClaims = false;

        // In development, disable HTTPS metadata requirement for self-signed certificates
        if (_environment.IsDevelopment())
        {
            options.RequireHttpsMetadata = false;
            options.BackchannelHttpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
        }

        // Add detailed logging for debugging authentication issues
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger<ConfigureJwtBearerOptions>();
                logger.LogError(context.Exception, "JWT Authentication failed: {Message}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger<ConfigureJwtBearerOptions>();
                var hasAuthHeader = context.Request.Headers.ContainsKey("Authorization");
                logger.LogDebug("JWT OnMessageReceived - Has Authorization header: {HasAuth}", hasAuthHeader);
                if (hasAuthHeader)
                {
                    var authHeader = context.Request.Headers["Authorization"].ToString();
                    logger.LogDebug("JWT OnMessageReceived - Auth header prefix: {Prefix}",
                        authHeader.Length > 20 ? authHeader[..20] + "..." : authHeader);
                }
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                    .CreateLogger<ConfigureJwtBearerOptions>();
                logger.LogDebug("JWT Token validated successfully for subject: {Subject}",
                    context.Principal?.FindFirst("sub")?.Value);
                return Task.CompletedTask;
            }
        };
    }
}