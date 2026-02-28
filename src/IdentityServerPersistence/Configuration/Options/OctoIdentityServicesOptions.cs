// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;

namespace IdentityServerPersistence.Configuration.Options;

public class OctoIdentityServicesOptions
{
    public OctoIdentityServicesOptions()
    {
        AuthorityUrl = "https://localhost:5003";
        RefineryStudioUrl = "https://localhost:4200";
        BrokerHost = "localhost";
        EnableTokenCleanup = true;
        TokenCleanupInterval = 60 * 60; // default: once an hour
        AllowDisplayInIframe = false;
#if DEBUGL || DEBUG
        MinLogLevel = LogLevelDto.Trace;
#else
        MinLogLevel = LogLevelDto.Warn;
#endif
    }

    /// <summary>
    /// The license key for the IdentityServer.
    /// </summary>
    public required string IdentityServerLicenseKey { get; set; }

    /// <summary>
    /// The license key for the AutoMapper.
    /// </summary>
    public required string AutoMapperLicenseKey { get; set; }

    /// <summary>
    ///     Gets or sets the prefix for the OctoMesh installation instance.
    /// </summary>
    public string? InstancePrefix { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq host name
    /// </summary>
    public string BrokerHost { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq user
    /// </summary>
    public string? BrokerUser { get; set; }

    /// <summary>
    ///     Gets or sets the RabbitMq password
    /// </summary>
    public string? BrokerPassword { get; set; }

    /// <summary>
    /// Gets or sets the public URL of the Identity service.
    /// </summary>
    public string AuthorityUrl { get; set; }

    /// <summary>
    /// Gets or sets the path to the certificate file used for signing tokens.
    /// </summary>
    public string? KeyFilePath { get; set; }

    /// <summary>
    /// Gets or sets the password for the certificate file used for signing tokens.
    /// </summary>
    public string? KeyFilePassword { get; set; }

    /// <summary>
    ///     If true, a host service is started to check periodically for expired tokens in grant store
    /// </summary>
    public bool EnableTokenCleanup { get; set; }

    /// <summary>
    ///     The interval in seconds, expired tokens in grant store are checked to be deleted.
    /// </summary>
    public int TokenCleanupInterval { get; set; }

    /// <summary>
    ///     Configure the SecurityHeaders so that displaying
    ///     Identity service in an iframe is allowed.
    /// </summary>
    public bool AllowDisplayInIframe { get; set; }

    /// <summary>
    /// Gets or sets the minimal log level to be logged
    /// </summary>
    public LogLevelDto MinLogLevel { get; set; }

    /// <summary>
    /// Gets or sets the path where ASP.NET Data Protection keys are persisted.
    /// When set, keys are stored on the filesystem at this path to survive pod restarts.
    /// </summary>
    public string? DataProtectionKeysPath { get; set; }

    /// <summary>
    /// Gets or sets the public URL of the Data Refinery Studio SPA.
    /// Used to auto-provision the <c>octo-data-refinery-studio</c> OIDC client with correct
    /// redirect URIs, post-logout URIs, CORS origins, and front-channel logout URI.
    /// When null or empty, the Refinery Studio client is not auto-provisioned.
    /// </summary>
    public string? RefineryStudioUrl { get; set; }
}