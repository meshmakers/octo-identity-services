// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;

namespace IdentityServerPersistence.Configuration.Options;

public class OctoIdentityServicesOptions
{
    public OctoIdentityServicesOptions()
    {
        AuthorityUrl = "https://localhost:5003";
        BrokerHost = "localhost";
        EnableTokenCleanup = true;
        TokenCleanupInterval = 60 * 60; // default: once an hour
        AllowDisplayInIframe = false;
        MinLogLevel = LogLevelDto.Trace;
    }

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
}