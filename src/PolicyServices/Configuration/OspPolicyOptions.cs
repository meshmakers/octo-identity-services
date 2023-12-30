namespace Meshmakers.Octo.Backend.PolicyServices.Configuration;

/// <summary>
///     Provides options for the Octo Policy Service
/// </summary>
public class OctoPolicyOptions
{
    /// <summary>
    ///     Initializes a new instance of the <see cref="OctoPolicyOptions" /> class.
    /// </summary>
    public OctoPolicyOptions()
    {
        BrokerHost = "localhost";
        AuthorityUrl = "https://localhost:5003";
    }

    /// <summary>
    ///     (public) base address of identity services
    /// </summary>
    public string AuthorityUrl { get; set; }

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
}