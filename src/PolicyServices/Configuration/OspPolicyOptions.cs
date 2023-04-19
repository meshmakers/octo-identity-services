namespace Meshmakers.Octo.Backend.PolicyServices.Configuration;

public class OctoPolicyOptions
{
    public OctoPolicyOptions()
    {
        RedisCacheHost = "localhost";
        AuthorityUrl = "https://localhost:5003";
    }

    /// <summary>
    ///     (public) base address of identity services
    /// </summary>
    public string AuthorityUrl { get; set; }

    /// <summary>
    ///     Gets or sets the redis cache host name
    /// </summary>
    public string RedisCacheHost { get; set; }

    /// <summary>
    ///     Gets or sets the redis cache password
    /// </summary>
    public string RedisCachePassword { get; set; }
}
