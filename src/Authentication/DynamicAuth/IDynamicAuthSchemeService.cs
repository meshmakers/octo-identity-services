namespace Meshmakers.Octo.Backend.Authentication.DynamicAuth;

/// <summary>
///     Interface of dynamic auth scheme service that allows to configure external identity
///     provider during run-time of identity services.
/// </summary>
public interface IDynamicAuthSchemeService
{
    /// <summary>
    ///     Configures authentication schemes.
    /// </summary>
    /// <returns></returns>
    Task ConfigureAsync(string? tenantId);
}