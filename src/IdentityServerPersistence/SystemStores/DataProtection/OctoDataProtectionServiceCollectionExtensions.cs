using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     Registration of ASP.NET Data Protection for identity services.
/// </summary>
public static class OctoDataProtectionServiceCollectionExtensions
{
    /// <summary>Application name all identity pods share (the key ring is isolated by it).</summary>
    public const string ApplicationName = "OctoIdentityServices";

    /// <summary>
    ///     Registers Data Protection with the key ring persisted in MongoDB (system tenant, shared by all pods,
    ///     <see cref="DataProtectionKeyStore" />), encrypted at rest with the platform key ring (AB#5530), and the
    ///     startup check <see cref="DataProtectionKeyRingStartupService" />. Needs <c>ISecretAttributeProtector</c>
    ///     (<c>AddRuntimeEngine()</c>).
    /// </summary>
    public static IServiceCollection AddOctoDataProtectionKeyRing(this IServiceCollection services)
    {
        services.AddSingleton<DataProtectionKeyStore>();
        services.AddSingleton<IXmlRepository>(sp => sp.GetRequiredService<DataProtectionKeyStore>());
        services.AddOptions<KeyManagementOptions>()
            .Configure<IXmlRepository>((options, repository) => options.XmlRepository = repository);
        services.AddDataProtection()
            .SetApplicationName(ApplicationName);
        services.AddHostedService<DataProtectionKeyRingStartupService>();
        return services;
    }
}
