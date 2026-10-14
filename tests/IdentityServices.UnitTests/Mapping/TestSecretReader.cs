using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;

namespace IdentityServices.UnitTests.Mapping;

internal static class TestSecretReader
{
    public static ServiceProvider CreateServices()
    {
        var protector = Substitute.For<ISecretAttributeProtector>();
        protector.IsKnownKeyId(Arg.Any<string?>()).Returns(true);
        protector.DescribeSecret(Arg.Any<RtSecretValue?>(), Arg.Any<SecretAccessContext?>())
            .Returns(call => SecretValueStates.Describe(call.Arg<RtSecretValue?>(), _ => true));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(protector);
        services.AddDynamicAuthentication();
        return services.BuildServiceProvider();
    }

    public static IIdentityProviderSecretReader From(ServiceProvider services) =>
        services.GetRequiredService<IIdentityProviderSecretReader>();
}
