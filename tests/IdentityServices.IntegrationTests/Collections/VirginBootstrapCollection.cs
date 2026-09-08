using IdentityServices.IntegrationTests.Fixtures;

using Xunit;

namespace IdentityServices.IntegrationTests.Collections;

/// <summary>
///     Shares the one <see cref="VirginBootstrapFixture" /> — a container that never gets a system tenant
///     provisioned for it (AB#5160).
/// </summary>
/// <remarks>
///     <c>VirginSystemDatabaseBootstrapIntegrationTests</c> drops the system database and its datasource
///     user before every fact to reproduce the AB#4854 fresh-install path. That is destructive to every
///     other test, so this fixture must never be shared with another collection.
/// </remarks>
[CollectionDefinition(Name)]
public class VirginBootstrapCollection : ICollectionFixture<VirginBootstrapFixture>
{
    public const string Name = "VirginBootstrap";
}
