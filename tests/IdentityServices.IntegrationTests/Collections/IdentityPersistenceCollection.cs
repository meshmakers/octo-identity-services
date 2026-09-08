using IdentityServices.IntegrationTests.Fixtures;

using Xunit;

namespace IdentityServices.IntegrationTests.Collections;

/// <summary>
///     Shares one <see cref="IdentityServicesFixture" /> — and therefore one MongoDB container plus the
///     provisioned system tenant and test tenant — across every persistence test class that joins this
///     collection, replacing the per-class <c>IClassFixture&lt;IdentityServicesFixture&gt;</c> (AB#5160,
///     same migration as AB#4963 in octo-asset-repo-services / octo-communication-controller-services).
/// </summary>
/// <remarks>
///     Every class in here creates its entities under GUID-suffixed names/ids and asserts only on what it
///     created, so the accumulated state of its siblings is invisible to it. The two classes that do make
///     assumptions about the database as a whole are deliberately NOT in this collection:
///     <see cref="DataProtectionKeySeedCollection" /> (needs an empty <c>DataProtectionKey</c> collection)
///     and <see cref="VirginBootstrapCollection" /> (drops the whole system database).
/// </remarks>
[CollectionDefinition(Name)]
public class IdentityPersistenceCollection : ICollectionFixture<IdentityServicesFixture>
{
    public const string Name = "IdentityPersistence";
}
