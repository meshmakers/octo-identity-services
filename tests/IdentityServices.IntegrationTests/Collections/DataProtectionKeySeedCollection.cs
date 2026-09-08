using IdentityServices.IntegrationTests.Fixtures;

using Xunit;

namespace IdentityServices.IntegrationTests.Collections;

/// <summary>
///     Its own <see cref="IdentityServicesFixture" /> instance — and therefore its own MongoDB container
///     (AB#5160).
/// </summary>
/// <remarks>
///     <c>DataProtectionKeySeedIntegrationTests</c> exercises the zero-logout migration path that only
///     fires when the <c>DataProtectionKey</c> collection is EMPTY. Sharing the fixture of
///     <see cref="IdentityPersistenceCollection" /> would put it behind
///     <c>DataProtectionKeyStoreIntegrationTests.StoreElement</c> writes and the seed would silently never
///     run — a permanently green test that pins nothing. Isolation is bought with one container, not with
///     a weakened assertion.
/// </remarks>
[CollectionDefinition(Name)]
public class DataProtectionKeySeedCollection : ICollectionFixture<IdentityServicesFixture>
{
    public const string Name = "DataProtectionKeySeed";
}
