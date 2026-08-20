namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Fixture for <c>VirginSystemDatabaseBootstrapIntegrationTests</c>.
/// </summary>
/// <remarks>
/// Derives from <see cref="DatabaseFixture" /> — NOT <see cref="IdentityServicesFixture" /> — so the
/// container starts without a system tenant: the tests drive <c>SetupAsync</c> against a virgin
/// MongoDB, the exact fresh-install path that release 3.4.93 permanently wedged (AB#4854). Its tests
/// create and destroy the system tenant at will, so this needs a container nobody else shares.
/// </remarks>
public class VirginBootstrapFixture : DatabaseFixture;
