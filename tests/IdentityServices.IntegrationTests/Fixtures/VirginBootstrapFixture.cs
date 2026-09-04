namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
/// Fixture for <c>VirginSystemDatabaseBootstrapIntegrationTests</c>.
/// </summary>
/// <remarks>
/// Derives from <see cref="DatabaseFixture" /> — NOT <see cref="IdentityServicesFixture" /> — so the
/// fixture comes up without a system tenant: the tests drive <c>SetupAsync</c> against a virgin
/// MongoDB, the exact fresh-install path that release 3.4.93 permanently wedged (AB#4854). Its tests
/// create and destroy the system tenant at will, so this needs a database nobody else shares — which
/// every fixture now has, because <see cref="ConfigurationFixture.SystemDatabaseName" /> is unique per
/// fixture instance (AB#5117).
/// </remarks>
public class VirginBootstrapFixture : DatabaseFixture;
