using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     AB#8564: the guard tests need many distinct platform roles (built-in roles a caller with <c>UserManagement</c> must
///     hold to grant), but the real platform set is the seventeen roles of <c>System.Identity.Bootstrap</c>. A test role whose
///     <c>rtWellKnownName</c> starts with <see cref="Prefix" /> counts as a platform role in the test host; every other
///     built-in role is judged by the real <see cref="BootstrapPlatformRoleCatalog" />, so app-role tests use the
///     production rule.
/// </summary>
public static class TestPlatformRoles
{
    /// <summary>Prefix of a test role that the test host treats as a platform role.</summary>
    public const string Prefix = "platform-";
}

/// <summary>The real catalog plus the <see cref="TestPlatformRoles.Prefix" /> roles of the tests.</summary>
internal sealed class TestPlatformRoleCatalog(BootstrapPlatformRoleCatalog bootstrap) : IPlatformRoleCatalog
{
    public bool IsPlatformRole(RtRole role) =>
        bootstrap.IsPlatformRole(role) ||
        role.RtWellKnownName?.StartsWith(TestPlatformRoles.Prefix, StringComparison.Ordinal) == true;
}
