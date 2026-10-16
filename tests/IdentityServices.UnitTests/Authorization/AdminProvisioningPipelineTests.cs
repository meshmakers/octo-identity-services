using System.Net;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Shared.TestUtilities.Fakes;
using NSubstitute;
using Xunit;
using static IdentityServices.UnitTests.Authorization.ScopedTenantApiHost;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#4824: the real HTTP pipeline of <c>POST {tenant}/v1/adminProvisioning/{target}/provisionCurrentUser</c> —
///     real routing, real <see cref="AdminProvisioningController" />, real
///     <see cref="IdentityServiceConstants.IdentityTenantAdministrationWritePolicy" /> (production policy
///     registration and role handler) and the real <see cref="AdminProvisioningTargetScopeFilter" /> — against a
///     fake tenant registry. Only the persistence below the action is faked: for a registered target tenant a
///     test-only innermost filter answers <c>201</c> (the action itself needs MongoDB); for an unregistered one
///     the real action runs and answers <c>404</c>, exactly like the live reproduction.
/// </summary>
public class AdminProvisioningPipelineTests : IAsyncDisposable
{
    private ScopedTenantApiHost _host = null!;

    private FakeTenantRegistry _registry => _host.Registry;
    private CapturingLogger<AdminProvisioningTargetScopeFilter> _filterLog => _host.FilterLog;
    private CapturingLogger<IdentityApiRoleAuthorizationHandler> _policyLog => _host.PolicyLog;
    private Meshmakers.Octo.Runtime.Contracts.MongoDb.ISystemContext _systemContext => _host.SystemContext;

    private async Task StartAsync(IdentityApiRoleEnforcementMode mode = IdentityApiRoleEnforcementMode.Enforce)
        => _host = await ScopedTenantApiHost.StartAsync(mode, typeof(AdminProvisioningController));

    public async ValueTask DisposeAsync()
    {
        if (_host != null)
        {
            await _host.DisposeAsync();
        }
    }

    // The route tenant is the system tenant (documented routing); the caller's tenant is the token's tenant_id.
    private Task<(HttpStatusCode Status, string Body, string Headers)> ProvisionAsync(string callerTenant,
        string target, string? roles = DefaultRoles)
        => _host.SendAsync(HttpMethod.Post,
            $"/{SystemTenant}/v1/adminProvisioning/{target}/provisionCurrentUser", callerTenant, roles);

    [Theory]
    [InlineData("a-child")]
    [InlineData("a-grandchild")]
    [InlineData("a")]
    public async Task RoleHolder_ProvisioningIntoOwnTenantOrDescendant_Succeeds(string target)
    {
        await StartAsync();

        var result = await ProvisionAsync("a", target);

        result.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal(target);
    }

    [Theory]
    [InlineData("s", "sibling")]
    [InlineData("s-child", "descendant of a sibling")]
    [InlineData("u", "unrelated tenant")]
    [InlineData(SystemTenant, "the system tenant")]
    [InlineData("does-not-exist", "unknown tenant")]
    public async Task RoleHolder_ProvisioningOutsideTheOwnSubtree_IsForbidden_AndTheActionNeverRuns(string target,
        string _)
    {
        await StartAsync();

        var result = await ProvisionAsync("a", target);

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _registry.ActionReachedFor.Should().BeEmpty();
        _systemContext.ReceivedCalls().Should().BeEmpty("nothing of the target tenant may be touched");
        _filterLog.AllText.Should().Contain("Admin provisioning denied, target outside the caller's tenant subtree");
    }

    [Fact]
    public async Task UnknownTarget_IsIndistinguishableFromAForeignTarget()
    {
        await StartAsync();

        var sibling = await ProvisionAsync("a", "s");
        var descendantOfSibling = await ProvisionAsync("a", "s-child");
        var unrelated = await ProvisionAsync("a", "u");
        var unknown = await ProvisionAsync("a", "does-not-exist");

        foreach (var other in new[] { descendantOfSibling, unrelated, unknown })
        {
            other.Status.Should().Be(sibling.Status);
            other.Body.Should().Be(sibling.Body);
            other.Headers.Should().Be(sibling.Headers);
        }
    }

    [Fact]
    public async Task SystemCaller_Succeeds_ForAnyRegisteredTenant()
    {
        await StartAsync();

        foreach (var target in new[] { "a", "a-grandchild", "s", "s-child", "u" })
        {
            (await ProvisionAsync(SystemTenant, target)).Status.Should().Be(HttpStatusCode.Created, target);
        }
    }

    [Fact]
    public async Task SystemCaller_OnAnUnknownTenant_PassesTheFilter_AndTheActionAnswers404()
    {
        // Documents the current behavior (live repro AB#4824): the system caller is allowed to learn that a
        // tenant does not exist; the filter lets it through and the action answers 404.
        await StartAsync();

        var result = await ProvisionAsync(SystemTenant, "does-not-exist");

        result.Status.Should().Be(HttpStatusCode.NotFound);
        result.Body.Should().Contain("not found");
        _filterLog.AllText.Should().BeEmpty();
        await _systemContext.Received(1).TryFindTenantRepositoryAsync("does-not-exist");
    }

    [Fact]
    public async Task TenantCreatedBelowTheCaller_ImmediatelyCountsAsDescendant()
    {
        // CreateTenant-then-provision in one step (octo-cli Create): the new tenant is registered below the
        // caller's tenant first, the provisioning call follows.
        await StartAsync();
        (await ProvisionAsync("a", "a-new")).Status.Should().Be(HttpStatusCode.Forbidden, "not created yet");

        _registry.AddTenant("a-new", "a");
        var result = await ProvisionAsync("a", "a-new");

        result.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal("a-new");
    }

    [Fact]
    public async Task Policy_And_Filter_ApplyTogether_RolelessCallerIsStoppedByThePolicyFirst()
    {
        await StartAsync();

        // roleless caller, even towards its own descendant
        var result = await ProvisionAsync("a", "a-child", roles: null);

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _policyLog.AllText.Should().Contain("required role missing");
        _filterLog.AllText.Should().BeEmpty("the filter never runs when the policy already denied");
        _registry.DescendantLookups.Should().Be(0);
        _registry.ActionReachedFor.Should().BeEmpty();
    }

    [Fact]
    public async Task Policy_And_Filter_ApplyTogether_RoleHolderIsStoppedByTheFilter()
    {
        // Isolates the filter: the policy lets the role holder through, so the 403 is the filter's.
        await StartAsync();

        var result = await ProvisionAsync("a", "u");

        result.Status.Should().Be(HttpStatusCode.Forbidden);
        _policyLog.AllText.Should().BeEmpty("the role policy was satisfied");
        _filterLog.AllText.Should().Contain("target outside the caller's tenant subtree");
        _registry.DescendantLookups.Should().Be(1);
    }

    [Fact]
    public async Task WarnMode_RoleHolderOutsideTheSubtree_PassesThrough_AndLogsTheWarning()
    {
        // Documents the dependency of the AB#4824/AB#5859 fix on RoleEnforcement: in Warn the filter only logs.
        await StartAsync(IdentityApiRoleEnforcementMode.Warn);

        var sibling = await ProvisionAsync("a", "s");
        var unrelated = await ProvisionAsync("a", "u");

        sibling.Status.Should().Be(HttpStatusCode.Created);
        unrelated.Status.Should().Be(HttpStatusCode.Created);
        _registry.ActionReachedFor.Should().Equal("s", "u");
        _filterLog.AllText.Should().Contain(
            "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn");
        _filterLog.Messages.Should().HaveCount(2);
    }

    [Fact]
    public async Task WarnMode_RolelessCaller_PassesThePolicyToo_AndLogsBothWarnings()
    {
        await StartAsync(IdentityApiRoleEnforcementMode.Warn);

        var result = await ProvisionAsync("a", "u", roles: null);

        result.Status.Should().Be(HttpStatusCode.Created);
        _policyLog.AllText.Should().Contain("allowed by RoleEnforcement=Warn");
        _filterLog.AllText.Should().Contain(
            "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn");
    }
}
