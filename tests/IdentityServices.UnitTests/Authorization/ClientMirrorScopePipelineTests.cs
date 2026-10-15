using System.Net;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using NSubstitute;
using Xunit;
using static IdentityServices.UnitTests.Authorization.ScopedTenantApiHost;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#6758: the client mirror actions that name a child tenant — <c>provisionInTenant?childTenantId=</c>
///     (query), <c>mirrors/{childTenantId}/secret</c> and <c>DELETE mirrors/{childTenantId}</c> (route) — only reach
///     the caller's own subtree. Real routing, controller, policy and filter against a fake tenant registry
///     (see <see cref="ScopedTenantApiHost" />).
/// </summary>
public class ClientMirrorScopePipelineTests : IAsyncDisposable
{
    private ScopedTenantApiHost _host = null!;

    public async ValueTask DisposeAsync()
    {
        if (_host != null)
        {
            await _host.DisposeAsync();
        }
    }

    private async Task StartAsync(IdentityApiRoleEnforcementMode mode = IdentityApiRoleEnforcementMode.Enforce)
        => _host = await ScopedTenantApiHost.StartAsync(mode, typeof(ClientMirrorController));

    public static TheoryData<string> Actions => new() { "provisionInTenant", "secret", "delete" };

    private static (HttpMethod Method, string Url) Request(string action, string callerTenant, string child) =>
        action switch
        {
            "provisionInTenant" => (HttpMethod.Post,
                $"/{callerTenant}/v1/clients/ci/mirrors/provisionInTenant?childTenantId={child}"),
            "secret" => (HttpMethod.Post, $"/{callerTenant}/v1/clients/ci/mirrors/{child}/secret"),
            _ => (HttpMethod.Delete, $"/{callerTenant}/v1/clients/ci/mirrors/{child}")
        };

    private Task<(HttpStatusCode Status, string Body, string Headers)> CallAsync(string action, string callerTenant,
        string child, string? roles = DefaultRoles)
    {
        var (method, url) = Request(action, callerTenant, child);
        return _host.SendAsync(method, url, callerTenant, roles);
    }

    private static HttpStatusCode Allowed(string action) =>
        action == "delete" ? HttpStatusCode.NoContent : HttpStatusCode.Created;

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task OwnTenantAndDescendants_AreAllowed(string action)
    {
        await StartAsync();

        foreach (var child in new[] { "a-child", "a-grandchild" })
        {
            (await CallAsync(action, "a", child)).Status.Should().Be(Allowed(action), child);
        }

        _host.Registry.ActionReachedFor.Should().Equal("a-child", "a-grandchild");
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task SiblingSiblingDescendantUnrelatedSystemAndUnknown_AreForbidden_AndTheActionNeverRuns(
        string action)
    {
        await StartAsync();

        foreach (var child in new[] { "s", "s-child", "u", SystemTenant, "does-not-exist" })
        {
            (await CallAsync(action, "a", child)).Status.Should().Be(HttpStatusCode.Forbidden, child);
        }

        _host.Registry.ActionReachedFor.Should().BeEmpty();
        _host.SystemContext.ReceivedCalls().Should().BeEmpty("nothing of the target tenant may be touched");
        _host.FilterLog.AllText.Should().Contain("target outside the caller's tenant subtree");
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task DenialsAreIndistinguishable_NoExistenceDisclosure(string action)
    {
        await StartAsync();

        var sibling = await CallAsync(action, "a", "s");
        foreach (var child in new[] { "s-child", "u", SystemTenant, "does-not-exist" })
        {
            var other = await CallAsync(action, "a", child);
            other.Status.Should().Be(sibling.Status);
            other.Body.Should().Be(sibling.Body);
            other.Headers.Should().Be(sibling.Headers);
        }
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task SystemCaller_ReachesEveryRegisteredTenant(string action)
    {
        await StartAsync();

        foreach (var child in new[] { "a", "a-grandchild", "s", "s-child", "u" })
        {
            (await CallAsync(action, SystemTenant, child)).Status.Should().Be(Allowed(action), child);
        }
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task RolelessCaller_IsStoppedByThePolicyFirst(string action)
    {
        await StartAsync();

        (await CallAsync(action, "a", "a-child", roles: null)).Status.Should().Be(HttpStatusCode.Forbidden);

        _host.PolicyLog.AllText.Should().Contain("required role missing");
        _host.FilterLog.AllText.Should().BeEmpty();
        _host.Registry.DescendantLookups.Should().Be(0);
    }

    [Fact]
    public async Task ProvisionInTenant_TheQueryValueIsChecked_NotJustTheRoute()
    {
        // The reported hole: the child is a query parameter, so a route-only check never saw it.
        await StartAsync();

        (await CallAsync("provisionInTenant", "a", "u")).Status.Should().Be(HttpStatusCode.Forbidden);

        // A second childTenantId value must not smuggle a foreign tenant past the check.
        var (status, _, _) = await _host.SendAsync(HttpMethod.Post,
            "/a/v1/clients/ci/mirrors/provisionInTenant?childTenantId=a-child&childTenantId=u", "a");
        status.Should().Be(HttpStatusCode.Forbidden);
        _host.Registry.ActionReachedFor.Should().BeEmpty();
    }

    [Fact]
    public async Task ProvisionInTenant_WithoutAChildTenant_NeverReachesTheAction()
    {
        await StartAsync();

        var (status, _, _) = await _host.SendAsync(HttpMethod.Post,
            "/a/v1/clients/ci/mirrors/provisionInTenant", "a");

        // The [ApiController] model validation (required query value) answers before the filter would.
        status.Should().Be(HttpStatusCode.BadRequest);
        _host.Registry.ActionReachedFor.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Actions))]
    public async Task WarnMode_PassesThrough_AndLogsTheWarning(string action)
    {
        await StartAsync(IdentityApiRoleEnforcementMode.Warn);

        (await CallAsync(action, "a", "u")).Status.Should().Be(Allowed(action));

        _host.FilterLog.AllText.Should().Contain(
            "Admin provisioning outside the caller's tenant subtree allowed by RoleEnforcement=Warn");
    }
}
