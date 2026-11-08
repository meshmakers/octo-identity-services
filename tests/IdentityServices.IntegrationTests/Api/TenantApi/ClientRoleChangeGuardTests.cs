using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#7928: a tenant administrator cannot give a client built-in roles they do not hold and then act as that client.
///     The REST client role endpoints (<c>PUT clients/{id}/roles</c>, <c>PUT clients/{id}/roles/{roleName}</c>) run the
///     "grant only what you hold" rule of <c>IRoleChangeGuard</c> (AB#7914): built-in roles only, custom roles free, removals
///     never judged, 403 <c>role-not-held</c> problem answer, audited as <c>Identity.RoleChangeRefused</c>. Real MongoDB, real
///     identity host. The method transport (client into a group via <c>Group.AddMember</c>) is pinned by
///     <c>GroupMethodTests.AddMember_AClientIntoAGroupWithABuiltInRoleTheCallerLacks_IsRefused_RoleNotHeld</c>; the bus path
///     (client mirroring, <c>DistClientDto.AssignedRoleNames</c>) by <c>ServiceAccountClientProvisioningIntegrationTests</c>.
/// </summary>
public class ClientRoleChangeGuardTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";

    private readonly WebApplicationFactory<Program> _host;
    private readonly List<string> _audit = [];

    public ClientRoleChangeGuardTests(CustomWebApplicationFactory factory) : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
                Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_audit)
                {
                    _audit.Add(call.ArgAt<string>(2));
                }
            });
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services => services.AddSingleton(events)));
    }

    /// <summary>An undisposed derived host keeps its configuration file watchers (inotify limit on the CI agents).</summary>
    public void Dispose() => _host.Dispose();

    #region Grant only what you hold

    [Fact]
    public async Task AddRole_ABuiltInRoleTheCallerLacks_IsRefused_RoleNotHeld_AndNothingIsWritten()
    {
        var client = await NewClientAsync();
        var notHeld = await NewRoleAsync(builtIn: true);

        var response = await PutAsync(User(TenantManagement), $"clients/{client.ClientId}/roles/{notHeld}");

        var problem = await AssertProblemAsync(response, HttpStatusCode.Forbidden, "role-not-held");
        problem.GetProperty("roleNames").EnumerateArray().Select(e => e.GetString()).Should().Equal(notHeld);
        (await DirectRoleIdsAsync(client)).Should().BeEmpty();
    }

    [Fact]
    public async Task AddRole_AHeldBuiltInRole_OrACustomRole_Succeeds()
    {
        var client = await NewClientAsync();
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var caller = User(TenantManagement, held);

        (await PutAsync(caller, $"clients/{client.ClientId}/roles/{held}")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutAsync(caller, $"clients/{client.ClientId}/roles/{custom}")).StatusCode.Should().Be(HttpStatusCode.OK);

        (await DirectRoleIdsAsync(client)).Should().BeEquivalentTo(await RoleIdAsync(held), await RoleIdAsync(custom));
    }

    [Fact]
    public async Task AddRole_TheUserManagementRole_ByATenantManagementHolder_IsRefused()
    {
        // the case of the story: TenantManagement (no UserManagement) must not make a client a user administrator
        var client = await NewClientAsync();
        var userManagement = await EnsureBuiltInRoleAsync("UserManagement");

        var single = await PutAsync(User(TenantManagement), $"clients/{client.ClientId}/roles/{userManagement.Name}");
        var replace = await PutJsonAsync(User(TenantManagement), $"clients/{client.ClientId}/roles",
            new[] { userManagement.RtId.ToString() });

        await AssertProblemAsync(single, HttpStatusCode.Forbidden, "role-not-held");
        await AssertProblemAsync(replace, HttpStatusCode.Forbidden, "role-not-held");
        (await DirectRoleIdsAsync(client)).Should().BeEmpty();
    }

    [Fact]
    public async Task SetRoles_WithABuiltInRoleTheCallerLacks_IsRefused_ButHeldAndCustomRolesSucceed()
    {
        var client = await NewClientAsync();
        var notHeld = await NewRoleAsync(builtIn: true);
        var held = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        var caller = User(TenantManagement, held);

        var refused = await PutJsonAsync(caller, $"clients/{client.ClientId}/roles",
            new[] { await RoleIdAsync(notHeld), await RoleIdAsync(held) });
        var allowed = await PutJsonAsync(caller, $"clients/{client.ClientId}/roles",
            new[] { await RoleIdAsync(held), await RoleIdAsync(custom) });

        var problem = await AssertProblemAsync(refused, HttpStatusCode.Forbidden, "role-not-held");
        problem.GetProperty("roleNames").EnumerateArray().Select(e => e.GetString()).Should().Equal(notHeld);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
        (await DirectRoleIdsAsync(client)).Should().BeEquivalentTo(await RoleIdAsync(held), await RoleIdAsync(custom));
    }

    [Fact]
    public async Task OnlyTheDifferenceIsJudged_KeepingOrReAddingANotHeldRole_AndRemovingIt_Succeed()
    {
        var client = await NewClientAsync();
        var notHeld = await NewRoleAsync(builtIn: true);
        var custom = await NewRoleAsync();
        await AssignDirectlyAsync(client, notHeld);
        var caller = User(TenantManagement);

        (await PutJsonAsync(caller, $"clients/{client.ClientId}/roles",
                new[] { await RoleIdAsync(notHeld), await RoleIdAsync(custom) }))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutAsync(caller, $"clients/{client.ClientId}/roles/{notHeld}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DeleteAsync(caller, $"clients/{client.ClientId}/roles/{notHeld}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);

        (await DirectRoleIdsAsync(client)).Should().Equal(await RoleIdAsync(custom));
    }

    [Fact]
    public async Task AClientCredentialsCaller_IsJudgedWithItsOwnRoles()
    {
        var client = await NewClientAsync();
        var builtIn = await NewRoleAsync(builtIn: true);

        var without = await PutAsync(Service(TenantManagement), $"clients/{client.ClientId}/roles/{builtIn}");
        var with = await PutAsync(Service(TenantManagement, builtIn), $"clients/{client.ClientId}/roles/{builtIn}");

        await AssertProblemAsync(without, HttpStatusCode.Forbidden, "role-not-held");
        with.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task SetRoles_WithAnUnknownOrMalformedRoleId_Is404_AndNothingIsWritten()
    {
        var client = await NewClientAsync();
        var custom = await NewRoleAsync();
        var caller = User(TenantManagement);

        var unknown = await PutJsonAsync(caller, $"clients/{client.ClientId}/roles",
            new[] { await RoleIdAsync(custom), OctoObjectId.GenerateNewId().ToString() });
        var malformed = await PutJsonAsync(caller, $"clients/{client.ClientId}/roles",
            new[] { await RoleIdAsync(custom), "not-an-id" });

        unknown.StatusCode.Should().Be(HttpStatusCode.NotFound);
        malformed.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DirectRoleIdsAsync(client)).Should().BeEmpty();
    }

    #endregion

    #region Audit and unchanged flows

    [Fact]
    public async Task EveryRefusal_WritesOneAuditRecord_WithCallerClientReasonAndRoleName_AndNoSecrets()
    {
        var client = await NewClientAsync();
        var notHeld = await NewRoleAsync(builtIn: true);
        var actor = Guid.NewGuid().ToString("N");
        int Count() { lock (_audit) { return _audit.Count; } }
        var before = Count();

        await AssertProblemAsync(await PutAsync(new CallerInfo(actor, null, [TenantManagement]),
            $"clients/{client.ClientId}/roles/{notHeld}"), HttpStatusCode.Forbidden, "role-not-held");

        Count().Should().Be(before + 1);
        string record;
        lock (_audit)
        {
            record = _audit[^1];
        }

        record.Should().Contain("Identity.RoleChangeRefused").And.Contain("role-not-held").And.Contain(actor)
            .And.Contain(client.ClientId!).And.Contain(notHeld);
        record.ToLowerInvariant().Should().NotContain("bearer").And.NotContain("secret=").And.NotContain("test-token");
    }

    [Fact]
    public async Task TheGuard_IsNotOnTheBusOrStorePath_SoClientMirroringStillAssignsRoles()
    {
        // client mirroring / service accounts over the bus write the AssignedRole edge without a caller (AB#5027)
        foreach (var type in new[] { typeof(CreateIdentityDataCommandRequestConsumer), typeof(ClientRoleStore) })
        {
            type.GetConstructors().SelectMany(c => c.GetParameters())
                .Should().NotContain(p => p.ParameterType.Name == "IRoleChangeGuard", type.Name);
        }
    }

    #endregion

    #region Helpers

    private sealed record CallerInfo(string? Subject, string? ClientId, string[] Roles);

    private static CallerInfo User(params string[] roles) => new(Guid.NewGuid().ToString("N"), null, roles);

    private static CallerInfo Service(params string[] roles) =>
        new(null, $"svc7928_{Guid.NewGuid():N}", roles);

    private HttpClient RestClient(CallerInfo caller)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        if (caller.ClientId != null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, caller.ClientId);
        }
        else
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, caller.Subject);
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        }

        foreach (var role in caller.Roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    private async Task<HttpResponseMessage> PutAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.PutAsync(TenantApiUrl(path), null, TestContext.Current.CancellationToken);
    }

    private async Task<HttpResponseMessage> PutJsonAsync<T>(CallerInfo caller, string path, T body)
    {
        using var client = RestClient(caller);
        return await client.PutAsJsonAsync(TenantApiUrl(path), body, TestContext.Current.CancellationToken);
    }

    private async Task<HttpResponseMessage> DeleteAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.DeleteAsync(TenantApiUrl(path), TestContext.Current.CancellationToken);
    }

    private static async Task<JsonElement> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status,
        string code)
    {
        response.StatusCode.Should().Be(status);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/problem+json");
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        json.GetProperty("code").GetString().Should().Be(code);
        return json;
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    /// <summary>A role; a built-in one carries an rtWellKnownName and counts as a platform role (<see cref="TestPlatformRoles" />).</summary>
    private async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? TestPlatformRoles.Prefix + "b7928" : "c7928");
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(name).Build();
        if (builtIn)
        {
            role.RtWellKnownName = name;
        }

        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return name;
    }

    private async Task<RtRole> EnsureBuiltInRoleAsync(string name)
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByNameAsync(name);
        if (role == null)
        {
            role = new RtRoleBuilder().WithName(name).Build();
            role.RtWellKnownName = name;
            (await roleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
        }

        role.RtWellKnownName.Should().NotBeNullOrEmpty($"{name} is a built-in role");
        return role;
    }

    private async Task<string> RoleIdAsync(string name)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name))!.RtId
            .ToString();
    }

    private async Task<RtClient> NewClientAsync() => await CreateTestClientAsync(NewName("c7928"));

    private async Task AssignDirectlyAsync(RtClient client, string roleName)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().AddRoleAsync(client.RtId, roleName);
    }

    private async Task<IReadOnlyList<string>> DirectRoleIdsAsync(RtClient client)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().GetDirectRoleIdsAsync(client.RtId);
    }

    #endregion
}
