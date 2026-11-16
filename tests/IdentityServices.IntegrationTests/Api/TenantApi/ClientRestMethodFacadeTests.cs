using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     The client methods of System.Identity 3.3.0 (<c>Client.SetRoles</c>, <c>AddRole</c>, <c>RemoveRole</c>,
///     <c>ApplyOverlayUris</c> and the static <c>CleanOverlayEntries</c>) and their REST facades in <c>ClientsController</c>.
///     Real MongoDB, real identity host. The REST contract itself stays covered by <see cref="ClientRoleChangeGuardTests" />
///     and the controller unit tests; these tests prove per method that REST and the method called through the dispatcher
///     (the GraphQL path) leave the same end state, that the facade runs the method in-process outside the request with one
///     <c>Identity.Method</c> event per REST call, the escalation guard of the user role methods, and the abuse cases.
/// </summary>
public class ClientRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";
    private const string UserManagement = "UserManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public ClientRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public static TheoryData<string> Endpoints => new() { "setRoles", "addRole", "removeRole", "applyOverlay", "clean" };

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region REST runs the method

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task EveryEndpoint_RunsItsMethodInProcess_OutsideTheRequest_WithExactlyOneIdentityMethodEvent(
        string endpoint)
    {
        var host = Host();
        var target = await NewClientAsync();
        var role = await NewRoleAsync();
        var caller = FacadeCaller.User(TenantManagement);
        using var client = caller.Client(host);
        var ct = TestContext.Current.CancellationToken;
        if (endpoint is "removeRole")
        {
            await AssignAsync(target, role);
        }

        if (endpoint is "clean")
        {
            await ApplyOverlayDirectlyAsync(target, "overlay-clean", "https://clean.example/");
        }

        var (response, methodId, eventTarget) = endpoint switch
        {
            "setRoles" => (await client.PutAsJsonAsync(TenantApiUrl($"clients/{target.ClientId}/roles"),
                new[] { await RoleIdAsync(role) }, ct), SystemIdentityCkIds.ClientSetRolesMethodId, target.RtId.ToString()),
            "addRole" => (await client.PutAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{role}"), null, ct),
                SystemIdentityCkIds.ClientAddRoleMethodId, target.RtId.ToString()),
            "removeRole" => (await client.DeleteAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{role}"), ct),
                SystemIdentityCkIds.ClientRemoveRoleMethodId, target.RtId.ToString()),
            "applyOverlay" => (await client.PostAsJsonAsync(TenantApiUrl($"clients/{target.ClientId}/overlayUris"),
                    new { overlayName = "overlay-test", redirectUris = new[] { "https://overlay.example/" } }, ct),
                SystemIdentityCkIds.ClientApplyOverlayUrisMethodId, target.RtId.ToString()),
            _ => (await client.DeleteAsync(TenantApiUrl("clients/cleanOverlayEntries?overlayName=overlay-clean"), ct),
                SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId, (string?)null)
        };

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var events = _audit.For(methodId, eventTarget);
        events.Should().ContainSingle();
        events[0]["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        events[0]["callerSubject"].Should().Be(caller.Subject);
        _probe.Calls.Should().BeGreaterThan(0, "the method ran through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
    }

    [Fact]
    public void TheClientMethods_RunInThisProcess()
    {
        var transport = Host().Services.GetRequiredService<ICkInProcessMethodTransport>();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.ClientSetRolesMethodId, SystemIdentityCkIds.ClientAddRoleMethodId,
                     SystemIdentityCkIds.ClientRemoveRoleMethodId, SystemIdentityCkIds.ClientApplyOverlayUrisMethodId,
                     SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId
                 })
        {
            transport.CanHandle(methodId).Should().BeTrue(methodId);
        }
    }

    #endregion

    #region Same end state as REST, per method

    [Fact]
    public async Task SetRoles_RestAndMethod_LeaveTheSameDirectRoles()
    {
        var host = Host();
        var (kept, added, dropped) = (await NewRoleAsync(), await NewRoleAsync(), await NewRoleAsync());
        var restClient = await NewClientAsync();
        var methodClient = await NewClientAsync();
        foreach (var c in new[] { restClient, methodClient })
        {
            await AssignAsync(c, kept);
            await AssignAsync(c, dropped);
        }

        using var client = FacadeCaller.User(TenantManagement).Client(host);
        (await client.PutAsJsonAsync(TenantApiUrl($"clients/{restClient.ClientId}/roles"),
            new[] { await RoleIdAsync(kept), await RoleIdAsync(added) }, TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientSetRolesMethodId, methodClient.RtId.ToString(),
            new ClientSetRolesParameters { RoleNames = [kept, added] })).Success.Should().BeTrue();

        var expected = new[] { await RoleIdAsync(kept), await RoleIdAsync(added) }.Order().ToArray();
        (await DirectRoleIdsAsync(restClient)).Should().Equal(expected);
        (await DirectRoleIdsAsync(methodClient)).Should().Equal(expected);
    }

    [Fact]
    public async Task AddRoleAndRemoveRole_RestAndMethod_LeaveTheSameDirectRoles_AndAreIdempotent()
    {
        var host = Host();
        var role = await NewRoleAsync();
        var restClient = await NewClientAsync();
        var methodClient = await NewClientAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        for (var i = 0; i < 2; i++)
        {
            (await client.PutAsync(TenantApiUrl($"clients/{restClient.ClientId}/roles/{role}"), null, ct)).StatusCode
                .Should().Be(HttpStatusCode.OK);
            (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientAddRoleMethodId, methodClient.RtId.ToString(),
                new ClientAddRoleParameters { RoleName = role })).Success.Should().BeTrue();
        }

        (await DirectRoleIdsAsync(restClient)).Should().Equal(await RoleIdAsync(role));
        (await DirectRoleIdsAsync(methodClient)).Should().Equal(await RoleIdAsync(role));

        for (var i = 0; i < 2; i++)
        {
            (await client.DeleteAsync(TenantApiUrl($"clients/{restClient.ClientId}/roles/{role}"), ct)).StatusCode
                .Should().Be(HttpStatusCode.OK);
            (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientRemoveRoleMethodId,
                methodClient.RtId.ToString(), new ClientRemoveRoleParameters { RoleName = role })).Success.Should()
                .BeTrue();
        }

        (await DirectRoleIdsAsync(restClient)).Should().BeEmpty();
        (await DirectRoleIdsAsync(methodClient)).Should().BeEmpty();

        // unknown role: REST add 404 / remove 200 (unchanged contract), the method ROLE_NOT_FOUND for both
        (await client.PutAsync(TenantApiUrl($"clients/{restClient.ClientId}/roles/no-such-role"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await client.DeleteAsync(TenantApiUrl($"clients/{restClient.ClientId}/roles/no-such-role"), ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientRemoveRoleMethodId, methodClient.RtId.ToString(),
                new ClientRemoveRoleParameters { RoleName = "no-such-role" })).Error!.Code.Should()
            .Be(UserRoleMethodErrors.RoleNotFound);
    }

    [Fact]
    public async Task ApplyOverlayUrisAndClean_RestAndMethod_LeaveTheSameUriLists_AndAnswerTheSameCounts()
    {
        var host = Host();
        var overlay = $"ov-{Guid.NewGuid():N}"[..20];
        var restClient = await NewClientAsync();
        var methodClient = await NewClientAsync();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var uris = new[] { "https://a.example/", "https://b.example/" };

        var rest = await client.PostAsJsonAsync(TenantApiUrl($"clients/{restClient.ClientId}/overlayUris"),
            new { overlayName = overlay, redirectUris = uris, allowedCorsOrigins = new[] { "https://a.example" } }, ct);
        rest.StatusCode.Should().Be(HttpStatusCode.OK);
        var restBody = (await rest.Content.ReadFromJsonAsync<ApplyOverlayUrisResultDto>(ct))!;
        var method = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientApplyOverlayUrisMethodId,
            methodClient.RtId.ToString(), new ClientApplyOverlayUrisParameters
            {
                OverlayName = overlay, RedirectUris = uris.ToList(), AllowedCorsOrigins = ["https://a.example"]
            });
        method.Success.Should().BeTrue();
        using var methodBody = JsonDocument.Parse(method.ResultJson!);
        restBody.RedirectUris.Added.Should().Be(2);
        methodBody.RootElement.GetProperty("redirectUrisAdded").GetInt32().Should().Be(restBody.RedirectUris.Added);
        methodBody.RootElement.GetProperty("allowedCorsOriginsAdded").GetInt32().Should()
            .Be(restBody.AllowedCorsOrigins.Added);

        var restStored = await LoadAsync(restClient);
        var methodStored = await LoadAsync(methodClient);
        Shape(methodStored.RedirectUris).Should().Equal(Shape(restStored.RedirectUris));
        Shape(methodStored.AllowedCorsOrigins).Should().Equal(Shape(restStored.AllowedCorsOrigins));
        restStored.RedirectUris.Should().OnlyContain(e => e.Source == ClientUriSources.OverlayPrefix + overlay);

        // clean: the REST call removes the overlay from both clients; the method then finds nothing left
        var cleaned = await client.DeleteAsync(TenantApiUrl($"clients/cleanOverlayEntries?overlayName={overlay}"), ct);
        cleaned.StatusCode.Should().Be(HttpStatusCode.OK);
        (await cleaned.Content.ReadFromJsonAsync<CleanOverlayEntriesResultDto>(ct))!.TotalEntriesRemoved.Should().Be(6);
        var again = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId, null,
            new ClientCleanOverlayEntriesParameters { OverlayName = overlay });
        again.Success.Should().BeTrue();
        JsonDocument.Parse(again.ResultJson!).RootElement.GetProperty("totalEntriesRemoved").GetInt32().Should().Be(0);
        (await LoadAsync(restClient)).RedirectUris.Should().BeEmpty();
        (await LoadAsync(methodClient)).RedirectUris.Should().BeEmpty();
    }

    #endregion

    #region Guard and abuse cases

    [Fact]
    public async Task GrantingABuiltInRoleTheCallerDoesNotHold_IsRefusedExactlyAsOnTheUserRoleMethods()
    {
        var host = Host();
        var builtIn = await NewRoleAsync(builtIn: true);
        var target = await NewClientAsync();
        var user = await CreateTestUserAsync(NewName("ucf"));
        var caller = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [TenantManagement, UserManagement],
            ["octo_api"]);

        var clientRefusal = await DispatchAsync(host, caller, SystemIdentityCkIds.ClientAddRoleMethodId,
            target.RtId.ToString(), new ClientAddRoleParameters { RoleName = builtIn });
        var userRefusal = await DispatchAsync(host, caller, SystemIdentityCkIds.UserAddRoleMethodId,
            user.RtId.ToString(), new UserAddRoleParameters { RoleName = builtIn }, IdentityMethodFacade.UserCkTypeId);
        var setRolesRefusal = await DispatchAsync(host, caller, SystemIdentityCkIds.ClientSetRolesMethodId,
            target.RtId.ToString(), new ClientSetRolesParameters { RoleNames = [builtIn] });

        foreach (var refusal in new[] { clientRefusal, setRolesRefusal })
        {
            refusal.Error!.Code.Should().Be(userRefusal.Error!.Code).And.Be(CkMethodErrorCodes.MethodForbidden);
            // the same reason and role names; only the methodId parameter names the other method
            refusal.Error.Parameters.Where(p => p.Key != "methodId").Should()
                .BeEquivalentTo(userRefusal.Error.Parameters.Where(p => p.Key != "methodId"));
            refusal.Error.Parameters.Should().Contain("reason", "role-not-held");
        }

        using var client = FacadeCaller.User(TenantManagement, UserManagement).Client(host);
        var rest = await client.PutAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{builtIn}"), null,
            TestContext.Current.CancellationToken);
        rest.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await rest.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code")
            .GetString().Should().Be("role-not-held");
        (await DirectRoleIdsAsync(target)).Should().BeEmpty();
    }

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingChanges()
    {
        var host = Host(enforceTenantGate: true);
        var role = await NewRoleAsync();
        var target = await NewClientAsync();
        var foreign = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [TenantManagement], ["octo_api"])
        {
            IsFromAccessToken = true, TokenTenantId = "othertenantcf"
        };

        var method = await DispatchAsync(host, foreign, SystemIdentityCkIds.ClientAddRoleMethodId,
            target.RtId.ToString(), new ClientAddRoleParameters { RoleName = role });
        var clean = await DispatchAsync(host, foreign, SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId, null,
            new ClientCleanOverlayEntriesParameters());

        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        clean.Error!.Parameters.Should().Contain("reason", "tenant-not-allowed");
        using var client = (FacadeCaller.User(TenantManagement) with { TokenTenant = "othertenantcf" }).Client(host);
        (await client.PutAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{role}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await DirectRoleIdsAsync(target)).Should().BeEmpty();
        _audit.For(SystemIdentityCkIds.ClientAddRoleMethodId, target.RtId.ToString()).Should().BeEmpty();
    }

    [Fact]
    public async Task ACallerWithoutTheDeclaredRole_IsRefused_AndNothingChanges()
    {
        var host = Host();
        var role = await NewRoleAsync();
        var target = await NewClientAsync();
        var outsider = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), ["CommunicationManagement"], ["octo_api"]);

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (SystemIdentityCkIds.ClientAddRoleMethodId, new ClientAddRoleParameters { RoleName = role }),
                     (SystemIdentityCkIds.ClientSetRolesMethodId, new ClientSetRolesParameters { RoleNames = [role] }),
                     (SystemIdentityCkIds.ClientApplyOverlayUrisMethodId, new ClientApplyOverlayUrisParameters
                         { OverlayName = "overlay-test", RedirectUris = ["https://x.example/"] })
                 })
        {
            var refusal = await DispatchAsync(host, outsider, methodId, target.RtId.ToString(), parameters);
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden, methodId);
        }

        using var client = FacadeCaller.User("CommunicationManagement").Client(host);
        (await client.PutAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{role}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await DirectRoleIdsAsync(target)).Should().BeEmpty();
        (await LoadAsync(target)).RedirectUris.Should().BeEmpty();
    }

    [Fact]
    public async Task RemovingAHeldRoleTheCallerCannotRead_Is403_AndTheRoleStays()
    {
        var host = Host(denyReads: true);
        var role = await NewRoleAsync();
        var target = await NewClientAsync();
        await AssignAsync(target, role);
        using var client = FacadeCaller.User(TenantManagement).Client(host);

        var response = await client.DeleteAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{role}"),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        problem.GetProperty("code").GetString().Should().Be(CkMethodErrorCodes.MethodForbidden);
        problem.GetProperty("parameters").GetProperty("reason").GetString().Should().Be("data-permission");
        (await DirectRoleIdsAsync(target)).Should().Equal(await RoleIdAsync(role));
    }

    [Fact]
    public async Task TheAuditRecordsTheRolesAsStored()
    {
        var host = Host();
        var (a, b) = (await NewRoleAsync(), await NewRoleAsync());
        var target = await NewClientAsync();
        await AssignAsync(target, a);
        using var client = FacadeCaller.User(TenantManagement).Client(host);

        (await client.PutAsync(TenantApiUrl($"clients/{target.ClientId}/roles/{b}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);

        var record = _audit.For(SystemIdentityCkIds.ClientAddRoleMethodId, target.RtId.ToString()).Should()
            .ContainSingle().Subject;
        record["rolesBefore"].Should().Be(a);
        record["rolesAfter"].Split(',').Should().BeEquivalentTo(a, b);
    }

    #endregion

    #region Helpers

    private static CkMethodPrincipal Admin() =>
        new(Guid.NewGuid().ToString("N"), [TenantManagement, UserManagement], ["octo_api"]);

    private WebApplicationFactory<Program> Host(bool enforceTenantGate = false, bool denyReads = false)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (enforceTenantGate)
            {
                b.UseSetting("TenantAuthorization:UserTokenEnforcement", "Enforce");
            }

            b.ConfigureTestServices(services =>
            {
                services.AddSingleton(_audit.Events);
                services.AddSingleton<ICkInProcessAmbientStateProbe>(_probe);
                services.AddSingleton<IStartupFilter, MarkRequestsStartupFilter>();
                if (denyReads)
                {
                    services.AddSingleton(FacadeDataPolicy.DenyAllReads());
                }
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, string? targetRtId, object parameters, string ckTypeId = IdentityMethodFacade.ClientCkTypeId)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? TestPlatformRoles.Prefix + "bcf" : "ccf");
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

    private async Task<string> RoleIdAsync(string name)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name))!.RtId
            .ToString();
    }

    private Task<RtClient> NewClientAsync() => CreateTestClientAsync(NewName("ccf"));

    private async Task AssignAsync(RtClient client, string roleName)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().AddRoleAsync(client.RtId, roleName);
    }

    private async Task<string[]> DirectRoleIdsAsync(RtClient client)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().GetDirectRoleIdsAsync(client.RtId))
            .Order().ToArray();
    }

    private async Task<RtClient> LoadAsync(RtClient client)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(client.ClientId))!;
    }

    private async Task ApplyOverlayDirectlyAsync(RtClient client, string overlay, string uri)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().MutateAsync(client.ClientId, current =>
        {
            current.RedirectUris.Add(new RtClientUriEntryRecord
                { Uri = uri, Source = ClientUriSources.OverlayPrefix + overlay });
            return true;
        });
    }

    private static string[] Shape(IEnumerable<RtClientUriEntryRecord> entries) =>
        entries.Select(e => $"{e.Source}|{e.Uri}").ToArray();

    #endregion
}
