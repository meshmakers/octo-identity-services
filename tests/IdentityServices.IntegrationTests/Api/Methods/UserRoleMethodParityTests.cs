using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7776: the parity table. Every guard of the REST role endpoints of <c>UsersController</c> is run against the real REST
///     pipeline and against the method handler with the same situation; both must refuse (or allow) alike and leave the same
///     roles behind. The one known difference is <c>SetRoles</c> with an unknown role (REST has removed the roles already).
/// </summary>
public class UserRoleMethodParityTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";
    private const string Missing = "NoSuchRole7776";

    public UserRoleMethodParityTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    // guard: the target user does not exist
    [Fact]
    public async Task Guard_UnknownUser()
    {
        var role = await NewRoleAsync();
        var rest = await RestAddAsync($"nouser-{Guid.NewGuid():N}", role);
        var method = await AddAsync("507f1f77bcf86cd799439011", Admin(), role);

        rest.StatusCode.Should().Be(HttpStatusCode.NotFound);
        method.Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    // guard: the role does not exist
    [Fact]
    public async Task Guard_UnknownRole_AddAndRemove()
    {
        var (user, _) = await NewUserAsync();

        (await RestAddAsync(user.UserName!, Missing)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await AddAsync(user.RtId.ToString(), Admin(), Missing)).Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await RestRemoveAsync(user.UserName!, Missing)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await RemoveAsync(user.RtId.ToString(), Admin(), Missing)).Failure!.Code.Should().Be("ROLE_NOT_FOUND");
    }

    // guard: AddRole of an assigned role
    [Fact]
    public async Task Guard_RoleAlreadyAssigned()
    {
        var (restUser, role) = await NewUserAsync(assign: true);
        var (methodUser, _) = await NewUserAsync(role, assign: true);

        (await RestAddAsync(restUser.UserName!, role)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await AddAsync(methodUser.RtId.ToString(), Admin(), role)).Failure!.Code.Should().Be("ROLE_ALREADY_ASSIGNED");
        (await RolesAsync(restUser)).Should().Equal(await RolesAsync(methodUser));
    }

    // guard: RemoveRole of a role that is not assigned
    [Fact]
    public async Task Guard_RoleNotAssigned()
    {
        var (restUser, role) = await NewUserAsync();
        var (methodUser, _) = await NewUserAsync(role);

        (await RestRemoveAsync(restUser.UserName!, role)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await RemoveAsync(methodUser.RtId.ToString(), Admin(), role)).Failure!.Code.Should().Be("ROLE_NOT_ASSIGNED");
    }

    // the allowed paths end in the same state
    [Fact]
    public async Task Allowed_AddRemoveAndSet_LeaveTheSameRoles()
    {
        var (restUser, a) = await NewUserAsync();
        var b = await NewRoleAsync();
        var (methodUser, _) = await NewUserAsync(a);

        (await RestAddAsync(restUser.UserName!, a)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await AddAsync(methodUser.RtId.ToString(), Admin(), a)).IsSuccess.Should().BeTrue();
        (await RolesAsync(restUser)).Should().Equal(await RolesAsync(methodUser)).And.Equal(a.ToUpperInvariant());

        (await RestSetAsync(restUser.UserName!, b)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await SetAsync(methodUser.RtId.ToString(), Admin(), b)).IsSuccess.Should().BeTrue();
        (await RolesAsync(restUser)).Should().Equal(await RolesAsync(methodUser)).And.Equal(b.ToUpperInvariant());

        (await RestRemoveAsync(restUser.UserName!, b)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RemoveAsync(methodUser.RtId.ToString(), Admin(), b)).IsSuccess.Should().BeTrue();
        (await RolesAsync(restUser)).Should().BeEmpty();
        (await RolesAsync(methodUser)).Should().BeEmpty();
    }

    // AB#7914: REST validates every role id before it writes, like the method: an unknown role changes nothing
    [Fact]
    public async Task Parity_SetRolesWithAnUnknownRole_ChangesNothing_InBothTransports()
    {
        var (restUser, a) = await NewUserAsync(assign: true);
        var (methodUser, _) = await NewUserAsync(a, assign: true);

        var rest = await RestSetAsync(restUser.UserName!, a, unknownId: "507f1f77bcf86cd799439011");
        var method = await SetAsync(methodUser.RtId.ToString(), Admin(), a, Missing);

        rest.StatusCode.Should().Be(HttpStatusCode.NotFound);
        method.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await RolesAsync(restUser)).Should().Equal(a.ToUpperInvariant());
        (await RolesAsync(methodUser)).Should().Equal(a.ToUpperInvariant());
    }

    // guard: scope and role of the caller
    [Fact]
    public async Task Guard_Caller_NoRole_ReadOnlyScope_AndServiceClient()
    {
        var (restUser, role) = await NewUserAsync();
        var (methodUser, _) = await NewUserAsync(role);

        // no UserManagement
        var noRole = CreateAuthenticatedClient(userId: $"c-{Guid.NewGuid():N}", roles: ["TenantManagement"]);
        (await noRole.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{role}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await AddAsync(methodUser.RtId.ToString(), new CkMethodPrincipal("c", ["TenantManagement"], ["octo_api"]), role))
            .Failure!.Code.Should().Be("METHOD_FORBIDDEN");

        // UserManagement, but only the read-only scope
        var readOnly = CreateAuthenticatedClient(userId: $"c-{Guid.NewGuid():N}", roles: [UserManagement],
            scopes: ["octo_api.read_only"]);
        (await readOnly.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{role}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await AddAsync(methodUser.RtId.ToString(),
            new CkMethodPrincipal("c", [UserManagement], ["octo_api.read_only"]), role)).Failure!.Code
            .Should().Be("METHOD_FORBIDDEN");

        (await RolesAsync(restUser)).Should().BeEmpty();
        (await RolesAsync(methodUser)).Should().BeEmpty();

        // a service client with UserManagement may (client roles, AB#4183)
        var service = CreateAuthenticatedClient(userId: $"c-{Guid.NewGuid():N}", roles: [UserManagement]);
        service.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, $"svc-{Guid.NewGuid():N}");
        (await service.PutAsync(TenantApiUrl($"users/{restUser.UserName}/roles/{role}"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await AddAsync(methodUser.RtId.ToString(), new CkMethodPrincipal(null, [UserManagement], ["octo_api"], "svc"),
            role)).IsSuccess.Should().BeTrue();
        (await RolesAsync(restUser)).Should().Equal(await RolesAsync(methodUser));
    }

    // AB#7914: a self grant is refused alike by REST and by the methods (see RoleChangeGuardTests for the full table)
    [Fact]
    public async Task Parity_SelfGrantOfABuiltInRole_IsRefusedAlike()
    {
        var (admin, _) = await NewUserAsync();
        var self = CreateAuthenticatedClient(userId: admin.RtId.ToString(), userName: admin.UserName!,
            roles: [UserManagement, "TenantManagement"]);

        (await self.PutAsync(TenantApiUrl($"users/{admin.UserName}/roles/TenantManagement"), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var method = await AddAsync(admin.RtId.ToString(),
            new CkMethodPrincipal(admin.RtId.ToString(), [UserManagement, "TenantManagement"], ["octo_api"]),
            "TenantManagement");
        method.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        method.Failure.Parameters.Should().Contain("reason", "self-grant");
        (await RolesAsync(admin)).Should().BeEmpty();
    }

    #region Helpers

    private static CkMethodPrincipal Admin() => new(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);

    private async Task<string> NewRoleAsync()
    {
        var name = $"p7776_{Guid.NewGuid():N}";
        using var scope = CreateScope();
        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>()
            .CreateAsync(new RtRoleBuilder().WithName(name).Build())).Succeeded.Should().BeTrue();
        return name;
    }

    private async Task<(RtUser User, string Role)> NewUserAsync(string? role = null, bool assign = false)
    {
        role ??= await NewRoleAsync();
        var user = await CreateTestUserAsync($"pu7776_{Guid.NewGuid():N}");
        if (assign)
        {
            using var scope = CreateScope();
            (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>()
                .AddToRoleAsync(user, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
        }

        return (user, role);
    }

    private async Task<string[]> RolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        var store = (OctoUserStore)scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
        return (await store.GetDirectRolesAsync(user)).Select(r => r.ToUpperInvariant()).Order().ToArray();
    }

    private HttpClient AdminClient() =>
        CreateAuthenticatedClient(userId: $"admin-{Guid.NewGuid():N}", roles: [UserManagement]);

    private Task<HttpResponseMessage> RestAddAsync(string userName, string role) =>
        AdminClient().PutAsync(TenantApiUrl($"users/{userName}/roles/{role}"), null, TestContext.Current.CancellationToken);

    private Task<HttpResponseMessage> RestRemoveAsync(string userName, string role) =>
        AdminClient().DeleteAsync(TenantApiUrl($"users/{userName}/roles/{role}"), TestContext.Current.CancellationToken);

    private async Task<HttpResponseMessage> RestSetAsync(string userName, string role, string? unknownId = null)
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var ids = new List<string>();
        if (unknownId != null)
        {
            ids.Add(unknownId); // first: REST has removed the direct roles when it reaches it
        }

        ids.Add((await roleManager.FindByNameAsync(role))!.RtId.ToString());

        return await AdminClient().PutAsJsonAsync(TenantApiUrl($"users/{userName}/roles"), ids,
            TestContext.Current.CancellationToken);
    }

    private Task<CkMethodOutcome> SetAsync(string target, CkMethodPrincipal principal, params string[] roles) =>
        InvokeAsync<UserSetRolesHandler, UserSetRolesParameters>(target, principal,
            new UserSetRolesParameters { RoleNames = roles }, SystemIdentityCkIds.UserSetRolesMethodId);

    private Task<CkMethodOutcome> AddAsync(string target, CkMethodPrincipal principal, string role) =>
        InvokeAsync<UserAddRoleHandler, UserAddRoleParameters>(target, principal,
            new UserAddRoleParameters { RoleName = role }, SystemIdentityCkIds.UserAddRoleMethodId);

    private Task<CkMethodOutcome> RemoveAsync(string target, CkMethodPrincipal principal, string role) =>
        InvokeAsync<UserRemoveRoleHandler, UserRemoveRoleParameters>(target, principal,
            new UserRemoveRoleParameters { RoleName = role }, SystemIdentityCkIds.UserRemoveRoleMethodId);

    private async Task<CkMethodOutcome> InvokeAsync<THandler, TParameters>(string target, CkMethodPrincipal principal,
        TParameters parameters, string methodId)
        where THandler : ICkMethodHandler<TParameters> where TParameters : class
    {
        using var scope = CreateScope();
        var handler = ActivatorUtilities.CreateInstance<THandler>(scope.ServiceProvider);
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = "System.Identity/User",
            TargetRtId = target,
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
            ParametersJson = "{}"
        };
        return await handler.HandleAsync(new CkMethodContext<TParameters>(request, parameters)
        {
            CallerPrincipal = principal
        }, TestContext.Current.CancellationToken);
    }

    #endregion
}
