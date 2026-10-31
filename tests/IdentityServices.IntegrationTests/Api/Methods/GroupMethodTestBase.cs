using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7779: shared setup of the tests of the <c>Group.*</c> and <c>DataPermission.*</c> methods: real MongoDB, the real
///     identity host (the handlers run in a fresh DI scope without an HTTP request, as on the bus), the REST pipeline of the same
///     host for the parity tests, and a capture of the <c>Identity.Method</c> audit events.
/// </summary>
public abstract class GroupMethodTestBase : IntegrationTestBase, IDisposable
{
    protected const string UserManagement = "UserManagement";

    private readonly List<(string Category, string Level, Dictionary<string, string> Details)> _events = [];
    protected readonly WebApplicationFactory<Program> Host;

    protected GroupMethodTestBase(CustomWebApplicationFactory factory, Action<IServiceCollection>? configure = null)
        : base(factory)
    {
        var events = Substitute.For<IEventRepository>();
        events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
                Arg.Any<RtEventLevelsEnum>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_events)
                {
                    _events.Add((call.ArgAt<string?>(4) ?? "", call.ArgAt<RtEventLevelsEnum>(2).ToString(),
                        (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(d => d.Key, d => d.Value)));
                }
            });
        events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
            Arg.Any<RtEntityId?>())).Do(_ => { });

        Host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddSingleton(events);
            configure?.Invoke(services);
        }));
    }

    /// <summary>Every test instance builds its own derived host; an undisposed host keeps its configuration file watchers.</summary>
    public void Dispose() => Host.Dispose();

    protected static CkMethodPrincipal Admin() => new(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);

    protected static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    #region Audit

    protected IReadOnlyList<(string Category, string Level, Dictionary<string, string> Details)> AuditEvents()
    {
        lock (_events)
        {
            return _events.Where(e => e.Category == "Identity.Method").ToList();
        }
    }

    #endregion

    #region Invocation

    /// <summary>Runs the handler in a new DI scope without an HTTP request, with the principal the host validated.</summary>
    protected async Task<CkMethodOutcome> InvokeAsync<THandler, TParameters>(string methodId, string ckTypeId,
        string target, CkMethodPrincipal? principal, TParameters parameters)
        where THandler : ICkMethodHandler<TParameters> where TParameters : class
    {
        using var scope = Host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<THandler>(scope.ServiceProvider);
        var context = new CkMethodContext<TParameters>(Request(methodId, ckTypeId, target, null, "{}"), parameters)
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, TestContext.Current.CancellationToken);
    }

    protected CkMethodRequest Request(string methodId, string ckTypeId, string target, string? token,
        string parametersJson) =>
        new(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = target,
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
            CallerAccessToken = token,
            ParametersJson = parametersJson
        };

    #endregion

    #region REST

    protected sealed record CallerInfo(string Subject, string[] Roles, string[]? Scopes = null);

    protected static CallerInfo Caller(RtUser user, params string[] roles) =>
        new(user.RtId.ToString(), roles.Length == 0 ? [UserManagement] : roles.Append(UserManagement).ToArray());

    protected static CallerInfo Caller(string subject, params string[] roles) => new(subject, roles);

    protected HttpClient RestClient(CallerInfo caller)
    {
        var client = Host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, caller.Subject);
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        foreach (var role in caller.Roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        foreach (var scope in caller.Scopes ?? [])
        {
            client.DefaultRequestHeaders.Add("X-Test-Scope", scope);
        }

        return client;
    }

    protected async Task<HttpResponseMessage> RestPutAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.PutAsync(TenantApiUrl(path), null, TestContext.Current.CancellationToken);
    }

    protected async Task<HttpResponseMessage> RestPutJsonAsync<T>(CallerInfo caller, string path, T body)
    {
        using var client = RestClient(caller);
        return await client.PutAsJsonAsync(TenantApiUrl(path), body, TestContext.Current.CancellationToken);
    }

    protected async Task<HttpResponseMessage> RestPostAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.PostAsync(TenantApiUrl(path), null, TestContext.Current.CancellationToken);
    }

    protected async Task<HttpResponseMessage> RestDeleteAsync(CallerInfo caller, string path)
    {
        using var client = RestClient(caller);
        return await client.DeleteAsync(TenantApiUrl(path), TestContext.Current.CancellationToken);
    }

    #endregion

    #region Data

    /// <summary>A role; a built-in one carries an rtWellKnownName like the roles of the Bootstrap blueprint.</summary>
    protected async Task<string> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? "b7779" : "c7779");
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

    protected async Task<RtRole> EnsureUserManagementAsync()
    {
        using var scope = CreateScope();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByNameAsync(UserManagement);
        if (role == null)
        {
            role = new RtRoleBuilder().WithName(UserManagement).Build();
            role.RtWellKnownName = UserManagement;
            (await roleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
        }

        role.RtWellKnownName.Should().NotBeNullOrEmpty("UserManagement is a built-in role");
        return role;
    }

    protected async Task<RtRole?> FindRoleAsync(string name)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name);
    }

    protected async Task<string> RoleIdAsync(string name)
    {
        if (name == UserManagement)
        {
            await EnsureUserManagementAsync();
        }

        return (await FindRoleAsync(name))!.RtId.ToString();
    }

    protected async Task<RtUser> NewUserAsync(params string[] directRoles)
    {
        if (directRoles.Contains(UserManagement))
        {
            await EnsureUserManagementAsync();
        }

        var user = await CreateTestUserAsync(NewName("u7779"));
        foreach (var role in directRoles)
        {
            using var scope = CreateScope();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var fresh = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
            (await userManager.AddToRoleAsync(fresh, role.ToUpperInvariant())).Succeeded.Should().BeTrue();
        }

        return user;
    }

    protected async Task<RtClient> NewClientAsync() => await CreateTestClientAsync(NewName("c7779"));

    protected async Task<OctoObjectId> NewGroupAsync(params string[] roles)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var name = NewName("g7779");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await store.StoreAsync(group);
        var ids = new List<string>();
        foreach (var role in roles)
        {
            ids.Add(await RoleIdAsync(role));
        }

        await store.SetRoleIdsAsync(group.RtId, ids);
        return group.RtId;
    }

    protected async Task AddMemberAsync(OctoObjectId group, RtUser user)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberUserAsync(group, user.RtId.ToString());
    }

    protected async Task AddClientMemberAsync(OctoObjectId group, OctoObjectId client)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IGroupStore>().AddMemberClientAsync(group, client.ToString());
    }

    protected async Task<IReadOnlyList<string>> MembersAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(group);
    }

    protected async Task<IReadOnlyList<string>> ClientMembersAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberClientIdsAsync(group);
    }

    protected async Task<IReadOnlyList<string>> RoleIdsAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetRoleIdsAsync(group)).Order().ToList();
    }

    /// <summary>The roles the user effectively holds (what the token claims are built from).</summary>
    protected async Task<string[]> EffectiveRolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().GetRolesAsync(user)).ToArray();
    }

    /// <summary>Removes every way to hold UserManagement (direct, groups, mappings), so a test starts from a known state.</summary>
    protected async Task ClearAdministratorsAsync()
    {
        var role = await EnsureUserManagementAsync();
        var roleId = role.RtId.ToString();
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        foreach (var holder in await userManager.GetUsersInRoleAsync(role.NormalizedName!))
        {
            await userManager.RemoveFromRoleAsync(holder, role.NormalizedName!);
        }

        var groups = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        foreach (var group in await groups.GetAllAsync())
        {
            var roles = await groups.GetRoleIdsAsync(group.RtId);
            if (roles.Contains(roleId))
            {
                await groups.SetRoleIdsAsync(group.RtId, roles.Where(r => r != roleId).ToList());
            }
        }

        var mappings = scope.ServiceProvider.GetRequiredService<IExternalTenantUserMappingStore>();
        foreach (var mapping in await mappings.GetAllAsync())
        {
            if (mapping.MappedRoleIds?.Contains(roleId) == true)
            {
                mapping.MappedRoleIds = new AttributeStringValueList(mapping.MappedRoleIds.Where(r => r != roleId).ToList());
                await mappings.StoreAsync(mapping);
            }
        }
    }

    #endregion
}
