using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     The admin provisioning writes of <c>AdminProvisioningController</c> and the mapping create of
///     <c>ExternalTenantUserMappingsController</c> are facades of the static <c>ExternalTenantUserMapping</c> methods
///     <c>ProvisionAdmin</c>, <c>ProvisionAdminWithGroups</c>, <c>ProvisionCurrentUser</c>, <c>RemoveAdminProvisioning</c>
///     and <c>CreateMapping</c>. Real MongoDB, real identity host, real child tenants. These tests prove the in-process path
///     outside the request with one <c>Identity.Method</c> event per call, the same end state for REST and the method, the
///     target-tenant rule on the method path (a target outside the caller's subtree is refused, nothing is written there)
///     and the abuse cases.
/// </summary>
public class AdminProvisioningRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";
    private const string UserManagement = "UserManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _errors = new();

    public AdminProvisioningRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region REST runs the method

    [Fact]
    public async Task EveryProvisioningWriteEndpoint_RunsItsMethodInProcess_OutsideTheRequest_OneEvent()
    {
        var host = Host();
        var ct = TestContext.Current.CancellationToken;
        var target = await CreateChildTenantAsync();
        var adminUser = await CreateTestUserAsync(NewName("apa"));
        var groupUser = await CreateTestUserAsync(NewName("apg"));
        var mappedUser = await CreateTestUserAsync(NewName("apm"));
        var tenantManagementRole = await RoleIdAsync(target, TenantManagement);
        var viewers = await GroupIdAsync(target);
        using var http = FacadeCaller.User(TenantManagement).Client(host);

        var created = await http.PostAsJsonAsync(ProvisioningUrl(target, ""), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = adminUser.RtId.ToString(),
            sourceUserName = adminUser.UserName, roleIds = new[] { tenantManagementRole }
        }, ct);
        created.StatusCode.Should().Be(HttpStatusCode.Created, await created.Content.ReadAsStringAsync(ct));
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>(ct);
        var mappingId = createdBody.GetProperty("id").GetString()!;
        createdBody.GetProperty("groupNames").EnumerateArray().Select(g => g.GetString()).Should()
            .Contain(CommonConstants.TenantOwnersGroup);

        var withGroups = await http.PostAsJsonAsync(ProvisioningUrl(target, "withGroups"), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = groupUser.RtId.ToString(),
            sourceUserName = groupUser.UserName, groupIds = new[] { viewers }
        }, ct);
        withGroups.StatusCode.Should().Be(HttpStatusCode.Created, await withGroups.Content.ReadAsStringAsync(ct));

        using var self = (FacadeCaller.User(TenantManagement) with { Subject = adminUser.RtId.ToString() }).Client(host);
        var current = await self.PostAsync(ProvisioningUrl(target, "provisionCurrentUser"), null, ct);
        current.StatusCode.Should().Be(HttpStatusCode.OK, await current.Content.ReadAsStringAsync(ct));
        current.Headers.GetValues("X-Provisioning-Outcome").Should().Equal("already-provisioned");

        // The role change guard of the mapping create reads the caller's subject as an object id, as a real token's is.
        using var targetAdmin = (FacadeCaller.User(UserManagement) with { Subject = OctoObjectId.GenerateNewId().ToString() })
            .Client(host);
        var mapping = await targetAdmin.PostAsJsonAsync(TenantApiUrl("ExternalTenantUserMappings", target), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = mappedUser.RtId.ToString(),
            sourceUserName = mappedUser.UserName, roleIds = Array.Empty<string>()
        }, ct);
        mapping.StatusCode.Should().Be(HttpStatusCode.Created, await mapping.Content.ReadAsStringAsync(ct));

        (await http.DeleteAsync(ProvisioningUrl(target, mappingId), ct)).StatusCode.Should().Be(HttpStatusCode.OK);

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId,
                     SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId
                 })
        {
            _audit.All.Where(e => e.GetValueOrDefault("methodId") == methodId).Should().ContainSingle(methodId)
                .Which["outcome"].Should().Be("SUCCESS");
        }

        _probe.Calls.Should().Be(5, "every REST call ran its method through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
        _eventHub.ReceivedCalls().Where(c => c.GetArguments().Any(a => a is CkMethodRequest)).Should().BeEmpty();
        (await MappingAsync(target, adminUser.RtId.ToString())).Should().BeNull("the mapping was deleted");
        (await MappingAsync(target, groupUser.RtId.ToString())).Should().NotBeNull();
        (await MappingAsync(target, mappedUser.RtId.ToString())).Should().NotBeNull();
    }

    #endregion

    #region Same end state as REST

    [Fact]
    public async Task RestAndMethod_LeaveTheSameMappingInTheTargetTenant()
    {
        var host = Host();
        var ct = TestContext.Current.CancellationToken;
        var target = await CreateChildTenantAsync();
        var restUser = await CreateTestUserAsync(NewName("apr"));
        var methodUser = await CreateTestUserAsync(NewName("apx"));
        var role = await RoleIdAsync(target, TenantManagement);
        using var http = FacadeCaller.User(TenantManagement).Client(host);

        (await http.PostAsJsonAsync(ProvisioningUrl(target, ""), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = restUser.RtId.ToString(),
            sourceUserName = restUser.UserName, roleIds = new[] { role }
        }, ct)).StatusCode.Should().Be(HttpStatusCode.Created);
        var method = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = target, SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = methodUser.RtId.ToString(), SourceUserName = methodUser.UserName!, RoleIds = [role]
            });
        method.Success.Should().BeTrue(method.Error?.Code);
        using var result = JsonDocument.Parse(method.ResultJson!);
        result.RootElement.GetProperty("groupNames").EnumerateArray().Select(g => g.GetString()).Should()
            .Contain(CommonConstants.TenantOwnersGroup);

        var restMapping = (await MappingAsync(target, restUser.RtId.ToString()))!;
        var methodMapping = (await MappingAsync(target, methodUser.RtId.ToString()))!;
        methodMapping.MappedRoleIds.Should().Equal(restMapping.MappedRoleIds);
        (await GroupNamesAsync(target, methodMapping)).Should().Equal(await GroupNamesAsync(target, restMapping));

        // a second create for the same user: REST 409 naming the mapping, the method MAPPING_ALREADY_EXISTS; nothing new
        var again = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = target, SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = methodUser.RtId.ToString(), SourceUserName = methodUser.UserName!
            });
        again.Error!.Code.Should().Be(AdminProvisioningMethodErrors.MappingAlreadyExists);
        again.Error.Parameters.Should().Contain(AdminProvisioningMethodErrors.ExistingMappingIdParameter,
            methodMapping.RtId.ToString());
        var restAgain = await http.PostAsJsonAsync(ProvisioningUrl(target, ""), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = restUser.RtId.ToString(),
            sourceUserName = restUser.UserName
        }, ct);
        restAgain.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await restAgain.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("existingMappingId").GetString()
            .Should().Be(restMapping.RtId.ToString());

        // remove through the method: gone; a second remove is MAPPING_NOT_FOUND / REST 404
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId,
            new ExternalTenantUserMappingRemoveAdminProvisioningParameters
                { TargetTenantId = target, MappingRtId = methodMapping.RtId.ToString() })).Success.Should().BeTrue();
        (await MappingAsync(target, methodUser.RtId.ToString())).Should().BeNull();
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId,
                new ExternalTenantUserMappingRemoveAdminProvisioningParameters
                    { TargetTenantId = target, MappingRtId = methodMapping.RtId.ToString() })).Error!.Code.Should()
            .Be(AdminProvisioningMethodErrors.MappingNotFound);
        (await http.DeleteAsync(ProvisioningUrl(target, methodMapping.RtId.ToString()), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ProvisionCurrentUser_ThroughTheMethod_ProvisionsTheCaller_ThenReportsAlreadyProvisioned()
    {
        var host = Host();
        var target = await CreateChildTenantAsync();
        var user = await CreateTestUserAsync(NewName("apc"));
        var caller = Admin() with { SubjectId = user.RtId.ToString() };
        var parameters = new ExternalTenantUserMappingProvisionCurrentUserParameters { TargetTenantId = target };

        var first = await DispatchAsync(host, caller,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId, parameters);
        var second = await DispatchAsync(host, caller,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId, parameters);

        first.Success.Should().BeTrue(first.Error?.Code);
        JsonDocument.Parse(first.ResultJson!).RootElement.GetProperty("outcome").GetString().Should().Be("created");
        JsonDocument.Parse(second.ResultJson!).RootElement.GetProperty("outcome").GetString().Should()
            .Be("already-provisioned");
        var mapping = (await MappingAsync(target, user.RtId.ToString()))!;
        mapping.SourceUserName.Should().Be(user.UserName, "the stored user name of the caller's tenant");
        (await GroupNamesAsync(target, mapping)).Should().Contain(CommonConstants.TenantOwnersGroup);

        // a service caller (no subject) is not a user
        var service = new CkMethodPrincipal(null, [TenantManagement], ["octo_api"], "svc-apc")
            { TokenTenantId = NormalizedSystemTenantId };
        var refused = await DispatchAsync(host, service,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId, parameters);
        refused.Error!.Code.Should().Be(AdminProvisioningMethodErrors.CallerNotAUser);
    }

    [Fact]
    public async Task AnUnknownTargetTenant_IsTenantNotFound_ForTheSystemCaller()
    {
        // The system caller reaches every tenant, so the target rule lets it through; the handler looks the tenant up.
        var host = Host();
        var user = await CreateTestUserAsync(NewName("apu"));
        var missing = $"nope{Guid.NewGuid():N}"[..16];

        var result = await DispatchAsync(host, Admin(),
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = missing, SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = user.RtId.ToString(), SourceUserName = user.UserName!
            });

        result.Error!.Code.Should().Be(AdminProvisioningMethodErrors.TenantNotFound);
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(missing)).Should()
            .BeNull("nothing was created for the unknown tenant");
    }

    #endregion

    #region Cross-tenant rule and abuse cases

    [Fact]
    public async Task ATargetOutsideTheCallersSubtree_IsRefusedOnEveryMethod_AndNothingIsWrittenThere()
    {
        var host = Host();
        var callerTenant = await CreateChildTenantAsync();
        var sibling = await CreateChildTenantAsync();
        var user = await CreateTestUserAsync(NewName("aps"));
        var existing = await SeedMappingAsync(sibling, user);
        var caller = Admin() with { SubjectId = user.RtId.ToString(), TokenTenantId = callerTenant };

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
                         new ExternalTenantUserMappingProvisionAdminParameters
                         {
                             TargetTenantId = sibling, SourceTenantId = NormalizedSystemTenantId,
                             SourceUserId = OctoObjectId.GenerateNewId().ToString(), SourceUserName = "x"
                         }),
                     (SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId,
                         new ExternalTenantUserMappingProvisionAdminWithGroupsParameters
                         {
                             TargetTenantId = sibling, SourceTenantId = NormalizedSystemTenantId,
                             SourceUserId = OctoObjectId.GenerateNewId().ToString(), SourceUserName = "y"
                         }),
                     (SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId,
                         new ExternalTenantUserMappingProvisionCurrentUserParameters { TargetTenantId = sibling }),
                     (SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId,
                         new ExternalTenantUserMappingRemoveAdminProvisioningParameters
                             { TargetTenantId = sibling, MappingRtId = existing.RtId.ToString() })
                 })
        {
            var refusal = await DispatchAsync(host, caller, methodId, parameters);
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden, methodId);
            refusal.Error.Parameters.Should().Contain("reason", CrossTenantMethodSupport.TenantOutOfScopeReason);
        }

        // On the bus path the host sets TenantId to the tenant of the call; the token's own tenant still decides.
        var busCaller = caller with { TenantId = NormalizedSystemTenantId };
        var busRefusal = await DispatchAsync(host, busCaller,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = sibling, SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = OctoObjectId.GenerateNewId().ToString(), SourceUserName = "z"
            });
        busRefusal.Error!.Parameters.Should().Contain("reason", CrossTenantMethodSupport.TenantOutOfScopeReason);

        (await MappingCountAsync(sibling)).Should().Be(1, "only the seeded mapping; nothing written, nothing removed");
        (await MappingAsync(sibling, user.RtId.ToString())).Should().NotBeNull();
    }

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingChanges()
    {
        var host = Host(enforceTenantGate: true);
        var target = await CreateChildTenantAsync();
        var user = await CreateTestUserAsync(NewName("apt"));
        var foreign = Admin() with { IsFromAccessToken = true, TokenTenantId = "othertenantap" };

        var method = await DispatchAsync(host, foreign,
            SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
            new ExternalTenantUserMappingProvisionAdminParameters
            {
                TargetTenantId = target, SourceTenantId = NormalizedSystemTenantId,
                SourceUserId = user.RtId.ToString(), SourceUserName = user.UserName!
            });

        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        using var http = (FacadeCaller.User(TenantManagement) with { TokenTenant = "othertenantap" }).Client(host);
        (await http.PostAsJsonAsync(ProvisioningUrl(target, ""), new
        {
            sourceTenantId = NormalizedSystemTenantId, sourceUserId = user.RtId.ToString(), sourceUserName = user.UserName
        }, TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await MappingAsync(target, user.RtId.ToString())).Should().BeNull();
    }

    [Fact]
    public async Task ACallerWithoutTheDeclaredRole_IsRefused_AndNothingChanges()
    {
        var host = Host();
        var target = await CreateChildTenantAsync();
        var user = await CreateTestUserAsync(NewName("apo"));
        var outsider = new CkMethodPrincipal(user.RtId.ToString(), ["CommunicationManagement"], ["octo_api"])
            { TokenTenantId = NormalizedSystemTenantId };

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId,
                         new ExternalTenantUserMappingProvisionAdminParameters
                         {
                             TargetTenantId = target, SourceTenantId = NormalizedSystemTenantId,
                             SourceUserId = user.RtId.ToString(), SourceUserName = user.UserName!
                         }),
                     (SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId,
                         new ExternalTenantUserMappingProvisionCurrentUserParameters { TargetTenantId = target })
                 })
        {
            (await DispatchAsync(host, outsider, methodId, parameters)).Error!.Code.Should()
                .Be(CkMethodErrorCodes.MethodForbidden, methodId);
        }

        // CreateMapping needs UserManagement (the REST policy of the mapping create): TenantManagement alone is refused
        var tenantManager = new CkMethodPrincipal(user.RtId.ToString(), [TenantManagement], ["octo_api"])
            { TokenTenantId = target };
        (await DispatchAsync(host, tenantManager, SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId,
            new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = user.RtId.ToString(),
                SourceUserName = user.UserName!
            }, target)).Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        (await MappingAsync(target, user.RtId.ToString())).Should().BeNull();
    }

    [Fact]
    public async Task CreateMapping_KeepsTheCrossTenantChecks_OfTheRestCreate()
    {
        var host = Host();
        var target = await CreateChildTenantAsync();
        var unrelated = await CreateChildTenantAsync();
        var user = await CreateTestUserAsync(NewName("apk"));
        var admin = new CkMethodPrincipal(OctoObjectId.GenerateNewId().ToString(), [UserManagement], ["octo_api"])
            { TokenTenantId = target };

        // a source that is neither an ancestor of the target nor permits it
        var notPermitted = await DispatchAsync(host, admin,
            SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId,
            new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = unrelated, SourceUserId = user.RtId.ToString(), SourceUserName = user.UserName!
            }, target);
        notPermitted.Error!.Code.Should().Be(AdminProvisioningMethodErrors.SourceTenantNotPermitted);

        // an unknown group: nothing stored
        var unknownGroup = OctoObjectId.GenerateNewId().ToString();
        var badGroup = await DispatchAsync(host, admin,
            SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId,
            new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = user.RtId.ToString(),
                SourceUserName = user.UserName!, GroupIds = [unknownGroup]
            }, target);
        badGroup.Error!.Code.Should().Be(AdminProvisioningMethodErrors.UnknownGroup);
        badGroup.Error.Parameters.Should().Contain(AdminProvisioningMethodErrors.UnknownGroupIdsParameter, unknownGroup);
        (await MappingAsync(target, user.RtId.ToString())).Should().BeNull();

        // the ancestor source: created, with the stored user name of the source tenant
        var created = await DispatchAsync(host, admin,
            SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId,
            new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = user.RtId.ToString(),
                SourceUserName = "a-name-the-request-made-up"
            }, target);
        created.Success.Should().BeTrue($"{created.Error?.Code}: {string.Join(" | ", _errors)}");
        (await MappingAsync(target, user.RtId.ToString()))!.SourceUserName.Should().Be(user.UserName);

        // the REST create answers the same refusals with its own problem bodies
        using var http = (FacadeCaller.User(UserManagement) with { Subject = OctoObjectId.GenerateNewId().ToString() })
            .Client(host);
        var rest = await http.PostAsJsonAsync(TenantApiUrl("ExternalTenantUserMappings", target), new
        {
            sourceTenantId = unrelated, sourceUserId = user.RtId.ToString(), sourceUserName = user.UserName
        }, TestContext.Current.CancellationToken);
        rest.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await rest.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code")
            .GetString().Should().Be("SourceTenantNotPermitted");
    }

    #endregion

    #region Helpers

    private CkMethodPrincipal Admin() =>
        new(OctoObjectId.GenerateNewId().ToString(), [TenantManagement, UserManagement], ["octo_api"])
        {
            TokenTenantId = NormalizedSystemTenantId
        };

    private static string NewName(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private string ProvisioningUrl(string target, string path) =>
        TenantApiUrl(path.Length == 0 ? $"adminProvisioning/{target}" : $"adminProvisioning/{target}/{path}");

    private WebApplicationFactory<Program> Host(bool enforceTenantGate = false)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (enforceTenantGate)
            {
                b.UseSetting("TenantAuthorization:UserTokenEnforcement", "Enforce");
            }

            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host (announcement, heartbeat).
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.AddSingleton(_audit.Events);
                services.RemoveAll<IDistributionEventHubService>();
                services.AddSingleton(_eventHub);
                services.AddSingleton<ICkInProcessAmbientStateProbe>(_probe);
                services.AddSingleton<IStartupFilter, MarkRequestsStartupFilter>();
                services.AddLogging(l => l.AddProvider(new ErrorCapture(_errors)));
            });
        });
        _hosts.Add(host);
        return host;
    }

    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, object parameters, string? tenantId = null)
    {
        var request = new CkMethodRequest(tenantId ?? NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = IdentityMethodFacade.ExternalTenantUserMappingCkTypeId,
            TargetRtId = null,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(90)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"apfc{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(childTenantId) !=
                null)
            {
                return childTenantId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new TimeoutException($"Tenant '{childTenantId}' did not appear in the registry.");
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId) =>
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;

    private async Task<string> RoleIdAsync(string tenantId, string roleName)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtRole.NormalizedName), roleName.ToUpperInvariant())))
            .Items.Single().RtId.ToString();
    }

    /// <summary>A new group of the target tenant (the default configuration seeds only TenantOwners).</summary>
    private async Task<string> GroupIdAsync(string tenantId)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        var name = NewName("grp");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await repo.InsertOneRtEntityAsync(session, group);
        return group.RtId.ToString();
    }

    private async Task<RtExternalTenantUserMapping?> MappingAsync(string tenantId, string sourceUserId)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId)))
            .Items.SingleOrDefault();
    }

    private async Task<int> MappingCountAsync(string tenantId)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create()))
            .Items.Count();
    }

    private async Task<RtExternalTenantUserMapping> SeedMappingAsync(string tenantId, RtUser user)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = NormalizedSystemTenantId,
            SourceUserId = user.RtId.ToString(),
            SourceUserName = user.UserName!
        };
        await repo.InsertOneRtEntityAsync(session, mapping);
        return mapping;
    }

    private async Task<List<string>> GroupNamesAsync(string tenantId, RtExternalTenantUserMapping mapping)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        var edges = await repo.GetRtAssociationsAsync(session, mapping.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Inbound,
                roleId: IdentityServerPersistence.IdentityAssociationConstants.GroupMemberId));
        var names = new List<string>();
        foreach (var edge in edges.Items)
        {
            var group = await repo.GetRtEntityByRtIdAsync<RtGroup>(session, edge.OriginRtId);
            if (group != null)
            {
                names.Add(group.GroupName);
            }
        }

        return names.Order(StringComparer.Ordinal).ToList();
    }

    #endregion

    /// <summary>Error log lines of the host (exception type and message), so a failing handler names its cause.</summary>
    private sealed class ErrorCapture(System.Collections.Concurrent.ConcurrentQueue<string> sink)
        : Microsoft.Extensions.Logging.ILoggerProvider
    {
        public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Logger(sink, categoryName);

        public void Dispose()
        {
        }

        private sealed class Logger(System.Collections.Concurrent.ConcurrentQueue<string> sink, string category)
            : Microsoft.Extensions.Logging.ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) =>
                logLevel >= Microsoft.Extensions.Logging.LogLevel.Error;

            public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId,
                TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                if (IsEnabled(logLevel))
                {
                    sink.Enqueue($"{category}: {exception?.GetType().Name} {exception?.Message}");
                }
            }
        }
    }
}
