using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
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
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     The client mirror write endpoints of <c>ClientMirrorController</c> and <c>ClientAutoProvisionFlagController</c> are
///     facades of <c>Client.ProvisionMirrors</c>, <c>ProvisionMirrorInTenant</c>, <c>RotateMirrorSecret</c>,
///     <c>RemoveMirror</c> and <c>SetMirrorAutoProvision</c>. Real MongoDB, real identity host, real child tenants. These
///     tests prove that every endpoint runs its method in-process outside the request with one <c>Identity.Method</c> event
///     and nothing on the broker, that REST and the method leave the same mirror state in parent and child, that the
///     rotated secret is never logged, audited or traced, the cross-tenant rule (a child outside the caller's subtree is
///     refused and nothing is written there) and the abuse cases.
/// </summary>
public class ClientMirrorRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";
    private const string SecretManagement = "SecretManagement";
    private const string ApiScope = "client-mirror-facade-api";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly ConcurrentQueue<(LogLevel Level, string Text)> _logs = new();
    private readonly ConcurrentQueue<string> _activityTags = new();
    private readonly ActivityListener _activities;
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public ClientMirrorRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _activities = new ActivityListener
        {
            ShouldListenTo = _ => true,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                _activityTags.Enqueue(activity.DisplayName);
                foreach (var tag in activity.TagObjects)
                {
                    _activityTags.Enqueue($"{tag.Key}={tag.Value}");
                }
            }
        };
        ActivitySource.AddActivityListener(_activities);
    }

    public static TheoryData<bool> SwitchValues => new() { false, true };

    public void Dispose()
    {
        _activities.Dispose();
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region REST runs the method

    [Theory]
    [MemberData(nameof(SwitchValues))]
    public async Task EveryMirrorWriteEndpoint_RunsItsMethodInProcess_OutsideTheRequest_OneEvent_NothingOnTheBroker(
        bool switchOn)
    {
        var host = Host(switchOn);
        var ct = TestContext.Current.CancellationToken;
        var client = await NewClientAsync(flagged: false);
        var child = await CreateChildTenantAsync();
        using var http = FacadeCaller.User(TenantManagement, SecretManagement).Client(host);
        var rtId = client.RtId.ToString();

        (await http.PatchAsJsonAsync(MirrorFlagUrl(client), new { enabled = true }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NoContent);
        var provisioned = await http.PostAsync(MirrorsUrl(client, $"provisionInTenant?childTenantId={child}"), null, ct);
        provisioned.StatusCode.Should().Be(HttpStatusCode.OK, await provisioned.Content.ReadAsStringAsync(ct));
        (await provisioned.Content.ReadFromJsonAsync<ClientMirrorProvisionResponseDto>(ct))!.FlaggedClientsConsidered
            .Should().BeGreaterThanOrEqualTo(1);
        var backfill = await http.PostAsync(MirrorsUrl(client, "provisionInExistingTenants"), null, ct);
        backfill.StatusCode.Should().Be(HttpStatusCode.OK, await backfill.Content.ReadAsStringAsync(ct));
        var rotated = await http.PostAsync(MirrorsUrl(client, $"{child}/secret"), null, ct);
        rotated.StatusCode.Should().Be(HttpStatusCode.OK, await rotated.Content.ReadAsStringAsync(ct));
        var secret = (await rotated.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("secret").GetString()!;
        (await http.DeleteAsync(MirrorsUrl(client, child), ct)).StatusCode.Should().Be(HttpStatusCode.NoContent);

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId,
                     SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
                     SystemIdentityCkIds.ClientProvisionMirrorsMethodId,
                     SystemIdentityCkIds.ClientRotateMirrorSecretMethodId,
                     SystemIdentityCkIds.ClientRemoveMirrorMethodId
                 })
        {
            _audit.For(methodId, rtId).Should().ContainSingle(methodId).Which["outcome"].Should().Be("SUCCESS");
        }

        _probe.Calls.Should().Be(5, "every REST call ran its method through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
        AssertNothingReachedTheBroker();
        AssertSecretNowhere(secret);
        (await GetTrackingRowAsync(client.ClientId!, child)).Should().BeNull();
        (await FindMirrorAsync(child, client.ClientId!)).Should().BeNull();
    }

    [Fact]
    public void SwitchOff_TheRotationIsLocalOnly_TheOtherMirrorMethodsAreOnTheBus()
    {
        var off = new IdentityMethodsOptions();
        IdentityMethodHost.SelectHandlers(off).Select(h => h.MethodId).Should()
            .NotContain(SystemIdentityCkIds.ClientRotateMirrorSecretMethodId)
            .And.Contain(SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId)
            .And.Contain(SystemIdentityCkIds.ClientRemoveMirrorMethodId);
        IdentityMethodHost.SelectLocalOnlyHandlers(off).Select(h => h.MethodId).Should()
            .Contain(SystemIdentityCkIds.ClientRotateMirrorSecretMethodId);
        Host(false).Services.GetRequiredService<ICkInProcessMethodTransport>()
            .CanHandle(SystemIdentityCkIds.ClientRotateMirrorSecretMethodId).Should().BeTrue();
    }

    #endregion

    #region Same mirror state as REST

    [Fact]
    public async Task RestAndMethod_LeaveTheSameMirrorStateInParentAndChild()
    {
        var host = Host(true);
        var ct = TestContext.Current.CancellationToken;
        var restClient = await NewClientAsync(flagged: true);
        var methodClient = await NewClientAsync(flagged: true);
        var child = await CreateChildTenantAsync();
        using var http = FacadeCaller.User(TenantManagement, SecretManagement).Client(host);

        // provision into one child
        (await http.PostAsync(MirrorsUrl(restClient, $"provisionInTenant?childTenantId={child}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        var provisioned = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
            methodClient.RtId.ToString(), new ClientProvisionMirrorInTenantParameters { ChildTenantId = child });
        provisioned.Success.Should().BeTrue(provisioned.Error?.Code);
        JsonDocument.Parse(provisioned.ResultJson!).RootElement.GetProperty("flaggedClientsConsidered").GetInt32()
            .Should().BeGreaterThanOrEqualTo(2);
        foreach (var client in new[] { restClient, methodClient })
        {
            (await GetTrackingRowAsync(client.ClientId!, child)).Should().NotBeNull();
            (await FindMirrorAsync(child, client.ClientId!)).Should().NotBeNull();
        }

        // rotate: each mirror gets its own secret, which authenticates in the child and only there
        var restSecret = (await (await http.PostAsync(MirrorsUrl(restClient, $"{child}/secret"), null, ct)).Content
            .ReadFromJsonAsync<JsonElement>(ct)).GetProperty("secret").GetString()!;
        var rotated = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientRotateMirrorSecretMethodId,
            methodClient.RtId.ToString(), new ClientRotateMirrorSecretParameters { ChildTenantId = child });
        rotated.Success.Should().BeTrue(rotated.Error?.Code);
        var methodSecret = JsonSerializer.Deserialize<string>(rotated.ResultJson!)!;
        (await RequestTokenAsync(host, child, restClient.ClientId!, restSecret, ct)).Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(host, child, methodClient.ClientId!, methodSecret, ct)).Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(host, NormalizedSystemTenantId, methodClient.ClientId!, methodSecret, ct)).Should()
            .Be(HttpStatusCode.Unauthorized, "a mirror secret proves exactly one tenant");
        foreach (var client in new[] { restClient, methodClient })
        {
            (await FindMirrorAsync(child, client.ClientId!))!.ClientSecrets.Should()
                .ContainSingle(s => ClientMirrorSecrets.IsOwnSecret(s), "the mirror's own secret is marked for the sync");
        }

        // auto-provision flag
        (await http.PatchAsJsonAsync(MirrorFlagUrl(restClient), new { enabled = false }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NoContent);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId,
            methodClient.RtId.ToString(), new ClientSetMirrorAutoProvisionParameters { Enabled = false })).Success
            .Should().BeTrue();
        (await LoadAsync(restClient)).AutoProvisionInChildTenants.Should().BeFalse();
        (await LoadAsync(methodClient)).AutoProvisionInChildTenants.Should().BeFalse();

        // a client without the flag: REST 400, the method AUTO_PROVISION_DISABLED; nothing is provisioned
        (await http.PostAsync(MirrorsUrl(restClient, "provisionInExistingTenants"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.BadRequest);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientProvisionMirrorsMethodId,
                methodClient.RtId.ToString(), new ClientProvisionMirrorsParameters())).Error!.Code.Should()
            .Be(ClientMirrorMethodErrors.AutoProvisionDisabled);

        // remove: both mirrors and tracking rows go; a second remove is REST 404 / MIRROR_NOT_FOUND
        (await http.DeleteAsync(MirrorsUrl(restClient, child), ct)).StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientRemoveMirrorMethodId, methodClient.RtId.ToString(),
            new ClientRemoveMirrorParameters { ChildTenantId = child })).Success.Should().BeTrue();
        foreach (var client in new[] { restClient, methodClient })
        {
            (await GetTrackingRowAsync(client.ClientId!, child)).Should().BeNull();
            (await FindMirrorAsync(child, client.ClientId!)).Should().BeNull();
        }

        (await http.DeleteAsync(MirrorsUrl(restClient, child), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientRemoveMirrorMethodId, methodClient.RtId.ToString(),
                new ClientRemoveMirrorParameters { ChildTenantId = child })).Error!.Code.Should()
            .Be(ClientMirrorMethodErrors.MirrorNotFound);
        AssertSecretNowhere(restSecret);
        AssertSecretNowhere(methodSecret);
    }

    [Fact]
    public async Task Backfill_RestAndMethod_ProvisionTheSameMirrors()
    {
        var host = Host(true);
        var ct = TestContext.Current.CancellationToken;
        var (restParent, restChild, restClient) = await IsolatedParentAsync();
        var (methodParent, methodChild, methodClient) = await IsolatedParentAsync();
        using var http = FacadeCaller.User(TenantManagement).Client(host);

        var rest = await http.PostAsync(MirrorsUrl(restClient, "provisionInExistingTenants", restParent), null, ct);
        var method = await DispatchAsync(host, Admin(methodParent), SystemIdentityCkIds.ClientProvisionMirrorsMethodId,
            methodClient.RtId.ToString(), new ClientProvisionMirrorsParameters(), methodParent);

        rest.StatusCode.Should().Be(HttpStatusCode.OK, await rest.Content.ReadAsStringAsync(ct));
        method.Success.Should().BeTrue(method.Error?.Code);
        var restBody = (await rest.Content.ReadFromJsonAsync<ClientMirrorBackfillResponseDto>(ct))!;
        using var methodBody = JsonDocument.Parse(method.ResultJson!);
        restBody.ChildTenantsConsidered.Should().Be(1);
        restBody.NewlyProvisioned.Should().Be(1);
        methodBody.RootElement.GetProperty("childTenantsConsidered").GetInt32().Should().Be(restBody.ChildTenantsConsidered);
        methodBody.RootElement.GetProperty("newlyProvisioned").GetInt32().Should().Be(restBody.NewlyProvisioned);
        methodBody.RootElement.GetProperty("alreadyPresent").GetInt32().Should().Be(restBody.AlreadyPresent);
        (await GetTrackingRowAsync(restClient.ClientId!, restChild, restParent)).Should().NotBeNull();
        (await GetTrackingRowAsync(methodClient.ClientId!, methodChild, methodParent)).Should().NotBeNull();
        (await FindMirrorAsync(restChild, restClient.ClientId!)).Should().NotBeNull();
        (await FindMirrorAsync(methodChild, methodClient.ClientId!)).Should().NotBeNull();
    }

    #endregion

    #region Cross-tenant rule and abuse cases

    [Fact]
    public async Task AChildOutsideTheCallersSubtree_IsRefused_AndNothingIsWrittenInEitherTenant()
    {
        var host = Host(true);
        var (parent, _, client) = await IsolatedParentAsync();
        var sibling = await CreateChildTenantAsync();
        // A caller whose token was issued for the parent; the sibling is not in its subtree.
        var caller = Admin(parent);

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
                         new ClientProvisionMirrorInTenantParameters { ChildTenantId = sibling }),
                     (SystemIdentityCkIds.ClientRotateMirrorSecretMethodId,
                         new ClientRotateMirrorSecretParameters { ChildTenantId = sibling }),
                     (SystemIdentityCkIds.ClientRemoveMirrorMethodId, new ClientRemoveMirrorParameters { ChildTenantId = sibling })
                 })
        {
            var refusal = await DispatchAsync(host, caller, methodId, client.RtId.ToString(), parameters, parent);
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden, methodId);
            refusal.Error.Parameters.Should().Contain("reason", CrossTenantMethodSupport.TenantOutOfScopeReason);
            _audit.For(methodId, client.RtId.ToString()).Should().ContainSingle()
                .Which["outcome"].Should().Be(CkMethodErrorCodes.MethodForbidden);
        }

        (await GetTrackingRowAsync(client.ClientId!, sibling, parent)).Should().BeNull();
        (await FindMirrorAsync(sibling, client.ClientId!)).Should().BeNull("no client is written in the foreign tenant");
    }

    [Fact]
    public async Task AChildThatIsNoTenantOfTheParentsSubtree_IsRefusedByTheServiceToo()
    {
        // The caller's token tenant is the system tenant (reaches everything); the method runs in a child tenant whose
        // subtree does not contain the sibling, so the parent-subtree rule of the mirror service refuses it.
        var host = Host(true);
        var parent = await CreateChildTenantAsync();
        var sibling = await CreateChildTenantAsync();
        var client = await NewClientAsync(flagged: true, tenantId: parent);

        var refusal = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
            client.RtId.ToString(), new ClientProvisionMirrorInTenantParameters { ChildTenantId = sibling }, parent);

        refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        refusal.Error.Parameters.Should().Contain("reason", CrossTenantMethodSupport.TenantOutOfScopeReason);
        (await FindMirrorAsync(sibling, client.ClientId!)).Should().BeNull();
    }

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingChanges()
    {
        var host = Host(true, enforceTenantGate: true);
        var (parent, child, client) = await IsolatedParentAsync();
        var foreign = Admin() with { IsFromAccessToken = true, TokenTenantId = "othertenantmf" };

        var method = await DispatchAsync(host, foreign, SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
            client.RtId.ToString(), new ClientProvisionMirrorInTenantParameters { ChildTenantId = child }, parent);

        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        using var http = (FacadeCaller.User(TenantManagement) with { TokenTenant = "othertenantmf" }).Client(host);
        (await http.PostAsync(MirrorsUrl(client, $"provisionInTenant?childTenantId={child}", parent), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetTrackingRowAsync(client.ClientId!, child, parent)).Should().BeNull();
        (await FindMirrorAsync(child, client.ClientId!)).Should().BeNull();
    }

    [Fact]
    public async Task ACallerWithoutTheDeclaredRole_IsRefused_AndNothingChanges()
    {
        var host = Host(true);
        var (parent, child, client) = await IsolatedParentAsync();
        var outsider = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), ["CommunicationManagement"], ["octo_api"])
        {
            TokenTenantId = parent
        };

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
                         new ClientProvisionMirrorInTenantParameters { ChildTenantId = child }),
                     (SystemIdentityCkIds.ClientProvisionMirrorsMethodId, new ClientProvisionMirrorsParameters()),
                     (SystemIdentityCkIds.ClientRotateMirrorSecretMethodId,
                         new ClientRotateMirrorSecretParameters { ChildTenantId = child }),
                     (SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId,
                         new ClientSetMirrorAutoProvisionParameters { Enabled = false }),
                     (SystemIdentityCkIds.ClientRemoveMirrorMethodId, new ClientRemoveMirrorParameters { ChildTenantId = child })
                 })
        {
            (await DispatchAsync(host, outsider, methodId, client.RtId.ToString(), parameters, parent)).Error!.Code.Should()
                .Be(CkMethodErrorCodes.MethodForbidden, methodId);
        }

        using var http = FacadeCaller.User("CommunicationManagement").Client(host);
        (await http.PostAsync(MirrorsUrl(client, $"provisionInTenant?childTenantId={child}", parent), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetTrackingRowAsync(client.ClientId!, child, parent)).Should().BeNull();
        (await LoadAsync(client, parent)).AutoProvisionInChildTenants.Should().BeTrue();
    }

    [Fact]
    public async Task AParentClientTheCallerCannotRead_Is404_AndNothingIsProvisioned()
    {
        var host = Host(true, evaluator: FacadeDataPolicy.DenyAllReads());
        var (parent, child, client) = await IsolatedParentAsync();

        var method = await DispatchAsync(host, Admin(parent), SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
            client.RtId.ToString(), new ClientProvisionMirrorInTenantParameters { ChildTenantId = child }, parent);
        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodTargetNotFound);
        using var http = FacadeCaller.User(TenantManagement).Client(host);
        (await http.PostAsync(MirrorsUrl(client, $"provisionInTenant?childTenantId={child}", parent), null,
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await GetTrackingRowAsync(client.ClientId!, child, parent)).Should().BeNull();
    }

    [Fact]
    public async Task TheRotation_NeedsTheSecretRole_WhenSecretManagementIsEnforced()
    {
        var host = Host(true, enforceSecretManagement: true);
        var client = await NewClientAsync(flagged: true);
        var child = await CreateChildTenantAsync();
        await ProvisionAsync(host, client, child);
        var ownBefore = OwnSecretValues(await FindMirrorAsync(child, client.ClientId!));

        var refusal = await DispatchAsync(host,
            new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [TenantManagement], ["octo_api"])
                { TokenTenantId = NormalizedSystemTenantId },
            SystemIdentityCkIds.ClientRotateMirrorSecretMethodId, client.RtId.ToString(),
            new ClientRotateMirrorSecretParameters { ChildTenantId = child });

        refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        OwnSecretValues(await FindMirrorAsync(child, client.ClientId!)).Should()
            .Equal(ownBefore, "no new mirror secret was issued");
    }

    [Fact]
    public async Task TheBackfill_InATenantOutsideTheCallersSubtree_IsRefused_AndNothingIsWritten()
    {
        var host = Host(true);
        var (parent, child, client) = await IsolatedParentAsync();
        var sibling = await CreateChildTenantAsync();
        // A caller past the tenant check whose token tenant is a sibling of the tenant it calls in, as an allow-listed
        // cross-tenant service client is: the backfill would write into the children of a tenant outside its subtree.
        var caller = Admin(sibling);

        var refusal = await DispatchAsync(host, caller, SystemIdentityCkIds.ClientProvisionMirrorsMethodId,
            client.RtId.ToString(), new ClientProvisionMirrorsParameters(), parent);

        refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        refusal.Error.Parameters.Should().Contain("reason", CrossTenantMethodSupport.TenantOutOfScopeReason);
        (await GetTrackingRowAsync(client.ClientId!, child, parent)).Should().BeNull();
        (await FindMirrorAsync(child, client.ClientId!)).Should().BeNull("no client is written in the child tenant");
    }

    [Fact]
    public async Task TheRotation_UnderRoleEnforcementWarn_IsStagedForItsRestFacadeOnly_NeverOnTheBus()
    {
        var host = Host(true, enforceSecretManagement: true, roleEnforcementWarn: true);
        var ct = TestContext.Current.CancellationToken;
        var client = await NewClientAsync(flagged: true);
        var child = await CreateChildTenantAsync();
        await ProvisionAsync(host, client, child);
        var ownBefore = OwnSecretValues(await FindMirrorAsync(child, client.ClientId!));

        // A caller with TenantManagement only, without SecretManagement: refused over the bus (the GraphQL gateway).
        var refusal = await DispatchAsync(host,
            new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [TenantManagement], ["octo_api"])
                { TokenTenantId = NormalizedSystemTenantId },
            SystemIdentityCkIds.ClientRotateMirrorSecretMethodId, client.RtId.ToString(),
            new ClientRotateMirrorSecretParameters { ChildTenantId = child });

        refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        refusal.Error.Parameters.Should().Contain("reason", "role-required");
        OwnSecretValues(await FindMirrorAsync(child, client.ClientId!)).Should()
            .Equal(ownBefore, "no new mirror secret was issued over the bus");

        // The same caller through the REST facade keeps the staged answer of existing REST callers.
        using var http = FacadeCaller.User(TenantManagement).Client(host);
        var rotated = await http.PostAsync(MirrorsUrl(client, $"{child}/secret"), null, ct);
        rotated.StatusCode.Should().Be(HttpStatusCode.OK, await rotated.Content.ReadAsStringAsync(ct));
    }

    #endregion

    #region Helpers

    private CkMethodPrincipal Admin(string? tokenTenantId = null) =>
        new(Guid.NewGuid().ToString("N"), [TenantManagement, SecretManagement], ["octo_api"])
        {
            TokenTenantId = tokenTenantId ?? NormalizedSystemTenantId
        };

    /// <summary>
    ///     An isolated parent: a child tenant of the system tenant with one child of its own and a flagged client inserted
    ///     after both (a new tenant mirrors the flagged clients of its parent at setup). The tests that prove "nothing was
    ///     written" run there, so the backfill of another test (which reaches the system tenant's flagged clients) cannot
    ///     provision this client.
    /// </summary>
    private async Task<(string Parent, string Child, RtClient Client)> IsolatedParentAsync()
    {
        var parent = await CreateChildTenantAsync();
        var child = await CreateChildTenantAsync(parent);
        var client = await NewClientAsync(flagged: true, tenantId: parent);
        return (parent, child, client);
    }

    private static List<string?> OwnSecretValues(RtClient? mirror) =>
        mirror?.ClientSecrets?.Where(ClientMirrorSecrets.IsOwnSecret).Select(s => s.Value).ToList() ?? [];

    private string MirrorsUrl(RtClient client, string path, string? tenantId = null) =>
        TenantApiUrl($"clients/{client.ClientId}/mirrors/{path}", tenantId);

    private string MirrorFlagUrl(RtClient client) => TenantApiUrl($"clients/{client.ClientId}/autoProvisionInChildTenants");

    private async Task ProvisionAsync(WebApplicationFactory<Program> host, RtClient client, string child)
    {
        var provisioned = await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId,
            client.RtId.ToString(), new ClientProvisionMirrorInTenantParameters { ChildTenantId = child });
        provisioned.Success.Should().BeTrue(provisioned.Error?.Code);
    }

    private WebApplicationFactory<Program> Host(bool enablePasswordMethods, bool enforceTenantGate = false,
        bool enforceSecretManagement = false, IRtDataPermissionEvaluator? evaluator = null, bool roleEnforcementWarn = false)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (roleEnforcementWarn)
            {
                b.UseSetting("IdentityApiAuthorization:RoleEnforcement", "Warn");
            }

            b.UseSetting("Methods:Identity:EnablePasswordMethods", enablePasswordMethods ? "true" : "false");
            if (enforceTenantGate)
            {
                b.UseSetting("TenantAuthorization:UserTokenEnforcement", "Enforce");
            }

            if (enforceSecretManagement)
            {
                b.UseSetting("IdentityApiAuthorization:SecretManagementRoleEnforcement", "Enforce");
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
                services.AddLogging(l => l.AddProvider(new LevelCapture(_logs)));
                if (evaluator != null)
                {
                    services.AddSingleton(evaluator);
                }
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, string targetRtId, object parameters, string? tenantId = null)
    {
        var request = new CkMethodRequest(tenantId ?? NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = IdentityMethodFacade.ClientCkTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(60)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private async Task<RtClient> NewClientAsync(bool flagged, string? tenantId = null)
    {
        var repo = await RepositoryAsync(tenantId ?? NormalizedSystemTenantId);
        await EnsureApiScopeAsync(repo);
        var builder = new RtClientBuilder().WithClientId($"mf-{Guid.NewGuid():N}")
            .WithGrantTypes("client_credentials").WithScopes(ApiScope).RequireClientSecret().RequirePkce(false);
        if (flagged)
        {
            builder.WithAutoProvisionInChildTenants();
        }

        // Inserted through the repository, not the client store: the store's hook would mirror a flagged client into every
        // child tenant at once, and these tests decide when a mirror is provisioned.
        var client = builder.Build();
        using var session = await repo.GetSessionAsync();
        await repo.InsertOneRtEntityAsync(session, client);
        return client;
    }

    private async Task<RtClient> LoadAsync(RtClient client, string? tenantId = null)
    {
        var repo = await RepositoryAsync(tenantId ?? NormalizedSystemTenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntityByRtIdAsync<RtClient>(session, client.RtId))!;
    }

    private static async Task EnsureApiScopeAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        var existing = await repo.GetRtEntitiesByTypeAsync<RtApiScope>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, ApiScope));
        if (existing.Items.Any())
        {
            return;
        }

        await repo.InsertOneRtEntityAsync(session, new RtApiScope
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = ApiScope,
            DisplayName = "Client mirror facade API",
            Enabled = true,
            ShowInDiscoveryDocument = true
        });
    }

    /// <summary>A new child tenant of the system tenant, or of <paramref name="parentTenantId" />.</summary>
    private async Task<string> CreateChildTenantAsync(string? parentTenantId = null)
    {
        var childTenantId = $"mfac{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        if (parentTenantId == null)
        {
            using var session = await systemContext.GetAdminSessionAsync();
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }
        else
        {
            var parentContext = await systemContext.GetChildTenantContextAsync(parentTenantId);
            using var session = await parentContext.GetAdminSessionAsync();
            session.StartTransaction();
            await parentContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        await EnsureApiScopeAsync(await RepositoryAsync(childTenantId));
        await WaitUntilRegistryKnowsAsync(childTenantId);
        return childTenantId;
    }

    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new TimeoutException($"Tenant '{tenantId}' did not appear in the registry.");
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId) =>
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;

    private async Task<RtClient?> FindMirrorAsync(string childTenantId, string clientId)
    {
        var repo = await RepositoryAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClient>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId))).Items.SingleOrDefault();
    }

    private async Task<RtClientMirror?> GetTrackingRowAsync(string clientId, string childTenantId,
        string? parentTenantId = null)
    {
        var repo = await RepositoryAsync(parentTenantId ?? NormalizedSystemTenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClientMirror>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId)))
            .Items.SingleOrDefault();
    }

    private static async Task<HttpStatusCode> RequestTokenAsync(WebApplicationFactory<Program> host, string tenantId,
        string clientId, string secret, CancellationToken ct)
    {
        using var http = host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["scope"] = ApiScope,
            ["acr_values"] = $"tenant:{tenantId}"
        }), ct);
        return response.StatusCode;
    }

    private void AssertNothingReachedTheBroker() =>
        _eventHub.ReceivedCalls().Where(c => c.GetArguments().Any(a => a is CkMethodRequest)).Should()
            .BeEmpty("the mirror methods run in-process; no method request is sent or published");

    /// <summary>The issued mirror secret (clear text and hash) is in no log line, no audit event and no trace tag.</summary>
    private void AssertSecretNowhere(string secret)
    {
        var hash = OctoSecretHasher.HashSecret(secret);
        _logs.Should().NotContain(l => l.Text.Contains(secret, StringComparison.Ordinal), "logs");
        _logs.Where(l => l.Level >= LogLevel.Information).Should()
            .NotContain(l => l.Text.Contains(hash, StringComparison.Ordinal), "no hash at Information or above");
        _audit.All.SelectMany(e => e.Values).Should()
            .NotContain(v => v.Contains(secret, StringComparison.Ordinal) || v.Contains(hash, StringComparison.Ordinal),
                "audit");
        _activityTags.Should().NotContain(t => t.Contains(secret, StringComparison.Ordinal), "traces");
    }

    private sealed class LevelCapture(ConcurrentQueue<(LogLevel Level, string Text)> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new Logger(sink);

        public void Dispose()
        {
        }

        private sealed class Logger(ConcurrentQueue<(LogLevel Level, string Text)> sink) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                sink.Enqueue((logLevel, formatter(state, exception) + " " + exception));
                if (state is IEnumerable<KeyValuePair<string, object?>> values)
                {
                    foreach (var value in values)
                    {
                        sink.Enqueue((logLevel, $"{value.Key}={value.Value}"));
                    }
                }
            }
        }
    }

    #endregion
}
