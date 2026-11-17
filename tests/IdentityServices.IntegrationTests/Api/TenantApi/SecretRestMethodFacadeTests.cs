using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
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
///     The secret write endpoints of <c>ApiSecretsController</c> are facades of <c>Client.AddSecret</c>,
///     <c>Client.UpdateSecret</c>, <c>Client.RemoveSecret</c> and <c>ApiResource.AddSecret/UpdateSecret/RemoveSecret</c>.
///     Real MongoDB, real identity host, both values of <c>Methods:Identity:EnablePasswordMethods</c>. The REST contract stays
///     covered by <see cref="ApiSecretsControllerTests" />; these tests prove that every endpoint runs its method in-process
///     outside the request with one <c>Identity.Method</c> event and nothing on the broker, that REST and the method (the
///     GraphQL path) leave the same end state, that no clear text reaches a log, audit or trace, the staged
///     <c>SecretManagementRoleEnforcement</c>, the abuse cases and the data permission of the owner (CWE-863).
/// </summary>
public class SecretRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";
    private const string SecretManagement = "SecretManagement";
    private const string ClientKind = "client";
    private const string ApiResourceKind = "apiResource";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly ConcurrentQueue<(LogLevel Level, string Text)> _logs = new();
    private readonly ConcurrentQueue<string> _activityTags = new();
    private readonly ActivityListener _activities;
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public SecretRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
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

    /// <summary>Owner kind x <c>EnablePasswordMethods</c>.</summary>
    public static TheoryData<string, bool> OwnersAndSwitch => new()
    {
        { ClientKind, false }, { ClientKind, true }, { ApiResourceKind, false }, { ApiResourceKind, true }
    };

    public static TheoryData<string> Owners => new() { ClientKind, ApiResourceKind };

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
    [MemberData(nameof(OwnersAndSwitch))]
    public async Task EveryWriteEndpoint_RunsItsMethodInProcess_OutsideTheRequest_OneEvent_NothingOnTheBroker(string kind,
        bool switchOn)
    {
        var host = Host(switchOn);
        var owner = await NewOwnerAsync(kind);
        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        // add
        var added = await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { description = "facade" }, ct);
        added.StatusCode.Should().Be(HttpStatusCode.OK, await added.Content.ReadAsStringAsync(ct));
        var body = (await added.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        var clearText = body["valueClearText"]!.GetValue<string>();
        var hash = body["valueEncrypted"]!.GetValue<string>();
        hash.Should().Be(OctoSecretHasher.HashSecret(clearText), "the REST body keeps the stored hash next to the clear text");
        body["description"]!.GetValue<string>().Should().Be("facade");
        (await StoredAsync(kind, owner.Name)).Should().ContainSingle(s => s.Value == hash);

        // update
        (await http.PutAsJsonAsync(SecretsUrl(kind, owner.Name), new { valueEncrypted = hash, description = "rotated" }, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await StoredAsync(kind, owner.Name)).Single().Description.Should().Be("rotated");

        // remove (body variant), then add + remove through the legacy path variant
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name) + "/delete", new { valueEncrypted = hash }, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        var second = (await (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct))
            .Content.ReadFromJsonAsync<JsonObject>(ct))!["valueEncrypted"]!.GetValue<string>();
        (await http.DeleteAsync(SecretsUrl(kind, owner.Name) + "/" + Uri.EscapeDataString(second.EncodeBase64()), ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await StoredAsync(kind, owner.Name)).Should().BeEmpty();

        var (add, update, remove) = MethodIds(kind);
        _audit.For(add, owner.RtId).Should().HaveCount(2).And.OnlyContain(e => e["outcome"] == "SUCCESS");
        _audit.For(update, owner.RtId).Should().ContainSingle().Which["outcome"].Should().Be("SUCCESS");
        _audit.For(remove, owner.RtId).Should().HaveCount(2).And.OnlyContain(e => e["outcome"] == "SUCCESS");
        _probe.Calls.Should().Be(5, "every REST call ran its method through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
        AssertNothingReachedTheBroker();
        AssertClearTextNowhere(clearText);
        AssertHashNotAboveDebug(hash);
    }

    [Fact]
    public void SwitchOff_TheSecretMethodsAreNotOfferedOnTheBus_SoGraphQlAnswersHandlerNotAvailable()
    {
        // The gateway reaches a method only through its announcement on the bus; local-only handlers are never announced.
        var offered = IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId).ToList();
        var localOnly = IdentityMethodHost.SelectLocalOnlyHandlers(new IdentityMethodsOptions()).Select(h => h.MethodId)
            .ToList();
        var transport = Host(false).Services.GetRequiredService<ICkInProcessMethodTransport>();

        foreach (var methodId in AllSecretMethodIds)
        {
            offered.Should().NotContain(methodId);
            localOnly.Should().Contain(methodId);
            transport.CanHandle(methodId).Should().BeTrue(methodId);
        }

        IdentityMethodHost.SelectHandlers(new IdentityMethodsOptions { EnablePasswordMethods = true })
            .Select(h => h.MethodId).Should().Contain(AllSecretMethodIds);
    }

    #endregion

    #region Same end state as REST, per method

    [Theory]
    [MemberData(nameof(OwnersAndSwitch))]
    public async Task RestAndMethod_LeaveTheSameSecrets_ForAddUpdateExpiredRemoveDuplicateAndUnknown(string kind,
        bool switchOn)
    {
        var host = Host(switchOn);
        var restOwner = await NewOwnerAsync(kind);
        var methodOwner = await NewOwnerAsync(kind);
        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var (add, update, remove) = MethodIds(kind);
        var expires = DateTime.UtcNow.AddDays(30);

        // add
        var restHash = (await (await http.PostAsJsonAsync(SecretsUrl(kind, restOwner.Name),
            new { description = "p", expirationDate = expires }, ct)).Content.ReadFromJsonAsync<JsonObject>(ct))!
            ["valueEncrypted"]!.GetValue<string>();
        var added = await DispatchAsync(host, Admin(), add, kind, methodOwner.RtId,
            AddParameters(kind, "p", expires));
        added.Success.Should().BeTrue(added.Error?.Code);
        var methodClearText = JsonSerializer.Deserialize<string>(added.ResultJson!)!;
        var methodHash = OctoSecretHasher.HashSecret(methodClearText);
        Shape(await StoredAsync(kind, restOwner.Name)).Should().Equal(Shape(await StoredAsync(kind, methodOwner.Name)));

        // update to an expiration in the past (an expired secret): both accept it
        var past = DateTime.UtcNow.AddDays(-1);
        (await http.PutAsJsonAsync(SecretsUrl(kind, restOwner.Name),
            new { valueEncrypted = restHash, description = "expired", expirationDate = past }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, Admin(), update, kind, methodOwner.RtId,
            UpdateParameters(kind, methodHash, "expired", past))).Success.Should().BeTrue();
        Shape(await StoredAsync(kind, restOwner.Name)).Should().Equal(Shape(await StoredAsync(kind, methodOwner.Name)));
        (await StoredAsync(kind, methodOwner.Name)).Single().ExpirationDateTime.Should().BeBefore(DateTime.UtcNow);

        // unknown secret value: REST 404 (no echo), the method SECRET_NOT_FOUND; nothing changes
        var unknown = OctoSecretHasher.HashSecret("never-issued");
        var restUnknown = await http.PutAsJsonAsync(SecretsUrl(kind, restOwner.Name),
            new { valueEncrypted = unknown, description = "x" }, ct);
        restUnknown.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await restUnknown.Content.ReadAsStringAsync(ct)).Should().NotContain(unknown);
        (await http.PostAsJsonAsync(SecretsUrl(kind, restOwner.Name) + "/delete", new { valueEncrypted = unknown }, ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DispatchAsync(host, Admin(), update, kind, methodOwner.RtId, UpdateParameters(kind, unknown, "x", null)))
            .Error!.Code.Should().Be(ClientSecretMethodErrors.SecretNotFound);
        (await DispatchAsync(host, Admin(), remove, kind, methodOwner.RtId, RemoveParameters(kind, unknown)))
            .Error!.Code.Should().Be(ClientSecretMethodErrors.SecretNotFound);

        // duplicate records with the same value: both paths remove every match
        await AddRawSecretAsync(kind, restOwner.Name, restHash);
        await AddRawSecretAsync(kind, methodOwner.Name, methodHash);
        (await http.PostAsJsonAsync(SecretsUrl(kind, restOwner.Name) + "/delete", new { valueEncrypted = restHash }, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, Admin(), remove, kind, methodOwner.RtId, RemoveParameters(kind, methodHash)))
            .Success.Should().BeTrue();
        (await StoredAsync(kind, restOwner.Name)).Should().BeEmpty();
        (await StoredAsync(kind, methodOwner.Name)).Should().BeEmpty();

        // unknown owner: REST 404, the method METHOD_TARGET_NOT_FOUND
        (await http.PostAsJsonAsync(SecretsUrl(kind, "no-such-owner-9037"), new { }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await DispatchAsync(host, Admin(), add, kind, OctoObjectId.GenerateNewId().ToString(),
            AddParameters(kind, null, null))).Error!.Code.Should().Be(CkMethodErrorCodes.MethodTargetNotFound);
        AssertClearTextNowhere(methodClearText);
    }

    [Fact]
    public async Task ClientSecretAddedOverRest_Authenticates_AndNoLongerAfterTheRestRemove()
    {
        var host = Host(false);
        var owner = await NewOwnerAsync(ClientKind);
        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        var body = (await (await http.PostAsJsonAsync(SecretsUrl(ClientKind, owner.Name), new { }, ct))
            .Content.ReadFromJsonAsync<JsonObject>(ct))!;
        var clearText = body["valueClearText"]!.GetValue<string>();
        (await RequestTokenAsync(host, owner.Name, clearText)).Should().Be(HttpStatusCode.OK);

        (await http.PostAsJsonAsync(SecretsUrl(ClientKind, owner.Name) + "/delete",
            new { valueEncrypted = body["valueEncrypted"]!.GetValue<string>() }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await RequestTokenAsync(host, owner.Name, clearText)).Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task IntendedChange_AddingASecretToAPublicClient_Is400_AndStoresNothing()
    {
        var host = Host(false);
        var clientId = $"s9037-public-{Guid.NewGuid():N}";
        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(new RtClientBuilder()
                .WithClientId(clientId).WithGrantTypes("authorization_code").WithScopes("openid").Build());
        }

        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var response = await http.PostAsJsonAsync(SecretsUrl(ClientKind, clientId), new { },
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await StoredAsync(ClientKind, clientId)).Should().BeEmpty();
    }

    [Fact]
    public async Task UpdatingAMirrorsOwnSecret_Is400_AndTheMarkerStays()
    {
        // the marker tells the mirror sync that the record is the mirror's own credential
        var host = Host(false);
        var owner = await NewOwnerAsync(ClientKind);
        var hash = await AddRawSecretAsync(ClientKind, owner.Name, null, ClientMirrorSecrets.OwnSecretDescription);
        using var http = FacadeCaller.User(SecretManagement).Client(host);

        (await http.PutAsJsonAsync(SecretsUrl(ClientKind, owner.Name), new { valueEncrypted = hash, description = "mine" },
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.ClientUpdateSecretMethodId, ClientKind, owner.RtId,
                UpdateParameters(ClientKind, hash, "mine", null))).Error!.Code.Should()
            .Be(CkMethodErrorCodes.MethodValidationFailed);
        (await StoredAsync(ClientKind, owner.Name)).Single().Description.Should().Be(ClientMirrorSecrets.OwnSecretDescription);
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task IntendedChange_AnExpirationInThePastOnAdd_Is400_AndStoresNothing(string kind)
    {
        var host = Host(false);
        var owner = await NewOwnerAsync(kind);
        using var http = FacadeCaller.User(SecretManagement).Client(host);

        var response = await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name),
            new { expirationDate = DateTime.UtcNow.AddMinutes(-5) }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await StoredAsync(kind, owner.Name)).Should().BeEmpty();
    }

    #endregion

    #region SecretManagementRoleEnforcement, abuse cases, data permission of the owner

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task Enforce_IsHonouredOnBothPaths_SecretManagementPasses_TenantManagementAloneIsRefused(string kind)
    {
        var host = Host(false, enforceSecretManagement: true);
        var owner = await NewOwnerAsync(kind);
        var ct = TestContext.Current.CancellationToken;
        var (add, _, _) = MethodIds(kind);

        using (var tenantAdmin = FacadeCaller.User(TenantManagement).Client(host))
        {
            (await tenantAdmin.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct)).StatusCode.Should()
                .Be(HttpStatusCode.Forbidden);
        }

        var refused = await DispatchAsync(host, new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [TenantManagement],
            ["octo_api"]), add, kind, owner.RtId, AddParameters(kind, null, null));
        refused.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        (await StoredAsync(kind, owner.Name)).Should().BeEmpty();

        using (var secretAdmin = FacadeCaller.User(SecretManagement).Client(host))
        {
            (await secretAdmin.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct)).StatusCode.Should()
                .Be(HttpStatusCode.OK);
        }

        (await DispatchAsync(host, new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [SecretManagement], ["octo_api"]),
            add, kind, owner.RtId, AddParameters(kind, null, null))).Success.Should().BeTrue();
        (await StoredAsync(kind, owner.Name)).Should().HaveCount(2);
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingChanges(string kind)
    {
        var host = Host(false, enforceTenantGate: true);
        var owner = await NewOwnerAsync(kind);
        var (add, _, _) = MethodIds(kind);
        var foreign = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [SecretManagement], ["octo_api"])
        {
            IsFromAccessToken = true, TokenTenantId = "othertenant9037"
        };

        var method = await DispatchAsync(host, foreign, add, kind, owner.RtId, AddParameters(kind, null, null));

        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        using var http = (FacadeCaller.User(SecretManagement) with { TokenTenant = "othertenant9037" }).Client(host);
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, TestContext.Current.CancellationToken))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await StoredAsync(kind, owner.Name)).Should().BeEmpty();
        _audit.For(add, owner.RtId).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task ACallerWithoutTheDeclaredRole_IsRefused_AndNothingChanges(string kind)
    {
        var host = Host(false);
        var owner = await NewOwnerAsync(kind);
        var hash = await AddRawSecretAsync(kind, owner.Name, null);
        var (add, update, remove) = MethodIds(kind);
        var outsider = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), ["CommunicationManagement"], ["octo_api"]);

        foreach (var (methodId, parameters) in new (string, object)[]
                 {
                     (add, AddParameters(kind, null, null)), (update, UpdateParameters(kind, hash, "x", null)),
                     (remove, RemoveParameters(kind, hash))
                 })
        {
            (await DispatchAsync(host, outsider, methodId, kind, owner.RtId, parameters)).Error!.Code.Should()
                .Be(CkMethodErrorCodes.MethodForbidden, methodId);
        }

        using var http = FacadeCaller.User("CommunicationManagement").Client(host);
        var ct = TestContext.Current.CancellationToken;
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.Forbidden);
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name) + "/delete", new { valueEncrypted = hash }, ct))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await StoredAsync(kind, owner.Name)).Should().ContainSingle(s => s.Value == hash && s.Description == null);
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task AnOwnerTheCallerCannotRead_AnswersAsUnknown_AndNothingChanges(string kind)
    {
        // CWE-863: an enforcing data policy hides the owner; REST must not add, change or remove its secrets behind it
        var host = Host(false, evaluator: Evaluator(RtDataPermissionDecision.NotVisible));
        var owner = await NewOwnerAsync(kind);
        var hash = await AddRawSecretAsync(kind, owner.Name, null);
        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await http.PutAsJsonAsync(SecretsUrl(kind, owner.Name), new { valueEncrypted = hash, description = "x" }, ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name) + "/delete", new { valueEncrypted = hash }, ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);

        var (add, _, remove) = MethodIds(kind);
        (await DispatchAsync(host, Admin(), add, kind, owner.RtId, AddParameters(kind, null, null))).Error!.Code
            .Should().Be(CkMethodErrorCodes.MethodTargetNotFound);
        (await DispatchAsync(host, Admin(), remove, kind, owner.RtId, RemoveParameters(kind, hash))).Error!.Code
            .Should().Be(CkMethodErrorCodes.MethodTargetNotFound);
        (await StoredAsync(kind, owner.Name)).Should().ContainSingle(s => s.Value == hash && s.Description == null);
    }

    [Theory]
    [MemberData(nameof(Owners))]
    public async Task AnOwnerTheCallerMayReadButNotWrite_Is403DataPermission_AndNothingChanges(string kind)
    {
        var host = Host(false, evaluator: Evaluator(RtDataPermissionDecision.NotPermitted));
        var owner = await NewOwnerAsync(kind);
        var hash = await AddRawSecretAsync(kind, owner.Name, null);
        using var http = FacadeCaller.User(SecretManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        var response = await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name) + "/delete", new { valueEncrypted = hash },
            ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        problem.GetProperty("code").GetString().Should().Be(CkMethodErrorCodes.MethodForbidden);
        problem.GetProperty("parameters").GetProperty("reason").GetString().Should().Be("data-permission");
        (await http.PostAsJsonAsync(SecretsUrl(kind, owner.Name), new { }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.Forbidden);
        (await StoredAsync(kind, owner.Name)).Should().ContainSingle(s => s.Value == hash);
    }

    #endregion

    #region Helpers

    private static readonly string[] AllSecretMethodIds =
    [
        SystemIdentityCkIds.ClientAddSecretMethodId, SystemIdentityCkIds.ClientUpdateSecretMethodId,
        SystemIdentityCkIds.ClientRemoveSecretMethodId, SystemIdentityCkIds.ApiResourceAddSecretMethodId,
        SystemIdentityCkIds.ApiResourceUpdateSecretMethodId, SystemIdentityCkIds.ApiResourceRemoveSecretMethodId
    ];

    private static (string Add, string Update, string Remove) MethodIds(string kind) => kind == ClientKind
        ? (SystemIdentityCkIds.ClientAddSecretMethodId, SystemIdentityCkIds.ClientUpdateSecretMethodId,
            SystemIdentityCkIds.ClientRemoveSecretMethodId)
        : (SystemIdentityCkIds.ApiResourceAddSecretMethodId, SystemIdentityCkIds.ApiResourceUpdateSecretMethodId,
            SystemIdentityCkIds.ApiResourceRemoveSecretMethodId);

    private static object AddParameters(string kind, string? description, DateTime? expiration) => kind == ClientKind
        ? new ClientAddSecretParameters { Description = description, ExpirationDate = expiration }
        : new ApiResourceAddSecretParameters { Description = description, ExpirationDate = expiration };

    private static object UpdateParameters(string kind, string value, string? description, DateTime? expiration) =>
        kind == ClientKind
            ? new ClientUpdateSecretParameters { SecretValue = value, Description = description, ExpirationDate = expiration }
            : new ApiResourceUpdateSecretParameters
                { SecretValue = value, Description = description, ExpirationDate = expiration };

    private static object RemoveParameters(string kind, string value) => kind == ClientKind
        ? new ClientRemoveSecretParameters { SecretValue = value }
        : new ApiResourceRemoveSecretParameters { SecretValue = value };

    private static CkMethodPrincipal Admin() =>
        new(Guid.NewGuid().ToString("N"), [TenantManagement, SecretManagement], ["octo_api"]);

    private string SecretsUrl(string kind, string name) => TenantApiUrl($"apiSecrets/{kind}/{name}");

    private WebApplicationFactory<Program> Host(bool enablePasswordMethods, bool enforceSecretManagement = false,
        bool enforceTenantGate = false, IRtDataPermissionEvaluator? evaluator = null)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", enablePasswordMethods ? "true" : "false");
            if (enforceSecretManagement)
            {
                b.UseSetting("IdentityApiAuthorization:SecretManagementRoleEnforcement", "Enforce");
            }

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

    /// <summary>An enforcing data policy for the owner: every Write evaluation answers <paramref name="decision" />.</summary>
    private static IRtDataPermissionEvaluator Evaluator(RtDataPermissionDecision decision)
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(decision, RtDataPermissionReason.NoGrant));
        return evaluator;
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host,
        CkMethodPrincipal caller, string methodId, string kind, string targetRtId, object parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = kind == ClientKind ? IdentityMethodFacade.ClientCkTypeId : IdentityMethodFacade.ApiResourceCkTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = Infrastructure.TestHostMethodDeadlineFloor.DeadlineFromNow()
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private async Task<(string Name, string RtId)> NewOwnerAsync(string kind)
    {
        var name = $"s9037-{Guid.NewGuid():N}";
        using var scope = CreateScope();
        if (kind == ClientKind)
        {
            var client = new RtClientBuilder().WithClientId(name).WithClientName(name).WithGrantTypes("client_credentials")
                .WithScopes("openid").RequireClientSecret().RequirePkce(false).Build();
            await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
            return (name, client.RtId.ToString());
        }

        var resource = new RtApiResource
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = name,
            DisplayName = name,
            Enabled = true,
            ShowInDiscoveryDocument = true,
            Claims = new AttributeStringValueList(),
            Scopes = new AttributeStringValueList()
        };
        await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().CreateApiResourceAsync(resource);
        return (name, resource.RtId.ToString());
    }

    /// <summary>Stores a secret record directly (fixture); returns its stored value.</summary>
    private async Task<string> AddRawSecretAsync(string kind, string name, string? hash, string? description = null)
    {
        hash ??= OctoSecretHasher.HashSecret($"fixture-{Guid.NewGuid():N}");
        using var scope = CreateScope();
        var record = new RtSecretRecord { Value = hash, Description = description };
        if (kind == ClientKind)
        {
            await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().MutateAsync(name, c =>
            {
                c.ClientSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
                c.ClientSecrets.Add(record);
                return true;
            });
        }
        else
        {
            await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().MutateApiResourceAsync(name, r =>
            {
                r.ApiSecrets ??= new AttributeRecordValueList<RtSecretRecord>();
                r.ApiSecrets.Add(record);
                return true;
            });
        }

        return hash;
    }

    private async Task<List<RtSecretRecord>> StoredAsync(string kind, string name)
    {
        using var scope = CreateScope();
        if (kind == ClientKind)
        {
            var client = await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(name);
            return client?.ClientSecrets?.ToList() ?? [];
        }

        var resource = await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().GetApiResourceByNameAsync(name);
        return resource?.ApiSecrets?.ToList() ?? [];
    }

    /// <summary>What both paths must agree on (the value differs: each call generates its own secret).</summary>
    private static string[] Shape(IEnumerable<RtSecretRecord> secrets) => secrets
        .Select(s => $"{s.Description}|{s.ExpirationDateTime?.ToUniversalTime():yyyy-MM-ddTHH:mm}|{s.Type}")
        .ToArray();

    private async Task<HttpStatusCode> RequestTokenAsync(WebApplicationFactory<Program> host, string clientId,
        string secret)
    {
        using var http = host.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = secret,
            ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
        }), TestContext.Current.CancellationToken);
        return response.StatusCode;
    }

    private void AssertNothingReachedTheBroker() =>
        _eventHub.ReceivedCalls().Where(c => c.GetArguments().Any(a => a is CkMethodRequest)).Should()
            .BeEmpty("the secret methods run in-process; no method request is sent or published");

    /// <summary>The clear text is in no log line (any level), no audit event and no trace tag.</summary>
    private void AssertClearTextNowhere(string clearText)
    {
        _logs.Should().NotContain(l => l.Text.Contains(clearText, StringComparison.Ordinal), "logs");
        _audit.All.SelectMany(e => e.Values).Should()
            .NotContain(v => v.Contains(clearText, StringComparison.Ordinal), "audit");
        _activityTags.Should().NotContain(t => t.Contains(clearText, StringComparison.Ordinal), "traces");
    }

    /// <summary>
    ///     The stored hash is in no log line at Information or above (the engine's MongoDB command log at Debug renders the
    ///     update command for REST and method alike, off in every environment).
    /// </summary>
    private void AssertHashNotAboveDebug(string hash) =>
        _logs.Where(l => l.Level >= LogLevel.Information).Should()
            .NotContain(l => l.Text.Contains(hash, StringComparison.Ordinal));

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
