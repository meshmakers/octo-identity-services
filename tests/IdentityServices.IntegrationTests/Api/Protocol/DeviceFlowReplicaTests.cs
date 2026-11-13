using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using IdentityServices.IntegrationTests.Persistence;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Mvc.Testing.Handlers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#7891: device-code sign-in to a non-system tenant works when the requests of one flow land on different
///     identity replicas, and when identity restarts between authorization and approval.
/// </summary>
/// <remarks>
///     <para>
///         Each "replica" is its own in-process host (<see cref="WebApplicationFactory{TEntryPoint}.WithWebHostBuilder" />)
///         over the same MongoDB — its own DI container, caches and OpenIddict server, like a second pod. One browser
///         (one cookie jar) and one octo-cli-shaped client talk to them in turn. The token poll sends exactly what
///         octo-cli sends (client_id + device_code, no acr_values).
///     </para>
///     <para>
///         The former in-process <c>TokenToTenantMap</c> was static, i.e. shared by all hosts of this test process, so two
///         hosts alone would not have caught the bug. The tests therefore also pin that the middleware holds no static
///         map (removed with AB#7892): with nothing in process memory the flow can only succeed because the tenant is
///         derived from the request.
///     </para>
/// </remarks>
public class DeviceFlowReplicaTests : IntegrationTestBase
{
    private const string DeviceClientId = "replica-device-client";
    private const string DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";

    public DeviceFlowReplicaTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task DeviceFlow_AuthorizeOnReplicaA_ApproveOnReplicaB_PollOnReplicaA_IssuesTokenForTheTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithDeviceClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        using var replicaA = Factory.WithWebHostBuilder(_ => { });
        using var replicaB = Factory.WithWebHostBuilder(_ => { });
        var cookies = new System.Net.CookieContainer();

        var (userCode, deviceCode) = await StartDeviceFlowAsync(replicaA, tenantId, ct);
        AssertNoDeviceEntryInProcessMemory(deviceCode);

        await SignInAsync(replicaA, cookies, tenantId, userName, ct);
        var context = await GetVerificationContextAsync(replicaB, cookies, tenantId, userCode, ct);
        context.StatusCode.Should().Be(HttpStatusCode.OK, "replica B resolves tenant T from the page's tenant hint");
        context.Body!["tenantId"]!.GetValue<string>().Should().BeEquivalentTo(tenantId);
        context.Body["accountUserName"]!.GetValue<string>().Should().Be(userName,
            "the user is looked up in T's user store, no 401/login loop");

        (await ApproveAsync(replicaB, cookies, tenantId, userCode, ct)).Should().BeTrue();

        var accessToken = await RedeemAsync(replicaA, deviceCode, ct);
        TenantOf(accessToken).Should().BeEquivalentTo(tenantId, "the token is issued in T, not the system tenant");
    }

    [Fact]
    public async Task DeviceFlow_IdentityRestartsBeforeApproval_VerificationAndPollStillResolveTheTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithDeviceClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new System.Net.CookieContainer();

        string userCode, deviceCode;
        using (var beforeRestart = Factory.WithWebHostBuilder(_ => { }))
        {
            (userCode, deviceCode) = await StartDeviceFlowAsync(beforeRestart, tenantId, ct);
        }

        // A fresh host = a restarted process: nothing of the first host survives except the database.
        using var afterRestart = Factory.WithWebHostBuilder(_ => { });
        AssertNoDeviceEntryInProcessMemory(deviceCode);

        await SignInAsync(afterRestart, cookies, tenantId, userName, ct);
        var context = await GetVerificationContextAsync(afterRestart, cookies, tenantId, userCode, ct);
        context.StatusCode.Should().Be(HttpStatusCode.OK);
        context.Body!["tenantId"]!.GetValue<string>().Should().BeEquivalentTo(tenantId);
        (await ApproveAsync(afterRestart, cookies, tenantId, userCode, ct)).Should().BeTrue();

        TenantOf(await RedeemAsync(afterRestart, deviceCode, ct)).Should().BeEquivalentTo(tenantId);
    }

    [Fact]
    public async Task Verification_UserCodeOfAnotherTenant_IsAnInvalidCode_AndRevealsNothingAboutThatTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        var foreignTenantId = await CreateTenantWithDeviceClientAsync();
        var homeTenantId = await CreateTenantWithDeviceClientAsync();
        var userName = await CreateLocalUserAsync(homeTenantId);
        var cookies = new System.Net.CookieContainer();
        var (foreignUserCode, _) = await StartDeviceFlowAsync(Factory, foreignTenantId, ct);

        await SignInAsync(Factory, cookies, homeTenantId, userName, ct);
        var context = await GetVerificationContextAsync(Factory, cookies, homeTenantId, foreignUserCode, ct);

        context.StatusCode.Should().Be(HttpStatusCode.NotFound);
        context.Raw.Should().Contain("Invalid or expired device code").And.NotContain(foreignTenantId);

        var approve = await CookieClient(Factory, cookies).PostAsync("/connect/deviceverification",
            VerificationForm(homeTenantId, foreignUserCode), ct);
        var approveRaw = await approve.Content.ReadAsStringAsync(ct);
        var body = JsonNode.Parse(approveRaw)!;
        body["success"]!.GetValue<bool>().Should().BeFalse("the code does not exist in the home tenant");
        body["errorMessage"]!.GetValue<string>().Should().Be("Invalid or expired device code");
        approveRaw.Should().NotContain(foreignTenantId);
    }

    [Fact]
    public async Task Poll_DeviceCodeWithAnotherTenantsMarker_IsInvalidGrant()
    {
        // The marker only selects the token store; a changed prefix points to a store without the code.
        var ct = TestContext.Current.CancellationToken;
        var tenantId = await CreateTenantWithDeviceClientAsync();
        var otherTenantId = await CreateTenantWithDeviceClientAsync();
        var userName = await CreateLocalUserAsync(tenantId);
        var cookies = new System.Net.CookieContainer();
        var (userCode, deviceCode) = await StartDeviceFlowAsync(Factory, tenantId, ct);
        await SignInAsync(Factory, cookies, tenantId, userName, ct);
        (await ApproveAsync(Factory, cookies, tenantId, userCode, ct)).Should().BeTrue();

        OidcTenantMarker.TryDecode(deviceCode, out var markedTenant, out var innerCode).Should().BeTrue();
        markedTenant.Should().BeEquivalentTo(tenantId);
        var response = await PollAsync(Factory, OidcTenantMarker.Encode(otherTenantId, innerCode), ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!["error"]!.GetValue<string>()
            .Should().Be("invalid_grant");
    }

    [Fact]
    public async Task DeviceFlow_SystemTenant_StillWorks()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureDeviceClientAsync(Factory.Services.GetRequiredService<ISystemContext>().GetSystemTenantRepositoryAsAdmin());
        var userName = $"replica-sys-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);
        var cookies = new System.Net.CookieContainer();
        var (userCode, deviceCode) = await StartDeviceFlowAsync(Factory, NormalizedSystemTenantId, ct);

        await SignInAsync(Factory, cookies, NormalizedSystemTenantId, userName, ct);
        (await ApproveAsync(Factory, cookies, NormalizedSystemTenantId, userCode, ct)).Should().BeTrue();

        TenantOf(await RedeemAsync(Factory, deviceCode, ct)).Should().BeEquivalentTo(NormalizedSystemTenantId);
    }

    private static void AssertNoDeviceEntryInProcessMemory(string deviceCode)
    {
        OidcTenantMarker.TryDecode(deviceCode, out _, out _).Should().BeTrue(
            "the device_code carries the tenant marker");
        // AB#7892: the middleware keeps no process-local token state at all (see
        // OidcTenantResolutionReplicaTests.Middleware_HoldsNoProcessLocalTokenToTenantState).
        typeof(OidcTenantResolutionMiddleware)
            .GetFields(System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic |
                       System.Reflection.BindingFlags.Public)
            .Should().NotContain(f => typeof(System.Collections.IDictionary).IsAssignableFrom(f.FieldType),
                "no device entry can be held in a static in-process map");
    }

    private static HttpClient AnonymousClient(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static HttpClient CookieClient(WebApplicationFactory<Program> host, System.Net.CookieContainer cookies)
        => host.CreateDefaultClient(new Uri("http://localhost"), new CookieContainerHandler(cookies));

    private static FormUrlEncodedContent VerificationForm(string tenantId, string userCode)
        => new(new Dictionary<string, string> { ["user_code"] = userCode, ["acr_values"] = $"tenant:{tenantId}" });

    private static async Task<(string UserCode, string DeviceCode)> StartDeviceFlowAsync(
        WebApplicationFactory<Program> host, string tenantId, CancellationToken ct)
    {
        var response = await AnonymousClient(host).PostAsync("/connect/deviceauthorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = DeviceClientId,
                ["scope"] = "openid",
                ["acr_values"] = $"tenant:{tenantId}"
            }), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, raw);
        var json = JsonNode.Parse(raw)!;
        return (json["user_code"]!.GetValue<string>(), json["device_code"]!.GetValue<string>());
    }

    private static async Task SignInAsync(WebApplicationFactory<Program> host, System.Net.CookieContainer cookies,
        string tenantId, string userName, CancellationToken ct)
    {
        var response = await CookieClient(host, cookies).PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!.Success.Should().BeTrue();
    }

    private static async Task<(HttpStatusCode StatusCode, string Raw, JsonNode? Body)> GetVerificationContextAsync(
        WebApplicationFactory<Program> host, System.Net.CookieContainer cookies, string tenantId, string userCode,
        CancellationToken ct)
    {
        var response = await CookieClient(host, cookies).GetAsync(
            $"/connect/deviceverification?user_code={Uri.EscapeDataString(userCode)}" +
            $"&acr_values={Uri.EscapeDataString($"tenant:{tenantId}")}", ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        return (response.StatusCode, raw, response.StatusCode == HttpStatusCode.OK ? JsonNode.Parse(raw) : null);
    }

    private static async Task<bool> ApproveAsync(WebApplicationFactory<Program> host, System.Net.CookieContainer cookies,
        string tenantId, string userCode, CancellationToken ct)
    {
        var response = await CookieClient(host, cookies).PostAsync("/connect/deviceverification",
            VerificationForm(tenantId, userCode), ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, raw);
        return JsonNode.Parse(raw)!["success"]!.GetValue<bool>();
    }

    /// <summary>Exactly what octo-cli sends (octo-sdk <c>RequestDeviceTokenAsync</c>): no acr_values.</summary>
    private static Task<HttpResponseMessage> PollAsync(WebApplicationFactory<Program> host, string deviceCode,
        CancellationToken ct)
        => AnonymousClient(host).PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = DeviceCodeGrant,
                ["client_id"] = DeviceClientId,
                ["device_code"] = deviceCode
            }), ct);

    private static async Task<string> RedeemAsync(WebApplicationFactory<Program> host, string deviceCode,
        CancellationToken ct)
    {
        var response = await PollAsync(host, deviceCode, ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "device code redemption: {0}",
            JsonNode.Parse(raw)?["error_description"]?.GetValue<string>());
        return JsonNode.Parse(raw)!["access_token"]!.GetValue<string>();
    }

    private static string? TenantOf(string accessToken)
        => new JsonWebToken(accessToken).Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;

    private async Task<string> CreateTenantWithDeviceClientAsync()
    {
        var tenantId = $"devrep{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        }

        await EnsureDeviceClientAsync((await systemContext.TryFindTenantRepositoryAsync(tenantId))!);
        return tenantId;
    }

    private static async Task EnsureDeviceClientAsync(ITenantRepository repository)
    {
        var clientStore = new ClientStore(new FixedTenantResolver(repository));
        if (await clientStore.FindRtClientByIdAsync(DeviceClientId) == null)
        {
            await clientStore.CreateAsync(new RtClientBuilder()
                .WithClientId(DeviceClientId)
                .WithClientName(DeviceClientId)
                .WithGrantTypes(DeviceCodeGrant)
                .WithScopes("openid")
                .RequirePkce(false)
                .Build());
        }
    }

    /// <summary>A local user of the tenant itself.</summary>
    private async Task<string> CreateLocalUserAsync(string tenantId)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repository = (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        using var scope = CreateScope();
        var sp = scope.ServiceProvider;
        using var userManager = new UserManager<RtUser>(
            new OctoUserStore(new FixedTenantResolver(repository), sp.GetRequiredService<IGroupRoleResolver>(), null),
            sp.GetRequiredService<IOptions<IdentityOptions>>(),
            sp.GetRequiredService<IPasswordHasher<RtUser>>(),
            sp.GetServices<IUserValidator<RtUser>>(),
            sp.GetServices<IPasswordValidator<RtUser>>(),
            sp.GetRequiredService<ILookupNormalizer>(),
            sp.GetRequiredService<IdentityErrorDescriber>(),
            sp,
            sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<UserManager<RtUser>>>());

        var userName = $"devrep_{Guid.NewGuid():N}";
        var user = new RtUserBuilder().WithUserName(userName).WithEmail($"{userName}@example.com")
            .WithEmailConfirmed(true).Build();
        (await userManager.CreateAsync(user, DefaultPassword)).Succeeded.Should().BeTrue();
        return userName;
    }
}
