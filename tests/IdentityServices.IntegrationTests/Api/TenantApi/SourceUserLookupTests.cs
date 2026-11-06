using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8341: <c>POST {T}/v1/ExternalTenantUserMappings/sourceUserLookup</c> through the real pipeline (authentication,
///     tenant gate, policies, rate limit, controller) against MongoDB.
/// </summary>
/// <remarks>
///     Registry of the shared arrangement: system → T (target), system → S (sibling that permits T through the test
///     policy), system → U (sibling that does not permit T: the shipped default). Users live in S, U and the system tenant
///     (a registry ancestor of T). The arrangement is built once per factory; every test uses its own caller, so the
///     per-caller lookup limit of one test never counts for another.
/// </remarks>
public class SourceUserLookupTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";

    private static readonly SemaphoreSlim ArrangeGate = new(1, 1);
    // Weak: the arrangement must not root a disposed factory (AB#8337, test host memory).
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CustomWebApplicationFactory, Arrangement>
        Arrangements = new();

    public SourceUserLookupTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    // ---------------------------------------------------------------- positive

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PermittedSibling_ExactUserNameOrEmail_CaseInsensitive_ReturnsTheUserWithoutEmail(bool byEmail)
    {
        var a = await ArrangeAsync();
        var identifier = byEmail ? a.Alice.Email.ToUpperInvariant() : a.Alice.UserName.ToUpperInvariant();

        var response = await LookupAsync(Admin(), a.Target, a.Source, identifier);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var result = JsonSerializer.Deserialize<SourceUserLookupResultDto>(raw, JsonSerializerOptions.Web)!;
        result.SourceTenantId.Should().Be(a.Source);
        result.UserId.Should().Be(a.Alice.Id.ToString());
        result.UserName.Should().Be(a.Alice.UserName);
        result.DisplayName.Should().Be("Alice Example");
        JsonNode.Parse(raw)!.AsObject().Select(p => p.Key).Should()
            .BeEquivalentTo("sourceTenantId", "userId", "userName", "displayName");
        raw.Should().NotContainEquivalentOf(a.Alice.Email, "the answer carries no e-mail address");
    }

    [Fact]
    public async Task RegistryAncestorUser_IsFoundThroughTheSameRoute_WithoutAnyPermission()
    {
        var a = await ArrangeAsync();

        var response = await LookupAsync(Admin(), a.Target, NormalizedSystemTenantId, a.AncestorUser.UserName);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = (await response.Content.ReadFromJsonAsync<SourceUserLookupResultDto>(
            TestContext.Current.CancellationToken))!;
        result.UserId.Should().Be(a.AncestorUser.Id.ToString());
    }

    // ---------------------------------------------------------------- uniform 404

    /// <summary>No prefix, substring, wildcard, regular expression or Mongo operator semantics — one case per row.</summary>
    [Theory]
    [InlineData("prefix")]
    [InlineData("suffix-wildcard")]
    [InlineData("regex-any")]
    [InlineData("regex-anchored")]
    [InlineData("mongo-operator")]
    [InlineData("empty")]
    [InlineData("whitespace")]
    [InlineData("email-domain")]
    public async Task PermittedSibling_NonExactIdentifier_IsTheUniform404(string kind)
    {
        var a = await ArrangeAsync();
        var name = a.Alice.UserName;
        var identifier = kind switch
        {
            "prefix" => name[..^3],
            "suffix-wildcard" => name[..^3] + "*",
            "regex-any" => ".*",
            "regex-anchored" => $"^{name[..^3]}.*$",
            "mongo-operator" => "{\"$ne\": null}",
            "empty" => "",
            "whitespace" => "   ",
            "email-domain" => a.Alice.Email[a.Alice.Email.IndexOf('@')..],
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };

        await AssertUniform404Async(await LookupAsync(Admin(), a.Target, a.Source, identifier));
    }

    [Theory]
    [InlineData("source-tenant-absent")]
    [InlineData("source-tenant-empty")]
    [InlineData("source-does-not-permit")]
    [InlineData("user-absent")]
    [InlineData("shadow-user")]
    [InlineData("locked-out-user")]
    [InlineData("duplicate-email")]
    [InlineData("user-of-another-sibling")]
    public async Task EveryNegativeCase_AnswersTheIdenticalBody(string kind)
    {
        var a = await ArrangeAsync();
        var (source, identifier) = kind switch
        {
            "source-tenant-absent" => ($"absent{Guid.NewGuid():N}"[..20], a.Alice.UserName),
            "source-tenant-empty" => ("", a.Alice.UserName),
            "source-does-not-permit" => (a.Stranger, a.StrangerUser.UserName),
            "user-absent" => (a.Source, $"nobody-{Guid.NewGuid():N}"),
            "shadow-user" => (a.Source, a.ShadowUserName),
            "locked-out-user" => (a.Source, a.LockedUserName),
            "duplicate-email" => (a.Source, a.DuplicateEmail),
            // A user of U named through the permitting S: the tenant decides, not the name.
            "user-of-another-sibling" => (a.Source, a.StrangerUser.UserName),
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };

        await AssertUniform404Async(await LookupAsync(Admin(), a.Target, source, identifier));
    }

    [Fact]
    public async Task NonPermittingSibling_TheShippedDefault_RefusesEvenAnExactMatch()
    {
        var a = await ArrangeAsync();

        var stranger = await LookupAsync(Admin(), a.Target, a.Stranger, a.StrangerUser.Email);
        await AssertUniform404Async(stranger);

        // The same user is found from the stranger's side of the permission: S permits T, U does not.
        (await LookupAsync(Admin(), a.Target, a.Source, a.Alice.UserName)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task MissingBody_Is400()
    {
        var a = await ArrangeAsync();
        using var content = new StringContent("", System.Text.Encoding.UTF8, "application/json");

        var response = await Admin().PostAsync(LookupUrl(a.Target), content, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    // ---------------------------------------------------------------- authorization

    [Theory]
    [InlineData("")]
    [InlineData("DashboardViewer")]
    [InlineData("TenantManagement")]
    public async Task CallerWithoutUserManagementInTheTarget_Is403(string role)
    {
        var a = await ArrangeAsync();
        var client = CreateAuthenticatedClient(userId: $"caller-{Guid.NewGuid():N}",
            roles: role.Length == 0 ? [] : [role]);
        if (role.Length == 0)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.NoRolesHeader, "true");
        }

        var response = await LookupAsync(client, a.Target, a.Source, a.Alice.UserName);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))
            .Should().NotContain(a.Alice.Id.ToString());
    }

    [Fact]
    public async Task Anonymous_Is401()
    {
        var a = await ArrangeAsync();

        var response = await LookupAsync(CreateAnonymousClient(), a.Target, a.Source, a.Alice.UserName);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TokenOfAnotherTenant_IsRefused()
    {
        var a = await ArrangeAsync();
        var client = Admin();
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, a.Source);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RealBearerPrincipalHeader, "true");

        var response = await LookupAsync(client, a.Target, a.Source, a.Alice.UserName);

        response.StatusCode.Should().BeOneOf(HttpStatusCode.Forbidden, HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- rate limit

    [Fact]
    public async Task TwentyFirstLookupWithinTenMinutes_Is429_WithRetryAfterHeaderAndBodyField()
    {
        var a = await ArrangeAsync();
        var caller = Admin();

        // Hits and misses count alike (default limit 20 per caller and target tenant in 10 minutes).
        for (var i = 0; i < 20; i++)
        {
            var identifier = i % 2 == 0 ? a.Alice.UserName : $"nobody-{i}";
            (await LookupAsync(caller, a.Target, a.Source, identifier)).StatusCode
                .Should().BeOneOf([HttpStatusCode.OK, HttpStatusCode.NotFound], $"lookup {i + 1} is within the limit");
        }

        var refused = await LookupAsync(caller, a.Target, a.Source, a.Alice.UserName);

        refused.StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        refused.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        var header = refused.Headers.RetryAfter!.Delta!.Value.TotalSeconds;
        var body = JsonNode.Parse(await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        body["code"]!.GetValue<string>().Should().Be(CrossTenantGrantProblemCodes.SourceUserLookupRateLimited);
        body["status"]!.GetValue<int>().Should().Be(429);
        var retryAfterSeconds = body["retryAfterSeconds"]!.GetValue<int>();
        retryAfterSeconds.Should().BeInRange(1, 600);
        header.Should().Be(retryAfterSeconds, "header and body field carry the same value");

        // The limit is per caller: another administrator of T is not affected.
        (await LookupAsync(Admin(), a.Target, a.Source, a.Alice.UserName)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------- helpers

    private HttpClient Admin()
        => CreateAuthenticatedClient(userId: $"admin-{Guid.NewGuid():N}", roles: [UserManagement]);

    private static string LookupUrl(string targetTenantId)
        => $"/{targetTenantId}/v1/ExternalTenantUserMappings/sourceUserLookup";

    private static Task<HttpResponseMessage> LookupAsync(HttpClient client, string targetTenantId,
        string sourceTenantId, string identifier)
        => client.PostAsJsonAsync(LookupUrl(targetTenantId),
            new SourceUserLookupRequestDto { SourceTenantId = sourceTenantId, Identifier = identifier },
            TestContext.Current.CancellationToken);

    /// <summary>
    ///     The 404 of every negative case: status, content type and the complete body are the same constant — compared
    ///     against the literal of the contract (<c>docs/CONCEPT-SIBLING-TENANT-GRANTS.md</c> §3), apart from the
    ///     framework's per-request <c>traceId</c>, if any.
    /// </summary>
    private static async Task AssertUniform404Async(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/problem+json");
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!
            .AsObject();
        body.Remove("traceId");
        body.ToJsonString().Should().Be(ExpectedNotFoundBody);
    }

    private static readonly string ExpectedNotFoundBody = new JsonObject
    {
        ["title"] = "Source user not found",
        ["status"] = 404,
        ["detail"] = "No user of the source tenant can be granted access with this identifier.",
        ["code"] = "SourceUserNotFound"
    }.ToJsonString();

    // ---------------------------------------------------------------- arrangement

    private sealed record TestUser(OctoObjectId Id, string UserName, string Email);

    private sealed record Arrangement(
        string Target,
        string Source,
        string Stranger,
        TestUser Alice,
        TestUser StrangerUser,
        TestUser AncestorUser,
        string ShadowUserName,
        string LockedUserName,
        string DuplicateEmail);

    private async Task<Arrangement> ArrangeAsync()
    {
        await ArrangeGate.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (Arrangements.TryGetValue(Factory, out var existing))
            {
                return existing;
            }

            var target = await CreateTenantAsync("lkt");
            var source = await CreateTenantAsync("lks");
            var stranger = await CreateTenantAsync("lku");
            Factory.SourceTenantGrantPolicy.Permit(source, target);

            var suffix = Guid.NewGuid().ToString("N")[..10];
            var alice = await InsertUserAsync(source, $"alice{suffix}", $"alice{suffix}@x.io", firstName: "Alice",
                lastName: "Example");
            var shadow = await InsertUserAsync(source, CrossTenantShadowUserName.Build(target, $"bob{suffix}"),
                $"shadow{suffix}@x.io");
            var locked = await InsertUserAsync(source, $"locked{suffix}", $"locked{suffix}@x.io",
                lockoutEnd: DateTimeOffset.UtcNow.AddDays(1));
            var duplicateEmail = $"dup{suffix}@x.io";
            await InsertUserAsync(source, $"dupa{suffix}", duplicateEmail);
            await InsertUserAsync(source, $"dupb{suffix}", duplicateEmail);
            var strangerUser = await InsertUserAsync(stranger, $"carol{suffix}", $"carol{suffix}@x.io");
            var ancestorUser = await InsertUserAsync(NormalizedSystemTenantId, $"root{suffix}", $"root{suffix}@x.io");

            var arrangement = new Arrangement(target, source, stranger, alice, strangerUser, ancestorUser,
                shadow.UserName, locked.UserName, duplicateEmail);
            Arrangements.Add(Factory, arrangement);
            return arrangement;
        }
        finally
        {
            ArrangeGate.Release();
        }
    }

    private async Task<string> CreateTenantAsync(string prefix)
    {
        var tenantId = $"{prefix}{Guid.NewGuid():N}"[..20];
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

        await WaitUntilRegistryKnowsAsync(tenantId);
        return tenantId;
    }

    /// <summary>The lookup reads tenants through the cached registry; wait until it knows a tenant created a moment ago.</summary>
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

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<TestUser> InsertUserAsync(string tenantId, string userName, string email,
        string? firstName = null, string? lastName = null, DateTimeOffset? lockoutEnd = null)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        ITenantRepository repository = tenantId == NormalizedSystemTenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            FirstName = firstName,
            LastName = lastName,
            LockoutEnabled = lockoutEnd.HasValue,
            LockoutEnd = lockoutEnd,
            SecurityStamp = Guid.NewGuid().ToString()
        };
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, user);
        await session.CommitTransactionAsync();
        return new TestUser(user.RtId, userName, email);
    }
}
