using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using IdentityServerPersistence.Configuration.Options;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8345: <c>GET/PUT {S}/v1/CrossTenantGrantPermissions</c> — the allow-list a source tenant S keeps — and its
///     effect on <c>POST {T}/v1/ExternalTenantUserMappings/sourceUserLookup</c>, through the real pipeline and the
///     production <see cref="AllowListSourceTenantGrantPolicy" /> (the test host's arranged pairs are not used here).
/// </summary>
/// <remarks>
///     Registry: system → S (source, its allow-list is under test), system → T and system → U (siblings of S). Tests of
///     one class run one after another; every test that depends on S's list sets it first.
/// </remarks>
public class CrossTenantGrantPermissionsTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";

    private static readonly SemaphoreSlim ArrangeGate = new(1, 1);
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<CustomWebApplicationFactory, Arrangement>
        Arrangements = new();

    public CrossTenantGrantPermissionsTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    // ---------------------------------------------------------------- default

    [Fact]
    public async Task TenantWithoutTheSetting_AsEveryTenantAfterTheUpgrade_PermitsNobody()
    {
        var a = await ArrangeAsync();
        // A tenant that never touched the setting: no configuration row, exactly like every tenant before AB#8345.
        var untouched = await CreateTenantAsync("cgn");
        var bob = await InsertUserAsync(untouched, $"bob{Guid.NewGuid():N}"[..14]);

        var get = await SourceAdmin(untouched).GetAsync(Url(untouched), TestContext.Current.CancellationToken);
        get.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ReadListAsync(get)).Should().BeEmpty();

        await AssertUniform404Async(await LookupAsync(a.Target, untouched, bob));
        (await HasConfigurationRowAsync(untouched)).Should().BeFalse("reading the list does not write it");
    }

    // ---------------------------------------------------------------- effect on the lookup

    [Fact]
    public async Task ListedTarget_FindsTheUser_UnlistedTarget_GetsTheSameAnswerAsForANonExistentTenant()
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);

        var hit = await LookupAsync(a.Target, a.Source, a.Alice);
        hit.StatusCode.Should().Be(HttpStatusCode.OK);
        (await hit.Content.ReadFromJsonAsync<SourceUserLookupResultDto>(TestContext.Current.CancellationToken))!
            .UserName.Should().Be(a.Alice);

        var unlisted = await LookupAsync(a.Stranger, a.Source, a.Alice);
        var absentTenant = await LookupAsync(a.Stranger, $"absent{Guid.NewGuid():N}"[..20], a.Alice);
        var unlistedBody = await AssertUniform404Async(unlisted);
        var absentBody = await AssertUniform404Async(absentTenant);
        unlistedBody.Should().Be(absentBody, "a tenant that does not permit T answers exactly as a tenant that does not exist");
    }

    [Fact]
    public async Task RemovingTheTarget_StopsItsLookupsWithTheNextRequest()
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target, a.Stranger])).StatusCode.Should().Be(HttpStatusCode.OK);
        (await LookupAsync(a.Target, a.Source, a.Alice)).StatusCode.Should().Be(HttpStatusCode.OK);

        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Stranger])).StatusCode.Should().Be(HttpStatusCode.OK);

        await AssertUniform404Async(await LookupAsync(a.Target, a.Source, a.Alice));
        (await LookupAsync(a.Stranger, a.Source, a.Alice)).StatusCode.Should().Be(HttpStatusCode.OK,
            "only the removed tenant loses the permission");

        (await PutAsync(SourceAdmin(a.Source), a.Source, [])).StatusCode.Should().Be(HttpStatusCode.OK);
        await AssertUniform404Async(await LookupAsync(a.Stranger, a.Source, a.Alice));
    }

    [Fact]
    public async Task ThePermissionIsDirectional()
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);
        var tUser = await InsertUserAsync(a.Target, $"tuser{Guid.NewGuid():N}"[..14]);

        // S permits T; that does not let S look up T's users.
        await AssertUniform404Async(await LookupAsync(a.Source, a.Target, tUser));
    }

    [Fact]
    public async Task UnreadableSetting_FailsClosed()
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);
        await WriteRawConfigurationAsync(a.Source, "this is not the expected JSON object");

        try
        {
            await AssertUniform404Async(await LookupAsync(a.Target, a.Source, a.Alice));
            // GET shows what the policy applies (nobody), and a PUT repairs the row.
            var get = await SourceAdmin(a.Source).GetAsync(Url(a.Source), TestContext.Current.CancellationToken);
            (await ReadListAsync(get)).Should().BeEmpty();
            (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);
            (await LookupAsync(a.Target, a.Source, a.Alice)).StatusCode.Should().Be(HttpStatusCode.OK);
        }
        finally
        {
            (await PutAsync(SourceAdmin(a.Source), a.Source, [])).StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }

    // ---------------------------------------------------------------- GET / PUT

    [Fact]
    public async Task Put_StoresTheNormalizedList_InTheSourceTenant_AndGetReturnsIt()
    {
        var a = await ArrangeAsync();

        var put = await PutAsync(SourceAdmin(a.Source), a.Source,
            [$" {a.Target.ToUpperInvariant()} ", a.Target, a.Stranger, "not-yet-created"]);

        put.StatusCode.Should().Be(HttpStatusCode.OK);
        var expected = new[] { a.Target, a.Stranger, "not-yet-created" }.Order(StringComparer.Ordinal).ToList();
        (await ReadListAsync(put)).Should().Equal(expected);
        var get = await SourceAdmin(a.Source).GetAsync(Url(a.Source), TestContext.Current.CancellationToken);
        (await ReadListAsync(get)).Should().Equal(expected);

        // Stored through the engine's tenant configuration (System/TenantConfiguration), readable by its own API.
        var stored = await ReadConfigurationThroughTheEngineAsync(a.Source);
        stored!.TargetTenantIds.Should().Equal(expected);
        stored.ChangedBy.Should().NotBeNullOrEmpty();
        stored.ChangedAtUtc.Should().NotBeNull();
        (await HasConfigurationRowAsync(a.Target)).Should().BeFalse("the list lives only in the source tenant");
    }

    public static TheoryData<string, string> InvalidBodies() => new()
    {
        { "missing-list", "{}" },
        { "null-list", "{\"targetTenantIds\":null}" },
        { "empty-entry", "{\"targetTenantIds\":[\"a\",\"\"]}" },
        { "invalid-characters", "{\"targetTenantIds\":[\"a/b\"]}" },
        { "operator", "{\"targetTenantIds\":[\"{\\\"$ne\\\":null}\"]}" },
        { "own-tenant", "{\"targetTenantIds\":[\"__SELF__\"]}" }
    };

    [Theory]
    [MemberData(nameof(InvalidBodies))]
    public async Task Put_InvalidList_Is400_AndChangesNothing(string kind, string body)
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);
        using var content = new StringContent(body.Replace("__SELF__", a.Source), System.Text.Encoding.UTF8,
            "application/json");

        var response = await SourceAdmin(a.Source).PutAsync(Url(a.Source), content, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, kind);
        var get = await SourceAdmin(a.Source).GetAsync(Url(a.Source), TestContext.Current.CancellationToken);
        (await ReadListAsync(get)).Should().Equal([a.Target], $"a refused PUT ({kind}) leaves the list as it was");
    }

    // ---------------------------------------------------------------- authorization

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    public async Task AdministratorOfTheTargetTenant_Is403_AndLearnsNothing(string method)
    {
        var a = await ArrangeAsync();
        (await PutAsync(SourceAdmin(a.Source), a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.OK);
        // T's administrator, with every role in T, calls S's route.
        var client = CreateAuthenticatedClient(userId: $"tadmin-{Guid.NewGuid():N}", roles: [UserManagement, TenantManagement]);
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, a.Target);

        var response = method == "GET"
            ? await client.GetAsync(Url(a.Source), TestContext.Current.CancellationToken)
            : await PutAsync(client, a.Source, [a.Target, a.Stranger]);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Should().NotContain(a.Target);
        var get = await SourceAdmin(a.Source).GetAsync(Url(a.Source), TestContext.Current.CancellationToken);
        (await ReadListAsync(get)).Should().Equal([a.Target]);
    }

    [Fact]
    public async Task TokenOfTheTargetTenant_ThroughTheTenantGate_IsRefused()
    {
        var a = await ArrangeAsync();
        var client = CreateAuthenticatedClient(userId: $"tadmin-{Guid.NewGuid():N}", roles: [UserManagement, TenantManagement]);
        client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, a.Target);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RealBearerPrincipalHeader, "true");

        var response = await client.GetAsync(Url(a.Source), TestContext.Current.CancellationToken);

        response.StatusCode.Should().BeOneOf(HttpStatusCode.Forbidden, HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData(UserManagement)]
    [InlineData(TenantManagement)]
    [InlineData("AdminPanelManagement")]
    public async Task SourceTenantUserWithoutBothRoles_Is403(string role)
    {
        var a = await ArrangeAsync();
        var client = CreateAuthenticatedClient(userId: $"user-{Guid.NewGuid():N}", roles: [role]);

        (await client.GetAsync(Url(a.Source), TestContext.Current.CancellationToken)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden);
        (await PutAsync(client, a.Source, [a.Target])).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Anonymous_Is401()
    {
        var a = await ArrangeAsync();

        (await CreateAnonymousClient().GetAsync(Url(a.Source), TestContext.Current.CancellationToken)).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- audit

    [Fact]
    public async Task Change_IsAuditedInTheSourceTenantOnly_AndAnUnchangedPutWritesNothing()
    {
        // The source tenant is fresh: the shared arrangement's list is changed by other tests of this class.
        var source = await CreateTenantAsync("cga");
        var audit = Substitute.For<IIdentityAuditService>();
        using var host = Factory.WithWebHostBuilder(b =>
            b.ConfigureTestServices(services => services.AddSingleton(audit)));
        HttpClient Admin() => HostAdmin(host);

        (await PutAsync(Admin(), source, ["cgt-one", "cgt-two"])).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutAsync(Admin(), source, ["cgt-two", "cgt-one"])).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutAsync(Admin(), source, ["cgt-two", "cgt-three"])).StatusCode.Should().Be(HttpStatusCode.OK);

        var calls = audit.ReceivedCalls()
            .Where(c => c.GetMethodInfo().Name == nameof(IIdentityAuditService.StoreInfoAsync)).ToList();
        calls.Should().HaveCount(2, "the second PUT leaves the list unchanged");
        calls.Select(c => (string)c.GetArguments()[0]!).Should().AllBe(source, "the event goes into S only");
        calls.Select(c => (string)c.GetArguments()[1]!).Should()
            .AllBe(CrossTenantGrantAuditEvents.GrantPermissionsChanged);
        var last = (IReadOnlyDictionary<string, string>)calls[1].GetArguments()[3]!;
        last["sourceTenantId"].Should().Be(source);
        last["actorTenantId"].Should().Be(source);
        last["actorName"].Should().Be("source-admin");
        last["permittedTargetTenantIds"].Should().Be("cgt-three,cgt-two");
        last["addedTargetTenantIds"].Should().Be("cgt-three");
        last["removedTargetTenantIds"].Should().Be("cgt-one");
        await audit.DidNotReceiveWithAnyArgs().StoreWarningAsync(default!, default!, default!, default);
    }

    // ---------------------------------------------------------------- concurrency (AB#8432)

    [Fact]
    public async Task Get_And_Put_ReturnTheETagOfTheList()
    {
        var source = await CreateTenantAsync("cge");
        var admin = SourceAdmin(source);

        var initial = await admin.GetAsync(Url(source), TestContext.Current.CancellationToken);
        var initialTag = ETagOf(initial);
        initialTag.IsWeak.Should().BeFalse();

        var put = await PutAsync(admin, source, ["cge-one"], initialTag.Tag);
        put.StatusCode.Should().Be(HttpStatusCode.OK);
        var putTag = ETagOf(put);
        putTag.Tag.Should().NotBe(initialTag.Tag, "the list changed");

        var get = await admin.GetAsync(Url(source), TestContext.Current.CancellationToken);
        ETagOf(get).Tag.Should().Be(putTag.Tag, "the PUT answers the tag a following GET returns");
    }

    [Fact]
    public async Task Put_WithStaleIfMatch_Is412_AndLeavesTheListUnchanged()
    {
        var source = await CreateTenantAsync("cgp");
        var first = SourceAdmin(source);
        var second = SourceAdmin(source);
        // Both administrators open the list.
        var readTag = ETagOf(await first.GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag;
        ETagOf(await second.GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag.Should().Be(readTag);

        var firstPut = await PutAsync(first, source, ["cgp-first"], readTag);
        firstPut.StatusCode.Should().Be(HttpStatusCode.OK);

        var secondPut = await PutAsync(second, source, ["cgp-second"], readTag);

        secondPut.StatusCode.Should().Be(HttpStatusCode.PreconditionFailed);
        (await ProblemCodeAsync(secondPut)).Should().Be(CrossTenantGrantPermissionsController.ListChangedCode);
        ETagOf(secondPut).Tag.Should().Be(ETagOf(firstPut).Tag, "the 412 names the current tag");
        var get = await first.GetAsync(Url(source), TestContext.Current.CancellationToken);
        (await ReadListAsync(get)).Should().Equal(["cgp-first"], "the first change is not overwritten");
    }

    [Theory]
    [InlineData("weak")]
    [InlineData("garbage")]
    [InlineData("other")]
    public async Task Put_WithNonMatchingIfMatch_Is412(string kind)
    {
        var source = await CreateTenantAsync("cgw");
        var admin = SourceAdmin(source);
        var tag = ETagOf(await admin.GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag;
        var ifMatch = kind switch
        {
            "weak" => "W/" + tag, // If-Match compares strongly (RFC 9110 §13.1.1)
            "garbage" => "not-a-tag",
            _ => "\"someone-else\""
        };

        var put = await PutAsync(admin, source, ["cgw-one"], ifMatch);

        put.StatusCode.Should().Be(HttpStatusCode.PreconditionFailed, kind);
        (await HasConfigurationRowAsync(source)).Should().BeFalse("nothing is written");
    }

    [Fact]
    public async Task Put_WithOneOfSeveralTagsOrStar_Matches()
    {
        var source = await CreateTenantAsync("cgm");
        var admin = SourceAdmin(source);
        var tag = ETagOf(await admin.GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag;

        (await PutAsync(admin, source, ["cgm-one"], $"\"old\", {tag}")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PutAsync(admin, source, ["cgm-two"], "*")).StatusCode.Should().Be(HttpStatusCode.OK);

        (await ReadListAsync(await admin.GetAsync(Url(source), TestContext.Current.CancellationToken)))
            .Should().Equal(["cgm-two"]);
    }

    [Fact]
    public async Task ParallelPuts_WithTheSameIfMatch_ExactlyOneWins()
    {
        // A fresh tenant without the row: the parallel first writes also race on the insert.
        var source = await CreateTenantAsync("cgr");
        var tag = ETagOf(await SourceAdmin(source).GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag;

        var responses = await Task.WhenAll(Enumerable.Range(0, 6)
            .Select(i => PutAsync(SourceAdmin(source), source, [$"cgr-{i}"], tag)));

        responses.Select(r => r.StatusCode).Should().ContainSingle(c => c == HttpStatusCode.OK);
        responses.Where(r => r.StatusCode != HttpStatusCode.OK).Select(r => r.StatusCode)
            .Should().AllBeEquivalentTo(HttpStatusCode.PreconditionFailed);
        var winner = await ReadListAsync(responses.Single(r => r.StatusCode == HttpStatusCode.OK));
        (await ReadListAsync(await SourceAdmin(source).GetAsync(Url(source), TestContext.Current.CancellationToken)))
            .Should().Equal(winner, "the stored list is the winner's");
    }

    [Fact]
    public async Task Put_WithoutIfMatch_ByDefault_StillReplaces_ForClientsThatDoNotSendItYet()
    {
        var source = await CreateTenantAsync("cgl");

        (await PutAsync(SourceAdmin(source), source, ["cgl-one"])).StatusCode.Should().Be(HttpStatusCode.OK);

        (await ReadListAsync(await SourceAdmin(source).GetAsync(Url(source), TestContext.Current.CancellationToken)))
            .Should().Equal(["cgl-one"]);
    }

    [Fact]
    public async Task Put_WithoutIfMatch_WhenRequired_Is428_AndChangesNothing()
    {
        var source = await CreateTenantAsync("cgq");
        using var host = Factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            services.PostConfigure<OctoIdentityServicesOptions>(o => o.CrossTenantGrantPermissions.RequireIfMatch = true)));
        var admin = HostAdmin(host);

        var withoutIfMatch = await PutAsync(admin, source, ["cgq-one"]);

        withoutIfMatch.StatusCode.Should().Be((HttpStatusCode)StatusCodes.Status428PreconditionRequired);
        (await ProblemCodeAsync(withoutIfMatch)).Should().Be(CrossTenantGrantPermissionsController.IfMatchRequiredCode);
        (await HasConfigurationRowAsync(source)).Should().BeFalse("nothing is written");

        var tag = ETagOf(await admin.GetAsync(Url(source), TestContext.Current.CancellationToken)).Tag;
        (await PutAsync(admin, source, ["cgq-one"], tag)).StatusCode.Should().Be(HttpStatusCode.OK,
            "with If-Match the same PUT goes through");
    }

    [Fact]
    public async Task UnchangedPut_WritesNothing_NotEvenChangedByOrChangedAtUtc()
    {
        var source = await CreateTenantAsync("cgn");
        var first = await PutAsync(SourceAdmin(source), source, ["cgn-a", "cgn-b"]);
        first.StatusCode.Should().Be(HttpStatusCode.OK);
        var stored = await ReadConfigurationThroughTheEngineAsync(source);

        var otherAdmin = CreateAuthenticatedClient(userId: $"sadmin-{Guid.NewGuid():N}", userName: "another-admin",
            roles: [UserManagement, TenantManagement]);
        var unchanged = await PutAsync(otherAdmin, source, ["CGN-B", " cgn-a "], ETagOf(first).Tag);

        unchanged.StatusCode.Should().Be(HttpStatusCode.OK);
        ETagOf(unchanged).Tag.Should().Be(ETagOf(first).Tag, "the list and so its tag are unchanged");
        var after = await ReadConfigurationThroughTheEngineAsync(source);
        after!.ChangedBy.Should().Be(stored!.ChangedBy, "an unchanged PUT does not record its caller");
        after.ChangedAtUtc.Should().Be(stored.ChangedAtUtc);
    }

    // ---------------------------------------------------------------- helpers

    private HttpClient SourceAdmin(string tenantId)
    {
        _ = tenantId; // the token tenant follows the route tenant (TestAuthHandler default)
        return CreateAuthenticatedClient(userId: $"sadmin-{Guid.NewGuid():N}", roles: [UserManagement, TenantManagement]);
    }

    private static string Url(string tenantId) => $"/{tenantId}/v1/CrossTenantGrantPermissions";

    private static async Task<HttpResponseMessage> PutAsync(HttpClient client, string tenantId, List<string> targets,
        string? ifMatch = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, Url(tenantId));
        request.Content = JsonContent.Create(new CrossTenantGrantPermissionsDto { TargetTenantIds = targets });
        if (ifMatch != null)
        {
            request.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        }

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static System.Net.Http.Headers.EntityTagHeaderValue ETagOf(HttpResponseMessage response)
    {
        response.Headers.ETag.Should().NotBeNull("every answer with the list carries its ETag (AB#8432)");
        return response.Headers.ETag!;
    }

    private static async Task<string?> ProblemCodeAsync(HttpResponseMessage response)
        => JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))?["code"]
            ?.GetValue<string>();

    private static HttpClient HostAdmin(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> host)
    {
        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, $"sadmin-{Guid.NewGuid():N}");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "source-admin");
        client.DefaultRequestHeaders.Add(TestAuthHandler.EmailHeader, "source-admin@example.com");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, UserManagement);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, TenantManagement);
        return client;
    }

    private static async Task<List<string>> ReadListAsync(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = await response.Content.ReadFromJsonAsync<CrossTenantGrantPermissionsDto>(
            TestContext.Current.CancellationToken);
        return dto!.TargetTenantIds!;
    }

    private Task<HttpResponseMessage> LookupAsync(string targetTenantId, string sourceTenantId, string identifier)
        => CreateAuthenticatedClient(userId: $"tadmin-{Guid.NewGuid():N}", roles: [UserManagement])
            .PostAsJsonAsync($"/{targetTenantId}/v1/ExternalTenantUserMappings/sourceUserLookup",
                new SourceUserLookupRequestDto { SourceTenantId = sourceTenantId, Identifier = identifier },
                TestContext.Current.CancellationToken);

    private static async Task<string> AssertUniform404Async(HttpResponseMessage response)
    {
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!
            .AsObject();
        body.Remove("traceId");
        body["code"]!.GetValue<string>().Should().Be("SourceUserNotFound");
        return body.ToJsonString();
    }

    private async Task<bool> HasConfigurationRowAsync(string tenantId)
    {
        var context = await Factory.Services.GetRequiredService<ISystemContext>().FindTenantContextAsync(tenantId);
        using var session = await context.GetAdminSessionAsync();
        return await context.GetConfigurationAsync(session, CrossTenantGrantPermissionStore.ConfigurationKey) != null;
    }

    private async Task<CrossTenantGrantPermissions?> ReadConfigurationThroughTheEngineAsync(string tenantId)
    {
        var context = await Factory.Services.GetRequiredService<ISystemContext>().FindTenantContextAsync(tenantId);
        using var session = await context.GetAdminSessionAsync();
        return await context.GetConfigurationAsync<CrossTenantGrantPermissions>(session,
            CrossTenantGrantPermissionStore.ConfigurationKey, defaultValue: null);
    }

    private async Task WriteRawConfigurationAsync(string tenantId, string value)
    {
        var context = await Factory.Services.GetRequiredService<ISystemContext>().FindTenantContextAsync(tenantId);
        using var session = await context.GetAdminSessionAsync();
        await context.SetConfigurationAsync(session, CrossTenantGrantPermissionStore.ConfigurationKey, value);
    }

    // ---------------------------------------------------------------- arrangement

    private sealed record Arrangement(string Source, string Target, string Stranger, string Alice);

    private async Task<Arrangement> ArrangeAsync()
    {
        await ArrangeGate.WaitAsync(TestContext.Current.CancellationToken);
        try
        {
            if (Arrangements.TryGetValue(Factory, out var existing))
            {
                return existing;
            }

            var source = await CreateTenantAsync("cgs");
            var target = await CreateTenantAsync("cgt");
            var stranger = await CreateTenantAsync("cgu");
            var alice = await InsertUserAsync(source, $"alice{Guid.NewGuid():N}"[..15]);

            var arrangement = new Arrangement(source, target, stranger, alice);
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

        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return tenantId;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<string> InsertUserAsync(string tenantId, string userName)
    {
        var repository = (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;
        var email = $"{userName}@x.io";
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        };
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, user);
        await session.CommitTransactionAsync();
        return userName;
    }
}
