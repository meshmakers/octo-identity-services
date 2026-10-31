using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#7899 — an administrator revokes every session and token of a user (and, in bulk, of all xt_ shadow users of
///     the tenant): refresh tokens, authorizations, the security stamp and the server-side browser sessions.
/// </summary>
public class UserSessionRevocationTests : IntegrationTestBase
{
    private const string Password = "Test123!";
    private const string RedirectUri = "https://revoke.example/callback";
    private const string ClientId = "revoke-spa";

    public UserSessionRevocationTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task RevokeUser_EndsRefreshTokensBrowserSessionAndRotatesTheStamp_OtherUsersUntouched()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"revoke_{Guid.NewGuid():N}";
        var otherName = $"revoke_other_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: Password);
        await CreateTestUserAsync(otherName, password: Password);
        var (browser, refreshToken) = await SignInWithRefreshTokenAsync(userName, ct);
        var (_, otherRefreshToken) = await SignInWithRefreshTokenAsync(otherName, ct);
        var stampBefore = await GetStampAsync(userName);

        var response = await PostAsync(TenantApiUrl($"users/{Uri.EscapeDataString(userName)}/revokeSessions"), new { });

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var result = (await response.Content.ReadFromJsonAsync<UserSessionRevocationResultDto>(ct))!;
        result.UserName.Should().Be(userName);
        result.SecurityStampRotated.Should().BeTrue();
        result.RevokedTokens.Should().BeGreaterThan(0);
        result.RemovedSessions.Should().BeGreaterThan(0);

        (await RedeemRefreshTokenAsync(refreshToken, ct)).StatusCode.Should().Be(HttpStatusCode.BadRequest,
            "the refresh token was revoked");
        (await browser.GetAsync(ManageApiUrl("profile"), ct)).StatusCode.Should().NotBe(HttpStatusCode.OK,
            "the server-side browser session is gone");
        (await GetStampAsync(userName)).Should().NotBe(stampBefore);
        (await RedeemRefreshTokenAsync(otherRefreshToken, ct)).StatusCode.Should().Be(HttpStatusCode.OK,
            "other users are not touched");
    }

    [Fact]
    public async Task RevokeUser_UnknownUser_Is404()
    {
        var response = await PostAsync(TenantApiUrl($"users/nobody_{Guid.NewGuid():N}/revokeSessions"), new { });

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task RevokeUser_WithoutUserManagementRole_Is403()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"revoke_403_{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName, password: Password);
        var request = new HttpRequestMessage(HttpMethod.Post,
            TenantApiUrl($"users/{Uri.EscapeDataString(userName)}/revokeSessions"))
        {
            Content = JsonContent.Create(new { })
        };
        request.Headers.Add(TestAuthHandler.RoleHeader, "AssetViewer");

        var response = await Client.SendAsync(request, ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task RevokeShadowUsers_DryRunByDefault_CountsAndChangesNothing_ApplyRevokesOnlyShadowUsers()
    {
        var ct = TestContext.Current.CancellationToken;
        var shadow = await CreateShadowUserAsync();
        var local = await CreateTestUserAsync($"revoke_local_{Guid.NewGuid():N}", password: Password);
        await CreateOAuthTokenAsync(shadow.RtId.ToString(), ClientId);
        await CreateOAuthTokenAsync(local.RtId.ToString(), ClientId);
        await CreateSessionAsync(shadow.RtId.ToString());
        await CreateSessionAsync(local.RtId.ToString());

        var dryRun = await PostAsync(TenantApiUrl("users/revokeSessions?scope=shadowUsers"), new { });

        dryRun.StatusCode.Should().Be(HttpStatusCode.OK, await dryRun.Content.ReadAsStringAsync(ct));
        var preview = (await dryRun.Content.ReadFromJsonAsync<ShadowUserSessionRevocationResultDto>(ct))!;
        preview.DryRun.Should().BeTrue("dry run is the default");
        preview.Users.Should().BeGreaterThanOrEqualTo(1);
        preview.UserNames.Should().Contain(shadow.UserName).And.NotContain(local.UserName);
        preview.Tokens.Should().BeGreaterThanOrEqualTo(1);
        preview.Sessions.Should().BeGreaterThanOrEqualTo(1);
        (await GetValidOAuthTokenCountForSubjectAsync(shadow.RtId.ToString())).Should().Be(1, "a dry run changes nothing");
        (await CountSessionsAsync(shadow.RtId.ToString())).Should().Be(1);

        var apply = await PostAsync(TenantApiUrl("users/revokeSessions?scope=shadowUsers&dryRun=false"), new { });

        apply.StatusCode.Should().Be(HttpStatusCode.OK, await apply.Content.ReadAsStringAsync(ct));
        (await apply.Content.ReadFromJsonAsync<ShadowUserSessionRevocationResultDto>(ct))!.DryRun.Should().BeFalse();
        (await GetValidOAuthTokenCountForSubjectAsync(shadow.RtId.ToString())).Should().Be(0);
        (await CountSessionsAsync(shadow.RtId.ToString())).Should().Be(0);
        (await GetValidOAuthTokenCountForSubjectAsync(local.RtId.ToString())).Should().Be(1, "local users are untouched");
        (await CountSessionsAsync(local.RtId.ToString())).Should().Be(1);
    }

    [Fact]
    public async Task RevokeShadowUsers_MixedTokenStates_DryRunReportsExactlyWhatTheApplyRevokes()
    {
        // AB#7957: on test-2 the dry run counted only "valid" tokens (318) while the apply revoked every entry (4,088).
        var ct = TestContext.Current.CancellationToken;
        (await PostAsync(TenantApiUrl("users/revokeSessions?scope=shadowUsers&dryRun=false"), new { }))
            .StatusCode.Should().Be(HttpStatusCode.OK, "clears shadow-user leftovers of sibling tests");
        var shadow = await CreateShadowUserAsync();
        var subject = shadow.RtId.ToString();
        foreach (var status in new[] { "valid", "redeemed", "inactive", "revoked" })
        {
            await CreateOAuthTokenWithStatusAsync(subject, status);
        }

        foreach (var status in new[] { "valid", "inactive", "revoked" })
        {
            await CreateOAuthAuthorizationAsync(subject, status);
        }

        await CreateSessionAsync(subject);
        await CreateSessionAsync(subject);

        var preview = await RevokeShadowUsersAsync(dryRun: true, ct);
        var applied = await RevokeShadowUsersAsync(dryRun: false, ct);

        preview.Tokens.Should().Be(3, "valid, redeemed and inactive are revocable; the revoked one is not counted");
        preview.Authorizations.Should().Be(2);
        preview.Sessions.Should().Be(2);
        applied.Users.Should().Be(preview.Users);
        applied.Tokens.Should().Be(preview.Tokens, "the dry run reports exactly what the apply revokes");
        applied.Authorizations.Should().Be(preview.Authorizations);
        applied.Sessions.Should().Be(preview.Sessions);
        (await GetStatusesAsync(subject)).Should().OnlyContain(s => s == "revoked");
        (await CountSessionsAsync(subject)).Should().Be(0);

        var after = await RevokeShadowUsersAsync(dryRun: true, ct);
        after.Tokens.Should().Be(0, "already revoked entries are counted by neither");
        after.Authorizations.Should().Be(0);
        after.Sessions.Should().Be(0);
    }

    [Fact]
    public async Task RevokeUser_AlreadyRevokedTokens_AreNotCountedAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"revoke_mixed_{Guid.NewGuid():N}";
        var user = await CreateTestUserAsync(userName, password: Password);
        var subject = user.RtId.ToString();
        await CreateOAuthTokenWithStatusAsync(subject, "valid");
        await CreateOAuthTokenWithStatusAsync(subject, "redeemed");
        await CreateOAuthTokenWithStatusAsync(subject, "revoked");
        await CreateOAuthAuthorizationAsync(subject, "revoked");

        var response = await PostAsync(TenantApiUrl($"users/{Uri.EscapeDataString(userName)}/revokeSessions"), new { });

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var result = (await response.Content.ReadFromJsonAsync<UserSessionRevocationResultDto>(ct))!;
        result.RevokedTokens.Should().Be(2);
        result.RevokedAuthorizations.Should().Be(0);
        result.SecurityStampRotated.Should().BeTrue();
        (await GetStatusesAsync(subject)).Should().OnlyContain(s => s == "revoked");
    }

    [Fact]
    public async Task RevokeBulk_UnknownScope_Is400()
    {
        var response = await PostAsync(TenantApiUrl("users/revokeSessions?scope=everybody"), new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, "v1 supports only scope=shadowUsers");
    }

    [Fact]
    public async Task RevokeAudit_CliUserToken_RecordsSubjectUserNameClientAndTenant_NoOtherClaimValues()
    {
        // AB#7958: the octo-cli token maps nothing to Identity.Name; the audit line said "acting user '(unknown)'".
        var ct = TestContext.Current.CancellationToken;
        var target = $"revoke_audit_{Guid.NewGuid():N}";
        await CreateTestUserAsync(target, password: Password);
        var callerSubject = OctoObjectId.GenerateNewId().ToString();
        var callerName = $"cli_admin_{Guid.NewGuid():N}";
        var callerEmail = $"{callerName}@audit.example";
        var callerTenant = new Uri(new Uri("http://x"), TenantApiUrl("users")).AbsolutePath
            .Split('/', StringSplitOptions.RemoveEmptyEntries)[0];
        using var capture = CaptureLogs();

        (await PostAsCliUserAsync(TenantApiUrl($"users/{Uri.EscapeDataString(target)}/revokeSessions"), callerSubject,
            callerName, callerEmail, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsCliUserAsync(TenantApiUrl("users/revokeSessions?scope=shadowUsers"), callerSubject, callerName,
            callerEmail, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await PostAsCliUserAsync(TenantApiUrl("users/revokeSessions?scope=shadowUsers&dryRun=false"), callerSubject,
            callerName, callerEmail, ct)).StatusCode.Should().Be(HttpStatusCode.OK);

        var lines = capture.Lines(callerSubject);
        lines.Should().HaveCount(3, "single user, shadow dry run and shadow apply each write one audit line");
        lines.Should().ContainSingle(l => l.StartsWith("Sessions revoked:", StringComparison.Ordinal));
        lines.Should().ContainSingle(l => l.Contains("counted (dry run)", StringComparison.Ordinal));
        foreach (var line in lines)
        {
            line.Should().Contain($"acting user '{callerName}'")
                .And.Contain($"subject '{callerSubject}'")
                .And.Contain($"client '{TestAuthHandler.CliClientId}', tenant '{callerTenant}')")
                .And.NotContain("(unknown)");
            line.Should().NotContain(callerEmail, "only sub, user name, client id and tenant are recorded")
                .And.NotContain("Bearer").And.NotContain("octo_api", "no scope values");
        }
    }

    [Fact]
    public async Task RevokeAudit_ClientCredentialsCaller_RecordsTheClientIdAsActor()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = $"revoke-svc-{Guid.NewGuid():N}";
        using var capture = CaptureLogs();
        var request = new HttpRequestMessage(HttpMethod.Post, TenantApiUrl("users/revokeSessions?scope=shadowUsers"))
        {
            Content = JsonContent.Create(new { })
        };
        request.Headers.Add(TestAuthHandler.ClientCredentialsHeader, clientId);

        (await Client.SendAsync(request, ct)).StatusCode.Should().Be(HttpStatusCode.OK);

        capture.Lines(clientId).Should().ContainSingle().Which.Should()
            .Contain($"acting user 'client {clientId}'").And.Contain($"client '{clientId}'")
            .And.NotContain("(unknown)");
    }

    #region Helpers

    private async Task<HttpResponseMessage> PostAsCliUserAsync(string url, string subject, string userName, string email,
        CancellationToken ct)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = JsonContent.Create(new { }) };
        request.Headers.Add(TestAuthHandler.CliUserTokenHeader, "true");
        request.Headers.Add(TestAuthHandler.UserIdHeader, subject);
        request.Headers.Add(TestAuthHandler.UserNameHeader, userName);
        request.Headers.Add(TestAuthHandler.EmailHeader, email);
        return await Client.SendAsync(request, ct);
    }

    private LogCapture CaptureLogs()
    {
        var capture = new LogCapture();
        Factory.Services.GetRequiredService<ILoggerFactory>().AddProvider(capture);
        return capture;
    }

    /// <summary>Keeps the rendered revocation audit lines (category <c>UserSessionRevocationService</c>).</summary>
    private sealed class LogCapture : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _lines = new();
        private volatile bool _disposed;

        public ILogger CreateLogger(string categoryName)
            => categoryName.EndsWith(nameof(UserSessionRevocationService), StringComparison.Ordinal)
                ? new Logger(this)
                : NullLogger.Instance;

        public void Dispose() => _disposed = true;

        /// <summary>The captured lines that contain <paramref name="marker" /> (isolates this test's calls).</summary>
        public List<string> Lines(string marker) => _lines.Where(l => l.Contains(marker, StringComparison.Ordinal)).ToList();

        private sealed class Logger(LogCapture owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => !owner._disposed;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!owner._disposed)
                {
                    owner._lines.Enqueue(formatter(state, exception));
                }
            }
        }
    }

    private async Task<ShadowUserSessionRevocationResultDto> RevokeShadowUsersAsync(bool dryRun, CancellationToken ct)
    {
        var response = await PostAsync(
            TenantApiUrl($"users/revokeSessions?scope=shadowUsers&dryRun={(dryRun ? "true" : "false")}"), new { });
        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var result = (await response.Content.ReadFromJsonAsync<ShadowUserSessionRevocationResultDto>(ct))!;
        result.DryRun.Should().Be(dryRun);
        return result;
    }

    private async Task CreateOAuthTokenWithStatusAsync(string subjectId, string status)
    {
        using var scope = CreateScope();
        var tokenStore = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenStore<RtOAuthToken>>();
        var token = await tokenStore.InstantiateAsync(CancellationToken.None);
        token.SubjectId = subjectId;
        token.ClientId = ClientId;
        token.TokenType = "refresh_token";
        token.Status = status;
        token.CreationDateTime = DateTime.UtcNow;
        token.ExpirationDateTime = DateTime.UtcNow.AddDays(30);
        await tokenStore.CreateAsync(token, CancellationToken.None);
    }

    private async Task CreateOAuthAuthorizationAsync(string subjectId, string status)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationStore<RtOAuthAuthorization>>();
        var authorization = await store.InstantiateAsync(CancellationToken.None);
        authorization.SubjectId = subjectId;
        authorization.ClientId = ClientId;
        authorization.Status = status;
        authorization.CreationDateTime = DateTime.UtcNow;
        await store.SetScopesAsync(authorization, ImmutableArray.Create("openid"), CancellationToken.None);
        await store.CreateAsync(authorization, CancellationToken.None);
    }

    /// <summary>Statuses of all tokens and authorizations of the subject.</summary>
    private async Task<List<string?>> GetStatusesAsync(string subjectId)
    {
        using var scope = CreateScope();
        var statuses = new List<string?>();
        await foreach (var token in scope.ServiceProvider.GetRequiredService<IOpenIddictTokenStore<RtOAuthToken>>()
                           .FindBySubjectAsync(subjectId, CancellationToken.None))
        {
            statuses.Add(token.Status);
        }

        await foreach (var authorization in scope.ServiceProvider
                           .GetRequiredService<IOpenIddictAuthorizationStore<RtOAuthAuthorization>>()
                           .FindBySubjectAsync(subjectId, CancellationToken.None))
        {
            statuses.Add(authorization.Status);
        }

        statuses.Should().NotBeEmpty();
        return statuses;
    }

    private async Task<RtUser> CreateShadowUserAsync()
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var userName = $"xt_{NormalizedSystemTenantId}parent_revoke{Guid.NewGuid():N}";
        var user = new RtUserBuilder().WithUserName(userName).WithEmail($"{userName}@example.com")
            .WithEmailConfirmed(true).Build();
        (await userManager.CreateAsync(user)).Succeeded.Should().BeTrue();
        return user;
    }

    private async Task CreateSessionAsync(string subjectId)
    {
        var repository = Factory.Services.GetRequiredService<ISystemContext>().GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, new RtServerSideSession
        {
            RtId = OctoObjectId.GenerateNewId(),
            SessionKey = Guid.NewGuid().ToString("N"),
            Scheme = "Identity.Application",
            SubjectId = subjectId,
            SessionId = Guid.NewGuid().ToString("N"),
            CreationDateTime = DateTime.UtcNow,
            RenewalDateTime = DateTime.UtcNow,
            ExpirationDateTime = DateTime.UtcNow.AddDays(1),
            Ticket = "not-a-real-ticket"
        });
        await session.CommitTransactionAsync();
    }

    private async Task<int> CountSessionsAsync(string subjectId)
    {
        var repository = Factory.Services.GetRequiredService<ISystemContext>().GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var result = await repository.GetRtEntitiesByTypeAsync<RtServerSideSession>(session,
            RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtServerSideSession.SubjectId), subjectId));
        await session.CommitTransactionAsync();
        return result.Items.Count();
    }

    private async Task<string?> GetStampAsync(string userName)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName))!
            .SecurityStamp;
    }

    private async Task<HttpResponseMessage> RedeemRefreshTokenAsync(string refreshToken, CancellationToken ct)
        => await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = refreshToken,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

    /// <summary>Signs in (cookie session) and runs the authorization-code + PKCE flow for a refresh token.</summary>
    private async Task<(HttpClient Browser, string RefreshToken)> SignInWithRefreshTokenAsync(string userName,
        CancellationToken ct)
    {
        using (var scope = CreateScope())
        {
            var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            if (await clientStore.FindRtClientByIdAsync(ClientId) == null)
            {
                await clientStore.CreateAsync(new RtClientBuilder()
                    .WithClientId(ClientId)
                    .WithClientName(ClientId)
                    .WithGrantTypes("authorization_code")
                    .WithScopes("openid", "profile", "offline_access")
                    .WithRedirectUris(RedirectUri)
                    .WithAllowOfflineAccess()
                    .RequirePkce()
                    .Build());
            }
        }

        var browser = (await LoginAndGetAuthenticatedClientAsync(userName, Password, ct))!;
        const string codeVerifier = "revoke-code-verifier-revoke-code-verifier-12345678";
        var codeChallenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var authorize = await browser.GetAsync("/connect/authorize" +
                                               $"?client_id={ClientId}" +
                                               $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
                                               "&response_type=code" +
                                               $"&scope={Uri.EscapeDataString("openid profile offline_access")}" +
                                               "&state=s&nonce=n" +
                                               $"&code_challenge={codeChallenge}&code_challenge_method=S256" +
                                               $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}",
            ct);
        ((int)authorize.StatusCode).Should().BeInRange(302, 303);
        var code = HttpUtility.ParseQueryString(authorize.Headers.Location!.Query)["code"];

        var tokenResponse = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["code"] = code!,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = codeVerifier
            }), ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        return (browser, JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync(ct))!["refresh_token"]!
            .GetValue<string>());
    }

    #endregion
}
