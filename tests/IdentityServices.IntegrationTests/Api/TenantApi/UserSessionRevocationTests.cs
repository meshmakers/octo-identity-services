using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Dtos;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
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
    public async Task RevokeBulk_UnknownScope_Is400()
    {
        var response = await PostAsync(TenantApiUrl("users/revokeSessions?scope=everybody"), new { });

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest, "v1 supports only scope=shadowUsers");
    }

    #region Helpers

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
