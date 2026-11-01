using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.DependencyInjection;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Cors;

/// <summary>
///     AB#7270 (AB#7265 AC 4): application-level CORS regression tests through the real identity pipeline
///     (<c>app.UseCors()</c> with <c>IdentityCorsPolicyProvider</c>: allowed origins = the registered client origins
///     of every tenant). Since AB#7265 the ingress no longer adds CORS headers, so the application policy is the only
///     thing that decides — these tests pin that it
///     (a) gives an unknown origin no <c>Access-Control-Allow-Origin</c>, on success and on error responses,
///     (b) reflects a registered client origin, and
///     (c) never sends <c>Access-Control-Allow-Credentials</c> on the bearer-only API routes.
/// </summary>
public class CorsRegressionTests : IntegrationTestBase
{
    private const string UnknownOrigin = "https://evil.example.com";
    private const string AllowOrigin = "Access-Control-Allow-Origin";
    private const string AllowCredentials = "Access-Control-Allow-Credentials";

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static string? _knownOrigin;

    public CorsRegressionTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private string UsersRoute => $"/{NormalizedSystemTenantId}/v1/users";

    private async Task<string> EnsureKnownOriginAsync()
    {
        await Gate.WaitAsync();
        try
        {
            if (_knownOrigin != null)
            {
                return _knownOrigin;
            }

            var origin = $"https://studio-{Guid.NewGuid():N}"[..28] + ".example.test";
            using var scope = Factory.Services.CreateScope();
            var systemContext = scope.ServiceProvider.GetRequiredService<ISystemContext>();
            var repository = (await systemContext.TryFindTenantRepositoryAsync(systemContext.TenantId))!;
            using var session = await repository.GetSessionAsync();
            session.StartTransaction();
            await repository.InsertOneRtEntityAsync(session, new RtClientBuilder()
                .WithClientId($"cors-{Guid.NewGuid():N}")
                .WithCorsOrigins(origin)
                .Build());
            await session.CommitTransactionAsync();

            // The policy is cached for CorsPolicyCacheSeconds; the CorsClientsUpdate event that clears it is
            // disabled in tests.
            Factory.Services.GetRequiredService<Meshmakers.Octo.Backend.IdentityServices.Services.IdentityCorsPolicyProvider>()
                .InvalidateCache();

            _knownOrigin = origin;
            return origin;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static HttpRequestMessage Get(string path, string origin, bool withBearer)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Origin", origin);
        if (withBearer)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        }

        return request;
    }

    private static HttpRequestMessage Preflight(string path, string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, path);
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "authorization");
        return request;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) =>
        await CreateAnonymousClient().SendAsync(request, TestContext.Current.CancellationToken);

    [Fact]
    public async Task UnknownOrigin_SuccessResponse_HasNoCorsHeaders()
    {
        await EnsureKnownOriginAsync();

        var response = await SendAsync(Get(UsersRoute, UnknownOrigin, withBearer: true));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.Contains(AllowOrigin).Should().BeFalse();
        response.Headers.Contains(AllowCredentials).Should().BeFalse();
    }

    [Fact]
    public async Task UnknownOrigin_ErrorResponse_HasNoCorsHeaders()
    {
        await EnsureKnownOriginAsync();

        var response = await SendAsync(Get(UsersRoute, UnknownOrigin, withBearer: false));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Headers.Contains(AllowOrigin).Should().BeFalse();
        response.Headers.Contains(AllowCredentials).Should().BeFalse();
    }

    [Fact]
    public async Task UnknownOrigin_Preflight_HasNoCorsHeaders()
    {
        await EnsureKnownOriginAsync();

        var response = await SendAsync(Preflight(UsersRoute, UnknownOrigin));

        response.Headers.Contains(AllowOrigin).Should().BeFalse();
        response.Headers.Contains(AllowCredentials).Should().BeFalse();
    }

    [Fact]
    public async Task KnownOrigin_SuccessResponse_GetsAllowOrigin_WithoutCredentials()
    {
        var origin = await EnsureKnownOriginAsync();

        var response = await SendAsync(Get(UsersRoute, origin, withBearer: true));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues(AllowOrigin).Should().ContainSingle().Which.Should().Be(origin);
        response.Headers.Contains(AllowCredentials).Should().BeFalse("the API routes are bearer-only");
    }

    [Fact]
    public async Task KnownOrigin_ErrorResponse_GetsAllowOrigin_WithoutCredentials()
    {
        var origin = await EnsureKnownOriginAsync();

        var response = await SendAsync(Get(UsersRoute, origin, withBearer: false));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        response.Headers.GetValues(AllowOrigin).Should().ContainSingle().Which.Should().Be(origin,
            "the SPA must be able to read the 401 to start a new login");
        response.Headers.Contains(AllowCredentials).Should().BeFalse();
    }

    [Fact]
    public async Task KnownOrigin_Preflight_AllowsAuthorizationHeader_WithoutCredentials()
    {
        var origin = await EnsureKnownOriginAsync();

        var response = await SendAsync(Preflight(UsersRoute, origin));

        response.Headers.GetValues(AllowOrigin).Should().ContainSingle().Which.Should().Be(origin);
        response.Headers.TryGetValues("Access-Control-Allow-Headers", out var allowedHeaders).Should().BeTrue();
        string.Join(",", allowedHeaders!).Should().ContainEquivalentOf("authorization");
        response.Headers.Contains(AllowCredentials).Should().BeFalse();
    }
}
