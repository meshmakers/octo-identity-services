using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8860: the identity wave of the password endpoints — <c>POST users</c> (replaced by <c>User.CreateUser</c>) and
///     <c>POST users/ResetPassword</c> (replaced by <c>User.ResetPassword</c>) — has its own dates
///     (<c>RestDeprecation:Waves:IdentityUsersPassword</c>), carries the deprecation headers on every response, is counted
///     per endpoint template and client id, and never puts request data (user name, e-mail, password) into a header or a
///     metric label. Without configured dates the endpoints answer exactly as before; only the <c>Link</c> header is added.
///     Which endpoints carry which wave is pinned in <see cref="UsersRestDeprecationTests" />.
/// </summary>
public class UsersPasswordRestDeprecationTests : IntegrationTestBase, IDisposable
{
    private const string Wave = "IdentityUsersPassword";
    private const string Since = "2026-12-01";
    private const string Sunset = "2027-01-15";

    // Pinned literals: the test is about the wire format.
    private const string DeprecationHeader = "@1796083200";
    private const string SunsetHeader = "Fri, 15 Jan 2027 00:00:00 GMT";
    private const string CreateUserLink =
        "<https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#usercreateuser>; rel=\"deprecation\"; type=\"text/html\"";
    private const string ResetPasswordLink =
        "<https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#userresetpassword>; rel=\"deprecation\"; type=\"text/html\"";

    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public UsersPasswordRestDeprecationTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>Both endpoints of the wave: the path below the tenant API and the expected link.</summary>
    public static TheoryData<string, string> Endpoints => new()
    {
        { "users", CreateUserLink },
        { "users/ResetPassword", ResetPasswordLink }
    };

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Endpoint_WithConfiguredWave_CarriesDeprecationSunsetAndLink(string path, string link)
    {
        using var client = RestClient(Host((Since, Sunset)));

        // A refused call (unknown user, or a password that fails the policy): the headers do not depend on the status code.
        var response = await client.PostAsJsonAsync(TenantApiUrl(path), RefusedBody(path),
            TestContext.Current.CancellationToken);

        ((int)response.StatusCode).Should().BeInRange(400, 499);
        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        response.Headers.GetValues("Sunset").Should().Equal(SunsetHeader);
        response.Headers.GetValues("Link").Should().Equal(link);
    }

    /// <remarks>The shape of a rollout before the sunset date is announced: <c>since</c> set, <c>sunset</c> empty.</remarks>
    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Endpoint_WithSinceButNoSunset_CarriesDeprecationAndLink_ButNoSunset(string path, string link)
    {
        using var client = RestClient(Host((Since, null)));

        var response = await client.PostAsJsonAsync(TenantApiUrl(path), RefusedBody(path),
            TestContext.Current.CancellationToken);

        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        response.Headers.Contains("Sunset").Should().BeFalse("the sunset date is not configured");
        response.Headers.GetValues("Link").Should().Equal(link);
    }

    /// <summary>
    ///     AC: without a configured date the endpoints behave exactly as before — same status, same (empty) body, the user is
    ///     created and the password is reset; no <c>Deprecation</c> or <c>Sunset</c> header, only the <c>Link</c> to the method.
    /// </summary>
    [Fact]
    public async Task WithoutWaveDates_CreateAndReset_BehaveAsBefore_AndCarryTheLinkOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = RestClient(Host(null));
        var userName = $"u8860_{Guid.NewGuid():N}";
        const string newPassword = "Reset8860!x";

        var create = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = userName, email = $"{userName}@example.com", password = DefaultPassword }, ct);
        var reset = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName, password = newPassword }, ct);

        create.StatusCode.Should().Be(HttpStatusCode.OK, await create.Content.ReadAsStringAsync(ct));
        reset.StatusCode.Should().Be(HttpStatusCode.OK, await reset.Content.ReadAsStringAsync(ct));
        (await create.Content.ReadAsStringAsync(ct)).Should().BeEmpty();
        (await reset.Content.ReadAsStringAsync(ct)).Should().BeEmpty();
        using (var scope = CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var stored = await userManager.FindByNameAsync(userName);
            stored.Should().NotBeNull();
            (await userManager.CheckPasswordAsync(stored!, newPassword)).Should().BeTrue();
        }

        foreach (var (response, link) in new[] { (create, CreateUserLink), (reset, ResetPasswordLink) })
        {
            response.Headers.Contains("Deprecation").Should().BeFalse("no date is invented while Since is not configured");
            response.Headers.Contains("Sunset").Should().BeFalse("no date is invented while Sunset is not configured");
            response.Headers.GetValues("Link").Should().Equal(link);
        }
    }

    /// <summary>
    ///     A successful call of each endpoint is counted with the endpoint template and the client id, and neither a response
    ///     header nor a metric label carries the user name, the e-mail address, the password or the tenant.
    /// </summary>
    [Fact]
    public async Task SuccessfulCalls_AreCounted_AndNoHeaderOrLabelCarriesRequestData()
    {
        var ct = TestContext.Current.CancellationToken;
        using var collector = new DeprecatedCallCollector();
        using var client = RestClient(Host((Since, Sunset)));
        client.DefaultRequestHeaders.Add(TestAuthHandler.CliUserTokenHeader, "true");
        var userName = $"u8860_{Guid.NewGuid():N}";
        var email = $"{userName}@example.com";
        var createPassword = $"Cr8860!{Guid.NewGuid():N}";
        var resetPassword = $"Rs8860!{Guid.NewGuid():N}";
        var requestData = new[] { userName, email, createPassword, resetPassword, NormalizedSystemTenantId };

        var create = await client.PostAsJsonAsync(TenantApiUrl("users"),
            new { name = userName, email, password = createPassword, firstName = userName, lastName = userName }, ct);
        var reset = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName, password = resetPassword }, ct);

        create.StatusCode.Should().Be(HttpStatusCode.OK, await create.Content.ReadAsStringAsync(ct));
        reset.StatusCode.Should().Be(HttpStatusCode.OK, await reset.Content.ReadAsStringAsync(ct));
        foreach (var response in new[] { create, reset })
        {
            response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
            response.Headers.GetValues("Sunset").Should().Equal(SunsetHeader);
            var headerValues = response.Headers.Concat(response.Content.Headers).SelectMany(h => h.Value).ToList();
            foreach (var value in requestData)
            {
                headerValues.Should().NotContain(h => h.Contains(value, StringComparison.OrdinalIgnoreCase));
            }
        }

        // The listener sees the whole process; other test classes may call the endpoints in parallel.
        var measurements = collector.Snapshot()
            .Where(m => m.Tags.GetValueOrDefault("client_id") == TestAuthHandler.CliClientId &&
                        m.Tags.GetValueOrDefault("endpoint", string.Empty).StartsWith("POST ", StringComparison.Ordinal))
            .ToList();
        measurements.Should().Contain(m => m.Tags["endpoint"].EndsWith("/Users", StringComparison.OrdinalIgnoreCase) &&
                                           m.Tags["status_class"] == "2xx");
        measurements.Should().Contain(m =>
            m.Tags["endpoint"].EndsWith("/Users/ResetPassword", StringComparison.OrdinalIgnoreCase) &&
            m.Tags["status_class"] == "2xx");
        foreach (var measurement in measurements)
        {
            measurement.Tags.Keys.Should().BeEquivalentTo("endpoint", "client_id", "status_class");
            foreach (var value in requestData)
            {
                measurement.Tags.Values.Should().NotContain(t => t.Contains(value, StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    /// <summary>Create: a password that fails the policy (400). Reset: an unknown user (404).</summary>
    private static object RefusedBody(string path) => path == "users"
        ? new { name = $"u8860_{Guid.NewGuid():N}", email = $"{Guid.NewGuid():N}@example.com", password = "weak" }
        : new { userName = $"nouser_{Guid.NewGuid():N}", password = "Unused8860!x" };

    private WebApplicationFactory<Program> Host((string Since, string? Sunset)? dates)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (dates != null)
            {
                b.UseSetting($"RestDeprecation:Waves:{Wave}:Since", dates.Value.Since);
                // No sunset: set the key explicitly to empty so that a Sunset configured in the environment cannot reach
                // the since-only host.
                b.UseSetting($"RestDeprecation:Waves:{Wave}:Sunset", dates.Value.Sunset ?? string.Empty);
            }
        });
        _hosts.Add(host);
        return host;
    }

    private static HttpClient RestClient(WebApplicationFactory<Program> host)
    {
        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "UserManagement");
        return client;
    }
}
