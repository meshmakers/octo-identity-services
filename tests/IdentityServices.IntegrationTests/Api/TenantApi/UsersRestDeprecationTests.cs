using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Services.RestDeprecation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8415: identity wave 1 — <c>PUT users/{userName}/roles</c>, <c>PUT|DELETE users/{userName}/roles/{roleName}</c> and
///     <c>POST users/{userName}/merge</c> carry the deprecation headers on every response, are deprecated in the OpenAPI
///     document (through the endpoint metadata) and are counted per endpoint template and client id. The dates come from
///     <c>RestDeprecation:Waves:IdentityUsers1</c>; without them only the <c>Link</c> header is sent. <c>POST users</c> and
///     <c>POST users/ResetPassword</c> are not part of this story (AB#8418) and stay unmarked.
/// </summary>
public class UsersRestDeprecationTests : IntegrationTestBase, IDisposable
{
    private const string Wave = "IdentityUsers1";
    private const string Since = "2026-12-01";
    private const string Sunset = "2027-01-15";

    // Pinned literals: the test is about the wire format.
    private const string DeprecationHeader = "@1796083200";
    private const string SunsetHeader = "Fri, 15 Jan 2027 00:00:00 GMT";
    private const string RolesLink =
        "<https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#user-roles>; rel=\"deprecation\"; type=\"text/html\"";
    private const string MergeLink =
        "<https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods#usermerge>; rel=\"deprecation\"; type=\"text/html\"";

    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public UsersRestDeprecationTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>Every deprecated endpoint of wave 1: HTTP method, path below <c>users/</c> and the expected link.</summary>
    public static TheoryData<string, string, string> Endpoints => new()
    {
        { "PUT", "{0}/roles", RolesLink },
        { "PUT", "{0}/roles/SomeRole", RolesLink },
        { "DELETE", "{0}/roles/SomeRole", RolesLink },
        { "POST", "{0}/merge", MergeLink }
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
    public async Task Endpoint_WithConfiguredWave_CarriesDeprecationSunsetAndLink(string method, string path,
        string link)
    {
        using var client = RestClient(DatedHost());

        // An unknown user: 404 from the action. The headers do not depend on the status code.
        var response = await SendAsync(client, method, path, $"nouser_{Guid.NewGuid():N}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        response.Headers.GetValues("Sunset").Should().Equal(SunsetHeader);
        response.Headers.GetValues("Link").Should().Equal(link);
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Endpoint_WithoutWaveDates_CarriesTheLinkOnly(string method, string path, string link)
    {
        using var client = RestClient(Host(null));

        var response = await SendAsync(client, method, path, $"nouser_{Guid.NewGuid():N}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Headers.Contains("Deprecation").Should().BeFalse("no date is invented while Since is not configured");
        response.Headers.Contains("Sunset").Should().BeFalse("no date is invented while Sunset is not configured");
        response.Headers.GetValues("Link").Should().Equal(link);
    }

    /// <remarks>
    ///     The shape the clusters run today (Gerald 2026-11-11): <c>since</c> is configured, the sunset date is to be
    ///     announced and stays empty, so no <c>Sunset</c> header is sent.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task Endpoint_WithSinceButNoSunset_CarriesDeprecationAndLink_ButNoSunset(string method, string path,
        string link)
    {
        using var client = RestClient(Host((Since, null)));

        var response = await SendAsync(client, method, path, $"nouser_{Guid.NewGuid():N}");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        response.Headers.Contains("Sunset").Should().BeFalse("the sunset date is to be announced and not configured");
        response.Headers.GetValues("Link").Should().Equal(link);
    }

    [Fact]
    public async Task SuccessfulCall_CarriesTheHeaders_AndIsCountedWithEndpointTemplateAndClientId()
    {
        using var collector = new DeprecatedCallCollector();
        var user = await CreateTestUserAsync($"u8415_{Guid.NewGuid():N}");
        using var client = RestClient(DatedHost());
        client.DefaultRequestHeaders.Add(TestAuthHandler.CliUserTokenHeader, "true");

        var response = await client.PutAsJsonAsync(TenantApiUrl($"users/{user.UserName}/roles"), Array.Empty<string>(),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        // The listener sees the whole process; other test classes may call the endpoint in parallel.
        var matches = collector.Snapshot().Where(m =>
            m.Tags["client_id"] == TestAuthHandler.CliClientId && m.Tags["endpoint"].StartsWith("PUT ") &&
            m.Tags["endpoint"].EndsWith("/{userName}/roles")).ToList();
        matches.Should().NotBeEmpty();
        var measurement = matches[0];
        measurement.Tags["status_class"].Should().Be("2xx");
        measurement.Tags["endpoint"].Should().NotContain(user.UserName!).And.NotContain(NormalizedSystemTenantId);
        measurement.Tags.Keys.Should().BeEquivalentTo("endpoint", "client_id", "status_class");
    }

    [Fact]
    public async Task UnmarkedUserEndpoints_CarryNoDeprecationHeader()
    {
        using var client = RestClient(DatedHost());

        var get = await client.GetAsync(TenantApiUrl($"users/nouser_{Guid.NewGuid():N}"),
            TestContext.Current.CancellationToken);
        // POST users (AB#8418) is not deprecated yet: an invalid body is enough to see its headers.
        var create = await client.PostAsJsonAsync(TenantApiUrl("users"), new { }, TestContext.Current.CancellationToken);

        foreach (var response in new[] { get, create })
        {
            response.Headers.Contains("Deprecation").Should().BeFalse();
            response.Headers.Contains("Sunset").Should().BeFalse();
            response.Headers.Contains("Link").Should().BeFalse();
        }
    }

    /// <remarks>
    ///     The OpenAPI flag itself (<c>deprecated: true</c> plus the sunset notice) is set by the transformer of
    ///     octo-common-services from exactly this metadata and is tested there; the test host here cannot render the
    ///     identity OpenAPI document (package XML docs are not in the test output).
    /// </remarks>
    [Fact]
    public void ExactlyTheFourWave1Endpoints_CarryTheAttribute_WithTheirLinks()
    {
        var marked = DatedHost().Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Select(e => (Endpoint: e, Attribute: e.Metadata.GetMetadata<OctoRestDeprecatedAttribute>()))
            .Where(e => e.Attribute != null)
            .Select(e => $"{string.Join(",", e.Endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods)} " +
                         $"{e.Endpoint.RoutePattern.RawText![(e.Endpoint.RoutePattern.RawText!.IndexOf("/Users/", StringComparison.OrdinalIgnoreCase) + 1)..]} " +
                         $"{e.Attribute!.Wave} {e.Attribute.Link[(e.Attribute.Link.IndexOf('#') + 1)..]}")
            .ToList();

        marked.Should().BeEquivalentTo(
            "PUT Users/{userName}/roles IdentityUsers1 user-roles",
            "PUT Users/{userName}/roles/{roleName} IdentityUsers1 user-roles",
            "DELETE Users/{userName}/roles/{roleName} IdentityUsers1 user-roles",
            "POST Users/{userName}/merge IdentityUsers1 usermerge");
    }

    private WebApplicationFactory<Program> DatedHost() => Host((Since, Sunset));

    private WebApplicationFactory<Program> Host((string Since, string? Sunset)? dates)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (dates != null)
            {
                b.UseSetting($"RestDeprecation:Waves:{Wave}:Since", dates.Value.Since);
                // No sunset: set the key explicitly to empty so that a Sunset configured in the environment
                // (OCTO_RestDeprecation__Waves__IdentityUsers1__Sunset) cannot reach the since-only host.
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

    private async Task<HttpResponseMessage> SendAsync(HttpClient client, string method, string path, string userName)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), TenantApiUrl("users/" + string.Format(path, userName)));
        request.Content = method switch
        {
            "PUT" when path.EndsWith("/roles") => JsonContent.Create(Array.Empty<string>()),
            "POST" => JsonContent.Create(new { sourceUserName = "source" }),
            _ => null
        };
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>Collects the measurements of <c>octo.rest.deprecated.calls</c> while it lives.</summary>
    private sealed class DeprecatedCallCollector : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<Measurement> _measurements = new();

        public DeprecatedCallCollector()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "Meshmakers.Octo.RestDeprecation" &&
                    instrument.Name == "octo.rest.deprecated.calls")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                var dictionary = new Dictionary<string, string>();
                foreach (var tag in tags)
                {
                    dictionary[tag.Key] = tag.Value?.ToString() ?? string.Empty;
                }

                _measurements.Enqueue(new Measurement(value, dictionary));
            });
            _listener.Start();
        }

        public IReadOnlyList<Measurement> Snapshot() => _measurements.ToArray();

        public void Dispose() => _listener.Dispose();
    }

    private sealed record Measurement(long Value, IReadOnlyDictionary<string, string> Tags);
}
