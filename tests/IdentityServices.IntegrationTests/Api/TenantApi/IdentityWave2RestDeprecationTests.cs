using System.Net;
using System.Net.Http.Headers;
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
///     Identity wave 2: the REST write endpoints that are facades of the group, client, secret, client mirror, data permission,
///     admin provisioning and CRUD methods carry the deprecation headers of wave <c>IdentityWave2</c> on every response (also a
///     refusal: the headers depend on the endpoint, not on the status code), never a <c>Sunset</c> header, are counted per
///     endpoint template and client id, and exactly these endpoints carry the attribute. The OpenAPI flag
///     (<c>deprecated: true</c>) is set by the transformer of octo-common-services from exactly this metadata and is tested
///     there; the pinned endpoint set below is the snapshot of what OpenAPI marks.
/// </summary>
public class IdentityWave2RestDeprecationTests : IntegrationTestBase, IDisposable
{
    private const string Wave = "IdentityWave2";
    private const string Since = "2026-12-01";

    // Pinned literals: the test is about the wire format.
    private const string DeprecationHeader = "@1796083200";
    private const string MethodsPage = "https://docs.meshmakers.cloud/docs/technologyGuide/identityService/methods";

    private const string Id = "65f0c0ffee65f0c0ffee65f0";
    private const string Id2 = "65f0c0ffee65f0c0ffee65f1";

    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public IdentityWave2RestDeprecationTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>
    ///     Every endpoint of wave 2: HTTP method, path below <c>{tenant}/v1/</c> and the anchor of its link on the methods page.
    ///     At least one row per controller.
    /// </summary>
    public static TheoryData<string, string, string> Endpoints => new()
    {
        // Group roles and members
        { "PUT", $"groups/{Id}/roles", "groups" },
        { "PUT", $"groups/{Id}/members/users/someuser", "groups" },
        { "DELETE", $"groups/{Id}/members/users/someuser", "groups" },
        { "PUT", $"groups/{Id}/members/clients/someclient", "groups" },
        { "DELETE", $"groups/{Id}/members/clients/someclient", "groups" },
        { "PUT", $"groups/{Id}/members/groups/{Id2}", "groups" },
        { "DELETE", $"groups/{Id}/members/groups/{Id2}", "groups" },
        // Client roles and overlay URIs
        { "PUT", "clients/someclient/roles", "client-roles" },
        { "PUT", "clients/someclient/roles/SomeRole", "client-roles" },
        { "DELETE", "clients/someclient/roles/SomeRole", "client-roles" },
        { "POST", "clients/someclient/overlayUris", "client-roles" },
        { "DELETE", "clients/cleanOverlayEntries", "client-roles" },
        // Secrets
        { "POST", "apiSecrets/client/someclient", "client-secrets" },
        { "PUT", "apiSecrets/client/someclient", "client-secrets" },
        { "POST", "apiSecrets/client/someclient/delete", "client-secrets" },
        { "DELETE", "apiSecrets/client/someclient/somevalue", "client-secrets" },
        { "POST", "apiSecrets/apiResource/someresource", "client-secrets" },
        { "PUT", "apiSecrets/apiResource/someresource", "client-secrets" },
        { "POST", "apiSecrets/apiResource/someresource/delete", "client-secrets" },
        { "DELETE", "apiSecrets/apiResource/someresource/somevalue", "client-secrets" },
        // Data permission grants and enforcement mode
        { "POST", "dataPermissions/somepermission/roles/SomeRole", "data-permissions" },
        { "DELETE", "dataPermissions/somepermission/roles/SomeRole", "data-permissions" },
        { "PUT", $"dataPermissions/policies/{Id}/enforcementMode", "data-permissions" },
        // Client mirrors
        { "POST", "clients/someclient/mirrors/provisionInExistingTenants", "client-mirrors" },
        { "POST", "clients/someclient/mirrors/provisionInTenant?childTenantId=childtenant", "client-mirrors" },
        { "POST", "clients/someclient/mirrors/childtenant/secret", "client-mirrors" },
        { "DELETE", "clients/someclient/mirrors/childtenant", "client-mirrors" },
        { "PATCH", "clients/someclient/autoProvisionInChildTenants", "client-mirrors" },
        // Admin provisioning and the mapping create
        { "POST", "adminProvisioning/childtenant", "admin-provisioning" },
        { "POST", "adminProvisioning/childtenant/withGroups", "admin-provisioning" },
        { "POST", "adminProvisioning/childtenant/provisionCurrentUser", "admin-provisioning" },
        { "DELETE", $"adminProvisioning/childtenant/{Id}", "admin-provisioning" },
        { "POST", "externalTenantUserMappings", "admin-provisioning" },
        // CRUD: roles, groups, API scopes, API resources
        { "POST", "roles", "crud" },
        { "PUT", "roles/SomeRole", "crud" },
        { "DELETE", "roles/SomeRole", "crud" },
        { "POST", "groups", "crud" },
        { "PUT", $"groups/{Id}", "crud" },
        { "DELETE", $"groups/{Id}", "crud" },
        { "POST", "apiScopes", "crud" },
        { "PUT", "apiScopes/somescope", "crud" },
        { "DELETE", "apiScopes/somescope", "crud" },
        { "POST", "apiResources", "crud" },
        { "PUT", "apiResources/someresource", "crud" },
        { "DELETE", "apiResources/someresource", "crud" },
        // CRUD: identity providers, e-mail domain group rules, mappings, data permissions and policies, clients
        { "POST", "identityProviders", "crud-wave-2" },
        { "PUT", $"identityProviders/{Id}", "crud-wave-2" },
        { "DELETE", $"identityProviders/{Id}", "crud-wave-2" },
        { "POST", "emailDomainGroupRules", "crud-wave-2" },
        { "PUT", $"emailDomainGroupRules/{Id}", "crud-wave-2" },
        { "DELETE", $"emailDomainGroupRules/{Id}", "crud-wave-2" },
        { "PUT", $"externalTenantUserMappings/{Id}", "crud-wave-2" },
        { "DELETE", $"externalTenantUserMappings/{Id}", "crud-wave-2" },
        { "POST", "dataPermissions", "crud-wave-2" },
        { "DELETE", "dataPermissions/somepermission", "crud-wave-2" },
        { "POST", "dataPermissions/somepermission/policies", "crud-wave-2" },
        { "DELETE", $"dataPermissions/policies/{Id}", "crud-wave-2" },
        { "POST", "clients", "crud-wave-2" },
        { "PUT", "clients/someclient", "crud-wave-2" },
        { "DELETE", "clients/someclient", "crud-wave-2" }
    };

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    /// <remarks>
    ///     The shape the clusters run: <c>since</c> is configured at the delivery of the release, the sunset date is to be
    ///     announced and stays empty, so no <c>Sunset</c> header is sent.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task AMigratedEndpoint_CarriesDeprecationAndLink_ButNoSunset(string method, string path, string anchor)
    {
        using var client = Host(Since).CreateClient();

        // No token: the bearer scheme refuses the call after routing selected the endpoint.
        var response = await SendAsync(client, method, path);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, path);
        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        response.Headers.GetValues("Link").Should().Equal(LinkHeader(anchor));
        response.Headers.Contains("Sunset").Should().BeFalse("the sunset date is to be announced and not configured");
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task WithoutTheWaveDate_OnlyTheLinkIsSent(string method, string path, string anchor)
    {
        using var client = Host(null).CreateClient();

        var response = await SendAsync(client, method, path);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, path);
        response.Headers.Contains("Deprecation").Should().BeFalse("no date is invented while Since is not configured");
        response.Headers.Contains("Sunset").Should().BeFalse();
        response.Headers.GetValues("Link").Should().Equal(LinkHeader(anchor));
    }

    /// <summary>The endpoints that stay REST (reads, secret lookups, cross-tenant lookups) carry no deprecation header.</summary>
    [Theory]
    [InlineData("GET", "groups")]
    [InlineData("GET", "clients")]
    [InlineData("GET", "roles")]
    [InlineData("GET", "dataPermissions")]
    [InlineData("GET", "externalTenantUserMappings")]
    [InlineData("GET", "clients/someclient/mirrors")]
    [InlineData("POST", "apiSecrets/client/someclient/lookup")]
    [InlineData("POST", "apiSecrets/apiResource/someresource/lookup")]
    [InlineData("POST", "externalTenantUserMappings/sourceUserLookup")]
    [InlineData("GET", "adminProvisioning/childtenant/sourceUsers")]
    [InlineData("PUT", "crossTenantGrantPermissions")]
    [InlineData("POST", "emailIdentifierBindings")]
    [InlineData("PUT", "users/someuser")]
    [InlineData("DELETE", "users/someuser")]
    public async Task AnEndpointThatStaysRest_CarriesNoDeprecationHeader(string method, string path)
    {
        using var client = Host(Since).CreateClient();

        var response = await SendAsync(client, method, path);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized, $"{path} exists and is refused without a token");
        response.Headers.Contains("Deprecation").Should().BeFalse(path);
        response.Headers.Contains("Sunset").Should().BeFalse(path);
        response.Headers.Contains("Link").Should().BeFalse(path);
    }

    [Fact]
    public async Task ACall_IsCounted_PerEndpointTemplateAndClientIdOnly()
    {
        using var collector = new DeprecatedCallCollector();
        using var client = Host(Since).CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "UserManagement");
        client.DefaultRequestHeaders.Add(TestAuthHandler.CliUserTokenHeader, "true");
        var roleName = $"norole_{Guid.NewGuid():N}";

        // An unknown role: refused by the action. The call is counted whatever the status code.
        var response = await client.DeleteAsync(TenantApiUrl($"roles/{roleName}"), TestContext.Current.CancellationToken);

        response.Headers.GetValues("Deprecation").Should().Equal(DeprecationHeader);
        // The listener sees the whole process; other test classes may call the endpoint in parallel.
        var matches = collector.Snapshot().Where(m =>
            m.Tags["client_id"] == TestAuthHandler.CliClientId && m.Tags["endpoint"].StartsWith("DELETE ") &&
            m.Tags["endpoint"].EndsWith("/Roles/{roleName}", StringComparison.OrdinalIgnoreCase)).ToList();
        matches.Should().NotBeEmpty();
        var measurement = matches[0];
        measurement.Tags.Keys.Should().BeEquivalentTo("endpoint", "client_id", "status_class");
        measurement.Tags["status_class"].Should().Be($"{(int)response.StatusCode / 100}xx");
        measurement.Tags["endpoint"].Should().NotContain(roleName).And.NotContain(NormalizedSystemTenantId);
        measurement.Tags.Values.Should().NotContain(v => v.Contains(roleName) || v.Contains(NormalizedSystemTenantId));
    }

    /// <summary>
    ///     The snapshot of what OpenAPI marks deprecated in wave 2: every endpoint that carries the attribute with this wave, its
    ///     link and empty dates; and no endpoint of the service carries a wave other than the three identity waves.
    /// </summary>
    [Fact]
    public void ExactlyTheWave2Endpoints_CarryTheAttribute_WithTheirLinks()
    {
        var marked = Host(Since).Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Select(e => (Endpoint: e, Attribute: e.Metadata.GetMetadata<OctoRestDeprecatedAttribute>()))
            .Where(e => e.Attribute != null)
            .ToList();

        marked.Select(e => e.Attribute!.Wave).Distinct()
            .Should().BeSubsetOf(["IdentityUsers1", "IdentityUsersPassword", Wave]);

        var wave2 = marked.Where(e => e.Attribute!.Wave == Wave).ToList();
        wave2.Should().OnlyContain(e => string.IsNullOrEmpty(e.Attribute!.Since) &&
                                        string.IsNullOrEmpty(e.Attribute.Sunset) &&
                                        string.IsNullOrEmpty(e.Attribute.Successor) &&
                                        e.Attribute.Link.StartsWith(MethodsPage + "#"));
        const string prefix = "/v{version:apiVersion}/";
        wave2.Select(e =>
            {
                var template = e.Endpoint.RoutePattern.RawText!;
                return $"{string.Join(",", e.Endpoint.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods)} " +
                       $"{template[(template.IndexOf(prefix, StringComparison.Ordinal) + prefix.Length)..]} " +
                       e.Attribute!.Link[(e.Attribute.Link.IndexOf('#') + 1)..];
            })
            .Should().BeEquivalentTo(
                "PUT Groups/{rtId}/roles groups",
                "PUT Groups/{rtId}/members/users/{userId} groups",
                "DELETE Groups/{rtId}/members/users/{userId} groups",
                "PUT Groups/{rtId}/members/clients/{clientId} groups",
                "DELETE Groups/{rtId}/members/clients/{clientId} groups",
                "PUT Groups/{rtId}/members/groups/{childGroupId} groups",
                "DELETE Groups/{rtId}/members/groups/{childGroupId} groups",
                "PUT Clients/{id}/roles client-roles",
                "PUT Clients/{id}/roles/{roleName} client-roles",
                "DELETE Clients/{id}/roles/{roleName} client-roles",
                "POST Clients/{id}/overlayUris client-roles",
                "DELETE Clients/cleanOverlayEntries client-roles",
                "POST ApiSecrets/client/{clientId} client-secrets",
                "PUT ApiSecrets/client/{clientId} client-secrets",
                "POST ApiSecrets/client/{clientId}/delete client-secrets",
                "DELETE ApiSecrets/client/{clientId}/{secretValue} client-secrets",
                "POST ApiSecrets/apiResource/{apiResourceName} client-secrets",
                "PUT ApiSecrets/apiResource/{apiResourceName} client-secrets",
                "POST ApiSecrets/apiResource/{apiResourceName}/delete client-secrets",
                "DELETE ApiSecrets/apiResource/{apiResourceName}/{secretValue} client-secrets",
                "POST DataPermissions/{permissionId}/roles/{roleName} data-permissions",
                "DELETE DataPermissions/{permissionId}/roles/{roleName} data-permissions",
                "PUT DataPermissions/policies/{policyRtId}/enforcementMode data-permissions",
                "POST clients/{clientId}/mirrors/provisionInExistingTenants client-mirrors",
                "POST clients/{clientId}/mirrors/provisionInTenant client-mirrors",
                "POST clients/{clientId}/mirrors/{childTenantId}/secret client-mirrors",
                "DELETE clients/{clientId}/mirrors/{childTenantId} client-mirrors",
                "PATCH clients/{clientId}/autoProvisionInChildTenants client-mirrors",
                "POST AdminProvisioning/{targetTenantId} admin-provisioning",
                "POST AdminProvisioning/{targetTenantId}/withGroups admin-provisioning",
                "POST AdminProvisioning/{targetTenantId}/provisionCurrentUser admin-provisioning",
                "DELETE AdminProvisioning/{targetTenantId}/{mappingRtId} admin-provisioning",
                "POST ExternalTenantUserMappings admin-provisioning",
                "POST Roles crud",
                "PUT Roles/{roleName} crud",
                "DELETE Roles/{roleName} crud",
                "POST Groups crud",
                "PUT Groups/{rtId} crud",
                "DELETE Groups/{rtId} crud",
                "POST ApiScopes crud",
                "PUT ApiScopes/{name} crud",
                "DELETE ApiScopes/{name} crud",
                "POST ApiResources crud",
                "PUT ApiResources/{name} crud",
                "DELETE ApiResources/{name} crud",
                "POST IdentityProviders crud-wave-2",
                "PUT IdentityProviders/{rtId} crud-wave-2",
                "DELETE IdentityProviders/{rtId} crud-wave-2",
                "POST EmailDomainGroupRules crud-wave-2",
                "PUT EmailDomainGroupRules/{rtId} crud-wave-2",
                "DELETE EmailDomainGroupRules/{rtId} crud-wave-2",
                "PUT ExternalTenantUserMappings/{rtId} crud-wave-2",
                "DELETE ExternalTenantUserMappings/{rtId} crud-wave-2",
                "POST DataPermissions crud-wave-2",
                "DELETE DataPermissions/{permissionId} crud-wave-2",
                "POST DataPermissions/{permissionId}/policies crud-wave-2",
                "DELETE DataPermissions/policies/{policyRtId} crud-wave-2",
                "POST Clients crud-wave-2",
                "PUT Clients/{id} crud-wave-2",
                "DELETE Clients/{id} crud-wave-2");
    }

    private static string LinkHeader(string anchor) => $"<{MethodsPage}#{anchor}>; rel=\"deprecation\"; type=\"text/html\"";

    private WebApplicationFactory<Program> Host(string? since)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            // Every key is set explicitly (empty = no date), so that dates configured in the environment
            // (OCTO_RestDeprecation__Waves__<wave>__Since|Sunset) cannot reach a host of this test.
            b.UseSetting($"RestDeprecation:Waves:{Wave}:Since", since ?? string.Empty);
            b.UseSetting($"RestDeprecation:Waves:{Wave}:Sunset", string.Empty);
        });
        _hosts.Add(host);
        return host;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpClient client, string method, string path)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), TenantApiUrl(path));
        if (method is "POST" or "PUT" or "PATCH")
        {
            request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }
}
