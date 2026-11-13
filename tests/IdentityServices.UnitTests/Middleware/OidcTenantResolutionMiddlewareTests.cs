using System.Text;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

public class OidcTenantResolutionMiddlewareTests
{
    [Fact]
    public void ParseTenantFromAcrValues_WithTenantValue_ReturnsTenantId()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithMultipleValues_ReturnsTenantId()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("idp:local tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithNoTenantValue_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("idp:local");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithEmptyString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithEmptyTenantValue_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant:");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_CaseInsensitivePrefix()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("Tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithValidJwt_ReturnsTenantId()
    {
        // Create a JWT with tenant_id claim in the payload
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"sub":"user1","tenant_id":"sbeg"}
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode("{\"sub\":\"user1\",\"tenant_id\":\"sbeg\"}");
        var jwt = $"{header}.{payload}.signature";

        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload(jwt);

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithNoTenantClaim_ReturnsNull()
    {
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode("{\"sub\":\"user1\"}");
        var jwt = $"{header}.{payload}.signature";

        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload(jwt);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithMalformedJwt_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("not-a-jwt");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithEmptyString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithInvalidBase64_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("header.!!!invalid!!!.signature");

        result.Should().BeNull();
    }

    // AB#7892: the authorization code carries its tenant, so the token request needs no in-process map.

    [Fact]
    public void MarkCodeInRedirectUri_Query_MarksOnlyTheCode()
    {
        var result = OidcTenantResolutionMiddleware.MarkCodeInRedirectUri(
            "https://localhost:4200/callback?code=ABC123&state=xyz&iss=https%3A%2F%2Fid", "child-a");

        result.Should().Be("https://localhost:4200/callback?code=child-a%3AABC123&state=xyz&iss=https%3A%2F%2Fid");
    }

    [Fact]
    public void MarkCodeInRedirectUri_Fragment_MarksTheCode()
    {
        var result = OidcTenantResolutionMiddleware.MarkCodeInRedirectUri(
            "/callback#state=xyz&code=DEF456", "child-a");

        result.Should().Be("/callback#state=xyz&code=child-a%3ADEF456");
    }

    [Theory]
    [InlineData("https://localhost:4200/callback?state=xyz")]
    [InlineData("https://localhost:4200/callback")]
    [InlineData("https://localhost:4200/callback?error=access_denied&state=xyz")]
    [InlineData("")]
    [InlineData(null)]
    public void MarkCodeInRedirectUri_WithoutCode_ReturnsNull(string? location)
    {
        OidcTenantResolutionMiddleware.MarkCodeInRedirectUri(location, "child-a").Should().BeNull();
    }

    [Theory]
    [InlineData("<input type='hidden' name='code' value='AUTH_CODE_123' />", "<input type='hidden' name='code' value='child-a:AUTH_CODE_123' />")]
    [InlineData("<input type=\"hidden\" name=\"code\" value=\"MY_CODE_456\" />", "<input type=\"hidden\" name=\"code\" value=\"child-a:MY_CODE_456\" />")]
    public void MarkCodeInFormPostBody_MarksTheHiddenCodeField(string field, string expected)
    {
        var html = $"<html><body><form method='post' action='https://app/cb'>{field}<input type='hidden' name='state' value='s' /></form></body></html>";
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(html));

        var result = OidcTenantResolutionMiddleware.MarkCodeInFormPostBody(stream, "child-a");

        Encoding.UTF8.GetString(result!).Should().Be(html.Replace(field, expected));
    }

    [Fact]
    public void MarkCodeInFormPostBody_WithoutCode_ReturnsNull()
    {
        using var stream = new MemoryStream("<form><input type='hidden' name='state' value='s' /></form>"u8.ToArray());

        OidcTenantResolutionMiddleware.MarkCodeInFormPostBody(stream, "child-a").Should().BeNull();
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_MarkedAuthorizationCode_ResolvesTenantAndStripsMarker()
    {
        var context = FormRequest("/connect/token",
            ("grant_type", "authorization_code"), ("client_id", "ec-app"), ("code", "child-a:opaque.code"));

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("child-a");
        var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
        form["code"].ToString().Should().Be("opaque.code", "OpenIddict must only see its own value");
        form["client_id"].ToString().Should().Be("ec-app");
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_UnmarkedAuthorizationCode_ReturnsNull()
    {
        // Issued before AB#7892: system tenant, where a code of another tenant is unknown (fail closed).
        var context = FormRequest("/connect/token", ("grant_type", "authorization_code"), ("code", "opaque.code"));

        (await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context)).Should().BeNull();
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_MarkedRefreshToken_WinsOverAcrValues()
    {
        var context = FormRequest("/connect/token",
            ("grant_type", "refresh_token"), ("refresh_token", "child-a:opaque.rt"), ("acr_values", "tenant:child-b"));

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("child-a", "the marker names the store the token lives in");
        (await context.Request.ReadFormAsync(TestContext.Current.CancellationToken))["refresh_token"].ToString()
            .Should().Be("opaque.rt");
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_UnmarkedRefreshToken_UsesAcrValuesOrNothing()
    {
        var withAcr = FormRequest("/connect/token",
            ("grant_type", "refresh_token"), ("refresh_token", "opaque.rt"), ("acr_values", "tenant:child-b"));
        (await CreateMiddleware().ResolveTenantFromTokenRequestAsync(withAcr)).Should().Be("child-b");

        var withoutAcr = FormRequest("/connect/token", ("grant_type", "refresh_token"), ("refresh_token", "opaque.rt"));
        (await CreateMiddleware().ResolveTenantFromTokenRequestAsync(withoutAcr)).Should().BeNull();
    }

    [Fact]
    public void MarkRefreshTokenInTokenResponse_MarksOnlyTheRefreshToken()
    {
        using var body = new MemoryStream(
            """{"access_token":"a.b.c","token_type":"Bearer","expires_in":3600,"refresh_token":"opaque.rt","scope":"openid offline_access"}"""u8.ToArray());

        var rewritten = CreateMiddleware().MarkRefreshTokenInTokenResponse(body, "child-a");

        var json = System.Text.Json.Nodes.JsonNode.Parse(rewritten!)!.AsObject();
        json["refresh_token"]!.GetValue<string>().Should().Be("child-a:opaque.rt");
        json["access_token"]!.GetValue<string>().Should().Be("a.b.c", "the access token is never touched");
        json["expires_in"]!.GetValue<int>().Should().Be(3600);
        json["scope"]!.GetValue<string>().Should().Be("openid offline_access");
    }

    [Fact]
    public void MarkRefreshTokenInTokenResponse_WithoutRefreshToken_IsLeftAlone()
    {
        using var body = new MemoryStream("""{"access_token":"a.b.c","token_type":"Bearer"}"""u8.ToArray());

        CreateMiddleware().MarkRefreshTokenInTokenResponse(body, "child-a").Should().BeNull();
    }

    [Fact]
    public async Task Revocation_MarkedToken_ResolvesTenantAndStripsMarker()
    {
        var context = FormRequest("/connect/revocation",
            ("token", "child-a:opaque.rt"), ("token_type_hint", "refresh_token"), ("client_id", "ec-app"));
        var systemContext = Substitute.For<ISystemContext>();
        context.RequestServices = ServicesWith(systemContext);

        await CreateMiddleware().InvokeAsync(context);

        await systemContext.Received(1).TryFindTenantRepositoryAsync("child-a");

        var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
        form["token"].ToString().Should().Be("opaque.rt");
    }

    /// <summary>
    ///     AB#5026 — the delegation grant must resolve its tenant from <c>acr_values</c> like
    ///     <c>client_credentials</c> and token-exchange do.
    /// </summary>
    /// <remarks>
    ///     The if/else chain in <c>ResolveTenantFromTokenRequestAsync</c> is a closed list of known
    ///     grant types; an unlisted one falls through to <c>null</c>, no tenant is wired into
    ///     <c>HttpContext.Items</c>, and every per-tenant store silently reads the SYSTEM tenant —
    ///     which for delegation means resolving the service account, the user and both role sets
    ///     from the wrong database. This test is the guard against re-introducing that gap.
    /// </remarks>
    [Fact]
    public async Task ResolveTenantFromTokenRequest_OnBehalfOfGrant_ResolvesTenantFromAcrValues()
    {
        var context = TokenRequest(DelegationConstants.OnBehalfOfGrantType, "tenant:sbeg");

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("sbeg");
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_OnBehalfOfGrantWithoutAcrValues_ReturnsNull()
    {
        // The grant validator then fails closed on the missing target tenant.
        var context = TokenRequest(DelegationConstants.OnBehalfOfGrantType, acrValues: null);

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().BeNull();
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_UnknownGrantType_ReturnsNull()
    {
        // Pins the fall-through the delegation branch exists to avoid.
        var context = TokenRequest("urn:example:grant-type:unknown", "tenant:sbeg");

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().BeNull();
    }

    // AB#7891: the device flow resolves its tenant without the in-process map.

    private const string DeviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code";

    [Fact]
    public async Task ResolveTenantFromTokenRequest_DeviceCodeWithTenantMarker_ResolvesTenantAndStripsMarker()
    {
        var context = FormRequest("/connect/token",
            ("grant_type", DeviceCodeGrant), ("client_id", "octo-cli"), ("device_code", "child-a:opaque.device.code"));

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("child-a");
        var form = await context.Request.ReadFormAsync(TestContext.Current.CancellationToken);
        form["device_code"].ToString().Should().Be("opaque.device.code", "OpenIddict must only see its own value");
        form["client_id"].ToString().Should().Be("octo-cli", "the other fields stay");
        context.Request.Body.Position = 0;
        var raw = await new StreamReader(context.Request.Body).ReadToEndAsync(TestContext.Current.CancellationToken);
        raw.Should().Contain("device_code=opaque.device.code").And.NotContain("child-a");
        context.Request.ContentLength.Should().Be(System.Text.Encoding.UTF8.GetByteCount(raw));
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_DeviceCodeWithoutMarker_FallsBackToAcrValues()
    {
        var context = FormRequest("/connect/token",
            ("grant_type", DeviceCodeGrant), ("device_code", "unmarked"), ("acr_values", "tenant:child-b"));

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("child-b");
        (await context.Request.ReadFormAsync(TestContext.Current.CancellationToken))["device_code"].ToString().Should().Be("unmarked");
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_DeviceCodeWithoutMarkerOrAcrValues_ReturnsNull()
    {
        // A code issued before AB#7891 (or for the system tenant without acr_values) runs in the system tenant.
        var context = FormRequest("/connect/token", ("grant_type", DeviceCodeGrant), ("device_code", "unmarked"));

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().BeNull();
    }

    [Fact]
    public async Task ResolveTenantForDeviceVerification_HintInQuery_ReturnsTenant()
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = "/connect/deviceverification";
        context.Request.QueryString = new QueryString("?user_code=ABCD-1234&acr_values=tenant%3Achild-a");

        var result = await CreateMiddleware().ResolveTenantForDeviceVerificationAsync(context);

        result.Should().Be("child-a");
    }

    [Fact]
    public async Task ResolveTenantForDeviceVerification_HintInForm_ReturnsTenantAndKeepsBodyReadable()
    {
        var context = FormRequest("/connect/deviceverification",
            ("user_code", "ABCD-1234"), ("acr_values", "tenant:child-a"));

        var result = await CreateMiddleware().ResolveTenantForDeviceVerificationAsync(context);

        result.Should().Be("child-a");
        context.Request.Body.Position.Should().Be(0, "OpenIddict and the controller read the form afterwards");
        (await context.Request.ReadFormAsync(TestContext.Current.CancellationToken))["user_code"].ToString().Should().Be("ABCD-1234");
    }

    [Fact]
    public async Task ResolveTenantForDeviceVerification_NoHint_ReturnsNull_EvenForAKnownUserCode()
    {
        // No server-side user_code → tenant state any more: without a hint the system tenant applies.
        var context = FormRequest("/connect/deviceverification", ("user_code", "ABCD-1234"));

        var result = await CreateMiddleware().ResolveTenantForDeviceVerificationAsync(context);

        result.Should().BeNull();
    }

    [Fact]
    public void RewriteDeviceAuthorizationResponse_MarksDeviceCodeAndPointsToTheTenantDevicePage()
    {
        const string response =
            """{"device_code":"opaque-device","user_code":"ABCD-1234","verification_uri":"https://id.example/connect/deviceverification","verification_uri_complete":"https://id.example/connect/deviceverification?user_code=ABCD-1234","expires_in":300,"interval":5}""";
        using var body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(response));

        var rewritten = CreateMiddleware().RewriteDeviceAuthorizationResponse(body, "child-a");

        rewritten.Should().NotBeNull();
        var json = System.Text.Json.Nodes.JsonNode.Parse(rewritten!)!.AsObject();
        json["device_code"]!.GetValue<string>().Should().Be("child-a:opaque-device");
        json["user_code"]!.GetValue<string>().Should().Be("ABCD-1234", "the user code stays human-typable");
        json["verification_uri"]!.GetValue<string>().Should().Be("https://id.example/child-a/device");
        json["verification_uri_complete"]!.GetValue<string>()
            .Should().Be("https://id.example/child-a/device?userCode=ABCD-1234");
        json["expires_in"]!.GetValue<int>().Should().Be(300);
        json["interval"]!.GetValue<int>().Should().Be(5);
    }

    [Fact]
    public void RewriteDeviceAuthorizationResponse_ErrorBodyWithoutDeviceCode_IsLeftAlone()
    {
        using var body = new MemoryStream("""{"error":"invalid_client"}"""u8.ToArray());

        CreateMiddleware().RewriteDeviceAuthorizationResponse(body, "child-a").Should().BeNull();
    }

    private static DefaultHttpContext FormRequest(string path, params (string Key, string Value)[] fields)
    {
        var form = string.Join('&', fields.Select(f => $"{Uri.EscapeDataString(f.Key)}={Uri.EscapeDataString(f.Value)}"));
        var bytes = System.Text.Encoding.UTF8.GetBytes(form);
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = path;
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        return context;
    }

    /// <summary>Request services whose system context knows no tenant (the lookup returns <c>null</c>).</summary>
    private static IServiceProvider ServicesWithoutTenants()
    {
        var systemContext = Substitute.For<ISystemContext>();
        systemContext.TryFindTenantRepositoryAsync(Arg.Any<string>())
            .Returns(Task.FromResult<Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository?>(null));
        return ServicesWith(systemContext);
    }

    private static IServiceProvider ServicesWith(ISystemContext systemContext)
    {
        return new ServiceCollection().AddSingleton(systemContext).BuildServiceProvider();
    }

    private static OidcTenantResolutionMiddleware CreateMiddleware() =>
        new(_ => Task.CompletedTask,
            NullLogger<OidcTenantResolutionMiddleware>.Instance,
            Options.Create(new OctoSystemConfiguration()));

    private static DefaultHttpContext TokenRequest(string grantType, string? acrValues)
    {
        var form = $"grant_type={Uri.EscapeDataString(grantType)}";
        if (acrValues != null)
        {
            form += $"&acr_values={Uri.EscapeDataString(acrValues)}";
        }

        var bytes = System.Text.Encoding.UTF8.GetBytes(form);
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/connect/token";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        return context;
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    // AB#5311: the discovery scope travels as a second acr_values entry and must neither be
    // mistaken for the tenant nor be lost when both are present.
    [Fact]
    public void ParseTenantFromAcrValues_IgnoresScopeEntry()
    {
        OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant_scope:accounting").Should().BeNull();
    }

    [Theory]
    [InlineData("tenant_scope:accounting", "accounting")]
    [InlineData("tenant_scope:accounting tenant:tecob", "accounting")]
    [InlineData("tenant:tecob tenant_scope:accounting", "accounting")]
    [InlineData("Tenant_Scope:accounting", "accounting")]
    public void ParseScopeFromAcrValues_ReturnsScope(string acrValues, string expected)
    {
        OidcTenantResolutionMiddleware.ParseScopeFromAcrValues(acrValues).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("tenant:tecob")]
    [InlineData("tenant_scope:")]
    [InlineData("idp:local")]
    public void ParseScopeFromAcrValues_WithoutScope_ReturnsNull(string acrValues)
    {
        OidcTenantResolutionMiddleware.ParseScopeFromAcrValues(acrValues).Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithScopeAndTenant_ReturnsTenant()
    {
        OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant_scope:accounting tenant:tecob")
            .Should().Be("tecob");
    }

    [Fact]
    public void BuildDiscoveryUrl_WithoutScope_CarriesOnlyReturnUrl()
    {
        var url = OidcTenantResolutionMiddleware.BuildDiscoveryUrl("https://id/connect/authorize?client_id=x", null);
        url.Should().Be("/tenant-discovery?returnUrl=https%3A%2F%2Fid%2Fconnect%2Fauthorize%3Fclient_id%3Dx");
    }

    [Fact]
    public void BuildDiscoveryUrl_WithScope_AppendsScopeParameter()
    {
        var url = OidcTenantResolutionMiddleware.BuildDiscoveryUrl("https://id/connect/authorize?client_id=x", "accounting");
        url.Should().StartWith("/tenant-discovery?returnUrl=");
        url.Should().EndWith("&scopeTenantId=accounting");
    }

    // AB#5311 (review finding): a scope-only PAR names no tenant, so the scope must travel with
    // the issued request_uri or the follow-up authorize call runs an unscoped discovery.
    [Fact]
    public async Task ScopeOnlyPar_RestoresTheScopeOnTheDiscoveryRedirect()
    {
        var requestUri = "urn:ietf:params:oauth:request_uri:" + Guid.NewGuid().ToString("N");
        RequestDelegate next = async ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status201Created;
            ctx.Response.ContentType = "application/json";
            await ctx.Response.WriteAsync($"{{\"request_uri\":\"{requestUri}\",\"expires_in\":60}}");
        };
        var middleware = new OidcTenantResolutionMiddleware(
            next,
            NullLogger<OidcTenantResolutionMiddleware>.Instance,
            Options.Create(new OctoSystemConfiguration()));

        var par = new DefaultHttpContext();
        par.Request.Method = "POST";
        par.Request.Path = "/connect/par";
        par.Request.ContentType = "application/x-www-form-urlencoded";
        par.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("client_id=x&acr_values=tenant_scope%3Aaccounting"));
        par.Response.Body = new MemoryStream();
        await middleware.InvokeAsync(par);
        par.Response.Body.Position = 0;
        var markedRequestUri = System.Text.Json.Nodes.JsonNode.Parse(par.Response.Body)!["request_uri"]!.GetValue<string>();
        markedRequestUri.Should().StartWith(OidcTenantMarker.RequestUriPrefix, "the request_uri stays a PAR URN");

        var authorize = new DefaultHttpContext();
        authorize.Request.Method = "GET";
        authorize.Request.Scheme = "https";
        authorize.Request.Host = new HostString("id.test");
        authorize.Request.Path = "/connect/authorize";
        authorize.Request.QueryString = new QueryString($"?client_id=x&request_uri={Uri.EscapeDataString(markedRequestUri)}");
        authorize.Response.Body = new MemoryStream();
        await middleware.InvokeAsync(authorize);

        authorize.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        var location = authorize.Response.Headers.Location.ToString();
        location.Should().StartWith("/tenant-discovery?returnUrl=");
        location.Should().EndWith("&scopeTenantId=accounting");
        location.Should().Contain(Uri.EscapeDataString(Uri.EscapeDataString(markedRequestUri)),
            "the returnUrl hands the request_uri back as the client sent it");
    }

    [Fact]
    public async Task TenantPar_MarksTheRequestUri_AndAuthorizeResolvesTheTenantAndSeesTheOriginalValue()
    {
        var requestUri = "urn:ietf:params:oauth:request_uri:" + Guid.NewGuid().ToString("N");
        string? requestUriSeenByOpenIddict = null;
        RequestDelegate next = async ctx =>
        {
            if (ctx.Request.Path.StartsWithSegments("/connect/par"))
            {
                ctx.Response.StatusCode = StatusCodes.Status201Created;
                ctx.Response.ContentType = "application/json";
                await ctx.Response.WriteAsync($"{{\"request_uri\":\"{requestUri}\",\"expires_in\":60}}");
            }
            else
            {
                requestUriSeenByOpenIddict = ctx.Request.Query["request_uri"];
            }
        };
        var middleware = new OidcTenantResolutionMiddleware(next,
            NullLogger<OidcTenantResolutionMiddleware>.Instance, Options.Create(new OctoSystemConfiguration()));

        var par = FormRequest("/connect/par", ("client_id", "x"), ("acr_values", "tenant:child-a"));
        par.Items[InfrastructureCommon.TenantIdName] = "child-a";
        par.RequestServices = ServicesWithoutTenants();
        par.Response.Body = new MemoryStream();
        await middleware.InvokeAsync(par);
        par.Response.Body.Position = 0;
        var marked = System.Text.Json.Nodes.JsonNode.Parse(par.Response.Body)!["request_uri"]!.GetValue<string>();

        OidcTenantMarker.TryDecodeRequestUri(marked, out var tenantId, out var scope, out var original).Should().BeTrue();
        tenantId.Should().Be("child-a");
        scope.Should().BeNull();
        original.Should().Be(requestUri);

        var authorize = new DefaultHttpContext();
        authorize.Request.Method = "GET";
        authorize.Request.Path = "/connect/authorize";
        authorize.Request.QueryString = new QueryString($"?client_id=x&request_uri={Uri.EscapeDataString(marked)}");
        authorize.Response.Body = new MemoryStream();
        // The tenant repository lookup needs the system context; this test stops at the query rewrite.
        authorize.RequestServices = ServicesWithoutTenants();
        await middleware.InvokeAsync(authorize);

        requestUriSeenByOpenIddict.Should().Be(requestUri, "OpenIddict only ever sees the value it issued");
    }

    [Fact]
    public async Task AuthorizeWithUnknownRequestUri_RedirectsToUnscopedDiscovery()
    {
        var middleware = new OidcTenantResolutionMiddleware(
            _ => Task.CompletedTask,
            NullLogger<OidcTenantResolutionMiddleware>.Instance,
            Options.Create(new OctoSystemConfiguration()));

        var authorize = new DefaultHttpContext();
        authorize.Request.Method = "GET";
        authorize.Request.Scheme = "https";
        authorize.Request.Host = new HostString("id.test");
        authorize.Request.Path = "/connect/authorize";
        authorize.Request.QueryString = new QueryString("?client_id=x&request_uri=urn%3Anever-pushed");
        authorize.Response.Body = new MemoryStream();
        await middleware.InvokeAsync(authorize);

        authorize.Response.StatusCode.Should().Be(StatusCodes.Status302Found);
        authorize.Response.Headers.Location.ToString().Should().NotContain("scopeTenantId=");
    }
}
