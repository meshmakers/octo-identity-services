using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Cookies;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace IdentityServices.UnitTests.Cookies;

public class TenantCookieManagerTests
{
    [Theory]
    [InlineData(".AspNetCore.Identity.Application")]
    [InlineData("idsrv")]
    [InlineData("idsrv.session")]
    public void ResolveScopedKey_WithTenantAndScopedCookie_AppendsTenantSuffix(string cookieName)
    {
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";

        var result = TenantCookieManager.ResolveScopedKey(context, cookieName);

        result.Should().Be($"{cookieName}.sbeg");
    }

    [Theory]
    [InlineData(".AspNetCore.Identity.External")]
    [InlineData(".AspNetCore.Identity.TwoFactorUserId")]
    [InlineData(".AspNetCore.Identity.TwoFactorRememberMe")]
    [InlineData("some-other-cookie")]
    public void ResolveScopedKey_WithUnscopedCookie_ReturnsOriginalKey(string cookieName)
    {
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";

        var result = TenantCookieManager.ResolveScopedKey(context, cookieName);

        result.Should().Be(cookieName);
    }

    [Fact]
    public void ResolveScopedKey_WithNoTenant_ReturnsOriginalKey()
    {
        var context = new DefaultHttpContext();
        // No tenant set in Items

        var result = TenantCookieManager.ResolveScopedKey(context, ".AspNetCore.Identity.Application");

        result.Should().Be(".AspNetCore.Identity.Application");
    }

    [Fact]
    public void ResolveScopedKey_WithEmptyTenant_ReturnsOriginalKey()
    {
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "";

        var result = TenantCookieManager.ResolveScopedKey(context, ".AspNetCore.Identity.Application");

        result.Should().Be(".AspNetCore.Identity.Application");
    }

    [Fact]
    public void ResolveScopedKey_NormalizesTenantToLowerCase()
    {
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "SBeg";

        var result = TenantCookieManager.ResolveScopedKey(context, ".AspNetCore.Identity.Application");

        result.Should().Be(".AspNetCore.Identity.Application.sbeg");
    }

    [Fact]
    public void ResolveScopedKey_CaseInsensitiveCookieNameMatch()
    {
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";

        // The HashSet uses OrdinalIgnoreCase
        var result = TenantCookieManager.ResolveScopedKey(context, "IDSRV");

        result.Should().Be("IDSRV.sbeg");
    }

    [Fact]
    public void GetRequestCookie_ReadsFromScopedCookieName()
    {
        var manager = new TenantCookieManager();
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";
        context.Request.Headers.Append("Cookie", ".AspNetCore.Identity.Application.sbeg=test-value");

        var result = manager.GetRequestCookie(context, ".AspNetCore.Identity.Application");

        result.Should().Be("test-value");
    }

    [Fact]
    public void GetRequestCookie_DoesNotReadUnscopedCookieWhenTenantSet()
    {
        var manager = new TenantCookieManager();
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";
        // Only the unscoped cookie is present
        context.Request.Headers.Append("Cookie", ".AspNetCore.Identity.Application=old-global-value");

        var result = manager.GetRequestCookie(context, ".AspNetCore.Identity.Application");

        result.Should().BeNull();
    }

    [Fact]
    public void AppendResponseCookie_WritesScopedCookieName()
    {
        var manager = new TenantCookieManager();
        var context = new DefaultHttpContext();
        context.Items[InfrastructureCommon.TenantIdName] = "sbeg";

        manager.AppendResponseCookie(context, ".AspNetCore.Identity.Application", "value",
            new CookieOptions());

        var setCookieHeader = context.Response.Headers.SetCookie.ToString();
        setCookieHeader.Should().Contain(".AspNetCore.Identity.Application.sbeg=");
    }
}
