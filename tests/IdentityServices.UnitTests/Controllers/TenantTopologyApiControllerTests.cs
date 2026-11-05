using System.Reflection;
using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>AB#7044: status mapping, contract shape and the "no new exemption" guards of the controller.</summary>
public class TenantTopologyApiControllerTests
{
    private readonly ITenantTopologyService _service = Substitute.For<ITenantTopologyService>();
    private readonly ITenantTopologyRateLimiter _limiter = Substitute.For<ITenantTopologyRateLimiter>();

    public TenantTopologyApiControllerTests()
    {
        _limiter.TryAcquire(Arg.Any<string>()).Returns(true);
    }

    private TenantTopologyApiController Create(params Claim[] claims) =>
        new(_service, _limiter, NullLogger<TenantTopologyApiController>.Instance)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"))
                }
            }
        };

    private static Claim[] UserClaims(params string[] allowed) =>
        [new Claim("sub", "user-1"), .. allowed.Select(a => new Claim("allowed_tenants", a))];

    [Fact]
    public async Task UserToken_MapsTheServiceResultToTheContractShape()
    {
        _service.GetTopologyAsync("root", Arg.Any<IReadOnlyCollection<string>>()).Returns(
            new TenantTopologyResult("root", true,
                [new TenantTopologyEntry("group", 1, true), new TenantTopologyEntry("leaf", 2, false)]));

        var result = await Create(UserClaims("group", "leaf")).Get("root");

        var dto = result.Should().BeOfType<OkObjectResult>().Subject.Value.Should().BeOfType<TenantTopologyDto>().Subject;
        dto.Scope.Should().Be("root");
        dto.ScopeHasChildren.Should().BeTrue();
        dto.Tenants.Select(t => (t.TenantId, t.Depth, t.HasChildren))
            .Should().Equal(("group", 1, true), ("leaf", 2, false));
        await _service.Received(1).GetTopologyAsync("root",
            Arg.Is<IReadOnlyCollection<string>>(a => a.SequenceEqual(new[] { "group", "leaf" })));
    }

    [Fact]
    public async Task ClientCredentialsToken_WithoutSubject_Is403_AndNeverReadsTheHierarchy()
    {
        var result = await Create(new Claim("client_id", "svc"), new Claim("allowed_tenants", "x")).Get("root");

        result.Should().BeOfType<ForbidResult>();
        await _service.DidNotReceiveWithAnyArgs().GetTopologyAsync(default!, default!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task MissingScope_Is400(string? scope)
    {
        var result = await Create(UserClaims()).Get(scope);

        result.Should().BeOfType<ObjectResult>().Which.StatusCode.Should().Be(StatusCodes.Status400BadRequest);
    }

    [Theory]
    [InlineData("../etc")]
    [InlineData("a b")]
    [InlineData("$where")]
    public async Task ScopeThatCannotNameATenant_IsAnUnknownScope_NotAnError_AndNeverHitsTheService(string scope)
    {
        var result = await Create(UserClaims("x")).Get(scope);

        var dto = result.Should().BeOfType<OkObjectResult>().Subject.Value.Should().BeOfType<TenantTopologyDto>().Subject;
        dto.ScopeHasChildren.Should().BeFalse();
        dto.Tenants.Should().BeEmpty();
        await _service.DidNotReceiveWithAnyArgs().GetTopologyAsync(default!, default!);
    }

    [Fact]
    public async Task UnreadableHierarchy_Is503_WithoutAPartialList()
    {
        _service.GetTopologyAsync("root", Arg.Any<IReadOnlyCollection<string>>())
            .Returns<Task<TenantTopologyResult>>(_ => throw new TenantHierarchyUnreadableException("boom"));

        var result = await Create(UserClaims("a")).Get("root");

        var objectResult = result.Should().BeOfType<ObjectResult>().Subject;
        objectResult.StatusCode.Should().Be(StatusCodes.Status503ServiceUnavailable);
        objectResult.Value.Should().BeOfType<ProblemDetails>().Which.Title.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task ExhaustedRateLimit_Is429_WithRetryAfter_AndNeverReadsTheHierarchy()
    {
        _limiter.TryAcquire("user-1").Returns(false);
        var controller = Create(UserClaims("a"));

        var result = await controller.Get("root");

        result.Should().BeOfType<StatusCodeResult>().Which.StatusCode.Should().Be(StatusCodes.Status429TooManyRequests);
        controller.Response.Headers.RetryAfter.ToString().Should().Be("60");
        await _service.DidNotReceiveWithAnyArgs().GetTopologyAsync(default!, default!);
    }

    [Fact]
    public void Route_HasNoTenantSegment_AndIsGuardedByTheReadOnlyPolicy_WithoutAnyExemptionMarker()
    {
        var type = typeof(TenantTopologyApiController);

        type.GetCustomAttribute<RouteAttribute>()!.Template.Should().Be("api/tenant-topology")
            .And.NotContain("{", "a tenant segment would put the route under the user-token tenant gate");
        type.GetCustomAttribute<AuthorizeAttribute>()!.Policy.Should().Be("IdentityApiReadOnlyPolicy");
        type.GetMethod(nameof(TenantTopologyApiController.Get))!.GetCustomAttributes()
            .Should().NotContain(a => a.GetType().Name.Contains("AllowAnonymous") || a is IAllowParentTenantAdministration);
        type.GetCustomAttributes().Should().NotContain(a => a is IAllowParentTenantAdministration);
    }
}

public class TenantTopologyRateLimiterTests
{
    private static TenantTopologyRateLimiter Create(int permits) => new(Options.Create(
        new OctoIdentityServicesOptions { TenantTopology = { RateLimitPermitsPerMinute = permits } }));

    [Fact]
    public void LimitsPerSubject_AndOneSubjectDoesNotUseUpAnothers()
    {
        using var limiter = Create(2);

        limiter.TryAcquire("alice").Should().BeTrue();
        limiter.TryAcquire("alice").Should().BeTrue();
        limiter.TryAcquire("alice").Should().BeFalse();
        limiter.TryAcquire("bob").Should().BeTrue();
    }

    [Fact]
    public void ANonPositiveConfiguration_StillAllowsOneRequest_InsteadOfLockingEveryoneOut()
    {
        using var limiter = Create(0);

        limiter.TryAcquire("alice").Should().BeTrue();
        limiter.TryAcquire("alice").Should().BeFalse();
    }
}
