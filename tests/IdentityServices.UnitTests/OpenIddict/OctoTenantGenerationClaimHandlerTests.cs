using System.Security.Claims;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.TenantLifecycle;
using Microsoft.Extensions.Logging;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace IdentityServices.UnitTests.OpenIddict;

/// <summary>
///     AB#8997: <c>tenant_gen</c> on every access token — value and precision, every grant type (incl. the RFC 8693
///     issued-token path), access token only, re-read on refresh, no claim without a generation, refusal before
///     redemption when the lifecycle store fails, one read per token request. <see cref="RunSignInAsync" /> runs the
///     three handlers the way OpenIddict's dispatcher does: in descriptor order, each only when its filter holds;
///     <see cref="TheHandlers_SitWhereOpenIddictRunsThem_WithTheirFilters" /> pins that order against OpenIddict.
/// </summary>
public class OctoTenantGenerationClaimHandlerTests
{
    private const string TenantId = "scratch-8997";

    // 2025-11-15T08:00:00.123Z plus 4,567 ticks (0.4567 ms) below the millisecond.
    private static readonly DateTime CreatedWithSubMilliseconds =
        new DateTime(2025, 11, 15, 8, 0, 0, 123, DateTimeKind.Utc).AddTicks(4_567);

    private const string CreatedMilliseconds = "1763193600123";

    private readonly ITenantLifecycleStore _store = Substitute.For<ITenantLifecycleStore>();
    private readonly CapturingLoggerProvider _logs = new();

    // --- value and precision -------------------------------------------------------------------------------------

    [Fact]
    public void FormatGeneration_TruncatesSubMillisecondTicks()
    {
        OctoTenantGenerationClaimHandler.FormatGeneration(CreatedWithSubMilliseconds).Should().Be(CreatedMilliseconds);
    }

    [Fact]
    public void FormatGeneration_NeverRoundsUp()
    {
        var almostNextMillisecond = new DateTime(2025, 11, 15, 8, 0, 0, 123, DateTimeKind.Utc).AddTicks(9_999);

        OctoTenantGenerationClaimHandler.FormatGeneration(almostNextMillisecond).Should().Be(CreatedMilliseconds);
    }

    [Fact]
    public void FormatGeneration_UnspecifiedKind_IsTakenAsUtc()
    {
        var unspecified = DateTime.SpecifyKind(CreatedWithSubMilliseconds, DateTimeKind.Unspecified);

        OctoTenantGenerationClaimHandler.FormatGeneration(unspecified).Should().Be(CreatedMilliseconds);
    }

    [Fact]
    public void FormatGeneration_LocalKind_IsConvertedToUtc()
    {
        var local = CreatedWithSubMilliseconds.ToLocalTime();
        local.Kind.Should().Be(DateTimeKind.Local);

        OctoTenantGenerationClaimHandler.FormatGeneration(local).Should().Be(CreatedMilliseconds);
    }

    [Fact]
    public void FormatGeneration_IsCultureInvariant()
    {
        var previous = Thread.CurrentThread.CurrentCulture;
        try
        {
            foreach (var culture in new[] { "de-DE", "ar-SA", "fa-IR", "hi-IN" })
            {
                Thread.CurrentThread.CurrentCulture = new System.Globalization.CultureInfo(culture);
                OctoTenantGenerationClaimHandler.FormatGeneration(CreatedWithSubMilliseconds)
                    .Should().Be(CreatedMilliseconds, "culture {0} must not change the value", culture);
            }
        }
        finally
        {
            Thread.CurrentThread.CurrentCulture = previous;
        }
    }

    [Fact]
    public void FormatGeneration_DefaultCreatedUtc_IsNoGeneration()
    {
        OctoTenantGenerationClaimHandler.FormatGeneration(default).Should().BeNull();
    }

    // --- handler placement --------------------------------------------------------------------------------------

    [Fact]
    public void TheHandlers_SitWhereOpenIddictRunsThem_WithTheirFilters()
    {
        var lookup = OctoTenantGenerationClaimHandler.Lookup.Descriptor;
        var access = OctoTenantGenerationClaimHandler.StampAccessToken.Descriptor;
        var issued = OctoTenantGenerationClaimHandler.StampIssuedToken.Descriptor;

        // The read happens before any code / device code / refresh token is redeemed (CodeRabbit, PR #304).
        lookup.Order.Should().BeGreaterThan(OpenIddictServerHandlers.ValidateSignInDemand.Descriptor.Order);
        lookup.Order.Should().BeLessThan(OpenIddictServerHandlers.RedeemTokenEntry.Descriptor.Order);
        lookup.FilterTypes.Should().BeEmpty("the token-endpoint check is inside the handler");

        access.Order.Should().BeGreaterThan(OpenIddictServerHandlers.PrepareAccessTokenPrincipal.Descriptor.Order);
        access.Order.Should().BeLessThan(OpenIddictServerHandlers.PrepareAuthorizationCodePrincipal.Descriptor.Order);
        access.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateAccessToken.Descriptor.Order);
        access.FilterTypes.Should().Equal(typeof(OpenIddictServerHandlerFilters.RequireAccessTokenGenerated));

        // RFC 8693: OpenIddict issues the exchanged access token as the "issued token" (GenerateAccessToken=false).
        issued.Order.Should().BeGreaterThan(OpenIddictServerHandlers.PrepareIssuedTokenPrincipal.Descriptor.Order);
        // OpenIddict 7.6 gives PrepareIssuedTokenPrincipal and PrepareRequestTokenPrincipal the same order, so the
        // stamp runs after both; it only has to run before the next principal and the token generation.
        issued.Order.Should().BeLessThan(OpenIddictServerHandlers.PrepareRefreshTokenPrincipal.Descriptor.Order);
        issued.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateIssuedToken.Descriptor.Order);
        issued.FilterTypes.Should().Equal(typeof(OpenIddictServerHandlerFilters.RequireIssuedTokenGenerated));

        OctoTenantGenerationClaimHandler.Descriptors.Should().Equal(lookup, access, issued);
    }

    // --- claim on every grant -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.DeviceCode)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(DelegationConstants.OnBehalfOfGrantType)]
    [InlineData(ImpersonationConstants.ImpersonationGrantType)]
    public async Task EveryAccessTokenGrant_GetsTheGenerationOfTheTokenTenant_WithOneRead(string grantType)
    {
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(grantType, TenantId);

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TokenExchange_IssuedAccessToken_GetsTheGenerationOfTheTargetTenant_WithOneRead()
    {
        ArrangeRecord("child-8997", CreatedWithSubMilliseconds);
        var context = TokenExchangeSignIn("child-8997", TokenTypeIdentifiers.AccessToken);

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse();
        context.AccessTokenPrincipal.Should().BeNull("OpenIddict generates no regular access token for an exchange");
        GenerationClaims(context.IssuedTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        context.IssuedTokenPrincipal!.FindFirst(OctoClaimTypes.TenantGeneration)!.GetDestinations()
            .Should().Equal(Destinations.AccessToken);
        await _store.Received(1).GetAsync("child-8997", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TokenExchange_IssuedRefreshToken_GetsNoClaim_AndCostsNoRead()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new TimeoutException("must not be called"));
        var context = TokenExchangeSignIn(TenantId, TokenTypeIdentifiers.RefreshToken);
        context.Transaction.Request!.RequestedTokenType = TokenTypeIdentifiers.RefreshToken;

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse("an exchange that issues no access token must not fail on the lifecycle store");
        GenerationClaims(context.IssuedTokenPrincipal!).Should().BeEmpty();
        await _store.DidNotReceiveWithAnyArgs().GetAsync(default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task CrossTenantLogin_GetsTheGenerationOfTheChildTenantInTenantId()
    {
        // Cross-tenant login: an authorization-code token whose tenant_id is the child tenant; the home tenant of the
        // user is only named in home_tenant_id and must not be looked up.
        ArrangeRecord("child-8997", CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(GrantTypes.AuthorizationCode, "child-8997");
        context.Principal!.SetClaim(OctoClaimTypes.HomeTenantId, "parent-8997");
        context.AccessTokenPrincipal!.SetClaim(OctoClaimTypes.HomeTenantId, "parent-8997");

        await RunSignInAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.DidNotReceive().GetAsync("parent-8997", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheTenantId_IsLookedUpInItsStoredForm()
    {
        ArrangeRecord("scratch-8997", CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(GrantTypes.ClientCredentials, " Scratch-8997 ");

        await RunSignInAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.Received(1).GetAsync("scratch-8997", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task OutsideTheTokenEndpoint_NothingIsRead()
    {
        // The authorization endpoint issues an authorization code, no access token.
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(GrantTypes.AuthorizationCode, TenantId,
            OpenIddictServerEndpointType.Authorization);
        context.GenerateAccessToken = false;

        await RunSignInAsync(context);

        await _store.DidNotReceiveWithAnyArgs().GetAsync(default!, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task WithoutAnEarlyLookup_TheStampReadsItself()
    {
        // Safety net for an access token issued outside the token endpoint (none today).
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(GrantTypes.AuthorizationCode, TenantId,
            OpenIddictServerEndpointType.Authorization);

        await RunSignInAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    // --- access token only -----------------------------------------------------------------------------------------

    [Fact]
    public async Task TheClaim_HasTheAccessTokenDestinationOnly_AndNeverReachesOtherPrincipals()
    {
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = AccessTokenSignIn(GrantTypes.AuthorizationCode, TenantId);
        context.IdentityTokenPrincipal = CreatePrincipal(TenantId);
        context.RefreshTokenPrincipal = CreatePrincipal(TenantId);

        await RunSignInAsync(context);

        var claim = context.AccessTokenPrincipal!.FindFirst(OctoClaimTypes.TenantGeneration)!;
        claim.GetDestinations().Should().Equal(Destinations.AccessToken);
        claim.ValueType.Should().Be(ClaimValueTypes.String, "the value is a decimal string, not a JSON number");
        GenerationClaims(context.IdentityTokenPrincipal).Should().BeEmpty();
        GenerationClaims(context.RefreshTokenPrincipal).Should().BeEmpty();
        GenerationClaims(context.Principal!).Should().BeEmpty("the sign-in principal feeds the stored code/refresh token");
    }

    [Fact]
    public void TheDestinationPolicy_SendsTenantGenToTheAccessTokenOnly()
    {
        var claim = new Claim(OctoClaimTypes.TenantGeneration, CreatedMilliseconds);

        OctoClaimsDestinations.Resolve(claim).Should().Equal(Destinations.AccessToken);
        OctoClaimsDestinations.ForClient(true)(claim).Should().Equal([Destinations.AccessToken],
            "AlwaysIncludeUserClaimsInIdToken must not put the generation into the id token");
    }

    // --- refresh re-stamps ----------------------------------------------------------------------------------------

    [Fact]
    public async Task Refresh_ReadsTheGenerationAgain_AndNeverKeepsACopiedValue()
    {
        var newGeneration = new DateTime(2026, 11, 15, 9, 30, 0, 456, DateTimeKind.Utc);
        ArrangeRecord(TenantId, newGeneration);
        var context = AccessTokenSignIn(GrantTypes.RefreshToken, TenantId);
        // A value copied from an earlier principal (e.g. the stored refresh-token principal) must not survive.
        context.AccessTokenPrincipal!.AddClaim(OctoClaimTypes.TenantGeneration, "1");

        await RunSignInAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should()
            .Equal(OctoTenantGenerationClaimHandler.FormatGeneration(newGeneration));
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    // --- no generation → no claim ---------------------------------------------------------------------------------

    [Fact]
    public async Task NoLifecycleRecord_NoClaim_AndIssuanceSucceeds()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).Returns((TenantLifecycleRecord?)null);
        var context = AccessTokenSignIn(GrantTypes.ClientCredentials, TenantId);

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RecordWithoutCreatedUtc_NoClaim_AndIssuanceSucceeds()
    {
        ArrangeRecord(TenantId, default);
        var context = AccessTokenSignIn(GrantTypes.AuthorizationCode, TenantId);

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
    }

    [Fact]
    public async Task NoRecordAndAStaleCopiedValue_LeavesNoClaim()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).Returns((TenantLifecycleRecord?)null);
        var context = AccessTokenSignIn(GrantTypes.RefreshToken, TenantId);
        context.AccessTokenPrincipal!.AddClaim(OctoClaimTypes.TenantGeneration, "1");

        await RunSignInAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
    }

    [Fact]
    public async Task TokenWithoutTenantId_IsNotLookedUp_AndGetsNoClaim()
    {
        var context = AccessTokenSignIn(GrantTypes.ClientCredentials, tenantId: null);

        await RunSignInAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
        await _store.DidNotReceiveWithAnyArgs().GetAsync(default!, TestContext.Current.CancellationToken);
    }

    // --- lookup failure -------------------------------------------------------------------------------------------

    [Fact]
    public async Task StoreFailure_RejectsWithServerError_BeforeRedemption_AndLogsNoTokenValue()
    {
        const string tokenCanary = "eyJ-canary-token-8997";
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new TimeoutException("server selection timed out"));
        var context = AccessTokenSignIn(GrantTypes.RefreshToken, TenantId);
        context.Transaction.Request!.AccessToken = tokenCanary;
        context.Transaction.Request.RefreshToken = tokenCanary;

        var lookupRejected = await RunSignInAsync(context);

        lookupRejected.Should().BeTrue("the refusal must come from the phase that runs before RedeemTokenEntry");
        context.IsRejected.Should().BeTrue();
        context.Error.Should().Be(Errors.ServerError);
        context.ErrorDescription.Should().NotContain(TenantId);
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();

        var entry = _logs.Entries.Should().ContainSingle(e => e.Level == LogLevel.Error).Subject;
        entry.Message.Should().Contain(TenantId).And.Contain(nameof(TimeoutException));
        entry.Message.Should().NotContain(tokenCanary);
    }

    [Fact]
    public async Task CancelledRequest_IsNotTurnedIntoAServerError()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException(cts.Token));
        var context = AccessTokenSignIn(GrantTypes.ClientCredentials, TenantId, cancellationToken: cts.Token);

        var act = () => RunSignInAsync(context);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // --- helpers --------------------------------------------------------------------------------------------------

    /// <summary>
    ///     Runs the three handlers like the dispatcher: descriptor order, filters evaluated, stop after a rejection.
    ///     Returns whether the early lookup (the phase before <c>RedeemTokenEntry</c>) rejected the request.
    /// </summary>
    private async Task<bool> RunSignInAsync(ProcessSignInContext context)
    {
        await new OctoTenantGenerationClaimHandler.Lookup(_store,
                _logs.CreateLogger<OctoTenantGenerationClaimHandler.Lookup>())
            .HandleAsync(context);
        if (context.IsRejected)
        {
            return true;
        }

        if (context.GenerateAccessToken)
        {
            await new OctoTenantGenerationClaimHandler.StampAccessToken(_store,
                    _logs.CreateLogger<OctoTenantGenerationClaimHandler.StampAccessToken>())
                .HandleAsync(context);
        }

        if (!context.IsRejected && context.GenerateIssuedToken)
        {
            await new OctoTenantGenerationClaimHandler.StampIssuedToken(_store,
                    _logs.CreateLogger<OctoTenantGenerationClaimHandler.StampIssuedToken>())
                .HandleAsync(context);
        }

        return false;
    }

    private void ArrangeRecord(string tenantId, DateTime createdUtc) =>
        _store.GetAsync(tenantId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleRecord { TenantId = tenantId, CreatedUtc = createdUtc });

    private static ProcessSignInContext AccessTokenSignIn(string grantType, string? tenantId,
        OpenIddictServerEndpointType endpoint = OpenIddictServerEndpointType.Token,
        CancellationToken? cancellationToken = null)
    {
        var context = CreateContext(grantType, endpoint, cancellationToken);
        context.Principal = CreatePrincipal(tenantId);
        context.GenerateAccessToken = true;
        context.AccessTokenPrincipal = CreatePrincipal(tenantId);
        return context;
    }

    private static ProcessSignInContext TokenExchangeSignIn(string tenantId, string issuedTokenType)
    {
        var context = CreateContext(GrantTypes.TokenExchange, OpenIddictServerEndpointType.Token, null);
        context.Principal = CreatePrincipal(tenantId);
        context.GenerateAccessToken = false;
        context.GenerateIssuedToken = true;
        context.IssuedTokenType = issuedTokenType;
        context.IssuedTokenPrincipal = CreatePrincipal(tenantId);
        return context;
    }

    private static ProcessSignInContext CreateContext(string grantType, OpenIddictServerEndpointType endpoint,
        CancellationToken? cancellationToken)
    {
        var transaction = new OpenIddictServerTransaction
        {
            Request = new OpenIddictRequest { GrantType = grantType },
            EndpointType = endpoint,
            CancellationToken = cancellationToken ?? TestContext.Current.CancellationToken
        };
        return new ProcessSignInContext(transaction);
    }

    private static ClaimsPrincipal CreatePrincipal(string? tenantId)
    {
        var identity = new ClaimsIdentity("test", Claims.Name, Claims.Role);
        identity.AddClaim(new Claim(Claims.Subject, "subject-8997"));
        if (tenantId != null)
        {
            identity.AddClaim(new Claim(OctoClaimTypes.TenantId, tenantId));
        }

        return new ClaimsPrincipal(identity);
    }

    private static IEnumerable<string> GenerationClaims(ClaimsPrincipal principal) =>
        principal.FindAll(OctoClaimTypes.TenantGeneration).Select(c => c.Value);

    private sealed class CapturingLoggerProvider
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public ILogger<T> CreateLogger<T>() => new Logger<T>(this);

        private sealed class Logger<T>(CapturingLoggerProvider owner) : ILogger<T>
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                owner.Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
