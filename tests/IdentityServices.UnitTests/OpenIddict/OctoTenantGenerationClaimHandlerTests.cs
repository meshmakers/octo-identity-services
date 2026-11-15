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
///     AB#8997: <c>tenant_gen</c> on every access token — value and precision, every grant type, access token only,
///     re-read on refresh, no claim without a generation, refusal when the lifecycle store fails, one read per issuance.
/// </summary>
public class OctoTenantGenerationClaimHandlerTests
{
    private const string TenantId = "scratch-8997";

    // 2025-11-15T08:00:00.123Z plus 4,567 ticks (0.4567 ms) below the millisecond.
    private static readonly DateTime CreatedWithSubMilliseconds =
        new DateTime(2025, 11, 15, 8, 0, 0, 123, DateTimeKind.Utc).AddTicks(4_567);

    private const string CreatedMilliseconds = "1763193600123";

    private readonly ITenantLifecycleStore _store = Substitute.For<ITenantLifecycleStore>();
    private readonly CapturingLogger _logger = new();

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
            // ar-SA uses Arabic-Indic digits for some formats and de-DE group separators; neither may appear.
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

    // --- claim on every grant -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.DeviceCode)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.TokenExchange)]
    [InlineData(DelegationConstants.OnBehalfOfGrantType)]
    [InlineData(ImpersonationConstants.ImpersonationGrantType)]
    public async Task EveryGrant_GetsTheGenerationOfTheTokenTenant(string grantType)
    {
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = CreateContext(grantType, TenantId);

        await CreateHandler().HandleAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CrossTenantLogin_GetsTheGenerationOfTheChildTenantInTenantId()
    {
        // Cross-tenant login: an authorization-code token whose tenant_id is the child tenant; the home tenant
        // of the user is only named in home_tenant_id and must not be looked up.
        ArrangeRecord("child-8997", CreatedWithSubMilliseconds);
        var context = CreateContext(GrantTypes.AuthorizationCode, "child-8997");
        context.AccessTokenPrincipal!.SetClaim(OctoClaimTypes.HomeTenantId, "parent-8997");

        await CreateHandler().HandleAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
        await _store.DidNotReceive().GetAsync("parent-8997", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheTenantId_IsLookedUpInItsStoredForm()
    {
        ArrangeRecord("scratch-8997", CreatedWithSubMilliseconds);
        var context = CreateContext(GrantTypes.ClientCredentials, " Scratch-8997 ");

        await CreateHandler().HandleAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().Equal(CreatedMilliseconds);
    }

    // --- access token only -----------------------------------------------------------------------------------------

    [Fact]
    public async Task TheClaim_HasTheAccessTokenDestinationOnly_AndNeverReachesTheIdentityToken()
    {
        ArrangeRecord(TenantId, CreatedWithSubMilliseconds);
        var context = CreateContext(GrantTypes.AuthorizationCode, TenantId);
        context.IdentityTokenPrincipal = CreatePrincipal(TenantId);

        await CreateHandler().HandleAsync(context);

        var claim = context.AccessTokenPrincipal!.FindFirst(OctoClaimTypes.TenantGeneration)!;
        claim.GetDestinations().Should().Equal(Destinations.AccessToken);
        claim.ValueType.Should().Be(ClaimValueTypes.String, "the value is a decimal string, not a JSON number");
        GenerationClaims(context.IdentityTokenPrincipal).Should().BeEmpty();
    }

    [Fact]
    public void TheDestinationPolicy_SendsTenantGenToTheAccessTokenOnly()
    {
        var claim = new Claim(OctoClaimTypes.TenantGeneration, CreatedMilliseconds);

        OctoClaimsDestinations.Resolve(claim).Should().Equal(Destinations.AccessToken);
        OctoClaimsDestinations.ForClient(true)(claim).Should().Equal([Destinations.AccessToken],
            "AlwaysIncludeUserClaimsInIdToken must not put the generation into the id token");
    }

    [Fact]
    public void TheHandler_RunsOnlyWhenAnAccessTokenIsGenerated_BetweenPrincipalPreparationAndTokenGeneration()
    {
        var descriptor = OctoTenantGenerationClaimHandler.Descriptor;

        descriptor.FilterTypes.Should().Contain(typeof(OpenIddictServerHandlerFilters.RequireAccessTokenGenerated));
        descriptor.Order.Should().BeGreaterThan(OpenIddictServerHandlers.PrepareAccessTokenPrincipal.Descriptor.Order);
        descriptor.Order.Should().BeLessThan(OpenIddictServerHandlers.GenerateAccessToken.Descriptor.Order);
    }

    // --- refresh re-stamps ----------------------------------------------------------------------------------------

    [Fact]
    public async Task Refresh_ReadsTheGenerationAgain_AndNeverKeepsACopiedValue()
    {
        var newGeneration = new DateTime(2026, 11, 15, 9, 30, 0, 456, DateTimeKind.Utc);
        ArrangeRecord(TenantId, newGeneration);
        var context = CreateContext(GrantTypes.RefreshToken, TenantId);
        // A value copied from an earlier principal (e.g. the stored refresh-token principal) must not survive.
        context.AccessTokenPrincipal!.AddClaim(OctoClaimTypes.TenantGeneration, "1");

        await CreateHandler().HandleAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should()
            .Equal(OctoTenantGenerationClaimHandler.FormatGeneration(newGeneration));
        await _store.Received(1).GetAsync(TenantId, Arg.Any<CancellationToken>());
    }

    // --- no generation → no claim ---------------------------------------------------------------------------------

    [Fact]
    public async Task NoLifecycleRecord_NoClaim_AndIssuanceSucceeds()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).Returns((TenantLifecycleRecord?)null);
        var context = CreateContext(GrantTypes.ClientCredentials, TenantId);

        await CreateHandler().HandleAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
    }

    [Fact]
    public async Task RecordWithoutCreatedUtc_NoClaim_AndIssuanceSucceeds()
    {
        ArrangeRecord(TenantId, default);
        var context = CreateContext(GrantTypes.AuthorizationCode, TenantId);

        await CreateHandler().HandleAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
    }

    [Fact]
    public async Task NoRecordAndAStaleCopiedValue_LeavesNoClaim()
    {
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>()).Returns((TenantLifecycleRecord?)null);
        var context = CreateContext(GrantTypes.RefreshToken, TenantId);
        context.AccessTokenPrincipal!.AddClaim(OctoClaimTypes.TenantGeneration, "1");

        await CreateHandler().HandleAsync(context);

        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
    }

    [Fact]
    public async Task TokenWithoutTenantId_IsNotLookedUp_AndGetsNoClaim()
    {
        var context = CreateContext(GrantTypes.ClientCredentials, tenantId: null);

        await CreateHandler().HandleAsync(context);

        context.IsRejected.Should().BeFalse();
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();
        await _store.DidNotReceiveWithAnyArgs().GetAsync(default!, TestContext.Current.CancellationToken);
    }

    // --- lookup failure -------------------------------------------------------------------------------------------

    [Fact]
    public async Task StoreFailure_RejectsWithServerError_AndLogsNoTokenValue()
    {
        const string accessTokenCanary = "eyJ-canary-access-token-8997";
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new TimeoutException("server selection timed out"));
        var context = CreateContext(GrantTypes.ClientCredentials, TenantId);
        context.Transaction.Request!.AccessToken = accessTokenCanary;

        await CreateHandler().HandleAsync(context);

        context.IsRejected.Should().BeTrue();
        context.Error.Should().Be(Errors.ServerError);
        context.ErrorDescription.Should().NotContain(TenantId);
        GenerationClaims(context.AccessTokenPrincipal!).Should().BeEmpty();

        _logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Error);
        var entry = _logger.Entries.Single();
        entry.Message.Should().Contain(TenantId).And.Contain(nameof(TimeoutException));
        entry.Message.Should().NotContain(accessTokenCanary);
    }

    [Fact]
    public async Task CancelledRequest_IsNotTurnedIntoAServerError()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        _store.GetAsync(TenantId, Arg.Any<CancellationToken>())
            .ThrowsAsync(new OperationCanceledException(cts.Token));
        var context = CreateContextWithToken(GrantTypes.ClientCredentials, TenantId, cts.Token);

        var act = () => CreateHandler().HandleAsync(context).AsTask();

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    // --- helpers --------------------------------------------------------------------------------------------------

    private OctoTenantGenerationClaimHandler CreateHandler() => new(_store, _logger);

    private void ArrangeRecord(string tenantId, DateTime createdUtc) =>
        _store.GetAsync(tenantId, Arg.Any<CancellationToken>())
            .Returns(new TenantLifecycleRecord { TenantId = tenantId, CreatedUtc = createdUtc });

    private static ProcessSignInContext CreateContext(string grantType, string? tenantId) =>
        CreateContextWithToken(grantType, tenantId, TestContext.Current.CancellationToken);

    private static ProcessSignInContext CreateContextWithToken(string grantType, string? tenantId,
        CancellationToken cancellationToken)
    {
        var transaction = new OpenIddictServerTransaction
        {
            Request = new OpenIddictRequest { GrantType = grantType },
            CancellationToken = cancellationToken
        };
        return new ProcessSignInContext(transaction)
        {
            AccessTokenPrincipal = CreatePrincipal(tenantId)
        };
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

    private sealed class CapturingLogger : ILogger<OctoTenantGenerationClaimHandler>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
