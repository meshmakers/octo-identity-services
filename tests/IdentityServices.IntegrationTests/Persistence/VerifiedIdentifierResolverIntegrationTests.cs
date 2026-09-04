using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     End-to-end checks of the verified external identifier directory (AB#5122) against a real
///     MongoDB (Testcontainers) with the full Octo runtime engine.
/// </summary>
/// <remarks>
///     <para>
///         The unit suite pins the trust arithmetic (<see cref="TrustLevels.Min" />) and the CK
///         defaults; what can only be proven here is the CK layer: the
///         <c>System.Identity/VerifiedExternalIdentifier</c> entity and its <c>IdentifiesUser</c>
///         edge introduced with System.Identity 2.15.0 really are writable and queryable, the
///         resolver combines the stored enrollment trust with the per-call message trust to the
///         effective minimum, the write side is additive + idempotent + rejects an unknown user, and
///         the (kind, value) uniqueness invariant holds.
///     </para>
///     <para>Users are created in-test so assertions do not depend on the blueprint seed.</para>
/// </remarks>
[Collection("Sequential")]
public class VerifiedIdentifierResolverIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public VerifiedIdentifierResolverIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task Resolve_PresentBinding_ReturnsUserAndEffectiveMinTrust()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, repo) = CreateResolver();

        var userRtId = await CreateUserAsync(repo);
        var value = NewValue("+4367612345");
        await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber, value, userRtId,
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.SelfService));

        // Strong enrollment, but the message only arrived Weak → effective = Weak.
        var resolution = await resolver.ResolveAsync(
            RtIdentifierKindEnum.PhoneNumber, value, RtTrustLevelEnum.Weak);

        resolution.Should().NotBeNull();
        resolution!.User.RtId.Should().Be(userRtId);
        resolution.EnrollmentTrust.Should().Be(RtTrustLevelEnum.Strong);
        resolution.MessageTrust.Should().Be(RtTrustLevelEnum.Weak);
        resolution.EffectiveTrust.Should().Be(RtTrustLevelEnum.Weak,
            "effective trust is the minimum of the enrollment and message dimensions");
    }

    [Fact]
    public async Task Resolve_AbsentBinding_ReturnsNull()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _) = CreateResolver();

        (await resolver.ResolveAsync(RtIdentifierKindEnum.EmailAddress, NewValue("ghost@x.io"),
                RtTrustLevelEnum.Strong))
            .Should().BeNull();
    }

    [Theory]
    // effective = min(enrollment, message) across the combinations.
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.Strong, RtTrustLevelEnum.Strong)]
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak)]
    [InlineData(RtTrustLevelEnum.Weak, RtTrustLevelEnum.Strong, RtTrustLevelEnum.Weak)]
    [InlineData(RtTrustLevelEnum.Strong, RtTrustLevelEnum.None, RtTrustLevelEnum.None)]
    [InlineData(RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak, RtTrustLevelEnum.Weak)]
    public async Task Resolve_EffectiveTrust_IsMinAcrossCombinations(
        RtTrustLevelEnum enrollment, RtTrustLevelEnum message, RtTrustLevelEnum expected)
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, repo) = CreateResolver();

        var userRtId = await CreateUserAsync(repo);
        var value = NewValue("oid");
        await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.EntraIdObjectId, value, userRtId,
            enrollment, RtIdentifierSourceEnum.IdentityProvider));

        var resolution = await resolver.ResolveAsync(
            RtIdentifierKindEnum.EntraIdObjectId, value, message);

        resolution.Should().NotBeNull();
        resolution!.EffectiveTrust.Should().Be(expected);
    }

    [Fact]
    public async Task Store_IsAdditive_AndIdempotent()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, repo) = CreateResolver();

        var userRtId = await CreateUserAsync(repo);
        var value = NewValue("dkim@x.io");
        var binding = new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.EmailAddress, value, userRtId,
            RtTrustLevelEnum.Weak, RtIdentifierSourceEnum.SelfService);

        var firstRtId = await resolver.StoreBindingAsync(binding);
        // Re-store with a raised enrollment trust: same single row, updated in place.
        var secondRtId = await resolver.StoreBindingAsync(binding with { EnrollmentTrust = RtTrustLevelEnum.Strong });

        secondRtId.Should().Be(firstRtId, "the (kind, value) upserts a single row — no duplicate");
        (await CountBindingsAsync(repo, value)).Should().Be(1);

        var resolution = await resolver.ResolveAsync(
            RtIdentifierKindEnum.EmailAddress, value, RtTrustLevelEnum.Strong);
        resolution!.EnrollmentTrust.Should().Be(RtTrustLevelEnum.Strong, "the update took effect");
    }

    [Fact]
    public async Task Store_UnknownUser_IsRejected()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, _) = CreateResolver();

        var act = async () => await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber, NewValue("+4300000"), OctoObjectId.GenerateNewId(),
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.Admin));

        await act.Should().ThrowAsync<NotExistingException>();
    }

    [Fact]
    public async Task Store_SameKindValue_RepointsToSingleUser_UniquenessHolds()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, repo) = CreateResolver();

        var userA = await CreateUserAsync(repo);
        var userB = await CreateUserAsync(repo);
        var value = NewValue("+4367699999");

        await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber, value, userA,
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.SelfService));
        // Same (kind, value), different user → the single row is re-pointed, not duplicated.
        await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber, value, userB,
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.Admin));

        (await CountBindingsAsync(repo, value)).Should().Be(1,
            "an (identifierKind, identifierValue) resolves to at most one user within a tenant");
        var resolution = await resolver.ResolveAsync(
            RtIdentifierKindEnum.PhoneNumber, value, RtTrustLevelEnum.Strong);
        resolution!.User.RtId.Should().Be(userB, "the binding now resolves to the re-pointed user");
    }

    [Fact]
    public async Task Remove_RemovesBinding_AndIsIdempotent()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();
        var (resolver, repo) = CreateResolver();

        var userRtId = await CreateUserAsync(repo);
        var value = NewValue("+4367688888");
        await resolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber, value, userRtId,
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.SelfService));

        (await resolver.RemoveBindingAsync(RtIdentifierKindEnum.PhoneNumber, value))
            .Should().BeTrue();
        (await resolver.ResolveAsync(RtIdentifierKindEnum.PhoneNumber, value, RtTrustLevelEnum.Strong))
            .Should().BeNull();
        // Idempotent: removing an absent binding is a no-op.
        (await resolver.RemoveBindingAsync(RtIdentifierKindEnum.PhoneNumber, value))
            .Should().BeFalse();
    }

    // ---------- helpers ----------

    private static string NewValue(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..24];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private (VerifiedIdentifierResolver resolver, ITenantRepository repo) CreateResolver()
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        var resolver = new VerifiedIdentifierResolver(
            new FixedTenantResolver(repo),
            NullLogger<VerifiedIdentifierResolver>.Instance);
        return (resolver, repo);
    }

    private static async Task<OctoObjectId> CreateUserAsync(ITenantRepository repo)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var userName = $"u{Guid.NewGuid():N}"[..16];
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@test.io",
            NormalizedEmail = $"{userName}@TEST.IO".ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private static async Task<int> CountBindingsAsync(ITenantRepository repo, string identifierValue)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var queryOptions = RtEntityQueryOptions.Create()
            .FieldEquals(nameof(RtVerifiedExternalIdentifier.IdentifierValue), identifierValue);
        var result = await repo
            .GetRtEntitiesByTypeAsync<RtVerifiedExternalIdentifier>(session, queryOptions);
        await session.CommitTransactionAsync();
        return result.Items.Count();
    }
}
