using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     End-to-end checks of the cross-tenant RFC 8693 token-exchange role resolution (AB#4338)
///     against a real MongoDB (Testcontainers) with the full Octo runtime engine. These pin the
///     <b>security linchpin</b> of <c>TenantExchangeProcessor</c>: the token minted for the
///     home-tenant (A) user runs on the <b>B-shadow user's</b> subject and therefore carries the
///     roles re-resolved <b>in B</b> — the subset granted by the child's
///     <c>RtExternalTenantUserMapping</c>, <b>not</b> A's full role set.
/// </summary>
/// <remarks>
///     The integration fixture is service/store level (no HTTP host), so — like the sibling
///     <c>ClientRoleAssignmentIntegrationTests</c> / <c>ClientMirrorProvisioningIntegrationTests</c>
///     — these tests drive the exact services the validator composes:
///     <see cref="CrossTenantAuthenticationService.ValidateCrossTenantAccessAsync" /> (the B-auth
///     gate) and <see cref="CrossTenantUserProvisioningService.FindOrCreateCrossTenantUserAsync" />
///     (the B-shadow user), then read the shadow user's effective roles through
///     <see cref="OctoUserStore.GetRolesAsync" /> — the same store that produces the token's
///     <c>role</c> claims — wired to the B tenant repository. This is the precise chain the grant
///     validator relies on; only the <c>subject_token</c> validation and
///     principal construction of <c>TenantExchangeProcessor</c> (unit
///     behaviour) are out of scope here.
/// </remarks>
public class TenantExchangeIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public TenantExchangeIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    /// <summary>
    ///     THE load-bearing privilege-escalation regression. A user in parent tenant A holds roles
    ///     rA1 + rA2. Child tenant B has a mapping granting the user only the B-side subset rB1.
    ///     After exchange, the B-shadow user's resolved roles must be exactly {rB1} — never A's full
    ///     set — because the token runs on the B-shadow sub with B-resolved roles.
    /// </summary>
    [Fact]
    public async Task Exchange_ResolvesBSubsetRoles_NotParentFullRoles()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;

        // Parent user in A with two roles.
        var (parentUserId, parentUserName) = await CreateUserAsync(
            systemContext, parentTenantId, "alice");
        var rA1 = await CreateRoleAsync(systemContext, parentTenantId, NewId("rA1"));
        var rA2 = await CreateRoleAsync(systemContext, parentTenantId, NewId("rA2"));
        await AssignRoleToUserAsync(systemContext, parentTenantId, parentUserId, rA1);
        await AssignRoleToUserAsync(systemContext, parentTenantId, parentUserId, rA2);

        // Child tenant B with A as parent, and a mapping granting ONLY the B subset (one role).
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var rB1 = await CreateRoleAsync(systemContext, childTenantId, NewId("rB1"));
        // A B-only role the user is NOT mapped to — must never appear in the exchanged token.
        await CreateRoleAsync(systemContext, childTenantId, NewId("rB2unmapped"));
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, parentUserId, parentUserName,
            mappedRoleIds: [rB1.ToString()]);

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var provisioning = CreateProvisioningService(childRepo);

        // B-auth gate: A must be an ancestor of B and the A user must exist.
        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            childTenantId, parentTenantId, parentUserId.ToString());
        authResult.Should().NotBeNull("A is an ancestor of B and the A user exists");

        // Provision (or find) the B-shadow user — the subject the token is issued for.
        var shadowUser = await provisioning.FindOrCreateCrossTenantUserAsync(authResult!, childTenantId);
        shadowUser.Should().NotBeNull();
        shadowUser!.UserName.Should().Be($"xt_{parentTenantId}_{parentUserName}",
            "the token must run on the B-shadow sub, not the A user");

        // Resolve the shadow user's roles through the SAME store that stamps the token's role claims,
        // wired to the B tenant repository.
        var rB1Name = await NameOfRoleInTenantAsync(rB1, childRepo);
        var resolvedRoles = await ResolveRolesInTenantAsync(childRepo, shadowUser);

        resolvedRoles.Should().Contain(rB1Name, "the mapped B role must be granted");
        // The privilege-escalation guard: A's roles must NOT leak into B.
        resolvedRoles.Should().HaveCount(1, "only the mapped B subset is granted, never A's full role set");
    }

    /// <summary>
    ///     B-authorization gate: when A is NOT an ancestor of B, the exchange must be denied
    ///     (the validator maps this to <c>unauthorized_client</c>).
    /// </summary>
    [Fact]
    public async Task Exchange_BNotDescendantOfA_Denied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (parentUserId, _) = await CreateUserAsync(systemContext, parentTenantId, "bob");

        // A child tenant that is NOT linked to A (no RtOctoTenantIdentityProvider pointing at A).
        var unrelatedTenantId = await CreateChildTenantAsync(NewId("unrel"));

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);

        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            unrelatedTenantId, parentTenantId, parentUserId.ToString());

        authResult.Should().BeNull("A is not an ancestor of the unrelated tenant → exchange denied");
    }

    /// <summary>
    ///     Missing / unknown subject user: even with a valid ancestor relationship, if the claimed A
    ///     user does not exist the exchange must be denied (defends against a forged sub in an
    ///     otherwise well-formed request).
    /// </summary>
    [Fact]
    public async Task Exchange_UnknownSubjectUser_Denied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);

        var crossTenantAuth = CreateCrossTenantAuthService(systemContext);

        var authResult = await crossTenantAuth.ValidateCrossTenantAccessAsync(
            childTenantId, parentTenantId, OctoObjectId.GenerateNewId().ToString());

        authResult.Should().BeNull("the claimed A user does not exist → exchange denied");
    }

    /// <summary>
    ///     AB#6839 (decision Gerald 2026-10-17): ancestry is not authority. A root-tenant user who holds roles
    ///     in A but has no mapping, group or direct role in child B is refused at the exchange with
    ///     <c>access_denied</c> and the stable <see cref="TenantExchangeProcessor.NotProvisionedMarker" />;
    ///     no token (and so no implicit admin role) comes out of it.
    /// </summary>
    [Fact]
    public async Task Exchange_AncestorUserWithoutProvisioning_IsRefusedWithAStableSignal()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (operatorId, _) = await CreateUserAsync(systemContext, parentTenantId, "op-unprov");
        var rootRole = await CreateRoleAsync(systemContext, parentTenantId, NewId("rootAdmin"));
        await AssignRoleToUserAsync(systemContext, parentTenantId, operatorId, rootRole);
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);

        var outcome = await (await CreateExchangeProcessorAsync(systemContext, childTenantId))
            .ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);

        outcome.ShadowUser.Should().BeNull("no token may be minted for an unprovisioned ancestor user");
        outcome.Error.Should().Be("access_denied");
        outcome.ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker);
        outcome.ErrorDescription.Should().Contain(childTenantId);
    }

    /// <summary>
    ///     AB#8304: an unprovisioned caller is refused before anything is written — no shadow user, no mapping
    ///     (AB#7088), no association is left in B, so a repeated exchange is refused the same way and B stays
    ///     exactly as it was (count before == after).
    /// </summary>
    [Fact]
    public async Task Exchange_RepeatedAfterEmptyMappingWasAutoCreated_StaysRefused()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (operatorId, _) = await CreateUserAsync(systemContext, parentTenantId, "op-repeat");
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var processor = await CreateExchangeProcessorAsync(systemContext, childTenantId);
        var before = await SnapshotIdentityStateAsync(childRepo);

        var first = await processor.ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);
        var second = await processor.ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);

        first.Error.Should().Be("access_denied");
        first.ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker);
        second.Error.Should().Be("access_denied", "the refused first attempt prepared nothing that could grant");
        second.ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker);
        (await SnapshotIdentityStateAsync(childRepo)).Should().Be(before,
            "a refused exchange leaves no xt_ user, mapping or association behind");
        before.ShadowUsers.Should().Be(0);
    }

    /// <summary>
    ///     AB#8304 with the mapping-side refusal: a mapping that lists only the id of a deleted role grants nothing at
    ///     token time, so the exchange is refused before a shadow user is created.
    /// </summary>
    [Fact]
    public async Task Exchange_MappingWithOnlyStaleRoleIds_IsRefused_AndCreatesNoShadowUser()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (operatorId, operatorName) = await CreateUserAsync(systemContext, parentTenantId, "op-stale");
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, operatorId, operatorName,
            mappedRoleIds: [OctoObjectId.GenerateNewId().ToString()]);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var before = await SnapshotIdentityStateAsync(childRepo);

        var outcome = await (await CreateExchangeProcessorAsync(systemContext, childTenantId))
            .ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);

        outcome.Error.Should().Be("access_denied");
        outcome.ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker);
        (await SnapshotIdentityStateAsync(childRepo)).Should().Be(before);
    }

    /// <summary>
    ///     The explicit-provisioning positive case (what <c>ProvisionCurrentUser -ttid</c> creates: a mapping
    ///     with roles): the exchange succeeds on the B-shadow user and its roles are exactly the mapped ones.
    /// </summary>
    [Fact]
    public async Task Exchange_ProvisionedOperator_GetsExactlyTheMappedRoles()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (operatorId, operatorName) = await CreateUserAsync(systemContext, parentTenantId, "op-prov");
        var rootRole = await CreateRoleAsync(systemContext, parentTenantId, NewId("rootAdmin"));
        await AssignRoleToUserAsync(systemContext, parentTenantId, operatorId, rootRole);
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var mapped = await CreateRoleAsync(systemContext, childTenantId, NewId("mapped"));
        await CreateRoleAsync(systemContext, childTenantId, NewId("unmapped"));
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, operatorId, operatorName,
            mappedRoleIds: [mapped.ToString()]);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;

        var outcome = await (await CreateExchangeProcessorAsync(systemContext, childTenantId))
            .ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);

        outcome.Error.Should().BeNull();
        outcome.ShadowUser.Should().NotBeNull();
        outcome.TargetTenantId.Should().Be(childTenantId);
        var roles = await ResolveRolesInTenantAsync(childRepo, outcome.ShadowUser!);
        roles.Should().BeEquivalentTo([await NameOfRoleInTenantAsync(mapped, childRepo)],
            "only the explicit mapping grants authority, never the root role");
    }

    /// <summary>
    ///     An existing shadow user behaves as before AB#8304: a role-less one (left behind by an exchange before the
    ///     fix) is refused and kept as it is; once an administrator of B grants it a role directly, the same exchange
    ///     succeeds on that very user. A NEW cross-tenant user is granted through a mapping instead (see
    ///     <see cref="Exchange_UserAddedAsCrossTenantUserWithGroups_GetsExactlyTheGroupsRolesOnTheFirstExchange" />).
    /// </summary>
    [Fact]
    public async Task Exchange_AfterDirectRoleGrantToTheShadowUser_Succeeds()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (operatorId, _) = await CreateUserAsync(systemContext, parentTenantId, "op-direct");
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var directRole = await CreateRoleAsync(systemContext, childTenantId, NewId("direct"));
        var processor = await CreateExchangeProcessorAsync(systemContext, childTenantId);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var authResult = await CreateCrossTenantAuthService(systemContext)
            .ValidateCrossTenantAccessAsync(childTenantId, parentTenantId, operatorId.ToString());
        // The role-less shadow user an exchange used to leave behind before AB#8304.
        var shadow = await CreateProvisioningService(childRepo)
            .FindOrCreateCrossTenantUserAsync(authResult!, childTenantId, storeMappingIfMissing: false);
        shadow.Should().NotBeNull();

        (await processor.ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false))
            .ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker);
        (await CreateProvisioningService(childRepo).FindCrossTenantUserAsync(authResult!))!
            .RtId.Should().Be(shadow!.RtId, "the exchange neither deletes nor replaces an existing shadow user");
        await AssignRoleToUserAsync(systemContext, childTenantId, shadow.RtId, directRole);

        var outcome = await processor.ExchangeAsync(parentTenantId, operatorId.ToString(), childTenantId, subjectHasSecondFactor: false);

        outcome.Error.Should().BeNull();
        outcome.ShadowUser!.RtId.Should().Be(shadow.RtId);
    }

    /// <summary>
    ///     AB#8304, the path behind Refinery Studio's "Add Cross-Tenant User" (AB#4652): an administrator of B creates
    ///     an <c>ExternalTenantUserMapping</c> without own roles and makes it a member of groups. Before the first
    ///     exchange there is no shadow user; the first exchange creates exactly one, whose roles are exactly the
    ///     roles of those groups (incl. a nested group) — never a role of a group the mapping is not in.
    /// </summary>
    [Fact]
    public async Task Exchange_UserAddedAsCrossTenantUserWithGroups_GetsExactlyTheGroupsRolesOnTheFirstExchange()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (userId, userName) = await CreateUserAsync(systemContext, parentTenantId, "xt-groups");
        var rootRole = await CreateRoleAsync(systemContext, parentTenantId, NewId("rootAdmin"));
        await AssignRoleToUserAsync(systemContext, parentTenantId, userId, rootRole);
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var readerRole = await CreateRoleAsync(systemContext, childTenantId, NewId("reader"));
        var writerRole = await CreateRoleAsync(systemContext, childTenantId, NewId("writer"));
        var nestedRole = await CreateRoleAsync(systemContext, childTenantId, NewId("nested"));
        var otherRole = await CreateRoleAsync(systemContext, childTenantId, NewId("other"));
        var groupStore = new GroupStore(new FixedTenantResolver(childRepo));
        var readers = await CreateGroupAsync(groupStore, NewId("readers"), readerRole);
        var writers = await CreateGroupAsync(groupStore, NewId("writers"), writerRole);
        var nested = await CreateGroupAsync(groupStore, NewId("nestedGrp"), nestedRole);
        await groupStore.AddMemberGroupAsync(writers, nested.ToString());
        await CreateGroupAsync(groupStore, NewId("others"), otherRole);
        // What "Add Cross-Tenant User" writes: a mapping without own roles, member of the chosen groups.
        await CreateMappingAsync(systemContext, childTenantId, parentTenantId, userId, userName, mappedRoleIds: []);
        var mapping = (await GetMappingsAsync(childRepo, parentTenantId, userId)).Single();
        await groupStore.AddMemberExternalUserAsync(readers, mapping.RtId.ToString());
        await groupStore.AddMemberExternalUserAsync(writers, mapping.RtId.ToString());
        var before = await SnapshotIdentityStateAsync(childRepo);
        before.ShadowUsers.Should().Be(0, "the shadow user is created by the first accepted exchange, not by the grant");
        var processor = await CreateExchangeProcessorAsync(systemContext, childTenantId);

        var first = await processor.ExchangeAsync(parentTenantId, userId.ToString(), childTenantId, subjectHasSecondFactor: false);
        var second = await processor.ExchangeAsync(parentTenantId, userId.ToString(), childTenantId, subjectHasSecondFactor: false);

        first.Error.Should().BeNull();
        first.ShadowUser!.UserName.Should().Be(CrossTenantShadowUserName.Build(parentTenantId, userName));
        second.Error.Should().BeNull();
        second.ShadowUser!.RtId.Should().Be(first.ShadowUser.RtId, "the shadow user is created exactly once");
        (await SnapshotIdentityStateAsync(childRepo)).ShadowUsers.Should().Be(1);
        (await GetMappingsAsync(childRepo, parentTenantId, userId)).Should().ContainSingle("the exchange stores no mapping");
        (await ResolveRolesInTenantAsync(childRepo, first.ShadowUser)).Should().BeEquivalentTo(
            [
                await NameOfRoleInTenantAsync(readerRole, childRepo),
                await NameOfRoleInTenantAsync(writerRole, childRepo),
                await NameOfRoleInTenantAsync(nestedRole, childRepo)
            ],
            "exactly the roles of the granted groups — not the root role, not the role of another group");
    }

    /// <summary>The ancestor gate is unchanged: a user of a tenant that is not an ancestor of B is refused.</summary>
    [Fact]
    public async Task Exchange_NonAncestorUser_IsStillUnauthorizedClient()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var (userId, _) = await CreateUserAsync(systemContext, systemContext.TenantId, "op-foreign");
        var unrelatedTenantId = await CreateChildTenantAsync(NewId("unrel2"));

        var outcome = await (await CreateExchangeProcessorAsync(systemContext, unrelatedTenantId))
            .ExchangeAsync(systemContext.TenantId, userId.ToString(), unrelatedTenantId, subjectHasSecondFactor: false);

        outcome.ShadowUser.Should().BeNull();
        outcome.Error.Should().Be("unauthorized_client");
    }

    /// <summary>
    ///     AB#5708: tenant ids may contain '_'. A sibling's shadow user of a user from an underscore
    ///     tenant H exchanges into H's child as the real home identity — the first-separator split
    ///     looked for the home user in a non-existent prefix of H and found nobody.
    /// </summary>
    [Fact]
    public async Task Exchange_ShadowUserOfAnUnderscoreTenant_UsesTheRealHomeIdentity()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var homeTenantId = await CreateChildTenantAsync($"{NewId("home")}_tenant");
        var (homeUserId, homeUserName) = await CreateUserAsync(systemContext, homeTenantId, "gina");
        var targetTenantId = await CreateChildWithParentProviderAsync(homeTenantId);
        await CreateMappingAsync(systemContext, targetTenantId, homeTenantId, homeUserId, homeUserName, mappedRoleIds: []);

        // The source is a sibling (no ancestor of the target) holding the home user's shadow.
        var siblingTenantId = await CreateChildTenantAsync(NewId("sibling"));
        var (shadowUserId, _) = await CreateUserAsync(systemContext, siblingTenantId,
            CrossTenantShadowUserName.Build(homeTenantId, homeUserName), exactUserName: true);

        var result = await (await CreateExchangeProcessorAsync(systemContext, targetTenantId))
            .ResolveExchangeSourceAsync(targetTenantId, siblingTenantId, shadowUserId.ToString());

        result.Should().NotBeNull("the home identity is an ancestor of the target and mapped there");
        result!.SourceTenantId.Should().Be(homeTenantId);
        result.SourceUserId.Should().Be(homeUserId.ToString());
    }

    /// <summary>
    ///     AB#5708 spoofing case. The victim <c>corp_{x}</c> of tenant V is mapped into V's child T. The
    ///     attacker owns tenant <c>{V}_corp</c>; the shadow of its user <c>{x}</c> in an unrelated tenant is
    ///     named <c>xt_{V}_corp_{x}</c>, which the first-separator split resolved to the victim — and the
    ///     victim may reach T, so the attacker exchanged into T as the victim. Both tenants are registered,
    ///     so the name is ambiguous: no home candidate, and the immediate source is no ancestor of T.
    /// </summary>
    [Fact]
    public async Task Exchange_SpoofedShadowNameFromAnUnderscoreTenant_IsDenied()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var victimTenantId = await CreateChildTenantAsync(NewId("victim"));
        var (victimUserId, victimUserName) = await CreateUserAsync(systemContext, victimTenantId, "corp_v");
        var targetTenantId = await CreateChildWithParentProviderAsync(victimTenantId);
        await CreateMappingAsync(systemContext, targetTenantId, victimTenantId, victimUserId, victimUserName, mappedRoleIds: []);

        var processor = await CreateExchangeProcessorAsync(systemContext, targetTenantId);
        (await processor.ResolveExchangeSourceAsync(targetTenantId, victimTenantId, victimUserId.ToString()))
            .Should().NotBeNull("the victim itself may exchange into the target");

        var attackerTenantId = await CreateChildTenantAsync($"{victimTenantId}_corp");
        var attackerUserName = victimUserName["corp_".Length..];
        var sourceTenantId = await CreateChildTenantAsync(NewId("src"));
        var spoofedShadowName = CrossTenantShadowUserName.Build(attackerTenantId, attackerUserName);
        spoofedShadowName.Should().Be(CrossTenantShadowUserName.Build(victimTenantId, victimUserName),
            "the attacker's shadow name reads exactly like the victim's");
        var (spoofedShadowId, _) = await CreateUserAsync(systemContext, sourceTenantId, spoofedShadowName, exactUserName: true);

        var result = await processor.ResolveExchangeSourceAsync(targetTenantId, sourceTenantId, spoofedShadowId.ToString());

        result.Should().BeNull("an ambiguous shadow name must never unwind to the victim's identity");
    }

    // ---------- AB#7088: ProvisionCurrentUser repairs a mapping that grants no role ----------

    /// <summary>
    ///     AB#7088 acceptance criterion 1: a mapping with empty <c>MappedRoleIds</c> exists (what the login path
    ///     still stores for a first-time shadow user), ProvisionCurrentUser is called, the exchange afterwards
    ///     succeeds — and the result says the mapping was repaired, not that nothing happened.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_RoleLessMappingExists_RepairsItAndTheExchangeSucceeds()
    {
        var ctx = await ArrangeProvisioningAsync();
        await CreateMappingAsync(ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId, ctx.UserName,
            mappedRoleIds: []);
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().Be("access_denied", "the role-less mapping grants nothing");

        var outcome = await ProvisionCurrentUserAsync(ctx);

        outcome.Should().Be(AdminProvisioningController.OutcomeRepaired);
        var mappings = await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId);
        mappings.Should().ContainSingle("the existing mapping is repaired in place, never duplicated");
        mappings[0].MappedRoleIds.Should().BeEquivalentTo(ctx.ChildRoleIds.Select(r => r.ToString()));
        (await IsMemberOfTenantOwnersAsync(ctx.ChildRepo, mappings[0])).Should().BeTrue();

        var exchange = await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false);
        exchange.Error.Should().BeNull("the repaired mapping now grants roles");
        exchange.ShadowUser.Should().NotBeNull();
    }

    /// <summary>
    ///     AB#8161: when TenantOwners carries the roles (production shape), a provisioned administrator is only a
    ///     member of the group — the mapping holds no direct role list — and the exchange still succeeds.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_WhenTenantOwnersCarriesRoles_MappingIsOnlyAGroupMember()
    {
        var ctx = await ArrangeProvisioningAsync();
        var groupStore = new GroupStore(new FixedTenantResolver(ctx.ChildRepo));
        await groupStore.SetRoleIdsAsync(ctx.OwnersGroupId, ctx.ChildRoleIds.Select(r => r.ToString()).ToList());

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeCreated);

        var mapping = (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single();
        mapping.MappedRoleIds.Should().BeNullOrEmpty("the group carries the roles");
        (await IsMemberOfTenantOwnersAsync(ctx.ChildRepo, mapping)).Should().BeTrue();
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>
    ///     The same symptom the bug was found with: the login path's find-or-create stores a bare mapping next to
    ///     the shadow user, and a later ProvisionCurrentUser used to answer "provisioned" without writing anything.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_AfterBareMappingOfTheLoginPath_RepairsIt()
    {
        var ctx = await ArrangeProvisioningAsync();
        var authResult = await CreateCrossTenantAuthService(ctx.SystemContext)
            .ValidateCrossTenantAccessAsync(ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId.ToString());
        await CreateProvisioningService(ctx.ChildRepo).FindOrCreateCrossTenantUserAsync(authResult!, ctx.ChildTenantId);
        (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Should().ContainSingle()
            .Which.MappedRoleIds.Should().BeNullOrEmpty();

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeRepaired);

        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>
    ///     Role lookup keys on the source user NAME, the lookup for an existing mapping on the user id. A mapping
    ///     with the right id and roles but a wrong name grants nothing at the exchange — it is repaired too, and
    ///     only the name is touched (the roles it has are kept).
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_MappingWithWrongSourceUserName_CorrectsTheName()
    {
        var ctx = await ArrangeProvisioningAsync();
        await CreateMappingAsync(ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId,
            "stale-name", mappedRoleIds: [ctx.ChildRoleIds[0].ToString()]);
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().Be("access_denied", "the roles are looked up by the real user name");

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeRepaired);

        var mapping = (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single();
        mapping.SourceUserName.Should().Be(ctx.UserName);
        mapping.MappedRoleIds.Should().BeEquivalentTo([ctx.ChildRoleIds[0].ToString()], "a mapping that grants a role keeps its roles");
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>A mapping that lists only role ids which no longer exist grants nothing and is repaired.</summary>
    [Fact]
    public async Task ProvisionCurrentUser_MappingWithOnlyStaleRoleIds_IsRepaired()
    {
        var ctx = await ArrangeProvisioningAsync();
        await CreateMappingAsync(ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId, ctx.UserName,
            mappedRoleIds: [OctoObjectId.GenerateNewId().ToString()]);

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeRepaired);

        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>Acceptance criterion 2: a fresh provisioning reports <c>created</c> (and still works end to end).</summary>
    [Fact]
    public async Task ProvisionCurrentUser_NoMapping_ReportsCreated_AndTheExchangeSucceeds()
    {
        var ctx = await ArrangeProvisioningAsync();

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeCreated);

        var mapping = (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single();
        mapping.MappedRoleIds.Should().BeEquivalentTo(ctx.ChildRoleIds.Select(r => r.ToString()));
        (await IsMemberOfTenantOwnersAsync(ctx.ChildRepo, mapping)).Should().BeTrue();
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>
    ///     Acceptance criterion 2: a mapping that already grants a role is left exactly as it is and reported as
    ///     <c>already provisioned</c> — a repair must not widen a deliberately narrow grant.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_MappingAlreadyGrantsARole_ReportsAlreadyProvisioned_AndChangesNothing()
    {
        var ctx = await ArrangeProvisioningAsync();
        var narrow = new[] { ctx.ChildRoleIds[0].ToString() };
        await CreateMappingAsync(ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId, ctx.UserName,
            mappedRoleIds: narrow);

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeAlreadyProvisioned);
        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeAlreadyProvisioned);

        var mapping = (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single();
        mapping.MappedRoleIds.Should().BeEquivalentTo(narrow);
        (await IsMemberOfTenantOwnersAsync(ctx.ChildRepo, mapping)).Should().BeFalse();
    }

    /// <summary>
    ///     A mapping without own roles that sits in a group which carries a role is provisioned through the group
    ///     (what the login path's group assignment and blueprints produce): nothing to repair.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_MappingGrantedThroughGroupRole_ReportsAlreadyProvisioned()
    {
        var ctx = await ArrangeProvisioningAsync();
        var groupStore = new GroupStore(new FixedTenantResolver(ctx.ChildRepo));
        await groupStore.SetRoleIdsAsync(ctx.OwnersGroupId, [ctx.ChildRoleIds[0].ToString()]);
        await CreateMappingAsync(ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId, ctx.UserName,
            mappedRoleIds: []);
        var mapping = (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single();
        await groupStore.AddMemberExternalUserAsync(ctx.OwnersGroupId, mapping.RtId.ToString());

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeAlreadyProvisioned);

        (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Single()
            .MappedRoleIds.Should().BeNullOrEmpty("a mapping that is provisioned through its group is not widened");
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    /// <summary>
    ///     Acceptance criterion 3 (negative test, security property kept): an exchange for a tenant the user is
    ///     not provisioned in is refused and leaves NO mapping and, since AB#8304, NO shadow user behind — the exchange grants nothing and prepares
    ///     nothing that could later be mistaken for provisioning. A later ProvisionCurrentUser is a plain create.
    /// </summary>
    [Fact]
    public async Task Exchange_ForNotProvisionedTenant_LeavesNoMapping_AndLaterProvisioningIsACreate()
    {
        var ctx = await ArrangeProvisioningAsync();
        var before = await SnapshotIdentityStateAsync(ctx.ChildRepo);

        var denied = await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false);

        denied.Error.Should().Be("access_denied");
        denied.ShadowUser.Should().BeNull();
        (await GetMappingsAsync(ctx.ChildRepo, ctx.ParentTenantId, ctx.UserId)).Should().BeEmpty(
            "a refused exchange must not store a mapping");
        (await SnapshotIdentityStateAsync(ctx.ChildRepo)).Should().Be(before,
            "a refused exchange must not leave a shadow user (AB#8304) or an association behind");
        before.ShadowUsers.Should().Be(0);

        (await ProvisionCurrentUserAsync(ctx)).Should().Be(AdminProvisioningController.OutcomeCreated);
        (await ctx.Processor.ExchangeAsync(ctx.ParentTenantId, ctx.UserId.ToString(), ctx.ChildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull();
    }

    // ---------- AB#8017: ProvisionCurrentUser with the token of a shadow user of an intermediate tenant ----------

    /// <summary>
    ///     AB#8017 acceptance criteria 1 and 2: user U of root R is provisioned in child A; a session scoped to A
    ///     (subject = shadow <c>xt_R_U</c>) provisions U into grandchild B. The mapping is written for U's home
    ///     identity, the call names it, and both exchange paths into B — from U's R token and from the A shadow —
    ///     succeed with the admin roles over the real exchange path (depth 2: R → A → B).
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ProvisionCurrentUser_AsShadowUserOfIntermediateTenant_WritesTheHomeMapping_AndBothExchangePathsSucceed(
        bool tokenCarriesUserName)
    {
        var nested = await ArrangeNestedAsync();

        var (result, outcome) = await CallProvisionCurrentUserAsync(
            nested.SystemContext, nested.GrandchildTenantId, nested.IntermediateTenantId, nested.ShadowUserId.ToString(),
            tokenCarriesUserName ? nested.ShadowUserName : null);

        outcome.Should().Be(AdminProvisioningController.OutcomeCreated);
        var dto = result.Result.Should().BeAssignableTo<Microsoft.AspNetCore.Mvc.ObjectResult>().Which.Value
            .Should().BeOfType<Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ExternalTenantUserMappingDto>().Which;
        dto.SourceTenantId.Should().Be(nested.RootTenantId, "the mapping is written for the home identity");
        dto.SourceUserId.Should().Be(nested.UserId.ToString());
        dto.SourceUserName.Should().Be(nested.UserName);
        (await GetMappingsAsync(nested.GrandchildRepo, nested.IntermediateTenantId, nested.ShadowUserId))
            .Should().BeEmpty("no mapping is keyed on the shadow user any more");

        var processor = await CreateExchangeProcessorAsync(nested.SystemContext, nested.GrandchildTenantId);
        var fromHome = await processor.ExchangeAsync(
            nested.RootTenantId, nested.UserId.ToString(), nested.GrandchildTenantId, subjectHasSecondFactor: false);
        var fromShadow = await processor.ExchangeAsync(
            nested.IntermediateTenantId, nested.ShadowUserId.ToString(), nested.GrandchildTenantId, subjectHasSecondFactor: false);

        fromHome.Error.Should().BeNull("the home token of the same person reaches B");
        fromShadow.Error.Should().BeNull("the A-scoped token reaches B through the home mapping");
        var expectedRoles = new List<string>();
        foreach (var roleId in nested.GrandchildRoleIds)
        {
            expectedRoles.Add(await NameOfRoleInTenantAsync(roleId, nested.GrandchildRepo));
        }

        (await ResolveRolesInTenantAsync(nested.GrandchildRepo, fromHome.ShadowUser!))
            .Should().BeEquivalentTo(expectedRoles, "provisionCurrentUser grants all roles of B");
        (await ResolveRolesInTenantAsync(nested.GrandchildRepo, fromShadow.ShadowUser!))
            .Should().BeEquivalentTo(expectedRoles);
    }

    /// <summary>
    ///     AB#8017 acceptance criterion 3: the state left on 2026-10-31 — a mapping keyed on the A shadow user — makes
    ///     the exchange from the home token fail. provisionCurrentUser from the home tenant R adds the home mapping
    ///     and the exchange from R succeeds; a second call from the A shadow finds it and changes nothing.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_FromHomeTenant_RepairsTheStateOfAShadowKeyedMapping()
    {
        var nested = await ArrangeNestedAsync();
        await CreateMappingAsync(nested.SystemContext, nested.GrandchildTenantId, nested.IntermediateTenantId,
            nested.ShadowUserId, nested.ShadowUserName, nested.GrandchildRoleIds.Select(r => r.ToString()).ToList());
        var processor = await CreateExchangeProcessorAsync(nested.SystemContext, nested.GrandchildTenantId);

        (await processor.ExchangeAsync(nested.RootTenantId, nested.UserId.ToString(), nested.GrandchildTenantId, subjectHasSecondFactor: false))
            .ErrorDescription.Should().StartWith(TenantExchangeProcessor.NotProvisionedMarker,
                "a shadow-keyed mapping is never found by an exchange from the home token (the bug)");

        var (_, outcome) = await CallProvisionCurrentUserAsync(
            nested.SystemContext, nested.GrandchildTenantId, nested.RootTenantId, nested.UserId.ToString(), nested.UserName);

        outcome.Should().Be(AdminProvisioningController.OutcomeCreated);
        (await processor.ExchangeAsync(nested.RootTenantId, nested.UserId.ToString(), nested.GrandchildTenantId, subjectHasSecondFactor: false))
            .Error.Should().BeNull("the home mapping repairs the exchange from the home token");

        var (_, again) = await CallProvisionCurrentUserAsync(
            nested.SystemContext, nested.GrandchildTenantId, nested.IntermediateTenantId, nested.ShadowUserId.ToString(), null);
        again.Should().Be(AdminProvisioningController.OutcomeAlreadyProvisioned,
            "the shadow caller resolves to the same home mapping");
    }

    /// <summary>
    ///     AB#8017 acceptance criterion 4 (fail closed): a shadow user whose home identity cannot be resolved — here
    ///     the home user does not exist — is refused with 409 and nothing is written into the target tenant.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_ShadowUserWithoutResolvableHome_IsRefusedAndWritesNothing()
    {
        var nested = await ArrangeNestedAsync();
        var orphanName = CrossTenantShadowUserName.Build(nested.RootTenantId, NewId("ghost"));
        var (orphanId, _) = await CreateUserAsync(
            nested.SystemContext, nested.IntermediateTenantId, orphanName, exactUserName: true);

        var (result, outcome) = await CallProvisionCurrentUserAsync(
            nested.SystemContext, nested.GrandchildTenantId, nested.IntermediateTenantId, orphanId.ToString(), orphanName);

        outcome.Should().BeNull();
        var conflict = result.Result.Should().BeOfType<Microsoft.AspNetCore.Mvc.ConflictObjectResult>().Which;
        conflict.Value.Should().BeOfType<Microsoft.AspNetCore.Mvc.ProblemDetails>()
            .Which.Detail.Should().Contain(orphanName).And.Contain("home tenant");
        await AssertNoMappingsAsync(nested.GrandchildRepo);
    }

    /// <summary>
    ///     AB#8017 fail closed for an ambiguous chain: the shadow's tenant prefix is not a registered tenant, so the
    ///     name does not unwind; the call is refused and writes nothing.
    /// </summary>
    [Fact]
    public async Task ProvisionCurrentUser_ShadowUserOfAnUnregisteredTenant_IsRefused()
    {
        var nested = await ArrangeNestedAsync();
        var foreignName = CrossTenantShadowUserName.Build(NewId("gone"), "someone");
        var (foreignId, _) = await CreateUserAsync(
            nested.SystemContext, nested.IntermediateTenantId, foreignName, exactUserName: true);

        var (result, _) = await CallProvisionCurrentUserAsync(
            nested.SystemContext, nested.GrandchildTenantId, nested.IntermediateTenantId, foreignId.ToString(), null);

        result.Result.Should().BeOfType<Microsoft.AspNetCore.Mvc.ConflictObjectResult>();
        await AssertNoMappingsAsync(nested.GrandchildRepo);
    }

    private sealed record NestedArrangement(
        ISystemContext SystemContext, string RootTenantId, string IntermediateTenantId, string GrandchildTenantId,
        ITenantRepository GrandchildRepo, OctoObjectId UserId, string UserName, OctoObjectId ShadowUserId,
        string ShadowUserName, IReadOnlyList<OctoObjectId> GrandchildRoleIds);

    /// <summary>
    ///     R (system tenant) → A → B. U of R is provisioned into A through the real controller and exchanges into A
    ///     once, which creates the shadow <c>xt_R_U</c> in A — the subject of an A-scoped session.
    /// </summary>
    private async Task<NestedArrangement> ArrangeNestedAsync()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var rootTenantId = systemContext.TenantId;
        var (userId, userName) = await CreateUserAsync(systemContext, rootTenantId, "op-nested");

        var intermediateTenantId = await CreateChildWithParentProviderAsync(rootTenantId);
        await CreateRoleAsync(systemContext, intermediateTenantId, NewId("aAdmin"));
        var (_, toA) = await CallProvisionCurrentUserAsync(
            systemContext, intermediateTenantId, rootTenantId, userId.ToString(), userName);
        toA.Should().Be(AdminProvisioningController.OutcomeCreated);
        var intoA = await (await CreateExchangeProcessorAsync(systemContext, intermediateTenantId))
            .ExchangeAsync(rootTenantId, userId.ToString(), intermediateTenantId, subjectHasSecondFactor: false);
        intoA.Error.Should().BeNull();
        var shadow = intoA.ShadowUser!;
        shadow.UserName.Should().Be(CrossTenantShadowUserName.Build(rootTenantId, userName));

        var grandchildTenantId = await CreateChildWithParentProviderAsync(intermediateTenantId);
        var grandchildRoles = new[]
        {
            await CreateRoleAsync(systemContext, grandchildTenantId, NewId("bRoleA")),
            await CreateRoleAsync(systemContext, grandchildTenantId, NewId("bRoleB"))
        };
        var grandchildRepo = (await systemContext.TryFindTenantRepositoryAsync(grandchildTenantId))!;

        return new NestedArrangement(systemContext, rootTenantId, intermediateTenantId, grandchildTenantId,
            grandchildRepo, userId, userName, shadow.RtId, shadow.UserName!, grandchildRoles);
    }

    private static async Task AssertNoMappingsAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var all = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        all.Items.Should().BeEmpty("a refused provisioning writes nothing");
    }

    private sealed record ProvisioningArrangement(
        ISystemContext SystemContext, string ParentTenantId, string ChildTenantId, ITenantRepository ChildRepo,
        OctoObjectId UserId, string UserName, IReadOnlyList<OctoObjectId> ChildRoleIds,
        TenantExchangeProcessor Processor, OctoObjectId OwnersGroupId);

    private async Task<ProvisioningArrangement> ArrangeProvisioningAsync()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var systemContext = _fixture.GetSystemContext();
        var parentTenantId = systemContext.TenantId;
        var (userId, userName) = await CreateUserAsync(systemContext, parentTenantId, "op-prov7088");
        var childTenantId = await CreateChildWithParentProviderAsync(parentTenantId);
        var childRoles = new[]
        {
            await CreateRoleAsync(systemContext, childTenantId, NewId("roleA")),
            await CreateRoleAsync(systemContext, childTenantId, NewId("roleB"))
        };
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        // The TenantOwners group comes from the Bootstrap blueprint in production; here it starts without roles.
        var ownersGroup = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(),
            GroupName = CommonConstants.TenantOwnersGroup,
            NormalizedGroupName = CommonConstants.TenantOwnersGroup.ToUpperInvariant()
        };
        await new GroupStore(new FixedTenantResolver(childRepo)).StoreAsync(ownersGroup);
        var processor = await CreateExchangeProcessorAsync(systemContext, childTenantId);
        return new ProvisioningArrangement(
            systemContext, parentTenantId, childTenantId, childRepo, userId, userName, childRoles, processor,
            ownersGroup.RtId);
    }

    /// <summary>Calls the real controller action as the given source user and returns the reported outcome.</summary>
    private async Task<string?> ProvisionCurrentUserAsync(ProvisioningArrangement ctx)
    {
        var (result, outcome) = await CallProvisionCurrentUserAsync(
            ctx.SystemContext, ctx.ChildTenantId, ctx.ParentTenantId, ctx.UserId.ToString(), ctx.UserName);

        result.Result.Should().BeAssignableTo<Microsoft.AspNetCore.Mvc.ObjectResult>()
            .Which.StatusCode.Should().BeOneOf(StatusCodes.Status200OK, StatusCodes.Status201Created);
        return outcome;
    }

    /// <summary>
    ///     Calls the real controller action with a token of <paramref name="callerUserId" /> in
    ///     <paramref name="callerTenantId" />. <paramref name="callerUserName" /> <c>null</c> = an access token without
    ///     profile claims.
    /// </summary>
    private static async Task<(Microsoft.AspNetCore.Mvc.ActionResult<Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ExternalTenantUserMappingDto> Result, string? Outcome)>
        CallProvisionCurrentUserAsync(
            ISystemContext systemContext, string targetTenantId, string callerTenantId, string callerUserId,
            string? callerUserName)
    {
        var claims = new List<System.Security.Claims.Claim>
        {
            new("sub", callerUserId),
            new("tenant_id", callerTenantId)
        };
        if (callerUserName != null)
        {
            claims.Add(new System.Security.Claims.Claim("preferred_username", callerUserName));
        }

        var httpContext = new DefaultHttpContext
        {
            User = new System.Security.Claims.ClaimsPrincipal(new System.Security.Claims.ClaimsIdentity(claims, "test"))
        };
        var controller = new AdminProvisioningController(
            systemContext, Substitute.For<Meshmakers.Octo.Backend.Authentication.DynamicAuth.IDynamicAuthSchemeService>(),
            new CrossTenantShadowUserChainResolver(systemContext),
            TestAncestryGuards.Create(systemContext),
            NullLogger<AdminProvisioningController>.Instance)
        {
            ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext { HttpContext = httpContext }
        };

        var result = await controller.ProvisionCurrentUser(targetTenantId);

        var outcome = httpContext.Response.Headers.TryGetValue(AdminProvisioningController.ProvisioningOutcomeHeader, out var value)
            ? value.ToString()
            : null;
        return (result, outcome);
    }

    private static async Task<List<RtExternalTenantUserMapping>> GetMappingsAsync(
        ITenantRepository repo, string sourceTenantId, OctoObjectId sourceUserId)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
            session, RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), sourceTenantId)
                .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), sourceUserId.ToString()));
        await session.CommitTransactionAsync();
        return result.Items.ToList();
    }

    private static async Task<bool> IsMemberOfTenantOwnersAsync(ITenantRepository repo, RtExternalTenantUserMapping mapping)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var associations = await repo.GetRtAssociationsAsync(
            session, mapping.ToRtEntityId(),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Inbound,
                roleId: IdentityAssociationConstants.GroupMemberId));
        var owners = false;
        foreach (var association in associations.Items.Where(a => a.OriginCkTypeId == RtEntityExtensions.GetRtCkTypeId<RtGroup>()))
        {
            var group = await repo.GetRtEntityByRtIdAsync<RtGroup>(session, association.OriginRtId);
            owners |= string.Equals(group?.GroupName, CommonConstants.TenantOwnersGroup, StringComparison.OrdinalIgnoreCase);
        }

        await session.CommitTransactionAsync();
        return owners;
    }

    // ---------- helpers ----------

    /// <summary>What a refused exchange must not change in B: users, xt_ users, mappings and their associations.</summary>
    private sealed record IdentityState(int Users, int ShadowUsers, int Mappings, int Associations);

    private static async Task<IdentityState> SnapshotIdentityStateAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var users = (await repo.GetRtEntitiesByTypeAsync<RtUser>(session, RtEntityQueryOptions.Create())).Items.ToList();
        var mappings = (await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create()))
            .Items.ToList();
        var groups = (await repo.GetRtEntitiesByTypeAsync<RtGroup>(session, RtEntityQueryOptions.Create())).Items.ToList();
        var entityIds = users.Select(u => u.ToRtEntityId())
            .Concat(mappings.Select(m => m.ToRtEntityId()))
            .Concat(groups.Select(g => g.ToRtEntityId()));
        var associations = 0;
        foreach (var entityId in entityIds)
        {
            // Every edge of the identity graph (AssignedRole, GroupMember, ChildGroup) starts at a user, mapping or
            // group, so the outbound edges of all of them count every association once.
            associations += (await repo.GetRtAssociationsAsync(
                session, entityId, RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound))).Items.Count();
        }

        await session.CommitTransactionAsync();
        return new IdentityState(users.Count,
            users.Count(u => CrossTenantShadowUserName.IsShadowUserName(u.UserName)), mappings.Count, associations);
    }

    private static async Task<OctoObjectId> CreateGroupAsync(GroupStore groupStore, string name, OctoObjectId roleId)
    {
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(),
            GroupName = name,
            NormalizedGroupName = name.ToUpperInvariant()
        };
        await groupStore.StoreAsync(group);
        await groupStore.SetRoleIdsAsync(group.RtId, [roleId.ToString()]);
        return group.RtId;
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private CrossTenantAuthenticationService CreateCrossTenantAuthService(ISystemContext systemContext)
    {
        // ValidateCrossTenantAccessAsync only walks the hierarchy + looks up the user via ISystemContext;
        // the identity-provider store and password hasher are only used by the password-login path.
        var idpStore = new IdentityProviderStore(
            new FixedTenantResolver(systemContext.GetSystemTenantRepositoryAsAdmin()));
        return new CrossTenantAuthenticationService(
            new TenantRegistry(systemContext, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions())),
            idpStore,
            new PasswordHasher<RtUser>(),
            new CrossTenantShadowUserChainResolver(systemContext),
            TestAncestryGuards.Create(systemContext),
            Options.Create(new IdentityOptions()),
            NullLogger<CrossTenantAuthenticationService>.Instance);
    }

    private async Task<TenantExchangeProcessor> CreateExchangeProcessorAsync(
        ISystemContext systemContext, string targetTenantId)
    {
        var targetRepo = (await systemContext.TryFindTenantRepositoryAsync(targetTenantId))!;
        var targetResolver = new FixedTenantResolver(targetRepo);
        return new TenantExchangeProcessor(
            Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>(),
            Options.Create(new OctoIdentityServicesOptions
            {
                AuthorityUrl = "https://identity.example.com/"
            }),
            CreateCrossTenantAuthService(systemContext),
            CreateProvisioningService(targetRepo),
            new CrossTenantShadowUserChainResolver(systemContext),
            new ExternalTenantUserMappingStore(targetResolver),
            BuildUserManager(targetResolver),
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IIdentityAuditService>(),
            NullLogger<TenantExchangeProcessor>.Instance);
    }

    private CrossTenantUserProvisioningService CreateProvisioningService(ITenantRepository childRepo)
    {
        var resolver = new FixedTenantResolver(childRepo);
        var mappingStore = new ExternalTenantUserMappingStore(resolver);
        var userManager = BuildUserManager(resolver);
        return new CrossTenantUserProvisioningService(
            userManager, mappingStore, resolver, new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()),
            NullLogger<CrossTenantUserProvisioningService>.Instance);
    }

    private async Task<IList<string>> ResolveRolesInTenantAsync(ITenantRepository repo, RtUser user)
    {
        var resolver = new FixedTenantResolver(repo);
        var groupStore = new GroupStore(resolver);
        var groupRoleResolver = new GroupRoleResolver(groupStore, new ExternalTenantUserMappingStore(resolver), new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()));
        var userStore = new OctoUserStore(resolver, groupRoleResolver, null);
        return await userStore.GetRolesAsync(user, TestContext.Current.CancellationToken);
    }

    private static async Task<string> NameOfRoleInTenantAsync(OctoObjectId roleRtId, ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
        await session.CommitTransactionAsync();
        return role!.Name!;
    }

    /// <summary>
    ///     Builds a real <see cref="UserManager{RtUser}" /> over an <see cref="OctoUserStore" /> bound
    ///     to the given tenant repository, so <c>CreateAsync</c> / <c>AddToRoleAsync</c> hit the right
    ///     database — mirroring how the provisioning service runs in production for tenant B.
    /// </summary>
    private UserManager<RtUser> BuildUserManager(FixedTenantResolver resolver)
    {
        var groupStore = new GroupStore(resolver);
        var groupRoleResolver = new GroupRoleResolver(groupStore, new ExternalTenantUserMappingStore(resolver), new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()));
        var store = new OctoUserStore(resolver, groupRoleResolver, null);

        var options = Microsoft.Extensions.Options.Options.Create(new IdentityOptions());
        return new UserManager<RtUser>(
            store,
            options,
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
    }

    private async Task<string> CreateChildTenantAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            try
            {
                await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
                await session.CommitTransactionAsync();
            }
            catch
            {
                await session.AbortTransactionAsync();
                throw;
            }
        }

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    /// <summary>
    ///     Creates a child tenant B and seeds an <see cref="RtOctoTenantIdentityProvider" /> whose
    ///     <c>ParentTenantId</c> is A, establishing the ancestor relationship the B-auth gate requires.
    /// </summary>
    private async Task<string> CreateChildWithParentProviderAsync(string parentTenantId)
    {
        var childTenantId = await CreateChildTenantAsync(NewId("child"));
        var systemContext = _fixture.GetSystemContext();
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;

        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{parentTenantId}",
                DisplayName = $"Login via {parentTenantId}",
                IsEnabled = true,
                ParentTenantId = parentTenantId
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        return childTenantId;
    }

    private static async Task<(OctoObjectId userId, string userName)> CreateUserAsync(
        ISystemContext systemContext, string tenantId, string userNamePrefix, bool exactUserName = false)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

        var userName = exactUserName ? userNamePrefix : NewId(userNamePrefix);
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = rtId,
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
        return (rtId, userName);
    }

    private static async Task<OctoObjectId> CreateRoleAsync(
        ISystemContext systemContext, string tenantId, string name)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = rtId,
            Name = name,
            NormalizedName = name.ToUpperInvariant()
        });
        await session.CommitTransactionAsync();
        return rtId;
    }

    private async Task AssignRoleToUserAsync(
        ISystemContext systemContext, string tenantId, OctoObjectId userRtId, OctoObjectId roleRtId)
    {
        var repo = tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;

        var resolver = new FixedTenantResolver(repo);
        var userStore = new OctoUserStore(
            resolver, new GroupRoleResolver(new GroupStore(resolver), new ExternalTenantUserMappingStore(resolver), new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext())), null);

        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var user = await repo.GetRtEntityByRtIdAsync<RtUser>(session, userRtId);
        var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, roleRtId);
        await session.CommitTransactionAsync();

        // AddToRoleAsync uses the normalized role name to look up the role, then writes the
        // AssignedRole association — the exact edge OctoUserStore.GetRolesAsync reads back.
        await userStore.AddToRoleAsync(user!, role!.NormalizedName!, TestContext.Current.CancellationToken);
    }

    private static async Task CreateMappingAsync(
        ISystemContext systemContext, string childTenantId, string sourceTenantId,
        OctoObjectId sourceUserId, string sourceUserName, IReadOnlyList<string> mappedRoleIds)
    {
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = sourceTenantId,
            SourceUserId = sourceUserId.ToString(),
            SourceUserName = sourceUserName,
            MappedRoleIds = new AttributeStringValueList()
        };
        foreach (var roleId in mappedRoleIds)
        {
            mapping.MappedRoleIds.Add(roleId);
        }

        using var session = await childRepo.GetSessionAsync();
        session.StartTransaction();
        await childRepo.InsertOneRtEntityAsync(session, mapping);
        await session.CommitTransactionAsync();
    }
}
