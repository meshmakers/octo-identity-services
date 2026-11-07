using FluentAssertions;
using IdentityServerPersistence.Services.ShadowUserCleanup;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.ShadowUserCleanup;

/// <summary>AB#8305: which xt_ shadow users are rights-less left-overs that the cleanup may delete. One test per rule.</summary>
public class ShadowUserCleanupPlannerTests
{
    private const string Tenant = "child";
    private const string ShadowName = "xt_octosystem_alice";

    private static ShadowUserFacts User(
        string userName = ShadowName,
        string rtId = "u1",
        ShadowUserEdge[]? edges = null,
        string[]? directUse = null) =>
        new(rtId, userName, new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc), edges ?? [], directUse ?? []);

    private static ShadowUserCleanupDecision Decide(
        ShadowUserFacts user,
        ShadowUserMappingSource[]? inTenant = null,
        ShadowUserMappingSource[]? allTenants = null) =>
        ShadowUserCleanupPlanner.Plan(Tenant, [user], inTenant ?? [], allTenants ?? []).Single();

    [Fact]
    public void ExchangeCreatedUserWithoutAnything_IsACandidate()
    {
        var decision = Decide(User());

        decision.IsCandidate.Should().BeTrue();
        decision.SkipReasons.Should().BeEmpty();
        decision.CreatedAt.Should().Be(new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc));
    }

    [Fact]
    public void UserWithoutShadowName_IsNotPartOfThePlan()
    {
        ShadowUserCleanupPlanner.Plan(Tenant, [User(userName: "alice")], [], []).Should().BeEmpty();
    }

    [Fact]
    public void UserWithARole_IsKept()
    {
        Decide(User(edges: [new ShadowUserEdge(ShadowUserEdgeKind.AssignedRole, "System.Identity/AssignedRole")]))
            .SkipReasons.Should().Equal("role");
    }

    [Fact]
    public void UserInAGroup_IsKept()
    {
        Decide(User(edges: [new ShadowUserEdge(ShadowUserEdgeKind.GroupMember, "System.Identity/GroupMember")]))
            .SkipReasons.Should().Equal("group");
    }

    [Fact]
    public void UserWithAnyOtherAssociation_IsKept()
    {
        Decide(User(edges: [new ShadowUserEdge(ShadowUserEdgeKind.Other, "System.Identity/BelongsToUser")]))
            .SkipReasons.Should().Equal("association:System.Identity/BelongsToUser");
    }

    [Fact]
    public void UserWithAMappingInThisTenantForItsSourceIdentity_IsKept()
    {
        Decide(User(), inTenant: [new ShadowUserMappingSource("OctoSystem", "src-id", "Alice")])
            .SkipReasons.Should().Equal("mapping");
    }

    [Fact]
    public void UserWithAMappingInThisTenantForAnIdentityFurtherUpItsChain_IsKept()
    {
        // xt_parent_xt_octosystem_alice: tiers (parent, xt_octosystem_alice) and (octosystem, alice).
        Decide(User(userName: "xt_parent_xt_octosystem_alice"),
                inTenant: [new ShadowUserMappingSource("octosystem", "src-id", "alice")])
            .SkipReasons.Should().Equal("mapping");
    }

    [Fact]
    public void MappingOfAnotherIdentity_DoesNotKeepTheUser()
    {
        Decide(User(), inTenant: [new ShadowUserMappingSource("octosystem", "src-id", "bob")])
            .IsCandidate.Should().BeTrue();
        // A name that only shares a shorter suffix is another identity.
        Decide(User(), inTenant: [new ShadowUserMappingSource("system", "src-id", "alice")])
            .IsCandidate.Should().BeTrue();
    }

    [Fact]
    public void UserThatIsTheSourceOfAMappingElsewhere_ByName_IsKept()
    {
        Decide(User(), allTenants: [new ShadowUserMappingSource(Tenant, "other-id", ShadowName.ToUpperInvariant())])
            .SkipReasons.Should().Equal("chain-source");
    }

    [Fact]
    public void UserThatIsTheSourceOfAMappingElsewhere_ById_IsKept()
    {
        Decide(User(), allTenants: [new ShadowUserMappingSource(Tenant, "u1", "renamed")])
            .SkipReasons.Should().Equal("chain-source");
    }

    [Fact]
    public void MappingElsewhereWithTheSameNameFromAnotherSourceTenant_DoesNotKeepTheUser()
    {
        Decide(User(), allTenants: [new ShadowUserMappingSource("sibling", "u1", ShadowName)])
            .IsCandidate.Should().BeTrue();
    }

    [Theory]
    [InlineData("password")]
    [InlineData("two-factor")]
    [InlineData("external-login")]
    [InlineData("user-token")]
    [InlineData("claim")]
    [InlineData("oauth-token")]
    [InlineData("oauth-authorization")]
    public void UserWithDirectUseData_IsKept(string kind)
    {
        Decide(User(directUse: [kind])).SkipReasons.Should().Equal($"direct-use:{kind}");
    }

    [Fact]
    public void EveryFailingRule_IsReported_InAStableOrder()
    {
        var decision = Decide(
            User(edges:
                [
                    new ShadowUserEdge(ShadowUserEdgeKind.GroupMember, "g"),
                    new ShadowUserEdge(ShadowUserEdgeKind.AssignedRole, "r"),
                    new ShadowUserEdge(ShadowUserEdgeKind.Other, "x")
                ],
                directUse: ["password"]),
            inTenant: [new ShadowUserMappingSource("octosystem", "s", "alice")],
            allTenants: [new ShadowUserMappingSource(Tenant, "u1", ShadowName)]);

        decision.SkipReasons.Should().Equal(
            "role", "group", "association:x", "mapping", "chain-source", "direct-use:password");
    }

    [Fact]
    public void Decisions_AreOrderedByRtId()
    {
        var plan = ShadowUserCleanupPlanner.Plan(Tenant,
            [User(rtId: "b", userName: "xt_t_b"), User(rtId: "a", userName: "xt_t_a")], [], []);

        plan.Select(d => d.RtId).Should().Equal("a", "b");
    }
}
