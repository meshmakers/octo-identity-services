using FluentAssertions;
using IdentityServerPersistence.Services.AdminRoleMigration;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SecretManagement;

/// <summary>AB#8165: which subjects move from direct admin roles to TenantOwners.</summary>
public class AdminRoleMigrationPlannerTests
{
    private const string Tm = "tm";
    private const string Um = "um";
    private static readonly IReadOnlySet<string> Owner = new HashSet<string> { Tm, Um, "dev", "sm" };

    private static AdminRoleMigrationSubject User(string id, params string[] roles) =>
        new(AdminRoleMigrationSubjectKind.User, id, roles.ToHashSet());

    private static IReadOnlyList<AdminRoleMigrationSubjectPlan> Plan(
        IReadOnlySet<string>? members, params AdminRoleMigrationSubject[] subjects) =>
        AdminRoleMigrationPlanner.Plan(subjects, Owner, members ?? new HashSet<string>(), Tm, Um);

    [Fact]
    public void FullyCovered_JoinsAndRemovesAllDirectRoles()
    {
        var plan = Plan(null, User("u1", Tm, Um, "dev"));

        plan.Should().ContainSingle().Which.Should().BeEquivalentTo(
            new AdminRoleMigrationSubjectPlan(AdminRoleMigrationSubjectKind.User, "u1", true, ["dev", Tm, Um]));
    }

    [Fact]
    public void PartlyCovered_RemovesOnlyTheCoveredRoles_AndKeepsTheOthers()
    {
        var plan = Plan(null, User("u1", Tm, Um, "custom"));

        plan.Single().RemoveRoleIds.Should().Equal(Tm, Um);
        plan.Single().RemoveRoleIds.Should().NotContain("custom");
    }

    [Fact]
    public void MissingUserManagementOrTenantManagement_IsNotMigrated()
    {
        Plan(null, User("a", Tm), User("b", Um), User("c", "dev")).Should().BeEmpty();
    }

    [Fact]
    public void AlreadyMemberWithoutDirectRoles_IsNotPlanned_SoASecondRunChangesNothing()
    {
        Plan(new HashSet<string> { "u1" }, User("u1")).Should().BeEmpty();
    }

    [Fact]
    public void AlreadyMemberWithLeftoverCoveredRoles_OnlyRemovesThem()
    {
        var plan = Plan(new HashSet<string> { "u1" }, User("u1", Tm, Um));

        plan.Single().JoinGroup.Should().BeFalse();
        plan.Single().RemoveRoleIds.Should().Equal(Tm, Um);
    }

    [Fact]
    public void MappingsAreMigratedLikeUsers()
    {
        var plan = AdminRoleMigrationPlanner.Plan(
            [new AdminRoleMigrationSubject(AdminRoleMigrationSubjectKind.Mapping, "m1", new HashSet<string> { Tm, Um })],
            Owner, new HashSet<string>(), Tm, Um);

        plan.Single().Kind.Should().Be(AdminRoleMigrationSubjectKind.Mapping);
        plan.Single().JoinGroup.Should().BeTrue();
    }
}
