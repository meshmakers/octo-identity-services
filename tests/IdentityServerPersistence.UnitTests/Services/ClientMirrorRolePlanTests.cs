using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     the rules of the mirror role list (deny-list, confidential clients only) and the per-mirror plan (add, adopt,
///     remove only managed, hand-set untouched, declined by the tenant, re-created mirror, missing role). Pure: no database.
/// </summary>
public class ClientMirrorRolePlanTests
{
    private static readonly string[] ChildRoles =
        ["TenantManagement", "UserManagement", "CommunicationManagement", "DashboardViewer", "BotManagement"];

    [Theory]
    [InlineData("TenantManagement")]
    [InlineData("usermanagement")]
    [InlineData(" SecretManagement ")]
    [InlineData("AdminPanelManagement")]
    [InlineData("AIBUDGETADMIN")]
    public void DenyList_RefusesTheAdministrativeRoles_InAnySpelling(string role) =>
        ClientMirrorRoleRules.IsDenied(role).Should().BeTrue();

    [Theory]
    [InlineData("CommunicationManagement")]
    [InlineData("DashboardViewer")]
    [InlineData("")]
    [InlineData(null)]
    public void DenyList_AdmitsOtherRoles(string? role) => ClientMirrorRoleRules.IsDenied(role).Should().BeFalse();

    [Fact]
    public void ConfidentialClientCredentialsClient_MayCarryAList() =>
        ClientMirrorRoleRules.MayCarryMirrorRoles(Client(requireSecret: true, "client_credentials")).Should().BeTrue();

    [Theory]
    [InlineData(false, "client_credentials")]
    [InlineData(true, "authorization_code")]
    [InlineData(false, "authorization_code")]
    public void PublicClient_OrOneWithoutClientCredentials_MayNotCarryAList(bool requireSecret, string grant) =>
        ClientMirrorRoleRules.MayCarryMirrorRoles(Client(requireSecret, grant)).Should().BeFalse();

    [Fact]
    public void DesiredRoles_OfAPublicClient_AreEmpty_EvenWithAStoredList()
    {
        var client = Client(requireSecret: false, "authorization_code");
        client.MirrorRoleNames = new AttributeStringValueList(["CommunicationManagement"]);

        ClientMirrorRoleRules.DesiredRoleNames(client).Should().BeEmpty(
            "a list that reached a public client another way never reaches its mirrors");
    }

    [Fact]
    public void DesiredRoles_DropDeniedBlankAndDuplicateNames()
    {
        var client = Client(requireSecret: true, "client_credentials");
        client.MirrorRoleNames =
            new AttributeStringValueList(["CommunicationManagement", " communicationmanagement", "", "TenantManagement"]);

        ClientMirrorRoleRules.DesiredRoleNames(client).Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void FirstPass_AddsTheListedRoles_AndManagesThem()
    {
        var plan = Plan(desired: ["CommunicationManagement"], current: [], managed: null, declined: null,
            sameMirror: false);

        plan.Add.Should().Equal("CommunicationManagement");
        plan.Managed.Should().Equal("CommunicationManagement");
        plan.ChangesRoles.Should().BeTrue();
    }

    [Fact]
    public void SecondPass_WritesNothing()
    {
        var plan = Plan(["CommunicationManagement"], ["CommunicationManagement"], ["CommunicationManagement"], [],
            sameMirror: true);

        plan.ChangesRoles.Should().BeFalse();
        plan.AlreadyPresent.Should().Equal("CommunicationManagement");
        plan.Adopted.Should().BeEmpty();
        plan.Managed.Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void ListedRoleTheMirrorHoldsByHand_IsAdopted_NotAddedTwice()
    {
        var plan = Plan(["CommunicationManagement"], ["CommunicationManagement"], managed: null, declined: null,
            sameMirror: false);

        plan.Add.Should().BeEmpty();
        plan.Adopted.Should().Equal("CommunicationManagement");
        plan.Managed.Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void ClearingTheList_RemovesManagedAndAdoptedRoles_ButNeverHandSetOnes()
    {
        var plan = Plan([], ["CommunicationManagement", "BotManagement"], ["CommunicationManagement"], [],
            sameMirror: true);

        plan.Remove.Should().Equal("CommunicationManagement");
        plan.HandSet.Should().Equal("BotManagement");
        plan.Managed.Should().BeEmpty();
    }

    [Fact]
    public void HandSetRoleOutsideTheList_IsListedAndLeftAlone()
    {
        var plan = Plan(["CommunicationManagement"], ["CommunicationManagement", "DashboardViewer"],
            ["CommunicationManagement"], [], sameMirror: true);

        plan.HandSet.Should().Equal("DashboardViewer");
        plan.Remove.Should().BeEmpty();
    }

    [Fact]
    public void ManagedRoleTheTenantRemoved_OnTheSameMirror_IsDeclined_AndNotAddedAgain()
    {
        var plan = Plan(["CommunicationManagement"], [], ["CommunicationManagement"], [], sameMirror: true);

        plan.Add.Should().BeEmpty("the tenant keeps the last word");
        plan.NewlyDeclined.Should().Equal("CommunicationManagement");
        plan.Declined.Should().Equal("CommunicationManagement");
        plan.DeclinedAfter.Should().Equal("CommunicationManagement");
        plan.Managed.Should().BeEmpty();

        var next = Plan(["CommunicationManagement"], [], plan.Managed, plan.DeclinedAfter, sameMirror: true);
        next.Add.Should().BeEmpty();
        next.NewlyDeclined.Should().BeEmpty("a decline is reported once");
        next.Declined.Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void RecreatedMirror_IsGrantedAgain_AndForgetsTheDecline()
    {
        // The tracking refers to another mirror rtId: the mirror was deleted and inserted again (not a tenant's removal).
        var plan = Plan(["CommunicationManagement"], [], ["CommunicationManagement"], ["CommunicationManagement"],
            sameMirror: false);

        plan.Add.Should().Equal("CommunicationManagement");
        plan.NewlyDeclined.Should().BeEmpty();
        plan.DeclinedAfter.Should().BeEmpty();
    }

    [Fact]
    public void DeclinedRoleTheTenantGaveBack_IsAdopted_AndNoLongerDeclined()
    {
        var plan = Plan(["CommunicationManagement"], ["CommunicationManagement"], [], ["CommunicationManagement"],
            sameMirror: true);

        plan.Adopted.Should().Equal("CommunicationManagement");
        plan.DeclinedAfter.Should().BeEmpty();
        plan.Managed.Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void ManagedRoleRemovedFromTheList_ThatTheTenantAlsoRemoved_IsSimplyForgotten()
    {
        var plan = Plan([], [], ["CommunicationManagement"], [], sameMirror: true);

        plan.Remove.Should().BeEmpty("the edge is gone already");
        plan.NewlyDeclined.Should().BeEmpty("only a listed role can be declined");
        plan.Managed.Should().BeEmpty();
    }

    [Fact]
    public void ManagedRoleWhoseDefinitionIsGoneFromTheChild_IsMissing_NotDeclined()
    {
        var plan = MirrorRolePlan.Compute(["MirrorTestRole"], ChildRoles, current: [], managed: ["MirrorTestRole"],
            declined: [], sameMirror: true);

        plan.NewlyDeclined.Should().BeEmpty("the tenant deleted the role definition, it did not take the role away");
        plan.RoleMissing.Should().Equal("MirrorTestRole");

        var recreated = MirrorRolePlan.Compute(["MirrorTestRole"], [.. ChildRoles, "MirrorTestRole"], current: [],
            plan.Managed, plan.DeclinedAfter, sameMirror: true);
        recreated.Add.Should().Equal(["MirrorTestRole"], "a re-created role is assigned on the first pass after it exists");
    }

    [Fact]
    public void RoleMissingInTheChild_IsReported_AndNotAdded()
    {
        var plan = Plan(["NoSuchRole", "CommunicationManagement"], [], null, null, sameMirror: false);

        plan.RoleMissing.Should().Equal("NoSuchRole");
        plan.Add.Should().Equal("CommunicationManagement");
    }

    [Fact]
    public void NamesAreComparedCaseInsensitively_AndTheChildsSpellingIsUsed()
    {
        var plan = Plan(["communicationmanagement"], [], null, null, sameMirror: false);

        plan.Add.Should().Equal("CommunicationManagement");
    }

    private static MirrorRolePlan Plan(IReadOnlyList<string> desired, IReadOnlyList<string> current,
        IReadOnlyList<string>? managed, IReadOnlyList<string>? declined, bool sameMirror) =>
        MirrorRolePlan.Compute(desired, ChildRoles, current, managed, declined, sameMirror);

    private static RtClient Client(bool requireSecret, string grant) => new()
    {
        ClientId = "c",
        RequireClientSecret = requireSecret,
        AllowedGrantTypes = new AttributeStringValueList([grant])
    };
}
