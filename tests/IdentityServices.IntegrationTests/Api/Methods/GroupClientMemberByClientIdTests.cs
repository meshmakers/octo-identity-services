using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#8571: a client is named as a group member by its OAuth client id or by its rtId — in the REST route
///     <c>PUT/DELETE groups/{group}/members/clients/{client}</c> (octo-cli <c>AddClientToGroup -cid</c>) as in the methods
///     <c>Group.AddMember</c> / <c>Group.RemoveMember</c>. An unknown client is a 404, never a 500, and leaves no edge behind.
/// </summary>
public class GroupClientMemberByClientIdTests(CustomWebApplicationFactory factory) : GroupMethodTestBase(factory)
{
    private static CallerInfo AnyAdmin() => Caller(Guid.NewGuid().ToString("N"), UserManagement);

    [Fact]
    public async Task Rest_AddAndRemoveByClientId_ChangeTheMembershipOfThatClient()
    {
        var group = await NewGroupAsync();
        var client = await NewClientAsync();

        (await RestPutAsync(AnyAdmin(), $"groups/{group}/members/clients/{client.ClientId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await ClientMembersAsync(group)).Should().Equal(client.RtId.ToString());

        // A second add by the rtId is the same client: no second edge.
        (await RestPutAsync(AnyAdmin(), $"groups/{group}/members/clients/{client.RtId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await ClientMembersAsync(group)).Should().Equal(client.RtId.ToString());

        (await RestDeleteAsync(AnyAdmin(), $"groups/{group}/members/clients/{client.ClientId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await ClientMembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task Rest_AClientIdThatLooksLikeAnRtId_IsResolvedAsClientId()
    {
        var group = await NewGroupAsync();
        var client = await CreateTestClientAsync(OctoObjectId.GenerateNewId().ToString());

        (await RestPutAsync(AnyAdmin(), $"groups/{group}/members/clients/{client.ClientId}")).StatusCode.Should()
            .Be(HttpStatusCode.OK);

        (await ClientMembersAsync(group)).Should().Equal(client.RtId.ToString());
    }

    [Fact]
    public async Task Rest_UnknownClientIdOrRtId_Is404_WithAMessage_AndLeavesNoEdge()
    {
        var group = await NewGroupAsync();

        foreach (var unknown in new[] { $"no-such-client-{Guid.NewGuid():N}", OctoObjectId.GenerateNewId().ToString() })
        {
            var response = await RestPutAsync(AnyAdmin(), $"groups/{group}/members/clients/{unknown}");

            response.StatusCode.Should().Be(HttpStatusCode.NotFound, unknown);
            var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
            body.GetRawText().Should().Contain(unknown).And.Contain("client id or by its rtId");
        }

        (await ClientMembersAsync(group)).Should().BeEmpty();
        (await RestDeleteAsync(AnyAdmin(), $"groups/{group}/members/clients/no-such-client")).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Rest_ByClientId_TheRoleChangeGuardStillJudgesTheClient()
    {
        var builtIn = await NewRoleAsync(builtIn: true); // the caller holds none of the built-in roles
        var group = await NewGroupAsync(builtIn);
        var client = await NewClientAsync();

        var response = await RestPutAsync(AnyAdmin(), $"groups/{group}/members/clients/{client.ClientId}");

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code").GetString()
            .Should().Be("role-not-held");
        (await ClientMembersAsync(group)).Should().BeEmpty();
    }

    [Fact]
    public async Task Method_AddAndRemoveByClientId_IncludingAClientIdThatLooksLikeAnRtId()
    {
        var group = await NewGroupAsync();
        var hexLooking = await CreateTestClientAsync(OctoObjectId.GenerateNewId().ToString());

        (await AddMemberAsync(group, hexLooking.ClientId!)).IsSuccess.Should().BeTrue();
        (await ClientMembersAsync(group)).Should().Equal(hexLooking.RtId.ToString());
        (await AddMemberAsync(group, hexLooking.RtId.ToString())).Failure!.Code.Should()
            .Be(GroupMethodErrors.MemberAlreadyInGroup, "the rtId names the same client");

        (await InvokeAsync<GroupRemoveMemberHandler, GroupRemoveMemberParameters>(
            SystemIdentityCkIds.GroupRemoveMemberMethodId, "System.Identity/Group", group.ToString(), Admin(),
            new GroupRemoveMemberParameters
            {
                MemberKind = RtGroupMemberKindEnum.Client, MemberId = hexLooking.ClientId
            })).IsSuccess.Should().BeTrue();
        (await ClientMembersAsync(group)).Should().BeEmpty();

        (await AddMemberAsync(group, "no-such-client")).Failure!.Code.Should().Be(GroupMethodErrors.MemberNotFound);
    }

    private Task<CkMethodOutcome> AddMemberAsync(OctoObjectId group, string memberId) =>
        InvokeAsync<GroupAddMemberHandler, GroupAddMemberParameters>(SystemIdentityCkIds.GroupAddMemberMethodId,
            "System.Identity/Group", group.ToString(), Admin(),
            new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.Client, MemberId = memberId });
}
