using System.Security.Claims;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     AB#7928: the client role endpoints write only what the guard judged. A role the client already holds is never
///     written again, so a concurrent removal of that role cannot be undone by a caller who does not hold it (the store's
///     replace-all re-reads the assignments in its own transaction and would re-insert it). The rule itself (403
///     <c>role-not-held</c>) is covered end to end by <c>ClientRoleChangeGuardTests</c>.
/// </summary>
public class ClientsControllerRoleGuardTests
{
    private const string ClientId = "c7928";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();
    private readonly RoleManager<RtRole> _roleManager =
        Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null, null, null, null);
    private readonly IRoleChangeGuard _guard = Substitute.For<IRoleChangeGuard>();
    private readonly RtClient _client;
    private readonly RtRole _notHeld;
    private readonly RtRole _custom;
    private readonly ClientsController _sut;

    public ClientsControllerRoleGuardTests()
    {
        _client = new RtClientBuilder().WithClientId(ClientId).WithClientName(ClientId).Build();
        _client.RtId = OctoObjectId.GenerateNewId();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(_client);
        _notHeld = Role("BuiltInNotHeld");
        _custom = Role("Custom");
        _guard.EvaluateClientGrantAsync(Arg.Any<RoleChangeCaller>(), Arg.Any<RtClient>(),
                Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns(RoleChangeDecision.Allowed);

        _sut = new ClientsController(_clientStore, Substitute.For<IDistributionEventHubService>(), _clientRoleStore,
            Substitute.For<IClientImpersonationStore>(), _roleManager, _guard, Substitute.For<IRoleChangeRefusals>())
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "admin"), new Claim("role", "TenantManagement")], "test"))
                }
            }
        };
    }

    private RtRole Role(string name)
    {
        var role = new RtRoleBuilder().WithName(name).Build();
        role.RtId = OctoObjectId.GenerateNewId();
        _roleManager.FindByIdAsync(role.RtId.ToString()).Returns(role);
        _roleManager.FindByNameAsync(name).Returns(role);
        return role;
    }

    [Fact]
    public async Task SetRoles_KeepingAHeldRole_WritesOnlyTheAddition_NeverTheKeptRole()
    {
        _clientRoleStore.GetDirectRoleIdsAsync(_client.RtId).Returns([_notHeld.RtId.ToString()]);

        var result = await _sut.UpdateClientRoles(ClientId, [_notHeld.RtId.ToString(), _custom.RtId.ToString()]);

        result.Should().BeOfType<OkResult>();
        await _guard.Received(1).EvaluateClientGrantAsync(Arg.Any<RoleChangeCaller>(), _client,
            Arg.Is<IReadOnlyCollection<string>>(n => n.SequenceEqual(new[] { "Custom" })), Arg.Any<CancellationToken>());
        await _clientRoleStore.Received(1).ApplyRoleChangesAsync(_client.RtId,
            Arg.Is<IReadOnlyCollection<string>>(a => a.SequenceEqual(new[] { _custom.RtId.ToString() })),
            Arg.Is<IReadOnlyCollection<string>>(r => r.Count == 0));
        await _clientRoleStore.DidNotReceiveWithAnyArgs().SetRoleIdsAsync(default, default!);
    }

    [Fact]
    public async Task SetRoles_DroppingARole_RemovesExactlyThatRole_WithoutJudgingIt()
    {
        _clientRoleStore.GetDirectRoleIdsAsync(_client.RtId).Returns([_notHeld.RtId.ToString(), _custom.RtId.ToString()]);

        var result = await _sut.UpdateClientRoles(ClientId, [_custom.RtId.ToString()]);

        result.Should().BeOfType<OkResult>();
        await _guard.DidNotReceiveWithAnyArgs().EvaluateClientGrantAsync(default!, default!, default!, TestContext.Current.CancellationToken);
        await _clientRoleStore.Received(1).ApplyRoleChangesAsync(_client.RtId,
            Arg.Is<IReadOnlyCollection<string>>(a => a.Count == 0),
            Arg.Is<IReadOnlyCollection<string>>(r => r.SequenceEqual(new[] { _notHeld.RtId.ToString() })));
    }

    [Fact]
    public async Task AddRole_ARoleTheClientAlreadyHolds_IsNotWrittenAgain()
    {
        _clientRoleStore.GetDirectRoleIdsAsync(_client.RtId).Returns([_notHeld.RtId.ToString()]);

        var result = await _sut.AddClientToRole(ClientId, _notHeld.Name!);

        result.Should().BeOfType<OkResult>();
        await _guard.DidNotReceiveWithAnyArgs().EvaluateClientGrantAsync(default!, default!, default!, TestContext.Current.CancellationToken);
        await _clientRoleStore.DidNotReceiveWithAnyArgs().AddRoleAsync(default, default!);
    }
}
