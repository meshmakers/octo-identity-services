using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     Contract pin-down for <c>GET /v1/clients/{id}/actors</c> — the MayActAs read surface
///     (AB#5114) the communication controller's service-account health aggregate verifies the
///     impersonation edge through. The store answers actor CLIENT ids (not rtIds); the endpoint
///     adds the 404-for-unknown-client shell and the empty-list-for-no-edges shape. The
///     direction-sensitivity of the edge itself is pinned at the store level
///     (ImpersonatedIdentityIntegrationTests).
/// </summary>
public class ClientsControllerActorsTests
{
    private const string ClientId = "octo-pipeline-sa-target";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();

    private readonly IClientImpersonationStore _clientImpersonationStore =
        Substitute.For<IClientImpersonationStore>();

    private readonly ClientsController _sut;

    public ClientsControllerActorsTests()
    {
        _sut = new ClientsController(_clientStore, _eventHub, _clientRoleStore, _clientImpersonationStore);
    }

    [Fact]
    public async Task GetClientActors_UnknownClient_Returns404_AndNeverAsksTheStore()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.GetClientActors(ClientId);

        result.Should().BeOfType<NotFoundObjectResult>();
        await _clientImpersonationStore.DidNotReceiveWithAnyArgs().GetActorClientIdsAsync(default!);
    }

    [Fact]
    public async Task GetClientActors_EdgesPresent_ReturnsTheActorClientIds()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        _clientImpersonationStore.GetActorClientIdsAsync(client.RtId)
            .Returns(["octo-pipeline-sa-adapter-a", "octo-pipeline-sa-adapter-b"]);

        var result = await _sut.GetClientActors(ClientId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeAssignableTo<List<string>>().Subject.Should()
            .BeEquivalentTo("octo-pipeline-sa-adapter-a", "octo-pipeline-sa-adapter-b");
    }

    [Fact]
    public async Task GetClientActors_NoEdges_ReturnsAnEmptyList_Not404()
    {
        // "Exists but nobody may act for it" is an authoritative answer, distinct from
        // "unknown client" — the health consumer relies on that distinction.
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        _clientStore.FindRtClientByIdAsync(ClientId).Returns(client);
        _clientImpersonationStore.GetActorClientIdsAsync(client.RtId).Returns([]);

        var result = await _sut.GetClientActors(ClientId);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        ok.Value.Should().BeAssignableTo<List<string>>().Subject.Should().BeEmpty();
    }
}
