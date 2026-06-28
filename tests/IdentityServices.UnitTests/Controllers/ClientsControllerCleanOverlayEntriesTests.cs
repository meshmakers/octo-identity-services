using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     Behavioural pin-down for <c>DELETE /v1/clients/cleanOverlayEntries</c>
///     (AB#4209 Step 5 PR 1). The endpoint is the cleanup half of the overlay system
///     — these tests lock the contract that filtering by name strips only that name,
///     no name strips every <c>overlay:*</c> source, and base / api / family entries
///     are always preserved. Mirrors the source-taxonomy table in the concept doc §4.5.
/// </summary>
public class ClientsControllerCleanOverlayEntriesTests
{
    private const string TenantId = "octosystem";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();
    private readonly ClientsController _sut;

    public ClientsControllerCleanOverlayEntriesTests()
    {
        _clientStore.TenantId.Returns(TenantId);
        _sut = new ClientsController(_clientStore, _eventHub, _clientRoleStore);
    }

    [Fact]
    public async Task CleanOverlayEntries_NoClients_ReturnsZeroCountsAndDoesNotPersist()
    {
        _clientStore.GetClients().Returns(Array.Empty<RtClient>());

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.OverlayName.Should().BeNull();
        dto.ClientsAffected.Should().Be(0);
        dto.TotalEntriesRemoved.Should().Be(0);
        dto.ClientResults.Should().BeEmpty();

        await _clientStore.DidNotReceiveWithAnyArgs().UpdateAsync(default!, default!);
    }

    [Fact]
    public async Task CleanOverlayEntries_NoOverlayEntries_SkipsUpdateAndCacheBust()
    {
        // Single client carrying only base entries — nothing to strip, the endpoint must
        // skip UpdateAsync entirely. Mirrors the ApplyOverlayUris no-op contract.
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .WithRedirectUris("https://studio.example/")
            .Build();
        _clientStore.GetClients().Returns(new[] { client });

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.ClientsAffected.Should().Be(0);
        dto.TotalEntriesRemoved.Should().Be(0);

        await _clientStore.DidNotReceiveWithAnyArgs().UpdateAsync(default!, default!);
    }

    [Fact]
    public async Task CleanOverlayEntries_WithoutName_StripsAllOverlaySources()
    {
        // Mixed overlay names + base + api entries. Without -overlayName the endpoint
        // strips every overlay:* but keeps everything else.
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .Build();
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "https://studio.example/",
            Source = ClientUriSources.Base
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://localhost:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "local-dev"
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://gerald.local:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "gerald-laptop"
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "https://partner.example/callback",
            Source = ClientUriSources.Api
        });
        _clientStore.GetClients().Returns(new[] { client });

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.ClientsAffected.Should().Be(1);
        dto.TotalEntriesRemoved.Should().Be(2);
        dto.ClientResults.Should().ContainSingle();
        dto.ClientResults[0].ClientId.Should().Be("octo-data-refinery-studio");
        dto.ClientResults[0].RedirectUrisRemoved.Should().Be(2);

        // Base + api survive; both overlay:* entries are gone.
        client.RedirectUris.Should().HaveCount(2);
        client.RedirectUris.Select(e => e.Source).Should().BeEquivalentTo(
            ClientUriSources.Base, ClientUriSources.Api);

        await _clientStore.Received(1).UpdateAsync("octo-data-refinery-studio", client);
    }

    [Fact]
    public async Task CleanOverlayEntries_WithName_StripsOnlyMatchingOverlay()
    {
        // Per-overlay clean: gerald-laptop entries vanish, local-dev survives.
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .Build();
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "https://studio.example/",
            Source = ClientUriSources.Base
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://localhost:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "local-dev"
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://gerald.local:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "gerald-laptop"
        });
        _clientStore.GetClients().Returns(new[] { client });

        var result = await _sut.CleanOverlayEntries(overlayName: "gerald-laptop");

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.OverlayName.Should().Be("gerald-laptop");
        dto.TotalEntriesRemoved.Should().Be(1);

        client.RedirectUris.Should().HaveCount(2);
        client.RedirectUris.Select(e => e.Source).Should().BeEquivalentTo(
            ClientUriSources.Base, ClientUriSources.OverlayPrefix + "local-dev");
    }

    [Fact]
    public async Task CleanOverlayEntries_PreservesFamilyEntries()
    {
        // Family entries are NOT overlay-sourced; they must survive every clean run.
        // The cleanup gate's load-bearing rule is "Source != base survives blueprint
        // re-apply"; the dump-clean filter's mirror rule is "only overlay:* gets stripped".
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .Build();
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://localhost:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "local-dev"
        });
        client.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "https://studio.test.octo-mesh.com/",
            Source = ClientUriSources.FamilyPrefix + "test"
        });
        _clientStore.GetClients().Returns(new[] { client });

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.TotalEntriesRemoved.Should().Be(1);

        client.RedirectUris.Should().ContainSingle();
        client.RedirectUris[0].Source.Should().Be(ClientUriSources.FamilyPrefix + "test");
    }

    [Fact]
    public async Task CleanOverlayEntries_StripsAcrossAllThreeUriLists()
    {
        var client = new RtClientBuilder()
            .WithClientId("octo-data-refinery-studio")
            .Build();
        var overlaySource = ClientUriSources.OverlayPrefix + "local-dev";
        client.RedirectUris.Add(new RtClientUriEntryRecord { Uri = "x1", Source = overlaySource });
        client.PostLogoutRedirectUris.Add(new RtClientUriEntryRecord { Uri = "x2", Source = overlaySource });
        client.AllowedCorsOrigins.Add(new RtClientUriEntryRecord { Uri = "x3", Source = overlaySource });
        client.AllowedCorsOrigins.Add(new RtClientUriEntryRecord { Uri = "x4", Source = overlaySource });
        _clientStore.GetClients().Returns(new[] { client });

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.TotalEntriesRemoved.Should().Be(4);
        dto.ClientResults.Should().ContainSingle();
        dto.ClientResults[0].RedirectUrisRemoved.Should().Be(1);
        dto.ClientResults[0].PostLogoutRedirectUrisRemoved.Should().Be(1);
        dto.ClientResults[0].AllowedCorsOriginsRemoved.Should().Be(2);
    }

    [Fact]
    public async Task CleanOverlayEntries_MultipleClients_OnlyAffectedReported()
    {
        var withOverlay = new RtClientBuilder().WithClientId("octo-data-refinery-studio").Build();
        withOverlay.RedirectUris.Add(new RtClientUriEntryRecord
        {
            Uri = "http://localhost:4200/auth-callback",
            Source = ClientUriSources.OverlayPrefix + "local-dev"
        });

        var withoutOverlay = new RtClientBuilder()
            .WithClientId("octo-cli")
            .WithRedirectUris("https://cli.example/callback")
            .Build();

        _clientStore.GetClients().Returns(new[] { withOverlay, withoutOverlay });

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<CleanOverlayEntriesResultDto>().Subject;
        dto.ClientsAffected.Should().Be(1);
        dto.ClientResults.Should().ContainSingle();
        dto.ClientResults[0].ClientId.Should().Be("octo-data-refinery-studio");

        // Only the affected client triggers UpdateAsync.
        await _clientStore.Received(1).UpdateAsync("octo-data-refinery-studio", withOverlay);
        await _clientStore.DidNotReceive().UpdateAsync("octo-cli", Arg.Any<RtClient>());
    }

    [Fact]
    public async Task CleanOverlayEntries_InvalidOverlayName_Returns400()
    {
        var result = await _sut.CleanOverlayEntries(overlayName: "bad name with space");

        result.Should().BeOfType<BadRequestObjectResult>();
        await _clientStore.DidNotReceiveWithAnyArgs().GetClients();
    }

    [Fact]
    public async Task CleanOverlayEntries_NullName_AllowedAndStripsAll()
    {
        // Null query param should NOT trip the regex validation — it means "match all
        // overlay:* prefixes", not "match an invalid empty name".
        _clientStore.GetClients().Returns(Array.Empty<RtClient>());

        var result = await _sut.CleanOverlayEntries(overlayName: null);

        result.Should().BeOfType<OkObjectResult>();
    }
}
