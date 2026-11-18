using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Http;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Microsoft.AspNetCore.Identity;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Mvc;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     Behavioural pin-down for <c>POST /v1/clients/{id}/overlayUris</c> (AB#4209 Step 4 PR 1).
///     The endpoint is the foundation the octo-cli command + octo-tools cmdlet stack on top of —
///     these tests lock the contract that <c>Source = "overlay:&lt;OverlayName&gt;"</c> is the
///     persisted marker, dedup-by-URI is the conflict rule, and the re-run is a no-op.
/// </summary>
public class ClientsControllerOverlayUrisTests
{
    private const string TenantId = "octosystem";
    private const string ClientId = "octo-data-refinery-studio";
    private const string OverlayName = "local-dev";

    private readonly IOctoClientStore _clientStore = Substitute.For<IOctoClientStore>();
    private readonly IDistributionEventHubService _eventHub = Substitute.For<IDistributionEventHubService>();
    private readonly IClientRoleStore _clientRoleStore = Substitute.For<IClientRoleStore>();

    private readonly IClientImpersonationStore _clientImpersonationStore =
        Substitute.For<IClientImpersonationStore>();
    private readonly ClientsController _sut;
    private readonly HandlerBackedMethodFacade _methods;
    private readonly List<string> _writes;

    public ClientsControllerOverlayUrisTests()
    {
        _clientStore.TenantId.Returns(TenantId);
        _writes = ClientStoreMutations.Attach(_clientStore);
        // The endpoint is a facade of Client.ApplyOverlayUris: the real handler runs behind it.
        _methods = new HandlerBackedMethodFacade(_clientStore, eventHub: _eventHub);
        _sut = new ClientsController(_clientStore, _clientRoleStore, _clientImpersonationStore,
            Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null, null, null, null),
            Substitute.For<IRoleChangeRefusals>(), _methods)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() }
        };
    }

    private void Given(RtClient client) => _clientStore.FindRtClientByIdAsync(ClientId).Returns(_methods.Know(client));

    [Fact]
    public async Task ApplyOverlayUris_UnknownClient_Returns404()
    {
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:5173/" }
        });

        result.Should().BeOfType<NotFoundObjectResult>();
        _writes.Should().BeEmpty();
    }

    [Fact]
    public async Task ApplyOverlayUris_UnknownClient_WithoutAnyUri_Is400_AsBefore()
    {
        // REST contract: the request without a non-blank URI is refused before the client is looked up.
        _clientStore.FindRtClientByIdAsync(ClientId).Returns((RtClient?)null);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "  " }
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        await _clientStore.DidNotReceiveWithAnyArgs().FindRtClientByIdAsync(default!);
        _methods.Audit.Records.Should().BeEmpty();
    }

    [Fact]
    public async Task ApplyOverlayUris_AllListsEmpty_Returns400_AndDoesNotPersist()
    {
        // Defensive — the endpoint requires at least one URI across the three lists. Without
        // this the caller could no-op-update a client and bump rtChangedDateTime / cache-bust
        // for no reason.
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName
            // all three URI lists null
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        _writes.Should().BeEmpty();
    }

    [Fact]
    public async Task ApplyOverlayUris_AppendsNewEntries_TaggedOverlayPrefixSource()
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithRedirectUris("https://studio.example/")    // existing base entry
            .Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/", "https://localhost:5173/" }
        });

        var ok = result.Should().BeOfType<OkObjectResult>().Subject;
        var dto = ok.Value.Should().BeOfType<ApplyOverlayUrisResultDto>().Subject;
        dto.OverlayName.Should().Be(OverlayName);
        dto.ClientId.Should().Be(ClientId);
        dto.RedirectUris.Added.Should().Be(2);
        dto.RedirectUris.SkippedDuplicate.Should().Be(0);

        // The two new entries must carry the overlay-source marker so Step 2a preserves them
        // across blueprint re-apply.
        client.RedirectUris.Should().HaveCount(3);
        client.RedirectUris.Skip(1).Should()
            .OnlyContain(e => e.Source == ClientUriSources.OverlayPrefix + OverlayName);
        client.RedirectUris.Select(e => e.Uri).Should().Equal(
            "https://studio.example/",
            "https://localhost:4200/",
            "https://localhost:5173/");

        _writes.Should().Equal(ClientId);
    }

    [Fact]
    public async Task ApplyOverlayUris_DupedAgainstAnySource_SkippedNotDuplicated()
    {
        // Conflict policy: any existing source wins (base / api / overlay:* / family:*),
        // overlay-incoming entry is silently dropped — matches concept doc §4.3.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .Build();
        // Manually add a "base" entry + an "api" entry to prove neither gets duplicated.
        client.RedirectUris.Add(new RtClientUriEntryRecord
            { Uri = "https://studio.example/", Source = ClientUriSources.Base });
        client.RedirectUris.Add(new RtClientUriEntryRecord
            { Uri = "https://operator.example/", Source = ClientUriSources.Api });
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string>
            {
                "https://studio.example/",      // dup-base → skip
                "https://operator.example/",    // dup-api → skip
                "https://localhost:4200/"       // new → append
            }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        dto.RedirectUris.SkippedDuplicate.Should().Be(2);
        client.RedirectUris.Should().HaveCount(3);
    }

    [Fact]
    public async Task ApplyOverlayUris_IsIdempotent_OnSecondCallSameInput()
    {
        // The cmdlet may run on every Start-Octo or every CI pipeline. Re-applying the same
        // overlay must be a no-op — Added=0 across the board AND no DB write / cache bust.
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithRedirectUris("https://studio.example/")
            .Build();
        Given(client);

        var dto = new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" }
        };

        var first = (await _sut.ApplyOverlayUris(ClientId, dto)) as OkObjectResult;
        var second = (await _sut.ApplyOverlayUris(ClientId, dto)) as OkObjectResult;

        var firstDto = first!.Value as ApplyOverlayUrisResultDto;
        var secondDto = second!.Value as ApplyOverlayUrisResultDto;
        firstDto!.RedirectUris.Added.Should().Be(1);
        secondDto!.RedirectUris.Added.Should().Be(0);
        secondDto.RedirectUris.SkippedDuplicate.Should().Be(1);
        // List doesn't grow past the seeded + first-apply state.
        client.RedirectUris.Should().HaveCount(2);

        // The load-bearing part of the idempotency contract: only the first call writes.
        // The second call MUST short-circuit before the write (and the matching CorsClient
        // cache-bust publish) so the cmdlet's repeated Start-Octo / CI runs don't churn
        // rtChangedDateTime or invalidate the per-tenant CORS cache for nothing.
        _writes.Should().Equal(ClientId);
    }

    [Fact]
    public async Task ApplyOverlayUris_AddsUris_PublishesCorsClientsUpdate()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(client);

        await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            AllowedCorsOrigins = new List<string> { "https://localhost:5173" }
        });

        await _eventHub.Received(1).PublishAsync(
            Arg.Is<CorsClientsUpdate>(m => m.TenantId == TenantId));
    }

    [Fact]
    public async Task ApplyOverlayUris_NothingAdded_StillPublishesCorsClientsUpdate_WithoutPersisting()
    {
        // AB#5487: an idempotent re-apply is the obvious repair for a CORS policy that was cached before the
        // client's origins existed, so "0 added" must still refresh the cache - but not touch the DB.
        var client = new RtClientBuilder().WithClientId(ClientId).WithCorsOrigins("https://studio.example").Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            AllowedCorsOrigins = new List<string> { "https://studio.example" }
        });

        var dto = result.Should().BeOfType<OkObjectResult>().Subject.Value
            .Should().BeOfType<ApplyOverlayUrisResultDto>().Subject;
        dto.AllowedCorsOrigins.Added.Should().Be(0);
        _writes.Should().BeEmpty();
        await _eventHub.Received(1).PublishAsync(
            Arg.Is<CorsClientsUpdate>(m => m.TenantId == TenantId));
    }

    [Fact]
    public async Task ApplyOverlayUris_AllWhitespaceInput_Returns400_AndDoesNotPersist()
    {
        // Whitespace-only payload is the same intent as all-null — both are no-ops and the
        // endpoint should reject up front rather than silently load + walk the dedup path.
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "   ", "" },
            PostLogoutRedirectUris = new List<string> { "\t" }
        });

        result.Should().BeOfType<BadRequestObjectResult>();
        _writes.Should().BeEmpty();
    }

    [Fact]
    public async Task ApplyOverlayUris_AppliesToAllThreeListsIndependently()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" },
            PostLogoutRedirectUris = new List<string> { "https://localhost:4200/" },
            AllowedCorsOrigins = new List<string> { "https://localhost:4200" }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        dto.PostLogoutRedirectUris.Added.Should().Be(1);
        dto.AllowedCorsOrigins.Added.Should().Be(1);

        var overlaySource = ClientUriSources.OverlayPrefix + OverlayName;
        client.RedirectUris.Single().Source.Should().Be(overlaySource);
        client.PostLogoutRedirectUris.Single().Source.Should().Be(overlaySource);
        client.AllowedCorsOrigins.Single().Source.Should().Be(overlaySource);
    }

    [Fact]
    public async Task ApplyOverlayUris_SkipsWhitespaceOnlyInputUris()
    {
        var client = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(client);

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/", "   ", "" }
        });

        var dto = (result as OkObjectResult)!.Value as ApplyOverlayUrisResultDto;
        dto!.RedirectUris.Added.Should().Be(1);
        client.RedirectUris.Should().HaveCount(1);
        client.RedirectUris.Single().Uri.Should().Be("https://localhost:4200/");
    }

    [Fact]
    public async Task ApplyOverlayUris_TheClientIdWasTakenOverByAnotherClient_Is404_AndChangesNeither()
    {
        // The method targets the rtId; the store resolves the client id. A client that replaced the target under the same
        // client id between the load and the write is never changed.
        var original = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(original);
        var successor = new RtClientBuilder().WithClientId(ClientId).Build();
        successor.RtId = OctoObjectId.GenerateNewId();
        _clientStore.MutateAsync(ClientId, Arg.Any<Func<RtClient, bool>>()).Returns(call =>
            {
                call.ArgAt<Func<RtClient, bool>>(1)(successor);
                return successor;
            });

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" }
        });

        result.Should().BeOfType<NotFoundObjectResult>();
        successor.RedirectUris.Should().BeEmpty();
        original.RedirectUris.Should().BeEmpty();
    }

    [Fact]
    public async Task ApplyOverlayUris_ARetryThatFindsTheTargetAgain_IsASuccess()
    {
        // The store runs the change again after a version conflict; the second run decides.
        var original = new RtClientBuilder().WithClientId(ClientId).Build();
        Given(original);
        var successor = new RtClientBuilder().WithClientId(ClientId).Build();
        successor.RtId = OctoObjectId.GenerateNewId();
        _clientStore.MutateAsync(ClientId, Arg.Any<Func<RtClient, bool>>()).Returns(call =>
        {
            var mutate = call.ArgAt<Func<RtClient, bool>>(1);
            mutate(successor);
            mutate(original);
            return original;
        });

        var result = await _sut.ApplyOverlayUris(ClientId, new ApplyOverlayUrisDto
        {
            OverlayName = OverlayName,
            RedirectUris = new List<string> { "https://localhost:4200/" }
        });

        result.Should().BeOfType<OkObjectResult>();
        original.RedirectUris.Should().ContainSingle();
        successor.RedirectUris.Should().BeEmpty();
    }
}
