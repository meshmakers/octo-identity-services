using FluentAssertions;
using IdentityServerPersistence.Services.SelfService;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the per-user outbound channel preference (AB#5149): a channel is only stored while the
///     user holds a VALID verified binding of the channel's identifier kind (TEAMS ⇒ EntraIdObjectId,
///     SIGNAL ⇒ PhoneNumber), the stored value is always the canonical uppercase spelling (the
///     cross-repo contract the mesh adapter propagates verbatim), clearing is always allowed, and a
///     refusal never touches the user.
/// </summary>
public class PreferredChannelServiceTests
{
    private readonly IVerifiedIdentifierResolver _resolver = Substitute.For<IVerifiedIdentifierResolver>();
    private readonly UserManager<RtUser> _userManager;
    private readonly PreferredChannelService _service;
    private readonly RtUser _user = new() { RtId = OctoObjectId.GenerateNewId(), UserName = "alice" };

    public PreferredChannelServiceTests()
    {
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore, null, null, null, null, null, null, null, null);
        _userManager.UpdateAsync(Arg.Any<RtUser>()).Returns(IdentityResult.Success);

        _resolver.GetByUserAsync(Arg.Any<OctoObjectId>())
            .Returns(Array.Empty<VerifiedIdentifierSummary>());

        _service = new PreferredChannelService(_resolver, _userManager,
            Substitute.For<ILogger<PreferredChannelService>>());
    }

    private void GivenBindings(params (RtIdentifierKindEnum Kind, bool IsValid)[] bindings)
    {
        var summaries = bindings.Select(b => new VerifiedIdentifierSummary(
                OctoObjectId.GenerateNewId(), b.Kind, "value-" + b.Kind,
                RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.SelfService,
                EnrolledAt: null, LastVerifiedAt: null, ValidUntil: null, IsValid: b.IsValid))
            .ToList();
        _resolver.GetByUserAsync(_user.RtId).Returns(summaries);
    }

    [Fact]
    public async Task Signal_with_a_valid_phone_binding_is_stored_canonically()
    {
        GivenBindings((RtIdentifierKindEnum.PhoneNumber, true));

        var result = await _service.SetPreferredChannelAsync(_user, "signal");

        result.Status.Should().Be(SetPreferredChannelStatus.Set);
        result.PreferredChannel.Should().Be("SIGNAL");
        _user.PreferredChannel.Should().Be("SIGNAL");
        await _userManager.Received(1).UpdateAsync(_user);
    }

    [Fact]
    public async Task Teams_requires_an_entra_id_binding_not_a_phone_binding()
    {
        GivenBindings((RtIdentifierKindEnum.PhoneNumber, true));

        var result = await _service.SetPreferredChannelAsync(_user, "TEAMS");

        result.Status.Should().Be(SetPreferredChannelStatus.ChannelNotBound);
        _user.PreferredChannel.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task Teams_with_a_valid_entra_id_binding_is_stored()
    {
        GivenBindings((RtIdentifierKindEnum.EntraIdObjectId, true));

        var result = await _service.SetPreferredChannelAsync(_user, "Teams");

        result.Status.Should().Be(SetPreferredChannelStatus.Set);
        result.PreferredChannel.Should().Be("TEAMS");
        _user.PreferredChannel.Should().Be("TEAMS");
    }

    [Fact]
    public async Task An_invalid_binding_does_not_qualify()
    {
        // IsValid folds expiry in — an expired binding must not keep the channel selectable.
        GivenBindings((RtIdentifierKindEnum.PhoneNumber, false));

        var result = await _service.SetPreferredChannelAsync(_user, "SIGNAL");

        result.Status.Should().Be(SetPreferredChannelStatus.ChannelNotBound);
        _user.PreferredChannel.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task An_email_binding_qualifies_for_no_channel_today()
    {
        GivenBindings((RtIdentifierKindEnum.EmailAddress, true));

        (await _service.SetPreferredChannelAsync(_user, "TEAMS")).Status
            .Should().Be(SetPreferredChannelStatus.ChannelNotBound);
        (await _service.SetPreferredChannelAsync(_user, "SIGNAL")).Status
            .Should().Be(SetPreferredChannelStatus.ChannelNotBound);
    }

    [Fact]
    public async Task An_unknown_channel_is_refused_without_touching_the_user()
    {
        GivenBindings((RtIdentifierKindEnum.PhoneNumber, true), (RtIdentifierKindEnum.EntraIdObjectId, true));

        var result = await _service.SetPreferredChannelAsync(_user, "CARRIER-PIGEON");

        result.Status.Should().Be(SetPreferredChannelStatus.UnknownChannel);
        _user.PreferredChannel.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task Clearing_is_always_allowed_even_without_any_binding()
    {
        _user.PreferredChannel = "TEAMS";

        var result = await _service.SetPreferredChannelAsync(_user, null);

        result.Status.Should().Be(SetPreferredChannelStatus.Cleared);
        result.PreferredChannel.Should().BeNull();
        _user.PreferredChannel.Should().BeNull();
        await _userManager.Received(1).UpdateAsync(_user);
    }

    [Fact]
    public async Task Clearing_an_already_clear_preference_is_a_no_op_write()
    {
        var result = await _service.SetPreferredChannelAsync(_user, "  ");

        result.Status.Should().Be(SetPreferredChannelStatus.Cleared);
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task A_refused_change_keeps_the_existing_preference()
    {
        GivenBindings((RtIdentifierKindEnum.PhoneNumber, true));
        _user.PreferredChannel = "SIGNAL";

        var result = await _service.SetPreferredChannelAsync(_user, "TEAMS");

        result.Status.Should().Be(SetPreferredChannelStatus.ChannelNotBound);
        result.PreferredChannel.Should().Be("SIGNAL");
        _user.PreferredChannel.Should().Be("SIGNAL");
    }

    [Fact]
    public void The_supported_channels_are_the_cross_repo_contract_spellings()
    {
        // WriteVerifiedCaller@1 emits these verbatim as "preferredChannel" — exact spellings are load-bearing.
        _service.SupportedChannels.Should().Equal("TEAMS", "SIGNAL");
    }
}
