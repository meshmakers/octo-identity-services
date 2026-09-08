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
///     Pins the binding-specific per-user outbound channel preference (AB#5149, revised): the user
///     stores the rtId of one of their OWN valid verified bindings, the channel kind is DERIVED from
///     the referenced binding (PhoneNumber ⇒ SIGNAL, EntraIdObjectId ⇒ TEAMS), only eligible
///     bindings are offered as options, clearing is always allowed, a refusal never touches the
///     user, and deleting the referenced binding clears the preference in the same operation.
/// </summary>
public class PreferredChannelServiceTests
{
    private readonly IVerifiedIdentifierResolver _resolver = Substitute.For<IVerifiedIdentifierResolver>();
    private readonly UserManager<RtUser> _userManager;
    private readonly PreferredChannelService _service;
    private readonly RtUser _user = new() { RtId = OctoObjectId.GenerateNewId(), UserName = "alice" };
    private readonly List<VerifiedIdentifierSummary> _bindings = [];

    public PreferredChannelServiceTests()
    {
        var userStore = Substitute.For<IUserStore<RtUser>>();
        _userManager = Substitute.For<UserManager<RtUser>>(
            userStore, null, null, null, null, null, null, null, null);
        _userManager.UpdateAsync(Arg.Any<RtUser>()).Returns(IdentityResult.Success);

        _resolver.GetByUserAsync(Arg.Any<OctoObjectId>())
            .Returns(Array.Empty<VerifiedIdentifierSummary>());
        _resolver.GetByUserAsync(_user.RtId).Returns(_ => _bindings);

        _service = new PreferredChannelService(_resolver, _userManager,
            Substitute.For<ILogger<PreferredChannelService>>());
    }

    private OctoObjectId GivenBinding(RtIdentifierKindEnum kind, bool isValid = true, string? value = null)
    {
        var rtId = OctoObjectId.GenerateNewId();
        _bindings.Add(new VerifiedIdentifierSummary(
            rtId, kind, value ?? "value-" + kind,
            RtTrustLevelEnum.Strong, RtIdentifierSourceEnum.SelfService,
            EnrolledAt: null, LastVerifiedAt: null, ValidUntil: null, IsValid: isValid));
        return rtId;
    }

    [Fact]
    public async Task A_valid_phone_binding_is_stored_and_derives_signal()
    {
        var bindingId = GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436601234567");

        var result = await _service.SetPreferredChannelAsync(_user, bindingId.ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.Set);
        result.Selection.BindingId.Should().Be(bindingId);
        result.Selection.Channel.Should().Be("SIGNAL");
        result.Selection.IdentifierValue.Should().Be("+436601234567");
        _user.PreferredChannelBindingId.Should().Be(bindingId.ToString());
        await _userManager.Received(1).UpdateAsync(_user);
    }

    [Fact]
    public async Task A_valid_entra_id_binding_derives_teams()
    {
        var bindingId = GivenBinding(RtIdentifierKindEnum.EntraIdObjectId);

        var result = await _service.SetPreferredChannelAsync(_user, bindingId.ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.Set);
        result.Selection.Channel.Should().Be("TEAMS");
        _user.PreferredChannelBindingId.Should().Be(bindingId.ToString());
    }

    [Fact]
    public async Task With_two_phone_bindings_the_chosen_number_wins()
    {
        GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436601111111");
        var second = GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436602222222");

        var result = await _service.SetPreferredChannelAsync(_user, second.ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.Set);
        result.Selection.IdentifierValue.Should().Be("+436602222222");
        _user.PreferredChannelBindingId.Should().Be(second.ToString());
    }

    [Fact]
    public async Task An_invalid_binding_does_not_qualify()
    {
        // IsValid folds expiry in — an expired binding must not be selectable.
        var bindingId = GivenBinding(RtIdentifierKindEnum.PhoneNumber, isValid: false);

        var result = await _service.SetPreferredChannelAsync(_user, bindingId.ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        _user.PreferredChannelBindingId.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task A_binding_of_an_unmapped_kind_does_not_qualify()
    {
        var emailBinding = GivenBinding(RtIdentifierKindEnum.EmailAddress);
        var certBinding = GivenBinding(RtIdentifierKindEnum.ClientCertificateFingerprint);

        (await _service.SetPreferredChannelAsync(_user, emailBinding.ToString())).Status
            .Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        (await _service.SetPreferredChannelAsync(_user, certBinding.ToString())).Status
            .Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task A_foreign_or_unknown_binding_id_is_refused_without_touching_the_user()
    {
        GivenBinding(RtIdentifierKindEnum.PhoneNumber);

        var result = await _service.SetPreferredChannelAsync(_user, OctoObjectId.GenerateNewId().ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        _user.PreferredChannelBindingId.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task A_malformed_binding_id_is_refused_without_touching_the_user()
    {
        GivenBinding(RtIdentifierKindEnum.PhoneNumber);

        var result = await _service.SetPreferredChannelAsync(_user, "not-a-binding-id");

        result.Status.Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        _user.PreferredChannelBindingId.Should().BeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task Clearing_is_always_allowed_even_without_any_binding()
    {
        _user.PreferredChannelBindingId = OctoObjectId.GenerateNewId().ToString();

        var result = await _service.SetPreferredChannelAsync(_user, null);

        result.Status.Should().Be(SetPreferredChannelStatus.Cleared);
        result.Selection.Should().Be(PreferredChannelSelection.None);
        _user.PreferredChannelBindingId.Should().BeNull();
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
        var existing = GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436601234567");
        _user.PreferredChannelBindingId = existing.ToString();

        var result = await _service.SetPreferredChannelAsync(_user, OctoObjectId.GenerateNewId().ToString());

        result.Status.Should().Be(SetPreferredChannelStatus.BindingNotEligible);
        result.Selection.BindingId.Should().Be(existing);
        result.Selection.Channel.Should().Be("SIGNAL");
        _user.PreferredChannelBindingId.Should().Be(existing.ToString());
    }

    [Fact]
    public async Task The_options_list_only_offers_valid_channel_mapped_bindings()
    {
        var phone = GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436601234567");
        var entra = GivenBinding(RtIdentifierKindEnum.EntraIdObjectId, value: "oid-1");
        GivenBinding(RtIdentifierKindEnum.PhoneNumber, isValid: false, value: "+436609999999");
        GivenBinding(RtIdentifierKindEnum.EmailAddress, value: "alice@example.com");
        GivenBinding(RtIdentifierKindEnum.ClientCertificateFingerprint, value: "AA:BB");

        var options = await _service.GetOptionsAsync(_user);

        options.Should().HaveCount(2);
        options.Should().ContainSingle(o => o.BindingId == phone)
            .Which.Channel.Should().Be("SIGNAL");
        options.Should().ContainSingle(o => o.BindingId == entra)
            .Which.Channel.Should().Be("TEAMS");
    }

    [Fact]
    public async Task The_selection_resolves_channel_and_value_from_the_referenced_binding()
    {
        var bindingId = GivenBinding(RtIdentifierKindEnum.PhoneNumber, value: "+436601234567");
        _user.PreferredChannelBindingId = bindingId.ToString();

        var selection = await _service.GetSelectionAsync(_user);

        selection.BindingId.Should().Be(bindingId);
        selection.Channel.Should().Be("SIGNAL");
        selection.IdentifierValue.Should().Be("+436601234567");
    }

    [Fact]
    public async Task A_dangling_stored_reference_reads_as_no_preference_without_writing()
    {
        // Binding removed outside the self-service path: reads never write, consumers see "none".
        _user.PreferredChannelBindingId = OctoObjectId.GenerateNewId().ToString();

        var selection = await _service.GetSelectionAsync(_user);

        selection.Should().Be(PreferredChannelSelection.None);
        _user.PreferredChannelBindingId.Should().NotBeNull();
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }

    [Fact]
    public async Task Removing_the_referenced_binding_clears_the_preference()
    {
        var bindingId = OctoObjectId.GenerateNewId();
        _user.PreferredChannelBindingId = bindingId.ToString();

        await _service.ClearIfReferencedAsync(_user, bindingId);

        _user.PreferredChannelBindingId.Should().BeNull();
        await _userManager.Received(1).UpdateAsync(_user);
    }

    [Fact]
    public async Task Removing_an_unreferenced_binding_leaves_the_preference_alone()
    {
        var keep = OctoObjectId.GenerateNewId();
        _user.PreferredChannelBindingId = keep.ToString();

        await _service.ClearIfReferencedAsync(_user, OctoObjectId.GenerateNewId());

        _user.PreferredChannelBindingId.Should().Be(keep.ToString());
        await _userManager.DidNotReceive().UpdateAsync(Arg.Any<RtUser>());
    }
}
