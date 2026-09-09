using FluentAssertions;
using IdentityServerPersistence.Services.SelfService;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the AB#5135 e-mail OTP transport: it REUSES identity's e-mail path by publishing a
///     <see cref="SendNotificationsRequest" /> (one <c>DistNotificationDto</c> to the enrolling
///     address, carrying the one-time code) onto the distribution event hub — no new SMTP client —
///     and a hub publish failure makes <see cref="NotificationEmailOtpDeliveryChannel.DeliverAsync" />
///     THROW so the OTP service never tells the user a code was sent when it was not.
/// </summary>
public class NotificationEmailOtpDeliveryChannelTests
{
    private const string TenantId = "acme";
    private const string Destination = "alice@example.com";
    private const string Code = "123456";

    private static OtpDeliveryContext Context() =>
        new(TenantId, Destination, Code, TimeSpan.FromMinutes(5), "alice");

    [Fact]
    public void Kind_is_email()
    {
        var channel = new NotificationEmailOtpDeliveryChannel(
            Substitute.For<IDistributionEventHubService>(),
            NullLogger<NotificationEmailOtpDeliveryChannel>.Instance);

        channel.Kind.Should().Be(OtpDeliveryChannelKind.Email);
    }

    [Fact]
    public async Task DeliverAsync_publishes_a_send_notifications_request_with_the_code_to_the_recipient()
    {
        var hub = Substitute.For<IDistributionEventHubService>();
        var channel = new NotificationEmailOtpDeliveryChannel(hub,
            NullLogger<NotificationEmailOtpDeliveryChannel>.Instance);

        await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        await hub.Received(1).PublishAsync(
            Arg.Is<SendNotificationsRequest>(r =>
                r.TenantId == TenantId &&
                r.Notifications.Count == 1 &&
                r.Notifications.Single().Recipient == Destination &&
                r.Notifications.Single().Body!.Contains(Code) &&
                !string.IsNullOrWhiteSpace(r.Notifications.Single().Subject)),
            Arg.Any<CancellationToken?>());
    }

    [Fact]
    public async Task DeliverAsync_throws_when_the_hub_publish_fails()
    {
        var hub = Substitute.For<IDistributionEventHubService>();
        hub.PublishAsync(Arg.Any<SendNotificationsRequest>(), Arg.Any<CancellationToken?>())
            .ThrowsAsync(new InvalidOperationException("hub down"));
        var channel = new NotificationEmailOtpDeliveryChannel(hub,
            NullLogger<NotificationEmailOtpDeliveryChannel>.Instance);

        var act = async () => await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }
}
