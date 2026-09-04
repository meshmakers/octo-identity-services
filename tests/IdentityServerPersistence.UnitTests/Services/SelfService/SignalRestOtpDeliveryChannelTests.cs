using System.Net;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services.SelfService;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the AB#5134 Signal OTP transport: it POSTs the signal-cli-rest-api <c>/v2/send</c> contract
///     ({ number, recipients, message }) to <c>{ApiUrl}/v2/send</c> with the configured sender and the
///     destination, the message carries the one-time code, and a non-success bridge response makes
///     <see cref="SignalRestOtpDeliveryChannel.DeliverAsync" /> THROW (so the OTP service never tells the
///     user a code was sent when it was not).
/// </summary>
public class SignalRestOtpDeliveryChannelTests
{
    private const string ApiUrl = "http://localhost:8080";
    private const string Sender = "+4366012345678";
    private const string Destination = "+436609876543";
    private const string Code = "123456";

    private static OtpDeliveryContext Context() =>
        new("acme", Destination, Code, TimeSpan.FromMinutes(5), "alice");

    private static SignalRestOtpDeliveryChannel CreateChannel(CapturingHandler handler, string? number = Sender)
    {
        var options = Options.Create(new SignalBridgeOptions
        {
            ApiUrl = ApiUrl,
            Number = number,
            TimeoutSeconds = 30
        });
        return new SignalRestOtpDeliveryChannel(
            new SingleClientHttpClientFactory(handler),
            options,
            NullLogger<SignalRestOtpDeliveryChannel>.Instance);
    }

    [Fact]
    public async Task DeliverAsync_posts_v2_send_with_bridge_contract()
    {
        var handler = new CapturingHandler(HttpStatusCode.Created);
        var channel = CreateChannel(handler);

        await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        handler.Request.Should().NotBeNull();
        handler.Request!.Method.Should().Be(HttpMethod.Post);
        handler.Request.RequestUri!.ToString().Should().Be($"{ApiUrl}/v2/send");

        using var doc = JsonDocument.Parse(handler.Body!);
        var root = doc.RootElement;
        root.GetProperty("number").GetString().Should().Be(Sender);
        var recipients = root.GetProperty("recipients").EnumerateArray().Select(e => e.GetString()).ToArray();
        recipients.Should().ContainSingle().Which.Should().Be(Destination);
        root.GetProperty("message").GetString().Should().Contain(Code);
    }

    [Fact]
    public async Task DeliverAsync_throws_on_non_success_response()
    {
        var handler = new CapturingHandler(HttpStatusCode.BadGateway, "bridge down");
        var channel = CreateChannel(handler);

        var act = () => channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<InvalidOperationException>())
            .Which.Message.Should().Contain("502");
    }

    [Fact]
    public async Task DeliverAsync_throws_when_sender_number_missing()
    {
        var handler = new CapturingHandler(HttpStatusCode.OK);
        var channel = CreateChannel(handler, number: null);

        var act = () => channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
        handler.Request.Should().BeNull("no request must be sent when the bridge is misconfigured");
    }

    /// <summary>Captures the single outbound request and returns a canned response.</summary>
    private sealed class CapturingHandler(HttpStatusCode statusCode, string responseBody = "")
        : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(statusCode) { Content = new StringContent(responseBody) };
        }
    }

    /// <summary>Minimal <see cref="IHttpClientFactory" /> handing back a client over the fake handler.</summary>
    private sealed class SingleClientHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
