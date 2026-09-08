using System.Net;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services.SelfService;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the AB#5134 Signal OTP transport and its AB#5154 per-tenant sender resolution chain:
///     a Registered tenant <c>SignalChannel</c> wins over the env-bound
///     <see cref="SignalBridgeOptions" />; without one the options fallback keeps its unchanged
///     semantics (POST of the signal-cli-rest-api <c>/v2/send</c> contract
///     ({ number, recipients, message }) to <c>{ApiUrl}/v2/send</c>, THROW on a non-success bridge
///     response so the OTP service never tells the user a code was sent when it was not); and with
///     neither source the delivery lands on the <see cref="LoggingOtpDeliveryChannel" /> dev stub
///     path exactly as before.
/// </summary>
public class SignalRestOtpDeliveryChannelTests
{
    private const string ApiUrl = "http://localhost:8080";
    private const string Sender = "+4366012345678";
    private const string TenantApiUrl = "http://signal-bridge.octo:8080";
    private const string TenantSender = "+436770000001";
    private const string Destination = "+436609876543";
    private const string Code = "123456";

    private readonly ITenantSignalChannelResolver _tenantChannelResolver =
        Substitute.For<ITenantSignalChannelResolver>();

    private readonly RecordingLogger<LoggingOtpDeliveryChannel> _stubLogger = new();

    private static OtpDeliveryContext Context() =>
        new("acme", Destination, Code, TimeSpan.FromMinutes(5), "alice");

    private SignalRestOtpDeliveryChannel CreateChannel(
        CapturingHandler handler, string? apiUrl = ApiUrl, string? number = Sender)
    {
        var options = Options.Create(new SignalBridgeOptions
        {
            ApiUrl = apiUrl,
            Number = number,
            TimeoutSeconds = 30
        });
        return new SignalRestOtpDeliveryChannel(
            new SingleClientHttpClientFactory(handler),
            options,
            _tenantChannelResolver,
            new LoggingOtpDeliveryChannel(_stubLogger),
            NullLogger<SignalRestOtpDeliveryChannel>.Instance);
    }

    private void GivenTenantChannel(TenantSignalBridgeEndpoint? endpoint)
    {
        _tenantChannelResolver
            .ResolveRegisteredChannelAsync("acme", Arg.Any<CancellationToken>())
            .Returns(endpoint);
    }

    [Fact]
    public async Task DeliverAsync_posts_v2_send_with_bridge_contract()
    {
        GivenTenantChannel(null);
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
    public async Task DeliverAsync_uses_registered_tenant_channel_over_options()
    {
        // AB#5154: the tenant's Studio-activated SignalChannel wins over the env-bound options —
        // both the sender number and the bridge URL come from the tenant entity.
        GivenTenantChannel(new TenantSignalBridgeEndpoint(TenantApiUrl, TenantSender));
        var handler = new CapturingHandler(HttpStatusCode.Created);
        var channel = CreateChannel(handler);

        await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        handler.Request!.RequestUri!.ToString().Should().Be($"{TenantApiUrl}/v2/send");
        using var doc = JsonDocument.Parse(handler.Body!);
        doc.RootElement.GetProperty("number").GetString().Should().Be(TenantSender);
    }

    [Fact]
    public async Task DeliverAsync_falls_back_to_options_when_no_registered_tenant_channel()
    {
        // A channel present but not Registered resolves to null (resolver contract) — the send
        // falls through to the unchanged SignalBridgeOptions semantics.
        GivenTenantChannel(null);
        var handler = new CapturingHandler(HttpStatusCode.Created);
        var channel = CreateChannel(handler);

        await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        handler.Request!.RequestUri!.ToString().Should().Be($"{ApiUrl}/v2/send");
        using var doc = JsonDocument.Parse(handler.Body!);
        doc.RootElement.GetProperty("number").GetString().Should().Be(Sender);
    }

    [Fact]
    public async Task DeliverAsync_delegates_to_dev_stub_when_neither_source_is_configured()
    {
        // Neither a registered tenant channel nor options — the unconfigured behavior is the
        // LoggingOtpDeliveryChannel stub path: no HTTP request, no throw, the stub's loud warning.
        GivenTenantChannel(null);
        var handler = new CapturingHandler(HttpStatusCode.Created);
        var channel = CreateChannel(handler, apiUrl: null, number: null);

        await channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        handler.Request.Should().BeNull("no bridge request must be sent when nothing is configured");
        _stubLogger.Entries.Should().ContainSingle(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("OTP DELIVERY STUB"));
    }

    [Fact]
    public async Task DeliverAsync_throws_on_non_success_response()
    {
        GivenTenantChannel(null);
        var handler = new CapturingHandler(HttpStatusCode.BadGateway, "bridge down");
        var channel = CreateChannel(handler);

        var act = () => channel.DeliverAsync(Context(), TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<InvalidOperationException>())
            .Which.Message.Should().Contain("502");
    }

    [Fact]
    public async Task DeliverAsync_throws_when_fallback_sender_number_missing()
    {
        GivenTenantChannel(null);
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

    /// <summary>Records formatted log entries so the stub's warning path is assertable.</summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
