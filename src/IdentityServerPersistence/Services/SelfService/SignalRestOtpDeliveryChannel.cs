using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using IdentityServerPersistence.Configuration.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     Real phone-OTP delivery over the <c>signal-cli-rest-api</c> bridge (AB#5134), replacing the
///     <see cref="LoggingOtpDeliveryChannel" /> dev stub for the <see cref="OtpDeliveryChannelKind.Signal" />
///     modality when the bridge is configured (<see cref="SignalBridgeOptions.ApiUrl" /> non-empty).
///     Sends <c>POST {ApiUrl}/v2/send</c> with <c>{ number, recipients, message }</c> — the same wire
///     contract the mesh adapter's <c>SignalSender</c> pipeline node uses. The bridge is local and
///     unauthenticated; the only secret that leaves identity-services is the one-time code itself.
/// </summary>
/// <remarks>
///     REVIEW: this is a direct HTTP call from identity-services to the local bridge. The longer-term
///     seam (noted on <see cref="LoggingOtpDeliveryChannel" />) is to publish a Signal notification
///     onto the distribution event hub — the same seam <c>NotificationService</c> uses for e-mail — so
///     the tenant's Signal adapter delivers it. That move is deliberately out of scope here (AB#5134):
///     it needs a Signal notification contract + consumer that does not yet exist. Keep this channel as
///     the concrete transport until that seam lands.
/// </remarks>
public sealed class SignalRestOtpDeliveryChannel : IOtpDeliveryChannel
{
    /// <summary>Named <see cref="HttpClient" /> this channel resolves from the factory.</summary>
    public const string HttpClientName = "SignalBridge";

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SignalRestOtpDeliveryChannel> _logger;
    private readonly SignalBridgeOptions _options;

    public SignalRestOtpDeliveryChannel(
        IHttpClientFactory httpClientFactory,
        IOptions<SignalBridgeOptions> options,
        ILogger<SignalRestOtpDeliveryChannel> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _options = options.Value;
    }

    public OtpDeliveryChannelKind Kind => OtpDeliveryChannelKind.Signal;

    public async Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiUrl))
        {
            // Registration only picks this channel when ApiUrl is set; this guards a misconfiguration
            // (and keeps the THROW-on-cannot-attempt contract) rather than silently no-op'ing.
            throw new InvalidOperationException(
                "Signal bridge OTP delivery is not configured (SignalBridge:ApiUrl is empty).");
        }

        if (string.IsNullOrWhiteSpace(_options.Number))
        {
            throw new InvalidOperationException(
                "Signal bridge OTP delivery is not configured (SignalBridge:Number is empty).");
        }

        var message = BuildMessage(context);
        var payload = new SignalSendPayload(_options.Number!, [context.Destination], message);
        var payloadJson = JsonSerializer.Serialize(payload, SerializerOptions);

        var url = $"{_options.ApiUrl!.TrimEnd('/')}/v2/send";

        // Never log the raw code at Information or above — only the destination and outcome.
        _logger.LogInformation(
            "[{TenantId}] AB#5123 sending phone OTP via Signal bridge to '{Destination}' (valid {TtlMinutes} min).",
            context.TenantId, context.Destination, (int)context.Ttl.TotalMinutes);

        var client = _httpClientFactory.CreateClient(HttpClientName);

        using var content = new StringContent(payloadJson, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        // Honour both the caller's cancellation token and the configured per-request timeout.
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var timeoutSeconds = _options.TimeoutSeconds > 0 ? _options.TimeoutSeconds : 30;
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        HttpResponseMessage response;
        try
        {
            response = await client.PostAsync(url, content, timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Timed out (not caller-cancelled) — surface as a failed delivery attempt.
            throw new InvalidOperationException(
                $"Signal bridge OTP delivery to '{context.Destination}' timed out after {timeoutSeconds}s.");
        }

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                return;
            }

            // Read a short reason for diagnostics; the OTP code is never in a response body.
            string reason;
            try
            {
                reason = await response.Content.ReadAsStringAsync(cancellationToken);
            }
            catch (Exception)
            {
                reason = string.Empty;
            }

            if (reason.Length > 500)
            {
                reason = reason[..500];
            }

            throw new InvalidOperationException(
                $"Signal bridge OTP delivery to '{context.Destination}' failed: " +
                $"{(int)response.StatusCode} {response.ReasonPhrase}. {reason}".TrimEnd());
        }
    }

    private static string BuildMessage(OtpDeliveryContext context)
    {
        var minutes = Math.Max(1, (int)Math.Round(context.Ttl.TotalMinutes));
        var greeting = string.IsNullOrWhiteSpace(context.UserName) ? string.Empty : $"{context.UserName}, ";
        return $"{greeting}your OctoMesh verification code is {context.Code}. " +
               $"It is valid for {minutes} minute{(minutes == 1 ? string.Empty : "s")}. " +
               "If you did not request it, you can ignore this message.";
    }

    /// <summary>
    ///     signal-cli-rest-api <c>/v2/send</c> body. Mirrors the mesh adapter's <c>SignalSendPayload</c>
    ///     (number / recipients / message); attachments are not needed for an OTP.
    /// </summary>
    private sealed record SignalSendPayload(
        [property: JsonPropertyName("number")] string Number,
        [property: JsonPropertyName("recipients")] IReadOnlyList<string> Recipients,
        [property: JsonPropertyName("message")] string Message);
}
