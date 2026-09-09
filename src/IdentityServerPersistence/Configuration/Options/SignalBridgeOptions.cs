// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace IdentityServerPersistence.Configuration.Options;

/// <summary>
///     <b>Local-dev fallback</b> connection to the <c>signal-cli-rest-api</c> bridge used to deliver
///     the self-service phone OTP over Signal (AB#5134, on top of the AB#5123
///     <see cref="Services.SelfService.IOtpDeliveryChannel" /> abstraction). Bound from the
///     <c>"SignalBridge"</c> configuration section in <c>Program.cs</c> — mirror of the <c>Oem</c> /
///     <c>OemOptions</c> binding.
/// </summary>
/// <remarks>
///     <para>
///         🔴 Since AB#5154 the sender number is <b>tenant state</b>, not deployment state:
///         production tenants use their Studio-activated
///         <c>System.Communication/SignalChannel</c> entity (AB#5143/5145 — Number + ApiUrl of the
///         channel in the <c>Registered</c> state), resolved per tenant at send time by
///         <see cref="Services.SelfService.ITenantSignalChannelResolver" />. These env-bound options
///         are only consulted when the tenant has NO registered channel — the local-dev path where
///         no Studio activation exists — so in cluster deployments the
///         <c>OCTO_SIGNALBRIDGE__*</c> variables are fully optional.
///     </para>
///     <para>
///         The bridge is the same local, unauthenticated HTTP endpoint the mesh adapter's
///         <c>SignalSender</c> pipeline node talks to (<c>POST {ApiUrl}/v2/send</c>). The bridge
///         holds the Signal credentials; identity-services only sends it the one-time code — no
///         secret leaves identity-services except the OTP itself.
///     </para>
///     <para>
///         Configure in local dev via, e.g.
///         <c>OCTO_SIGNALBRIDGE__APIURL=http://localhost:8080</c>,
///         <c>OCTO_SIGNALBRIDGE__NUMBER=+4366012345678</c>,
///         <c>OCTO_SIGNALBRIDGE__TIMEOUTSECONDS=30</c>. When neither a registered tenant channel
///         exists nor <see cref="ApiUrl" /> is set, the Signal modality is <em>unconfigured</em> and
///         the clearly-marked dev stub (<c>LoggingOtpDeliveryChannel</c>, with its loud warning)
///         handles the delivery, so dev without a bridge keeps working.
///     </para>
/// </remarks>
public class SignalBridgeOptions
{
    /// <summary>Configuration section name this options object is bound from.</summary>
    public const string SectionName = "SignalBridge";

    /// <summary>
    ///     Base URL of the signal-cli-rest-api bridge, e.g. <c>http://localhost:8080</c>. Local-dev
    ///     fallback only (AB#5154): consulted when the tenant has no Registered
    ///     <c>SignalChannel</c>. When null or empty this fallback is considered unconfigured
    ///     (a tenant without a registered channel then gets the dev stub).
    /// </summary>
    public string? ApiUrl { get; set; }

    /// <summary>
    ///     The bridge's registered sender account number in E.164, e.g. <c>+4366012345678</c>. Required
    ///     when <see cref="ApiUrl" /> is set — the fallback path refuses to send without it.
    /// </summary>
    public string? Number { get; set; }

    /// <summary>HTTP request timeout in seconds. Default 30.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}
