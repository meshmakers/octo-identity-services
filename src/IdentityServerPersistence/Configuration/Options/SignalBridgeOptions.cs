// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace IdentityServerPersistence.Configuration.Options;

/// <summary>
///     Connection to the <c>signal-cli-rest-api</c> bridge used to deliver the self-service phone OTP
///     over Signal (AB#5134, on top of the AB#5123 <see cref="Services.SelfService.IOtpDeliveryChannel" />
///     abstraction). Bound from the <c>"SignalBridge"</c> configuration section in
///     <c>Program.cs</c> — mirror of the <c>Oem</c> / <c>OemOptions</c> binding.
/// </summary>
/// <remarks>
///     <para>
///         The bridge is the same local, unauthenticated HTTP endpoint the mesh adapter's
///         <c>SignalSender</c> pipeline node talks to (<c>POST {ApiUrl}/v2/send</c>). The bridge
///         holds the Signal credentials; identity-services only sends it the one-time code — no
///         secret leaves identity-services except the OTP itself.
///     </para>
///     <para>
///         Configure in local dev / a deployment via, e.g.
///         <c>OCTO_SIGNALBRIDGE__APIURL=http://localhost:8080</c>,
///         <c>OCTO_SIGNALBRIDGE__NUMBER=+4366012345678</c>,
///         <c>OCTO_SIGNALBRIDGE__TIMEOUTSECONDS=30</c>. When <see cref="ApiUrl" /> is empty the
///         bridge is treated as <em>unconfigured</em> and the clearly-marked dev stub
///         (<c>LoggingOtpDeliveryChannel</c>, with its loud warning) stays the Signal channel, so
///         dev without a bridge keeps working.
///     </para>
/// </remarks>
public class SignalBridgeOptions
{
    /// <summary>Configuration section name this options object is bound from.</summary>
    public const string SectionName = "SignalBridge";

    /// <summary>
    ///     Base URL of the signal-cli-rest-api bridge, e.g. <c>http://localhost:8080</c>. When null or
    ///     empty the bridge is considered unconfigured (dev stub stays active).
    /// </summary>
    public string? ApiUrl { get; set; }

    /// <summary>
    ///     The bridge's registered sender account number in E.164, e.g. <c>+4366012345678</c>. Required
    ///     when <see cref="ApiUrl" /> is set — the real channel refuses to send without it.
    /// </summary>
    public string? Number { get; set; }

    /// <summary>HTTP request timeout in seconds. Default 30.</summary>
    public int TimeoutSeconds { get; set; } = 30;
}
