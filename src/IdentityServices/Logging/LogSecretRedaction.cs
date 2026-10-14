using NLog;
using NLog.Config;
using OpenIddict.Abstractions;

namespace Meshmakers.Octo.Backend.IdentityServices.Logging;

/// <summary>
/// Keeps credentials out of structured log properties (AB#5792).
/// </summary>
/// <remarks>
/// <para>
/// The JSON layout in <c>nlog.config</c> uses <c>includeEventProperties="true"</c>, which serializes every
/// message-template argument by reflection over its public properties. That bypasses the redaction OpenIddict
/// implements in <see cref="OpenIddictMessage.ToString"/>: the message text is safe, but the JSON property
/// <c>Response</c> carried <c>access_token</c>, <c>id_token</c> and <c>refresh_token</c> in clear text (and
/// <c>Request</c> carried <c>client_secret</c>, <c>code</c> and <c>refresh_token</c>).
/// </para>
/// <para>
/// The fix is an NLog object transformation: the message types are rendered through their own
/// <c>ToString()</c> (the OpenIddict redacting one) wherever NLog serializes them, in any layout.
/// It has to be registered before the configuration is loaded.
/// </para>
/// </remarks>
public static class LogSecretRedaction
{
    /// <summary>
    /// Registers the redacting object transformations on the given NLog factory setup.
    /// </summary>
    public static ISetupBuilder RegisterSecretRedaction(this ISetupBuilder setup)
    {
        return setup.SetupSerialization(s =>
        {
            // OpenIddictRequest and OpenIddictResponse derive from OpenIddictMessage; NLog matches the
            // registration on the exact runtime type, so every concrete type is listed explicitly.
            s.RegisterObjectTransformation<OpenIddictMessage>(Redact);
            s.RegisterObjectTransformation<OpenIddictRequest>(Redact);
            s.RegisterObjectTransformation<OpenIddictResponse>(Redact);
        });
    }

    private static string Redact(OpenIddictMessage message) => message.ToString();
}
