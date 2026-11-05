using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Logging;

/// <summary>
///     Keeps credentials that outdated clients still put into request URLs (AB#8008) and issued token values (AB#8324)
///     out of every log line, at every level.
/// </summary>
/// <remarks>
///     <para>
///         The current clients send the admin reset password and the stored secret value in the request body. Older
///         octo-cli/SDK/Refinery Studio versions sent <c>users/ResetPassword?…&amp;password=…</c> (refused with 400) and
///         <c>apiSecrets/{client|apiResource}/{id}/{value}</c> (deprecated, kept for one release). ASP.NET Core writes the
///         request URL (<c>Request starting/finished …</c>) before any controller code runs, so the value is masked in
///         the log pipeline itself.
///     </para>
///     <para>
///         Implemented as a decorator of <see cref="ILoggerFactory" />, not of a single provider: it covers every
///         provider (NLog, OpenTelemetry, test providers) and keeps provider-specific filter rules intact. Only
///         structured log values of URL types (<see cref="string" />, <see cref="PathString" />,
///         <see cref="QueryString" />, <see cref="Uri" />) are inspected, in log states and in scope states (the hosting
///         scope carries <c>RequestPath</c>); a log line without a match passes unchanged.
///     </para>
///     <para>
///         AB#8324: OpenIddict writes token values at Trace/Debug, e.g. EventId 6013 <i>"A new '{Type}' JSON Web Token was
///         successfully created: {Payload}."</i> carries the complete signed access token. Three rules keep every token
///         value out of the log, for the known events and for future ones: (1) JWT-shaped values (JWS with three, JWE with
///         five segments, starting with <c>eyJ</c>) and ASP.NET Core Data Protection payloads (<c>CfDJ8…</c>) are masked in
///         every structured string value and in the formatted message of any state; (2) values whose name denotes a token
///         or secret (<see cref="TokenValueNames" />) are masked whatever their shape (opaque reference tokens);
///         (3) <c>{Payload}</c> is masked in OpenIddict categories only (OpenIddict uses it for token payloads, other
///         libraries for harmless data). The line itself stays, with <see cref="Mask" /> in place of the value.
///     </para>
/// </remarks>
public static partial class CredentialLogRedaction
{
    /// <summary>The replacement of a masked value.</summary>
    public const string Mask = "***";

    // ?password=… / &newPassword=… / &secret=… — the value up to the next separator.
    [GeneratedRegex(@"(?<prefix>[?&](?:password|newPassword|secret|secretValue|clientSecret)=)[^&#\s]*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CredentialQueryParameter();

    // …/apiSecrets/client/{id}/{value} and …/apiSecrets/apiResource/{name}/{value}; the action segments of the body
    // variants (delete, lookup) are not values.
    [GeneratedRegex(
        @"(?<prefix>/apiSecrets/(?:client|apiResource)/[^/?#\s]+/)(?!(?:delete|lookup)(?:[/?#\s]|$))[^/?#\s]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ApiSecretPathValue();

    // JWS (header.payload.signature, the signature may be empty for alg=none) and JWE (five segments, the encrypted key
    // is empty for alg=dir). Every JOSE header is a JSON object, so its Base64url form starts with "eyJ".
    [GeneratedRegex(
        @"eyJ[A-Za-z0-9_-]{4,}\.(?:[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*)",
        RegexOptions.CultureInvariant)]
    private static partial Regex JsonWebToken();

    // ASP.NET Core Data Protection payloads (magic header 09 F0 C9 F0 = "CfDJ8" in Base64url): OpenIddict's
    // Data Protection tokens, authorization codes and cookies.
    [GeneratedRegex(@"CfDJ8[A-Za-z0-9_-]{16,}", RegexOptions.CultureInvariant)]
    private static partial Regex DataProtectionPayload();

    /// <summary>
    ///     Names of structured log values that always carry a token or a secret (AB#8324), compared case-insensitively.
    ///     Their value is masked whatever its shape, so opaque reference tokens are covered too. Not <c>Code</c>: the
    ///     dev OTP stub logs its one-time code on purpose (<c>LoggingOtpDeliveryChannel</c>).
    /// </summary>
    public static readonly IReadOnlySet<string> TokenValueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Token", "AccessToken", "RefreshToken", "IdToken", "IdentityToken", "ReferenceId", "AuthorizationCode",
        "DeviceCode", "UserCode", "SubjectToken", "ActorToken", "ClientAssertion", "ClientSecret"
    };

    /// <summary>Value names masked only in OpenIddict categories (there they carry token payloads).</summary>
    private static readonly IReadOnlySet<string> OpenIddictTokenValueNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Payload" };

    /// <summary>
    ///     Masks credential values in a URL, a path or a query string and token values (JWT, Data Protection payload) in
    ///     any text; returns the same instance when nothing matches.
    /// </summary>
    public static string Redact(string value)
    {
        var redacted = value;
        if (MayCarryCredential(value))
        {
            redacted = CredentialQueryParameter().Replace(redacted, m => m.Groups["prefix"].Value + Mask);
            redacted = ApiSecretPathValue().Replace(redacted, m => m.Groups["prefix"].Value + Mask);
        }

        if (redacted.Contains("eyJ", StringComparison.Ordinal))
        {
            redacted = JsonWebToken().Replace(redacted, Mask);
        }

        if (redacted.Contains("CfDJ8", StringComparison.Ordinal))
        {
            redacted = DataProtectionPayload().Replace(redacted, Mask);
        }

        // Regex.Replace returns the input instance when nothing matched; keep that contract for the caller.
        return string.Equals(redacted, value, StringComparison.Ordinal) ? value : redacted;
    }

    private static bool MayCarryCredential(string value)
        => value.Contains("apiSecrets", StringComparison.OrdinalIgnoreCase) ||
           value.Contains("password", StringComparison.OrdinalIgnoreCase) ||
           value.Contains("secret", StringComparison.OrdinalIgnoreCase);

    private static bool IsTokenValueName(string key, bool openIddictCategory)
        => TokenValueNames.Contains(key) || (openIddictCategory && OpenIddictTokenValueNames.Contains(key));

    /// <summary>
    ///     Replaces the registered <see cref="ILoggerFactory" /> with the redacting decorator. Call after the logging
    ///     providers are configured; later <c>AddLogging</c> calls (test hosts) keep it, they only <c>TryAdd</c>.
    /// </summary>
    public static IServiceCollection AddCredentialLogRedaction(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<ILoggerFactory>(sp => new RedactingLoggerFactory(new LoggerFactory(
            sp.GetServices<ILoggerProvider>(),
            sp.GetRequiredService<IOptionsMonitor<LoggerFilterOptions>>(),
            sp.GetService<IOptions<LoggerFactoryOptions>>(),
            sp.GetService<IExternalScopeProvider>()))));
        return services;
    }

    /// <summary>Wraps every logger of <paramref name="inner" /> in a <see cref="RedactingLogger" />.</summary>
    internal sealed class RedactingLoggerFactory(ILoggerFactory inner) : ILoggerFactory
    {
        public ILogger CreateLogger(string categoryName) =>
            new RedactingLogger(inner.CreateLogger(categoryName),
                categoryName.StartsWith("OpenIddict.", StringComparison.Ordinal));

        public void AddProvider(ILoggerProvider provider) => inner.AddProvider(provider);

        public void Dispose() => inner.Dispose();
    }

    /// <summary>Masks credential values in the structured values of a log line before the providers see it.</summary>
    internal sealed class RedactingLogger(ILogger inner, bool openIddictCategory = false) : ILogger
    {
        // Scopes are redacted too: the ASP.NET Core hosting scope carries RequestPath, and nlog.config renders scope
        // properties into every record of the request (includeScopeProperties).
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            => state is IReadOnlyList<KeyValuePair<string, object?>> values &&
               TryRedact(values, openIddictCategory, out var redacted)
                ? inner.BeginScope(redacted)
                : inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (state is IReadOnlyList<KeyValuePair<string, object?>> values)
            {
                if (TryRedact(values, openIddictCategory, out var redacted))
                {
                    inner.Log(logLevel, eventId, redacted, exception, (s, _) => s.ToString());
                    return;
                }

                inner.Log(logLevel, eventId, state, exception, formatter);
                return;
            }

            // A state without structured values (custom state types): the providers can only render the formatter's
            // text, so that text is masked (AB#8324).
            inner.Log(logLevel, eventId, state, exception, (s, e) => Redact(formatter(s, e)));
        }

        private static bool TryRedact(IReadOnlyList<KeyValuePair<string, object?>> values, bool openIddictCategory,
            out RedactedLogValues redacted)
        {
            List<KeyValuePair<string, object?>>? copy = null;
            for (var i = 0; i < values.Count; i++)
            {
                var (key, value) = values[i];
                if (value != null && key != "{OriginalFormat}" && IsTokenValueName(key, openIddictCategory))
                {
                    if (value is string { Length: 0 } || Equals(value, Mask))
                    {
                        continue;
                    }

                    copy ??= values.ToList();
                    copy[i] = new KeyValuePair<string, object?>(key, Mask);
                    continue;
                }

                var text = value switch
                {
                    string s => s,
                    PathString p => p.Value,
                    QueryString q => q.Value,
                    Uri u => u.OriginalString,
                    _ => null
                };
                if (text == null || key == "{OriginalFormat}")
                {
                    continue;
                }

                var masked = Redact(text);
                if (ReferenceEquals(masked, text))
                {
                    continue;
                }

                copy ??= values.ToList();
                copy[i] = new KeyValuePair<string, object?>(key, masked);
            }

            redacted = copy == null ? null! : new RedactedLogValues(copy);
            return copy != null;
        }
    }

    /// <summary>
    ///     The structured values of a log line with masked values. Keeps <c>{OriginalFormat}</c>, so providers that
    ///     render the message template (NLog) render the masked values; <see cref="ToString" /> renders the template
    ///     for the others.
    /// </summary>
    internal sealed partial class RedactedLogValues(List<KeyValuePair<string, object?>> values)
        : IReadOnlyList<KeyValuePair<string, object?>>
    {
        public KeyValuePair<string, object?> this[int index] => values[index];

        public int Count => values.Count;

        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => values.GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public override string ToString()
        {
            var format = values.FirstOrDefault(v => v.Key == "{OriginalFormat}").Value as string;
            if (format == null)
            {
                return string.Join(", ", values.Select(v => $"{v.Key}={v.Value}"));
            }

            return TemplateHole().Replace(format, m =>
            {
                var name = m.Groups["name"].Value;
                var match = values.FirstOrDefault(v => v.Key == name);
                return match.Key == null ? m.Value : Convert.ToString(match.Value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
            });
        }

        [GeneratedRegex(@"\{@?(?<name>[^{}:,]+)(?:[,:][^{}]*)?\}")]
        private static partial Regex TemplateHole();
    }
}
