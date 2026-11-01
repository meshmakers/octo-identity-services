using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Logging;

/// <summary>
///     Keeps credentials that outdated clients still put into request URLs out of every log line (AB#8008).
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

    /// <summary>Masks credential values in a URL, a path or a query string; returns the input when nothing matches.</summary>
    public static string Redact(string value)
    {
        if (!MayCarryCredential(value))
        {
            return value;
        }

        var redacted = CredentialQueryParameter().Replace(value, m => m.Groups["prefix"].Value + Mask);
        return ApiSecretPathValue().Replace(redacted, m => m.Groups["prefix"].Value + Mask);
    }

    private static bool MayCarryCredential(string value)
        => value.Contains("apiSecrets", StringComparison.OrdinalIgnoreCase) ||
           value.Contains("password", StringComparison.OrdinalIgnoreCase) ||
           value.Contains("secret", StringComparison.OrdinalIgnoreCase);

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
        public ILogger CreateLogger(string categoryName) => new RedactingLogger(inner.CreateLogger(categoryName));

        public void AddProvider(ILoggerProvider provider) => inner.AddProvider(provider);

        public void Dispose() => inner.Dispose();
    }

    /// <summary>Masks credential values in the structured values of a log line before the providers see it.</summary>
    internal sealed class RedactingLogger(ILogger inner) : ILogger
    {
        // Scopes are redacted too: the ASP.NET Core hosting scope carries RequestPath, and nlog.config renders scope
        // properties into every record of the request (includeScopeProperties).
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            => state is IReadOnlyList<KeyValuePair<string, object?>> values && TryRedact(values, out var redacted)
                ? inner.BeginScope(redacted)
                : inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (state is IReadOnlyList<KeyValuePair<string, object?>> values && TryRedact(values, out var redacted))
            {
                inner.Log(logLevel, eventId, redacted, exception, (s, _) => s.ToString());
                return;
            }

            inner.Log(logLevel, eventId, state, exception, formatter);
        }

        private static bool TryRedact(IReadOnlyList<KeyValuePair<string, object?>> values,
            out RedactedLogValues redacted)
        {
            List<KeyValuePair<string, object?>>? copy = null;
            for (var i = 0; i < values.Count; i++)
            {
                var (key, value) = values[i];
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
