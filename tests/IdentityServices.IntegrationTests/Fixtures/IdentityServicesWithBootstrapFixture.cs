using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     The identity fixture with the embedded <c>System.Identity.Bootstrap</c> blueprint registered as in production, so the
///     tenant setup applies the real seed through the blueprint service, and with a log sink that keeps every warning of
///     the run (with its scope values) for the test to inspect.
/// </summary>
public class IdentityServicesWithBootstrapFixture : IdentityServicesFixture
{
    public IdentityServicesWithBootstrapFixture()
    {
        Services.AddBlueprintSystemIdentityBootstrapV1();
        Services.AddLogging(builder => builder.AddProvider(Warnings));
    }

    /// <summary>Every warning (and above) logged while the fixture runs.</summary>
    public CapturingLoggerProvider Warnings { get; } = new();

    /// <summary>Keeps the warnings (and above) of all loggers with the values of their log scopes.</summary>
    public sealed class CapturingLoggerProvider : ILoggerProvider, ISupportExternalScope
    {
        private IExternalScopeProvider _scopes = new LoggerExternalScopeProvider();

        public ConcurrentQueue<CapturedLog> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

        public void SetScopeProvider(IExternalScopeProvider scopeProvider) => _scopes = scopeProvider;

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => owner._scopes.Push(state);

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel))
                {
                    return;
                }

                var properties = new Dictionary<string, object?>();
                owner._scopes.ForEachScope((scope, props) =>
                {
                    if (scope is IEnumerable<KeyValuePair<string, object>> pairs)
                    {
                        foreach (var pair in pairs)
                        {
                            props[pair.Key] = pair.Value;
                        }
                    }
                }, properties);
                if (state is IEnumerable<KeyValuePair<string, object?>> messageProperties)
                {
                    foreach (var pair in messageProperties)
                    {
                        properties[pair.Key] = pair.Value;
                    }
                }

                owner.Entries.Enqueue(new CapturedLog(category, logLevel, formatter(state, exception), properties));
            }
        }
    }

    public sealed record CapturedLog(string Category, LogLevel Level, string Message,
        IReadOnlyDictionary<string, object?> Properties);
}
