using Meshmakers.Octo.Backend.IdentityServices.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog;
using NLog.Extensions.Logging;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using NLog.Targets;
using Xunit;
using MelLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace IdentityServices.UnitTests.Logging;

/// <summary>
///     AB#8008: credentials that outdated clients still put into request URLs are masked in every log line - in the
///     rendered message and in the structured values, through the real <c>nlog.config</c> as well.
/// </summary>
public class CredentialLogRedactionTests
{
    // Fake values, recognisable in the output.
    private const string FakePassword = "FAKE-pw-8008!";
    private const string FakeSecretSegment = "RkFLRS1oYXNoLTgwMDg%3D";

    // The template ASP.NET Core's hosting diagnostics use for "Request starting".
    private const string RequestStartingTemplate =
        "Request starting {Protocol} {Method} {Scheme}://{Host}{PathBase}{Path}{QueryString} - {ContentType} {ContentLength}";

    [Theory]
    [InlineData("?userName=bob&password=FAKE-pw-8008!", "?userName=bob&password=***")]
    [InlineData("?password=FAKE-pw-8008!&userName=bob", "?password=***&userName=bob")]
    [InlineData("?PASSWORD=FAKE-pw-8008!", "?PASSWORD=***")]
    [InlineData("?newPassword=x&clientSecret=y", "?newPassword=***&clientSecret=***")]
    [InlineData("/t/v1/apiSecrets/client/my-client/RkFLRS1oYXNoLTgwMDg%3D", "/t/v1/apiSecrets/client/my-client/***")]
    [InlineData("/t/v1/apiSecrets/apiResource/res/RkFLRQ==?x=1", "/t/v1/apiSecrets/apiResource/res/***?x=1")]
    [InlineData("http://h/t/v1/apiSecrets/client/c/abc - 404", "http://h/t/v1/apiSecrets/client/c/*** - 404")]
    public void Redact_MasksTheValue_KeepsTheRest(string input, string expected)
    {
        Assert.Equal(expected, CredentialLogRedaction.Redact(input));
    }

    [Theory]
    [InlineData("/t/v1/apiSecrets/client/my-client/delete")]
    [InlineData("/t/v1/apiSecrets/apiResource/res/lookup")]
    [InlineData("/t/v1/apiSecrets/client/my-client")]
    [InlineData("/t/v1/users/ResetPassword")]
    [InlineData("?userName=bob")]
    [InlineData("nothing to see")]
    public void Redact_LeavesValueFreeTextAlone(string input)
    {
        Assert.Same(input, CredentialLogRedaction.Redact(input));
    }

    [Fact]
    public void RequestLog_ThroughTheDecoratedFactory_IsMaskedInMessageAndValues()
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);

        factory.CreateLogger("Microsoft.AspNetCore.Hosting.Diagnostics").Log(MelLogLevel.Information,
            RequestStartingTemplate, "HTTP/1.1", "POST", "http", "localhost", new PathString(""),
            new PathString("/t/v1/apiSecrets/client/c/" + FakeSecretSegment),
            new QueryString("?userName=bob&password=" + FakePassword), null, 0);

        var line = Assert.Single(capture.Lines);
        Assert.DoesNotContain(FakePassword, line.Message);
        Assert.DoesNotContain(FakeSecretSegment, line.Message);
        Assert.Contains("/t/v1/apiSecrets/client/c/***?userName=bob&password=***", line.Message);
        Assert.DoesNotContain(line.Values, v => (v.Value?.ToString() ?? string.Empty).Contains(FakePassword));
        Assert.Contains(line.Values, v => v.Key == "{OriginalFormat}" && (string?)v.Value == RequestStartingTemplate);
    }

    [Fact]
    public void LogLine_WithoutCredential_PassesUnchanged()
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);

        factory.CreateLogger("x").LogInformation("Request to {Path}", "/t/v1/users");

        var line = Assert.Single(capture.Lines);
        Assert.Equal("Request to /t/v1/users", line.Message);
        Assert.Equal("Microsoft.Extensions.Logging.FormattedLogValues", line.StateType);
    }

    [Fact]
    public void ProviderAddedLater_IsCoveredToo()
    {
        var capture = new CapturingProvider();
        var services = new ServiceCollection();
        services.AddLogging(l => l.SetMinimumLevel(MelLogLevel.Trace));
        services.AddCredentialLogRedaction();
        // A later AddLogging (as a test host or another library does) must not bring the plain factory back.
        services.AddLogging(l => l.AddProvider(capture));
        using var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ILogger<CredentialLogRedactionTests>>()
            .LogTrace("Query {QueryString}", "?password=" + FakePassword);

        Assert.Equal("Query ?password=***", Assert.Single(capture.Lines).Message);
    }

    [Fact]
    public void RequestLog_ThroughTheRealNLogConfig_IsMaskedInTheJsonRecord()
    {
        var xml = File.ReadAllText(FindNlogConfig())
            .Replace("xsi:type=\"Console\"", "xsi:type=\"Memory\"", StringComparison.Ordinal)
            .Replace("${environment:OCTO_LOG_LEVEL_ROOT:whenEmpty=Warn}", "Trace", StringComparison.Ordinal)
            .Replace("${environment:OCTO_LOG_LEVEL:whenEmpty=Info}", "Trace", StringComparison.Ordinal);
        var logFactory = new NLog.LogFactory().Setup().RegisterSecretRedaction().LoadConfigurationFromXml(xml).LogFactory;
        try
        {
            var services = new ServiceCollection();
            services.AddLogging(l =>
            {
                l.SetMinimumLevel(MelLogLevel.Trace);
                l.AddProvider(new NLogLoggerProvider(new NLogProviderOptions(), logFactory));
            });
            services.AddCredentialLogRedaction();
            using (var provider = services.BuildServiceProvider())
            {
                provider.GetRequiredService<ILoggerFactory>().CreateLogger("Microsoft.AspNetCore.Hosting.Diagnostics")
                    .Log(MelLogLevel.Information, RequestStartingTemplate, "HTTP/1.1", "POST", "http", "localhost",
                        new PathString(""), new PathString("/t/v1/users/ResetPassword"),
                        new QueryString("?userName=bob&password=" + FakePassword), null, 0);
            }

            logFactory.Flush();
            var output = string.Join('\n', logFactory.Configuration!.FindTargetByName<MemoryTarget>("console")!.Logs);
            Assert.Contains("ResetPassword?userName=bob&password=***", output);
            Assert.DoesNotContain(FakePassword, output);
        }
        finally
        {
            logFactory.Shutdown();
        }
    }

    private static ILoggerFactory BuildFactory(CapturingProvider capture)
    {
        var services = new ServiceCollection();
        services.AddLogging(l =>
        {
            l.SetMinimumLevel(MelLogLevel.Trace);
            l.AddProvider(capture);
        });
        services.AddCredentialLogRedaction();
        var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<ILoggerFactory>();
    }

    private static string FindNlogConfig()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "IdentityServices", "nlog.config");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new FileNotFoundException("src/IdentityServices/nlog.config not found above " + AppContext.BaseDirectory);
    }

    private sealed record CapturedLine(string Message, IReadOnlyList<KeyValuePair<string, object?>> Values, string StateType);

    private sealed class CapturingProvider : ILoggerProvider
    {
        public List<CapturedLine> Lines { get; } = [];

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(MelLogLevel logLevel) => true;

            public void Log<TState>(MelLogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var values = state as IReadOnlyList<KeyValuePair<string, object?>> ?? [];
                lock (owner.Lines)
                {
                    owner.Lines.Add(new CapturedLine(formatter(state, exception), values.ToList(),
                        state?.GetType().FullName ?? string.Empty));
                }
            }
        }
    }
}
