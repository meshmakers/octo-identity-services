using Meshmakers.Octo.Backend.IdentityServices.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using NLog.Extensions.Logging;
using NLog.Targets;
using Xunit;
using MelLogLevel = Microsoft.Extensions.Logging.LogLevel;

namespace IdentityServices.UnitTests.Logging;

/// <summary>
///     AB#8324: no token value reaches a log line, at any level - neither a JSON Web Token (JWS/JWE), nor an ASP.NET Core
///     Data Protection token, nor an opaque reference token in a token-named value. The line itself stays, masked.
/// </summary>
public class TokenLogRedactionTests
{
    // Fake canary values, recognisable in the output; none of them is a real token.
    // {"alg":"none","typ":"JWT"} . {"canary":"AB8324"} . FAKE-signature-8324
    private const string FakeJws = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJjYW5hcnkiOiJBQjgzMjQifQ.RkFLRS1zaWduYXR1cmUtODMyNA";

    // Five segments, the second empty (alg "dir"), as OpenIddict writes encrypted tokens.
    private const string FakeJwe =
        "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..RkFLRS1pdi04MzI0.RkFLRS1jaXBoZXJ0ZXh0LTgzMjQ.RkFLRS10YWctODMyNA";

    private const string FakeDataProtectionToken = "CfDJ8FAKEcanaryAB8324dataProtectionPayloadXyZ_-0123456789";
    private const string FakeReferenceToken = "FAKE-opaque-reference-token-AB8324";

    // OpenIddict 7.6 templates (OpenIddict.Abstractions SR, EventId 6013 and neighbours).
    private const string JwtCreatedTemplate = "A new '{Type}' JSON Web Token was successfully created: {Payload}.";
    private const string ReferenceIdTemplate =
        "The reference identifier ({ReferenceId}) was successfully attached to the token entry '{Identifier}' of type '{Type}'.";
    private const string TokenValidatedTemplate =
        "The token '{Token}' was successfully validated and the following claims could be extracted: {Claims}.";

    [Theory]
    [InlineData(FakeJws)]
    [InlineData(FakeJwe)]
    [InlineData(FakeDataProtectionToken)]
    public void Redact_MasksTokenShapedValues_InFreeText(string token)
    {
        var redacted = CredentialLogRedaction.Redact($"created: {token}. done");

        Assert.Equal("created: ***. done", redacted);
    }

    [Theory]
    [InlineData("Bearer eyJ")]
    [InlineData("eyJhbGciOiJub25lIn0 without dots")]
    [InlineData("version 1.2.3")]
    [InlineData("CfDJ8 short")]
    public void Redact_LeavesTextThatIsNoToken(string input)
    {
        Assert.Same(input, CredentialLogRedaction.Redact(input));
    }

    [Theory]
    [InlineData(FakeJws)]
    [InlineData(FakeJwe)]
    public void OpenIddictJwtCreatedEvent_IsMaskedInMessageAndValues_AndTheLineStays(string token)
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);

        factory.CreateLogger("OpenIddict.Server.OpenIddictServerDispatcher").Log(MelLogLevel.Trace, new EventId(6013),
            JwtCreatedTemplate, "urn:ietf:params:oauth:token-type:access_token", token);

        var line = Assert.Single(capture.Lines);
        Assert.False(line.AllText.Contains(token, StringComparison.Ordinal), "the token must not reach the provider");
        Assert.Contains("JSON Web Token was successfully created: ***.", line.Message);
        Assert.Contains(line.Values, v => v.Key == "Payload" && (string?)v.Value == CredentialLogRedaction.Mask);
        Assert.Contains(line.Values, v => v.Key == "{OriginalFormat}" && (string?)v.Value == JwtCreatedTemplate);
    }

    [Fact]
    public void OpaqueReferenceToken_InATokenNamedValue_IsMasked()
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);
        var logger = factory.CreateLogger("OpenIddict.Server.OpenIddictServerDispatcher");

        logger.LogTrace(ReferenceIdTemplate, FakeReferenceToken, "507f1f77bcf86cd799439011", "access_token");
        logger.LogTrace(TokenValidatedTemplate, FakeReferenceToken, "sub: x");

        Assert.Equal(2, capture.Lines.Count);
        Assert.All(capture.Lines,
            l => Assert.False(l.AllText.Contains(FakeReferenceToken, StringComparison.Ordinal), "reference token leaked"));
        Assert.Contains("entry '507f1f77bcf86cd799439011'", capture.Lines[0].Message);
    }

    [Fact]
    public void PayloadOutsideOpenIddict_IsNotMaskedByName()
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);

        factory.CreateLogger("Meshmakers.Test").LogInformation("Payload {Payload}", "plain value");

        Assert.Equal("Payload plain value", Assert.Single(capture.Lines).Message);
    }

    [Fact]
    public void StateThatIsNoValueList_HasItsFormattedMessageMasked()
    {
        var capture = new CapturingProvider();
        using var factory = BuildFactory(capture);

        factory.CreateLogger("x").Log(MelLogLevel.Trace, default, new object(), null, (_, _) => "token " + FakeJws);

        var line = Assert.Single(capture.Lines);
        Assert.Equal("token ***", line.Message);
    }

    [Fact]
    public void OpenIddictJwtCreatedEvent_ThroughTheRealNLogConfigAtTrace_HasNoTokenInTheJsonRecord()
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
                provider.GetRequiredService<ILoggerFactory>().CreateLogger("OpenIddict.Server.OpenIddictServerDispatcher")
                    .Log(MelLogLevel.Trace, new EventId(6013), JwtCreatedTemplate,
                        "urn:ietf:params:oauth:token-type:access_token", FakeJws);
            }

            logFactory.Flush();
            var output = string.Join('\n', logFactory.Configuration!.FindTargetByName<MemoryTarget>("console")!.Logs);
            Assert.Contains("JSON Web Token was successfully created: ***.", output);
            Assert.False(output.Contains(FakeJws, StringComparison.Ordinal), "the JSON record carries the token");
            Assert.False(output.Contains(FakeJws.Split('.')[2], StringComparison.Ordinal), "the signature leaked");
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
        return services.BuildServiceProvider().GetRequiredService<ILoggerFactory>();
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

    private sealed record CapturedLine(string Message, IReadOnlyList<KeyValuePair<string, object?>> Values)
    {
        public string AllText => Message + " | " + string.Join("; ", Values.Select(v => $"{v.Key}={v.Value}"));
    }

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
                    owner.Lines.Add(new CapturedLine(formatter(state, exception), values.ToList()));
                }
            }
        }
    }
}
