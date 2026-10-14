using System.Text.Json;
using Meshmakers.Octo.Backend.IdentityServices.Logging;
using NLog;
using NLog.Targets;
using OpenIddict.Abstractions;
using Xunit;

namespace IdentityServices.UnitTests.Logging;

/// <summary>
/// AB#5792 D5: no OpenIddict message may reach a JSON log property with a credential in clear text.
/// The tests run the real <c>src/IdentityServices/nlog.config</c> (its Console target swapped for a
/// memory target) so a change to the layout's <c>includeEventProperties</c> is covered too.
/// </summary>
public class LogSecretRedactionTests
{
    // Fake values, recognisable in the output.
    private const string FakeAccessToken = "eyJFAKE.access.token";
    private const string FakeIdToken = "eyJFAKE.id.token";
    private const string FakeRefreshToken = "FAKE-refresh-token";
    private const string FakeClientSecret = "FAKE-client-secret";
    private const string FakeCode = "FAKE-auth-code";

    private static readonly string[] FakeValues =
        [FakeAccessToken, FakeIdToken, FakeRefreshToken, FakeClientSecret, FakeCode];

    [Fact]
    public void OpenIddictResponse_AsTemplateArgument_DoesNotLeakTokensIntoJsonProperties()
    {
        var response = new OpenIddictResponse
        {
            AccessToken = FakeAccessToken,
            IdToken = FakeIdToken,
            RefreshToken = FakeRefreshToken,
            TokenType = "Bearer",
            ExpiresIn = 3600,
        };

        var output = LogThroughRealConfig(logger =>
            logger.Info("The response was successfully returned as a JSON document: {Response}", response));

        AssertNoSecret(output);
        // Not vacuous: the record was written and the non-secret parameters survive.
        Assert.Contains("\"Response\"", output);
        Assert.Contains("Bearer", output);
    }

    [Fact]
    public void OpenIddictRequest_AsTemplateArgument_DoesNotLeakSecretsIntoJsonProperties()
    {
        var request = new OpenIddictRequest
        {
            GrantType = "authorization_code",
            ClientId = "some-client",
            ClientSecret = FakeClientSecret,
            Code = FakeCode,
            RefreshToken = FakeRefreshToken,
        };

        var output = LogThroughRealConfig(logger =>
            logger.Info("The request was successfully extracted: {Request}", request));

        AssertNoSecret(output);
        Assert.Contains("\"Request\"", output);
        Assert.Contains("some-client", output);
    }

    [Fact]
    public void OpenIddictMessage_AsTemplateArgument_DoesNotLeakTokensIntoJsonProperties()
    {
        var message = new OpenIddictMessage();
        message.SetParameter("access_token", FakeAccessToken);
        message.SetParameter("client_secret", FakeClientSecret);

        var output = LogThroughRealConfig(logger => logger.Info("Message: {Message}", message));

        AssertNoSecret(output);
    }

    [Fact]
    public void WithoutRedactionRegistered_TheSameRecordLeaks_ProvingTheTestDetectsTheDefect()
    {
        var response = new OpenIddictResponse { AccessToken = FakeAccessToken };

        var output = LogThroughRealConfig(
            logger => logger.Info("Response: {Response}", response),
            registerRedaction: false);

        Assert.Contains(FakeAccessToken, output);
    }

    private static void AssertNoSecret(string output)
    {
        foreach (var fake in FakeValues)
        {
            Assert.DoesNotContain(fake, output);
        }

        // The record must still be one valid JSON document.
        using var document = JsonDocument.Parse(output.Trim().Split('\n')[0]);
        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
    }

    private static string LogThroughRealConfig(Action<Logger> log, bool registerRedaction = true)
    {
        var xml = File.ReadAllText(FindNlogConfig())
            .Replace("xsi:type=\"Console\"", "xsi:type=\"Memory\"", StringComparison.Ordinal)
            // The real file reads the level from the environment; pin it so the test is independent of it.
            .Replace("${environment:OCTO_LOG_LEVEL_ROOT:whenEmpty=Warn}", "Trace", StringComparison.Ordinal)
            .Replace("${environment:OCTO_LOG_LEVEL:whenEmpty=Info}", "Trace", StringComparison.Ordinal);

        var setup = new LogFactory().Setup();
        if (registerRedaction)
        {
            setup = setup.RegisterSecretRedaction();
        }

        var factory = setup.LoadConfigurationFromXml(xml).LogFactory;
        try
        {
            log(factory.GetLogger("OpenIddict.Server.OpenIddictServerDispatcher"));
            factory.Flush();
            var target = factory.Configuration!.FindTargetByName<MemoryTarget>("console");
            Assert.NotNull(target);
            return string.Join('\n', target.Logs);
        }
        finally
        {
            factory.Shutdown();
        }
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
}
