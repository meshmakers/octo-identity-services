using System.Xml.Linq;
using FluentAssertions;
using IdentityServerPersistence.SystemStores.DataProtection;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
///     AB#5530 through the real identity host (<c>Program.cs</c>, key ring <c>SecretEncryption</c> k1 of the test
///     factory, fresh system database): the Data Protection keys the host creates are stored encrypted, and
///     Data Protection payloads and antiforgery tokens still protect and unprotect. Cookies and cross-tenant tokens
///     are exercised by the login and cross-tenant suites on the same host setup.
/// </summary>
public class DataProtectionKeyEncryptionHostTests : IntegrationTestBase
{
    public DataProtectionKeyEncryptionHostTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Host_StoresItsKeysEncrypted_AndProtectionStillWorks()
    {
        Factory.Services.GetServices<IHostedService>().Should()
            .ContainSingle(s => s is DataProtectionKeyRingStartupService);

        var protector = Factory.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("AB5530.Host");
        protector.Unprotect(protector.Protect("payload")).Should().Be("payload");

        var antiforgery = Factory.Services.GetRequiredService<IAntiforgery>();
        var context = new DefaultHttpContext { RequestServices = Factory.Services };
        var tokens = antiforgery.GetAndStoreTokens(context);
        var validation = new DefaultHttpContext { RequestServices = Factory.Services };
        validation.Request.Method = "POST";
        var cookieName = Factory.Services.GetRequiredService<IOptions<AntiforgeryOptions>>().Value.Cookie.Name;
        validation.Request.Headers.Cookie = $"{cookieName}={tokens.CookieToken}";
        validation.Request.Headers[tokens.HeaderName!] = tokens.RequestToken;
        (await antiforgery.IsRequestValidAsync(validation)).Should().BeTrue();

        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repository = systemContext.GetSystemTenantRepositoryAsAdmin();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var keys = await repository.GetRtEntitiesByTypeAsync<RtDataProtectionKey>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        keys.Items.Should().NotBeEmpty();
        keys.Items.Should().OnlyContain(k => !k.XmlData.Contains("masterKey") && k.XmlData.Contains("enc:v2:k1:"));
        keys.Items.Should().OnlyContain(k => !DataProtectionKeyXml.ContainsUnencryptedSecret(XElement.Parse(k.XmlData)));
    }
}
