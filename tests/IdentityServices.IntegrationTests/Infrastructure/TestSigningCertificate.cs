using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     Process-wide, in-memory signing/encryption certificate for the integration-test hosts.
/// </summary>
/// <remarks>
///     The test host runs in the Development environment, where <c>OpenIddictConfiguration</c> calls
///     <c>AddDevelopmentSigningCertificate()</c>. OpenIddict then publishes EVERY certificate with the
///     subject <c>CN=OpenIddict Server Signing Certificate</c> found in the current user's X509 store —
///     including expired ones and duplicates created when several test hosts start concurrently on an
///     empty store. On a long-lived CI agent (persistent <c>/root/.dotnet/corefx/cryptography/x509stores</c>)
///     that store accumulates certificates, so the JWKS and the signing key depended on the agent the
///     build ran on (AB#5880: <c>JwksDocument_StructureMatchesGoldenBaseline</c> saw two keys on
///     <c>azure-devops-agents-ci-1</c> only). <see cref="CustomWebApplicationFactory" /> replaces those
///     credentials with this single certificate, mirroring the production path
///     (<c>AddSigningCertificate</c> / <c>AddEncryptionCertificate</c> with one static certificate).
/// </remarks>
internal static class TestSigningCertificate
{
    private static readonly Lazy<X509Certificate2> LazyCertificate = new(Create);

    public static X509Certificate2 Certificate => LazyCertificate.Value;

    private static X509Certificate2 Create()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Octo Identity Integration Test Signing Certificate",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));

        var now = DateTimeOffset.UtcNow;
        using var ephemeral = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        // Round-trip through PKCS#12 (as OpenIddict does for its development certificate) so the
        // private key is a regular persisted-in-memory key usable for signing on every platform.
        // EphemeralKeySet is deliberately not used: macOS does not support it.
        return X509CertificateLoader.LoadPkcs12(
            ephemeral.Export(X509ContentType.Pkcs12, string.Empty),
            string.Empty,
            X509KeyStorageFlags.Exportable);
    }
}
