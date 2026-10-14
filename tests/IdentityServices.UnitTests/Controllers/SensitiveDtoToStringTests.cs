using System.Collections;
using System.Reflection;
using System.Text.RegularExpressions;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Xunit;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
/// AB#5792 D6: ASP.NET Core logs action arguments at Trace through <c>ToString()</c>. No DTO in
/// <c>Controllers/Api</c> may render a password, code, secret or token member there.
/// </summary>
public partial class SensitiveDtoToStringTests
{
    // The AB#5792 pattern plus SharedKey (the TOTP seed of AuthenticatorSetupDto).
    [GeneratedRegex("Password|Code|Secret|Token|SharedKey", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveName();

    public static IEnumerable<object[]> SensitiveDtoTypes() =>
        DtoTypes().Where(t => SensitiveMembers(t).Any()).Select(t => new object[] { t });

    // Every public DTO record of Controllers/Api plus the internal cross-tenant payload.
    private static IEnumerable<Type> DtoTypes() =>
        typeof(AuthApiController).Assembly.GetTypes()
            .Where(t => t.Namespace == typeof(AuthApiController).Namespace
                        && t.IsClass && !t.IsAbstract
                        && (t.Name.EndsWith("Dto", StringComparison.Ordinal) || t.Name.EndsWith("Payload", StringComparison.Ordinal)));

    // Only members that can hold a secret: strings and string collections. bool/int flags such as
    // HasPassword or RecoveryCodesLeft carry no credential.
    private static IEnumerable<PropertyInfo> SensitiveMembers(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => SensitiveName().IsMatch(p.Name)
                        && (p.PropertyType == typeof(string) || typeof(IEnumerable<string>).IsAssignableFrom(p.PropertyType)));

    [Fact]
    public void ReflectionScan_FindsTheKnownSensitiveDtos()
    {
        // Guards the scan itself: if the namespace/name filter ever matched nothing, the theory below
        // would pass vacuously.
        var names = SensitiveDtoTypes().Select(o => ((Type)o[0]).Name).ToList();
        Assert.Contains("LoginRequestDto", names);
        Assert.Contains("LdapLoginRequestDto", names);
        Assert.Contains("ChangePasswordRequestDto", names);
        Assert.Contains("SetupAdminRequestDto", names);
        Assert.Contains("TwoFactorLoginRequestDto", names);
        Assert.Contains("RecoveryCodeLoginRequestDto", names);
        Assert.Contains("VerifyPhoneRequestDto", names);
        Assert.Contains("AuthenticatorSetupDto", names);
    }

    [Theory]
    [MemberData(nameof(SensitiveDtoTypes))]
    public void ToString_DoesNotRenderSensitiveMembers(Type dtoType)
    {
        var dto = Activator.CreateInstance(dtoType, nonPublic: true)!;
        var markers = new List<string>();

        foreach (var property in SensitiveMembers(dtoType))
        {
            var marker = $"LEAK-{dtoType.Name}-{property.Name}";
            markers.Add(marker);
            property.SetValue(dto, property.PropertyType == typeof(string) ? marker : new[] { marker });
        }

        var rendered = dto.ToString()!;

        foreach (var marker in markers)
        {
            Assert.DoesNotContain(marker, rendered);
        }
    }

    [Fact]
    public void ToString_KeepsNonSensitiveMembersForDiagnostics()
    {
        var rendered = new LoginRequestDto { Username = "alice", Password = "hunter2", RememberLogin = true }.ToString();

        Assert.DoesNotContain("hunter2", rendered);
        Assert.Contains("Username = alice", rendered);
        Assert.Contains("RememberLogin = True", rendered);
        Assert.Contains("Password = [REDACTED]", rendered);
    }
}
