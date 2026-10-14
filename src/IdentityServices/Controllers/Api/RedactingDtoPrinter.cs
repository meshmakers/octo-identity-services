using System.Collections;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
/// Renders an API DTO for <c>ToString()</c> with every credential-like member redacted (AB#5792).
/// </summary>
/// <remarks>
/// ASP.NET Core logs action arguments at Trace through <c>ToString()</c> ("Executing action method … with
/// arguments"); the compiler-generated record <c>ToString()</c> prints every member, so a login request
/// ended up in the log with its plaintext password and 2FA code. A record that carries such a member
/// declares <c>protected virtual bool PrintMembers(StringBuilder builder) =&gt; RedactingDtoPrinter.Print(this, builder);</c>.
/// The printer decides per member name, so a member added later is redacted without touching the record;
/// <c>SensitiveDtoToStringTests</c> fails for a DTO that carries such a member and does not use it.
/// </remarks>
internal static partial class RedactingDtoPrinter
{
    internal const string Redacted = "[REDACTED]";

    /// <summary>Member names whose value must never be rendered.</summary>
    [GeneratedRegex("Password|Code|Secret|Token|SharedKey", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    internal static partial Regex SensitiveMemberName();

    public static bool Print(object dto, StringBuilder builder)
    {
        var first = true;
        foreach (var property in dto.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length > 0)
            {
                continue;
            }

            if (!first)
            {
                builder.Append(", ");
            }

            first = false;
            builder.Append(property.Name).Append(" = ");

            if (SensitiveMemberName().IsMatch(property.Name))
            {
                builder.Append(Redacted);
                continue;
            }

            var value = property.GetValue(dto);
            if (value is IEnumerable enumerable and not string)
            {
                builder.Append('[').Append(string.Join(", ", enumerable.Cast<object?>())).Append(']');
            }
            else
            {
                builder.Append(value);
            }
        }

        return !first;
    }
}
