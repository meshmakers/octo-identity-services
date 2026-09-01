using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     Record-or-compare helper for the AB#4989 OpenIddict migration golden baseline.
///     While Duende IdentityServer is still active, running the golden tests records the
///     wire-visible shapes (discovery document, token headers/claims, protocol response
///     bodies) into <c>tests/IdentityServices.IntegrationTests/GoldenFiles/</c>. After the
///     swap to OpenIddict the same tests compare the new responses against the recorded
///     baseline — any drift in claims, audiences, scopes or endpoint shapes fails loudly.
/// </summary>
/// <remarks>
///     Recording happens automatically when a golden file is missing, or forcibly when the
///     environment variable <c>OCTO_GOLDEN_RECORD=1</c> is set. A recording run reports the
///     test as skipped so a baseline refresh is visible in the test summary and can never be
///     mistaken for a verified comparison.
/// </remarks>
public static class GoldenFile
{
    private static readonly JsonSerializerOptions WriteOptions = new() { WriteIndented = true };

    /// <summary>
    ///     JWT claims whose values change on every issuance (timestamps, token ids, hashes,
    ///     generated subject ids). Their presence is pinned, their value is normalized.
    /// </summary>
    private static readonly HashSet<string> VolatileClaims = new(StringComparer.Ordinal)
    {
        "jti", "iat", "exp", "nbf", "auth_time", "sid", "sub",
        "at_hash", "s_hash", "c_hash", "nonce", "session_state", "updated_at"
    };

    private static string GoldenDirectory([CallerFilePath] string callerFilePath = "")
        => Path.GetFullPath(Path.Combine(Path.GetDirectoryName(callerFilePath)!, "..", "GoldenFiles"));

    /// <summary>
    ///     Compares each pair against its golden file, recording every missing baseline first.
    ///     When anything was recorded the test is reported as skipped (single skip AFTER all
    ///     files are written — a per-file skip would abort the test before later captures of the
    ///     same flow get recorded). Only a run with all files present is a verified comparison.
    /// </summary>
    public static async Task MatchAllAsync(CancellationToken ct, params (string Name, JsonNode Actual)[] pairs)
    {
        var dir = GoldenDirectory();
        Directory.CreateDirectory(dir);
        var forceRecord = Environment.GetEnvironmentVariable("OCTO_GOLDEN_RECORD") == "1";

        var recorded = new List<string>();
        var comparisons = new List<(string Path, string Normalized)>();
        foreach (var (name, actual) in pairs)
        {
            var path = Path.Combine(dir, name + ".json");
            var normalized = Normalize(actual).ToJsonString(WriteOptions) + "\n";
            if (!File.Exists(path) || forceRecord)
            {
                await File.WriteAllTextAsync(path, normalized, ct);
                recorded.Add(Path.GetFileName(path));
            }
            else
            {
                comparisons.Add((path, normalized));
            }
        }

        if (recorded.Count > 0)
        {
            Assert.Skip($"Golden baseline recorded: {string.Join(", ", recorded)}");
        }

        foreach (var (path, normalized) in comparisons)
        {
            var expected = await File.ReadAllTextAsync(path, ct);
            Assert.Equal(expected.ReplaceLineEndings("\n"), normalized);
        }
    }

    /// <summary>
    ///     Projects a JWT into its comparison-stable shape: header (alg/typ/kid) plus all claims,
    ///     with multi-value claims as sorted arrays and volatile claim values (see
    ///     <see cref="VolatileClaims" />) replaced by a placeholder so only their presence is pinned.
    /// </summary>
    public static JsonObject NormalizeJwt(string jwt)
    {
        var token = new JsonWebToken(jwt);

        var header = new JsonObject
        {
            ["alg"] = token.Alg,
            ["typ"] = token.Typ
        };
        if (!string.IsNullOrEmpty(token.Kid))
        {
            header["kid"] = token.Kid;
        }

        var claims = new JsonObject();
        foreach (var group in token.Claims.GroupBy(c => c.Type).OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            if (VolatileClaims.Contains(group.Key))
            {
                claims[group.Key] = "<dynamic>";
                continue;
            }

            var values = group.Select(c => c.Value).OrderBy(v => v, StringComparer.Ordinal).ToList();
            claims[group.Key] = values.Count == 1
                ? JsonValue.Create(values[0])
                : new JsonArray(values.Select(v => (JsonNode)JsonValue.Create(v)).ToArray());
        }

        return new JsonObject { ["header"] = header, ["claims"] = claims };
    }

    /// <summary>
    ///     Reduces a protocol JSON response body to its sorted key list plus the values of the
    ///     explicitly named stable properties — everything else is treated as per-request data.
    /// </summary>
    public static JsonObject NormalizeResponseShape(JsonObject body, params string[] stableProperties)
    {
        var keys = body.Select(kv => kv.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
        var result = new JsonObject
        {
            ["keys"] = new JsonArray(keys.Select(k => (JsonNode)JsonValue.Create(k)).ToArray())
        };

        var stable = new JsonObject();
        foreach (var property in stableProperties.OrderBy(p => p, StringComparer.Ordinal))
        {
            if (body.TryGetPropertyValue(property, out var value))
            {
                stable[property] = value?.DeepClone();
            }
        }

        result["stable"] = stable;
        return result;
    }

    /// <summary>Sorts all object properties recursively so comparisons are order-insensitive.</summary>
    private static JsonNode Normalize(JsonNode node)
    {
        switch (node)
        {
            case JsonObject obj:
                var sorted = new JsonObject();
                foreach (var kv in obj.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                {
                    sorted[kv.Key] = kv.Value is null ? null : Normalize(kv.Value.DeepClone());
                }

                return sorted;
            case JsonArray arr:
                // Pure string arrays (scope lists, claims_supported, …) are sets on the wire —
                // their enumeration order is storage-dependent, so sort them for stability.
                if (arr.Count > 0 && arr.All(i => i is JsonValue v && v.GetValueKind() == JsonValueKind.String))
                {
                    var sortedValues = arr.Select(i => i!.GetValue<string>())
                        .OrderBy(v => v, StringComparer.Ordinal);
                    return new JsonArray(sortedValues.Select(v => (JsonNode)JsonValue.Create(v)).ToArray());
                }

                var copy = new JsonArray();
                foreach (var item in arr)
                {
                    copy.Add(item is null ? null : Normalize(item.DeepClone()));
                }

                return copy;
            default:
                return node.DeepClone();
        }
    }
}
