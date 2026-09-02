using System.Security.Cryptography;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services;

/// <summary>
///     The per-tenant mirror secret (AB#5061) — the material that makes a mirrored client's
///     credentials prove <i>which tenant</i> the caller holds credentials for.
/// </summary>
/// <remarks>
///     <para>
///         🔴 <b>The problem.</b> <c>ClientMirrorProvisioningService.CreateMirrorClient</c> copies
///         <c>ClientSecrets</c> verbatim into every child tenant, so for a confidential client one
///         <c>ClientId</c>/secret pair is valid on the whole instance. Whoever legitimately holds a
///         child tenant's mirror credentials thereby also holds the parent's, and can request a
///         <b>system-tenant</b> token explicitly — a request the token endpoint cannot tell apart
///         from the real parent's, because it literally is the same credential. AB#5058 closed the
///         silent variant (omit <c>acr_values</c>, get the system tenant for free) but could not
///         close this one, which is why a <c>tenant_id == systemTenant</c> claim on a
///         client-credentials token is not usable as proof of provenance and the system-route
///         hardening (AB#5055) stayed blocked.
///     </para>
///     <para>
///         <b>The fix, and why it is additive.</b> Every mirror of a confidential parent gets its
///         <b>own</b> generated secret, marked with <see cref="OwnSecretDescription" />. Possession
///         of it proves only that tenant. The inherited copy of the parent secret is
///         <b>deliberately left in place for now</b>: the caller inventory found live fleet
///         credentials that authenticate with the parent secret against child tenants — the
///         <c>ci-deploy</c> / <c>ci-deploy-{cluster}</c> workload-deployment pipeline, the
///         <c>octo-ai-adapter</c> MCP token issuer and the <c>claude-agent</c> automation client.
///         Dropping the inherited secret in the same step would break every workload rollout on
///         every cluster. ⚠️ <b>While the inherited secret is still accepted the escalation is
///         open</b>; it closes only when the follow-up step removes it (see
///         <c>docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md</c> § Migration).
///     </para>
///     <para>
///         <b>Distribution.</b> Secrets are stored SHA-256 hashed and are unrecoverable after
///         creation, so an auto-generated secret that is never handed out would be a credential
///         nobody could use. The generated value is therefore returned <b>exactly once</b>, from
///         the rotate endpoint (<c>POST {parent}/v1/clients/{id}/mirrors/{child}/secret</c>), to a
///         caller that already holds parent-tenant management rights. That direction is the one that
///         is safe: parent → child is legitimate delegation, child → parent is the escalation being
///         removed. Nothing recoverable is persisted, so this adds no new class of stored
///         credential.
///     </para>
/// </remarks>
public static class ClientMirrorSecrets
{
    /// <summary>
    ///     Marks the one <see cref="RtSecretRecord" /> on a mirror that belongs to <i>that mirror</i>
    ///     rather than being an inherited copy of the parent's. Carried in
    ///     <see cref="RtSecretRecord.Description" /> because the CK record has no other free
    ///     discriminator — deliberately avoiding a schema bump on <c>System.Identity</c>, which
    ///     would cascade a version bump through every dependent construction kit.
    /// </summary>
    public const string OwnSecretDescription = "octo:mirror-own-secret";

    /// <summary>The <c>Type</c> every shared client secret in this service uses.</summary>
    public const string SharedSecretType = "SharedSecret";

    /// <summary>True when the client can authenticate with a shared secret.</summary>
    /// <remarks>
    ///     Both signals count and either alone is enough. <c>RequireClientSecret</c> is the declared
    ///     intent and can be set before the first secret exists; a non-empty <c>ClientSecrets</c>
    ///     list is the material itself, which the token endpoint's secret validation honours even if
    ///     the flag was switched off afterwards.
    /// </remarks>
    public static bool IsConfidential(RtClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        return client.RequireClientSecret || client.ClientSecrets is { Count: > 0 };
    }

    /// <summary>True for the mirror's own secret, false for an inherited copy of the parent's.</summary>
    public static bool IsOwnSecret(RtSecretRecord secret)
    {
        ArgumentNullException.ThrowIfNull(secret);

        return string.Equals(secret.Description, OwnSecretDescription, StringComparison.Ordinal);
    }

    /// <summary>
    ///     Returns the mirror-own secret record of a client, or <c>null</c> when it has none (a
    ///     public mirror, or one provisioned before AB#5061).
    /// </summary>
    public static RtSecretRecord? FindOwnSecret(RtClient client)
    {
        ArgumentNullException.ThrowIfNull(client);

        return client.ClientSecrets?.FirstOrDefault(IsOwnSecret);
    }

    /// <summary>
    ///     Generates a fresh, high-entropy client secret in plaintext. 32 bytes from
    ///     <see cref="RandomNumberGenerator" />, base64url-encoded so it survives env vars, form
    ///     bodies and shell quoting without escaping.
    /// </summary>
    public static string GenerateSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncode(bytes);
    }

    /// <summary>
    ///     Builds the <see cref="RtSecretRecord" /> for a mirror-own secret from its
    ///     <b>plaintext</b>. Only the SHA-256 hash is stored — the same convention
    ///     <c>ClientsController</c> and <c>CreateIdentityDataCommandRequestConsumer</c> use.
    /// </summary>
    public static RtSecretRecord CreateOwnSecretRecord(string plaintextSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintextSecret);

        return new RtSecretRecord
        {
            Type = SharedSecretType,
            Value = Sha256(plaintextSecret),
            Description = OwnSecretDescription
        };
    }

    /// <summary>
    ///     SHA-256 over the UTF-8 bytes, base64-encoded — the legacy hash format every stored
    ///     <c>RtSecretRecord.Value</c> uses and <c>OctoApplicationManager</c> validates against
    ///     (identical to <c>OctoSecretHasher.HashSecret</c>, and before the OpenIddict migration to
    ///     Duende's <c>string.Sha256()</c> extension). Kept here rather than referenced so this type
    ///     stays free of a protocol dependency: it lives in the persistence layer, which the
    ///     OpenIddict migration (Epic AB#4989) keeps protocol-agnostic. 🔴 A divergence would store
    ///     rotated secrets in a shape the token endpoint can never match.
    /// </summary>
    public static string Sha256(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
