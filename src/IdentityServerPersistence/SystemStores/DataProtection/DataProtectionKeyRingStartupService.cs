using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NLog;

namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     Startup check and migration of the Data Protection key ring encryption (AB#5530).
/// </summary>
/// <remarks>
///     <list type="bullet">
///         <item><c>Identity:DataProtection:EncryptExistingKeys=true</c> without a <c>SecretEncryption</c> key: identity
///         refuses to start (<see cref="DataProtectionKeyRingException" />).</item>
///         <item>A stored key wrapped with a platform key id that is not configured: identity refuses to start.</item>
///         <item>Keys wrapped with a non-active key id are re-wrapped with the active one (platform key rotation);
///         with the flag on, plain keys are rewritten encrypted. Idempotent, safe on every pod at once.</item>
///         <item>Every other failure (database not reachable, write conflict) is logged and retried on the next start;
///         the key ring stays readable either way.</item>
///     </list>
///     No key material is ever logged.
/// </remarks>
public sealed class DataProtectionKeyRingStartupService(
    DataProtectionKeyStore keyStore,
    ISecretAttributeProtector secretProtector,
    IOptions<OctoIdentityServicesOptions> identityOptions) : IHostedService
{
    private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var encryptExistingKeys = identityOptions.Value.DataProtection.EncryptExistingKeys;

        if (encryptExistingKeys && !secretProtector.IsConfigured)
        {
            const string message =
                "Identity refuses to start: Identity:DataProtection:EncryptExistingKeys is true but no SecretEncryption " +
                "key is configured (OCTO_SECRETENCRYPTION__KEYS__<id>, OCTO_SECRETENCRYPTION__ACTIVEKEYID). Data " +
                "Protection keys are never stored unencrypted in this mode.";
            Logger.Fatal(message);
            throw new DataProtectionKeyRingException(message);
        }

        if (!secretProtector.IsConfigured)
        {
            Logger.Warn(
                "No SecretEncryption key ring is configured: ASP.NET Data Protection keys are stored unencrypted in " +
                "the system database (AB#5530)");
        }
        else if (!encryptExistingKeys)
        {
            Logger.Info(
                "Identity:DataProtection:EncryptExistingKeys is false: stored Data Protection keys stay as they are and " +
                "new keys are written unencrypted while the store holds keys (AB#5530 rollout step 1)");
        }

        try
        {
            var result = await keyStore.CheckAndProtectStoredKeysAsync(encryptExistingKeys);
            if (!result.SystemTenantExists)
            {
                Logger.Info("Data Protection key ring check skipped: the system tenant does not exist yet");
                return;
            }

            Logger.Info(
                "Data Protection key ring checked: {Total} keys, {Encrypted} encrypted now, {Rewrapped} re-wrapped with " +
                "platform key id '{ActiveKeyId}', {Plain} still unencrypted",
                result.TotalKeys, result.EncryptedKeys, result.RewrappedKeys, secretProtector.ActiveKeyId ?? "-",
                result.PlainKeys);
            if (result.PlainKeys > 0 && encryptExistingKeys)
            {
                Logger.Warn("{Plain} Data Protection keys are still unencrypted; retried on the next start",
                    result.PlainKeys);
            }
        }
        catch (DataProtectionKeyRingException ex)
        {
            Logger.Fatal(ex.Message);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error(ex,
                "Data Protection key ring check failed ({Message}); retried on the next start", ex.Message);
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
