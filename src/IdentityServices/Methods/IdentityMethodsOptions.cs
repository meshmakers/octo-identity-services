namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Options of the CK methods that the identity service hosts (section <c>Methods:Identity</c>, AB#5672).
///     Environment variable form: <c>OCTO_Methods__Identity__EnablePasswordMethods</c>.
/// </summary>
public sealed class IdentityMethodsOptions
{
    /// <summary>Configuration section.</summary>
    public const string SectionName = "Methods:Identity";

    /// <summary>
    ///     Production gate (decided by Gerald 2026-10-23): no method that carries a password or another secret may be
    ///     enabled on staging-1, prod-1 and prod-2 before the restricted broker user (B0) is rolled out, because the
    ///     method queues carry the parameters. When <c>false</c> (the default) the handlers of methods with a sensitive
    ///     parameter or result are not registered: the service does not announce them and the gateway answers
    ///     <c>METHOD_HANDLER_NOT_AVAILABLE</c>. Local and test-2 may switch it on with test accounts.
    /// </summary>
    public bool EnablePasswordMethods { get; set; }
}
