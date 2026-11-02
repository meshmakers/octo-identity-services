namespace IdentityServerPersistence.Services.AdminRoleMigration;

/// <summary>Mode of the admin role migration (AB#8165).</summary>
public enum AdminRoleMigrationMode
{
    /// <summary>Nothing is read or written. The default.</summary>
    Off = 0,

    /// <summary>Logs per tenant what would change and writes nothing.</summary>
    DryRun = 1,

    /// <summary>Moves the admins to TenantOwners and removes the direct roles the group covers.</summary>
    Apply = 2
}

/// <summary>
///     Options of the admin role migration, bound from the <c>"IdentityApiAuthorization"</c> configuration section,
///     i.e. <c>OCTO_IDENTITYAPIAUTHORIZATION__ADMINROLEMIGRATION=Off|DryRun|Apply</c>. Shares the section with the
///     identity REST API authorization options; only this key is read here.
/// </summary>
public class AdminRoleMigrationOptions
{
    /// <summary>The configuration section name.</summary>
    public const string SectionName = "IdentityApiAuthorization";

    /// <summary>Gets or sets the migration mode. Default <see cref="AdminRoleMigrationMode.Off" />.</summary>
    public AdminRoleMigrationMode AdminRoleMigration { get; set; } = AdminRoleMigrationMode.Off;
}
