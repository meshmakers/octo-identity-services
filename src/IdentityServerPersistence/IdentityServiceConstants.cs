namespace IdentityServerPersistence;

public static class IdentityServiceConstants
{
    public const string ApiPathPrefix = "{tenantId:tenantId}/v{version:apiVersion}";
    public const string ApiVersion1 = "1.0";

    public const string IdentityApiReadOnlyPolicy = "IdentityApiReadOnlyPolicy";
    public const string IdentityApiReadWritePolicy = "IdentityApiReadWritePolicy";

    // AB#5859: scope AND tenant role. Users, roles, groups, mappings, data permissions → UserManagement.
    public const string IdentityUserAdministrationReadPolicy = "IdentityUserAdministrationReadPolicy";
    public const string IdentityUserAdministrationWritePolicy = "IdentityUserAdministrationWritePolicy";

    // AB#5859: clients, client mirrors, API resources/scopes/secrets, identity providers, e-mail domain
    // group rules, cross-tenant admin provisioning → TenantManagement or UserManagement.
    public const string IdentityTenantAdministrationReadPolicy = "IdentityTenantAdministrationReadPolicy";
    public const string IdentityTenantAdministrationWritePolicy = "IdentityTenantAdministrationWritePolicy";

    // AB#5859: read-only directory lookups that operational UIs need (role names, a client's roles and
    // actors) → UserManagement, TenantManagement, AdminPanelManagement or CommunicationManagement.
    public const string IdentityDirectoryReadPolicy = "IdentityDirectoryReadPolicy";

    // AB#5859: the slim user directory (id + display name only) → every signed-in caller whose token
    // was issued for the route tenant (no role, but a strict own-tenant check).
    public const string IdentityUserDirectoryReadPolicy = "IdentityUserDirectoryReadPolicy";

    // AB#5859: service-wide operations (log level) → TenantManagement in the system tenant only.
    public const string IdentityServiceAdministrationPolicy = "IdentityServiceAdministrationPolicy";

    public const string MailNotificationConfigurationName = "MailNotificationConfiguration";

    public const string WelcomeEmailTemplateName = "Welcome_Email_Template";
    public const string ResetPasswordEmailTemplateName = "Reset_Password_Email_Template";
    public const string WelcomeEmailWithNoPasswordTemplateName = "Welcome_Email_With_No_Password_Template";

    public const string IdentityMigrationVersionKey = "IdentityServiceMigrations";

    /// <summary>
    /// AB#6180: tenant role that may create, change and delete entries of the platform file system
    /// (<c>System/FileSystemItem</c>). Seeded by <c>System.Identity.Bootstrap</c> 1.5.0 (660…61), granted to
    /// the initial tenant administrator and, once, to every holder of <c>ReportingManagement</c>.
    /// TODO(AB#6180): replace with <c>CommonConstants.FileManagementRole</c> once the octo-sdk build that
    /// introduces it is in the NuGet feed.
    /// </summary>
    public const string FileManagementRole = "FileManagement";

    /// <summary>
    /// AB#6180: tenant role that may browse and download the platform file system (read-only). Seeded by
    /// <c>System.Identity.Bootstrap</c> 1.5.0 (660…62), granted to the initial tenant administrator and, once,
    /// to every holder of <c>ReportingViewer</c>.
    /// TODO(AB#6180): replace with <c>CommonConstants.FileViewerRole</c> once the octo-sdk build that
    /// introduces it is in the NuGet feed.
    /// </summary>
    public const string FileViewerRole = "FileViewer";

    /// <summary>
    /// AB#6180: TenantConfiguration row recording that the one-time grant of <see cref="FileManagementRole"/> /
    /// <see cref="FileViewerRole"/> to the holders of the Reporting roles (<c>FileRoleGrant</c>) has run.
    /// Present = never run again.
    /// </summary>
    public const string FileRoleGrantKey = "FileRoleGrant";

    /// <summary>
    /// Phase 3 PR #4: TenantConfiguration row used by <c>PreBlueprintCleanupMigration</c> to hand
    /// captured User → Role and ExternalTenantUserMapping → Role assignments (by role name) over
    /// to the post-blueprint restore step in
    /// <c>DefaultConfigurationCreatorService.SetupTenantAsync</c>. The row is deleted after the
    /// restore completes, so its presence on tenant startup is the gate that runs the restore.
    /// </summary>
    public const string PendingPostBlueprintRoleAssignmentsKey = "PendingPostBlueprintRoleAssignments";
}