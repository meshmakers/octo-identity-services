using System.Net.Mail;
using System.Text.Json;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserEmailInteractionService(
    IEventRepository eventRepository,
    INotificationService notificationService,
    IIdentityConfigurationService identityConfigurationService,
    IOptions<OctoIdentityServicesOptions> options,
    ILogger<UserEmailInteractionService> logger,
    UserManager<RtUser> userManager,
    IOctoPersistentGrantStore persistedGrantStore)
    : IUserEmailInteractionService
{
    public async Task SendWelcomeNotificationAsync(string tenantId, RtUser user)
    {
        if (!await CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateConfirmEmailTokenAsync(tenantId, user);

        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "ConfirmToken", () => confirmationToken }
        };

        await SendNotificationAsync(tenantId, IdentityServiceConstants.WelcomeEmailTemplateName, user, replaceFunctions);
    }

    public async Task SendWelcomeNotificationWithoutPasswordAsync(string tenantId, RtUser user)
    {
        if (!await CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateResetPasswordTokenAsync(tenantId, user);
        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "ConfirmToken", () => confirmationToken }
        };

        await SendNotificationAsync(tenantId, IdentityServiceConstants.WelcomeEmailWithNoPasswordTemplateName, user, replaceFunctions);
    }

    public async Task<string> ValidateEmailNotificationTokenAsync(string tenantId, string token)
    {
        var grant = await persistedGrantStore.GetAsync(token);
        if (grant == null)
        {
            logger.LogDebug("Confirm email token {Token} not found", token);
            throw UserEmailInteractionException.InvalidToken();
        }

        var data = JsonSerializer.Deserialize<EmailConfirmationGrantData>(grant.Data);
        if (data == null)
        {
            logger.LogDebug("Can't deserialize data for confirm email token {Token}", token);
            throw UserEmailInteractionException.InvalidToken();
        }


        var user = await userManager.FindByIdAsync(data.UserId);
        if (user == null)
        {
            logger.LogDebug("User {UserId} not found", data.UserId);
            throw UserEmailInteractionException.UnknownUser();
        }

        var result = await userManager.ConfirmEmailAsync(user, data.ConfirmationToken);

        if (!result.Succeeded)
        {
            logger.LogDebug("Confirm email token {Token} failed with errors: {Errors}", token,
                result.Errors.Select(x => x.Code));
            throw UserEmailInteractionException.InvalidToken();
        }

        return data.RedirectUrl;
    }


    public async Task SendPasswordResetNotificationAsync(string tenantId, RtUser user)
    {
        if (!await CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateResetPasswordTokenAsync(tenantId, user);
        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "ConfirmToken", () => confirmationToken }
        };

        
        await SendNotificationAsync(tenantId, IdentityServiceConstants.ResetPasswordEmailTemplateName, user, replaceFunctions);
    }

    public async Task<string> ValidateAndResetPasswordAsync(string tenantId, string token, string newPassword)
    {
        var grant = await persistedGrantStore.GetAsync(token);
        if (grant == null)
        {
            logger.LogDebug("Confirm email token {Token} not found", token);
            throw UserEmailInteractionException.InvalidToken();
        }

        var data = JsonSerializer.Deserialize<EmailConfirmationGrantData>(grant.Data);
        if (data == null)
        {
            logger.LogDebug("Can't deserialize data for confirm email token {Token}", token);
            throw UserEmailInteractionException.InvalidToken();
        }

        var user = await userManager.FindByIdAsync(data.UserId);
        if (user == null)
        {
            logger.LogDebug("User {UserId} not found", data.UserId);
            throw UserEmailInteractionException.UnknownUser();
        }

        var result = await userManager.ResetPasswordAsync(user, data.ConfirmationToken, newPassword);

        if (!result.Succeeded)
        {
            throw PasswordComplexityTooLowException.PasswordChangeFailed(
                string.Join(", ", result.Errors.Select(x => x.Code)),
                result.Errors);
        }

        // we know the user email address is valid so we can set it to confirmed.

        if (!user.EmailConfirmed)
        {
            var emailToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
            await userManager.ConfirmEmailAsync(user, emailToken);
        }


        return data.RedirectUrl;
    }

    private async Task<string> GenerateResetPasswordTokenAsync(string tenantId, RtUser user)
    {
        return await GenerateAndPersistUserManagerToken(tenantId, "password_reset",
            () => userManager.GeneratePasswordResetTokenAsync(user),
            "Password Reset Token",
            user.RtId.ToString()
        );
    }

    private async Task<string> GenerateConfirmEmailTokenAsync(string tenantId, RtUser user)
    {
        return await GenerateAndPersistUserManagerToken(tenantId, "email_confirmation",
            () => userManager.GenerateEmailConfirmationTokenAsync(user),
            "Email Confirmation Token",
            user.RtId.ToString());
    }

    private async Task<string> GenerateAndPersistUserManagerToken(string tenantId, string grantType, Func<Task<string>> tokenGenerator,
        string tokenDescription, string userId)
    {
        var token = await tokenGenerator();
        var key = Guid.NewGuid().ToString();
        var rtMailNotificationConfiguration = await identityConfigurationService.GetMailNotificationConfigurationAsync(tenantId);
        var grant = new RtPersistedGrant
        {
            GrantKey = key,
            SubjectId = userId,
            ClientId = "-",
            GrantType = grantType,
            CreationDateTime = DateTime.UtcNow,
            ExpirationDateTime = DateTime.UtcNow.AddHours(1),
            Description = tokenDescription,
            Data = JsonSerializer.Serialize(new EmailConfirmationGrantData
            {
                ConfirmationToken = token,
                RedirectUrl = rtMailNotificationConfiguration.RedirectAfterEmailInteractionUrl!,
                UserId = userId
            })
        };
        await persistedGrantStore.StoreAsync(grant);
        return key;
    }

    private string? GetName(RtUser user)
    {
        if (!string.IsNullOrEmpty(user.FirstName))
        {
            return user.FirstName;
        }

        if (!string.IsNullOrEmpty(user.UserName))
        {
            return user.UserName;
        }

        return user.Email;
    }

    private async Task<bool> CanSendEmail(string tenantId, RtUser user)
    {
        var rtMailNotificationConfiguration = await identityConfigurationService.GetMailNotificationConfigurationAsync(tenantId);
        if (!rtMailNotificationConfiguration.EnableEmailNotifications)
        {
            return false;
        }

        if (!MailAddress.TryCreate(user.Email, out _))
        {
            await eventRepository.StoreEventAsync(tenantId, RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Warning,
                $"Email address {user.Email} of user {user.RtId} is not valid", user.ToRtEntityId());
            return false;
        }

        return true;
    }
    
    private async Task SendNotificationAsync(string tenantId, string templateName, RtUser user, Dictionary<string, Func<string>> replaceFunctions)
    {
        if (string.IsNullOrWhiteSpace(user.Email))
        {
            await eventRepository.StoreEventAsync(tenantId, RtEventSourcesEnum.IdentityService, RtEventLevelsEnum.Warning,
                $"User with RtId '{user.RtId}' has no email address", user.ToRtEntityId());
            return;
        }

        await notificationService.SendAsync(tenantId, templateName, user.Email, replaceFunctions);
    }


    private class EmailConfirmationGrantData
    {
        public string UserId { get; init; } = null!;
        public string ConfirmationToken { get; init; } = null!;
        public string RedirectUrl { get; init; } = null!;
    }
}