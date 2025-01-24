using System.Net.Mail;
using System.Text.Json;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v1;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserEmailInteractionService(
    IEventRepository eventRepository,
    INotificationService notificationService,
    IOptions<OctoIdentityServicesOptions> options,
    ILogger<UserEmailInteractionService> logger,
    UserManager<RtUser> userManager,
    IOctoPersistentGrantStore persistedGrantStore,
    IOptions<EmailInteractionConfiguration> emailOptions)
    : IUserEmailInteractionService
{
    private const string WelcomeEmailTemplateName = "Welcome_Email_Template";
    private const string ResetPasswordEmailTemplateName = "Reset_Password_Email_Template";
    private const string WelcomeEmailWithNoPasswordTemplateName = "Welcome_Email_With_No_Password_Template";

    public async Task SendWelcomeNotificationAsync(string tenantId, RtUser user)
    {
        if (!CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateConfirmEmailTokenAsync(user);

        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "id", () => confirmationToken }
        };

        await SendNotificationAsync(tenantId, WelcomeEmailTemplateName, user, replaceFunctions);
    }

    public async Task SendWelcomeNotificationWithoutPasswordAsync(string tenantId, RtUser user)
    {
        if (!CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateResetPasswordTokenAsync(user);
        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "id", () => confirmationToken }
        };

        await SendNotificationAsync(tenantId, WelcomeEmailWithNoPasswordTemplateName, user, replaceFunctions);
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
        if (!CanSendEmail(tenantId, user))
        {
            return;
        }

        var confirmationToken = await GenerateResetPasswordTokenAsync(user);
        var identityServerUrl = options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>
        {
            { "Username", () => GetName(user) ?? "" },
            { "IdentityServerUrl", () => identityServerUrl },
            { "id", () => confirmationToken }
        };

        
        await SendNotificationAsync(tenantId, ResetPasswordEmailTemplateName, user, replaceFunctions);
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

    private async Task<string> GenerateResetPasswordTokenAsync(RtUser user)
    {
        return await GenerateAndPersistUserManagerToken(
            () => userManager.GeneratePasswordResetTokenAsync(user),
            "Password Reset Token",
            user.RtId.ToString()
        );
    }

    private async Task<string> GenerateConfirmEmailTokenAsync(RtUser user)
    {
        return await GenerateAndPersistUserManagerToken(
            () => userManager.GenerateEmailConfirmationTokenAsync(user),
            "Email Confirmation Token",
            user.RtId.ToString());
    }

    private async Task<string> GenerateAndPersistUserManagerToken(Func<Task<string>> tokenGenerator,
        string tokenDescription, string userId)
    {
        var token = await tokenGenerator();
        var key = Guid.NewGuid().ToString();
        var grant = new RtPersistedGrant
        {
            GrantKey = key,
            CreationDateTime = DateTime.UtcNow,
            ExpirationDateTime = DateTime.UtcNow.AddHours(1),
            Description = tokenDescription,
            Data = JsonSerializer.Serialize(new EmailConfirmationGrantData
            {
                ConfirmationToken = token,
                RedirectUrl = emailOptions.Value.RedirectAfterEmailInteractionUrl!,
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

    private bool CanSendEmail(string tenantId, RtUser user)
    {
        if (!emailOptions.Value.EnableEmailNotifications)
        {
            return false;
        }

        if (!MailAddress.TryCreate(user.Email, out _))
        {
            eventRepository.StoreEventAsync(tenantId, RtEventLevelsEnum.Warning,
                $"Email address {user.Email} of user {user.RtId} is not valid", user.ToRtEntityId());
            return false;
        }

        return true;
    }
    
    private async Task SendNotificationAsync(string tenantId, string templateName, RtUser user, Dictionary<string, Func<string>> replaceFunctions)
    {
        if (string.IsNullOrWhiteSpace(user.Email))
        {
            await eventRepository.StoreEventAsync(tenantId, RtEventLevelsEnum.Warning,
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