using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.IdentityServer.Stores;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Common.Shared.DataTransferObjects;
using Meshmakers.Octo.Common.Shared.Services;
using Meshmakers.Octo.SystematizedData.Persistence;
using Meshmakers.Octo.SystematizedData.Persistence.CkModelEntities;
using Meshmakers.Octo.SystematizedData.Persistence.DataAccess;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserEmailInteractionService : IUserEmailInteractionService
{
    private const string WelcomeEmailTemplateName = "Welcome_Email_Template";
    private const string ResetPasswordEmailTemplateName = "Reset_Password_Email_Template";
    private const string WelcomeEmailWithNoPasswordTemplateName = "Welcome_Email_With_No_Password_Template";
    private const string SkipMarkdownRenderingMark = "#SKIP_MARKDOWN_RENDERING#";

    private readonly INotificationRepository _notificationRepository;
    private readonly IMarkdownRenderService _markdownRenderService;
    private readonly ISystemContext _systemContext;
    private readonly UserManager<OctoUser> _userManager;
    private readonly IPersistedGrantStore _persistedGrantStore;
    private readonly IOptions<OctoIdentityServicesOptions> _options;
    private readonly ILogger<UserEmailInteractionService> _logger;
    private readonly EmailInteractionConfiguration _emailConfiguration;

    public UserEmailInteractionService(
        INotificationRepository notificationRepository,
        IOptions<OctoIdentityServicesOptions> options,
        ILogger<UserEmailInteractionService> logger,
        ISystemContext systemContext,
        UserManager<OctoUser> userManager,
        IMarkdownRenderService markdownRenderService,
        IPersistedGrantStore persistedGrantStore,
        IOptions<EmailInteractionConfiguration> emailOptions)
    {
        _notificationRepository = notificationRepository;
        _options = options;
        _logger = logger;
        _systemContext = systemContext;
        _userManager = userManager;
        _markdownRenderService = markdownRenderService;
        _persistedGrantStore = persistedGrantStore;
        _emailConfiguration = emailOptions.Value;
    }

    public async Task SendWelcomeNotificationAsync(OctoUser user)
    {
        if (!CanSendEmail(user))
            return;

        var confirmationToken = await GenerateConfirmEmailTokenAsync(user);

        var template = await GetNotificationTemplateAsync(WelcomeEmailTemplateName);
        var identityServerUrl = _options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>()
        {
            { "{{Username}}", () => GetName(user) },
            { "{{IdentityServerUrl}}", () => identityServerUrl },
            { "{{id}}", () => confirmationToken },
        };

        var skipRendering = ShouldSkipRendering(template);
        var messageBody = skipRendering
            ? _markdownRenderService.RenderPlainText(template.BodyTemplate!, replaceFunctions)
            : _markdownRenderService.RenderHtml(template.BodyTemplate!, replaceFunctions);

        await _notificationRepository.AddEMailMessageAsync(_emailConfiguration.NotificationTenant!, user.Email, template.SubjectTemplate!,
            messageBody);
    }

    public async Task SendWelcomeNotificationWithoutPasswordAsync(OctoUser user)
    {
        if (!CanSendEmail(user))
            return;
        
        var confirmationToken = await GenerateResetPasswordTokenAsync(user);

        var template = await GetNotificationTemplateAsync(WelcomeEmailWithNoPasswordTemplateName);
        var identityServerUrl = _options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>()
        {
            { "{{Username}}", () => GetName(user) },
            { "{{IdentityServerUrl}}", () => identityServerUrl },
            { "{{id}}", () => confirmationToken },
        };

        var skipRendering = ShouldSkipRendering(template);
        var messageBody = skipRendering
            ? _markdownRenderService.RenderPlainText(template.BodyTemplate!, replaceFunctions)
            : _markdownRenderService.RenderHtml(template.BodyTemplate!, replaceFunctions);

        await _notificationRepository.AddEMailMessageAsync(_emailConfiguration.NotificationTenant!, user.Email, template.SubjectTemplate!,
            messageBody);
    }

    public async Task<string> ValidateEmailNotificationTokenAsync(string token)
    {
        var grant = await _persistedGrantStore.GetAsync(token);
        if (grant == null)
        {
            _logger.LogDebug("Confirm email token {Token} not found", token);
            throw UserEmailInteractionException.InvalidToken();
        }

        var data = JsonSerializer.Deserialize<EmailConfirmationGrantData>(grant.Data);
        if (data == null)
        {
            _logger.LogDebug("Can't deserialize data for confirm email token {Token}", token);
            throw UserEmailInteractionException.InvalidToken();
        }


        var user = await _userManager.FindByIdAsync(data.UserId);

        var result = await _userManager.ConfirmEmailAsync(user, data.ConfirmationToken);

        if (!result.Succeeded)
        {
            _logger.LogDebug("Confirm email token {Token} failed with errors: {Errors}", token,
                result.Errors.Select(x => x.Code));
            throw UserEmailInteractionException.InvalidToken();
        }

        return data.RedirectUrl;
    }


    public async Task SendPasswordResetNotificationAsync(OctoUser user)
    {
        if (!CanSendEmail(user))
            return;
        var confirmationToken = await GenerateResetPasswordTokenAsync(user);

        var template = await GetNotificationTemplateAsync(ResetPasswordEmailTemplateName);

        var identityServerUrl = _options.Value.AuthorityUrl.EnsureEndsWith("/");

        var replaceFunctions = new Dictionary<string, Func<string>>()
        {
            { "{{Username}}", () => GetName(user) },
            { "{{IdentityServerUrl}}", () => identityServerUrl },
            { "{{id}}", () => confirmationToken },
        };

        var skipRendering = ShouldSkipRendering(template);
        var messageBody = skipRendering
            ? _markdownRenderService.RenderPlainText(template.BodyTemplate!, replaceFunctions)
            : _markdownRenderService.RenderHtml(template.BodyTemplate!, replaceFunctions);

        await _notificationRepository.AddEMailMessageAsync(_emailConfiguration.NotificationTenant!, user.Email, template.SubjectTemplate!,
            messageBody);
    }

    public async Task<string> ValidateAndResetPasswordAsync(string token, string newPassword)
    {
        var grant = await _persistedGrantStore.GetAsync(token);
        if (grant == null)
        {
            _logger.LogDebug("Confirm email token {Token} not found", token);
            throw UserEmailInteractionException.InvalidToken();
        }

        var data = JsonSerializer.Deserialize<EmailConfirmationGrantData>(grant.Data);
        if (data == null)
        {
            _logger.LogDebug("Can't deserialize data for confirm email token {Token}", token);
            throw UserEmailInteractionException.InvalidToken();
        }


        var user = await _userManager.FindByIdAsync(data.UserId);

        var result = await _userManager.ResetPasswordAsync(user, data.ConfirmationToken, newPassword);

        if (!result.Succeeded)
        {
            throw PasswordComplexityTooLowException.PasswordChangeFailed(string.Join(", ", result.Errors.Select(x => x.Code)), result.Errors);
        }
        
        // we know the user email address is valid so we can set it to confirmed.

        if (!user.EmailConfirmed)
        {
            var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            await _userManager.ConfirmEmailAsync(user, emailToken);
        }
        

        return data.RedirectUrl;
    }

    private async Task<string> GenerateResetPasswordTokenAsync(OctoUser user)
    {
        return await GenerateAndPersistUserManagerToken(
            () => _userManager.GeneratePasswordResetTokenAsync(user),
            "Password Reset Token",
            user.Id.ToString()
        );
    }

    private async Task<string> GenerateConfirmEmailTokenAsync(OctoUser user)
    {
        return await GenerateAndPersistUserManagerToken(
            () => _userManager.GenerateEmailConfirmationTokenAsync(user),
            "Email Confirmation Token",
            user.Id.ToString());
    }

    private async Task<string> GenerateAndPersistUserManagerToken(Func<Task<string>> tokenGenerator, string tokenDescription, string userId)
    {
        var token = await tokenGenerator();
        var key = Guid.NewGuid().ToString();
        var grant = new OctoPersistedGrant()
        {
            Key = key,
            CreationTime = DateTime.UtcNow,
            Expiration = DateTime.UtcNow.AddHours(1),
            Description = tokenDescription,
            Data = JsonSerializer.Serialize(new EmailConfirmationGrantData()
            {
                ConfirmationToken = token,
                RedirectUrl = _emailConfiguration.RedirectAfterEmailInteraction!,
                UserId = userId,
            }),
        };
        await _persistedGrantStore.StoreAsync(grant);
        return key;
    }

    private string GetName(OctoUser user)
    {
        if (!string.IsNullOrEmpty(user.FirstName))
            return user.FirstName;
        if (!string.IsNullOrEmpty(user.UserName))
            return user.UserName;
        return user.Email;
    }

    private bool CanSendEmail(OctoUser user)
    {
        if (!_emailConfiguration.EnableEmailNotifications || string.IsNullOrWhiteSpace(_emailConfiguration.NotificationTenant))
        {
            return false;
        }

        if (!MailAddress.TryCreate(user.Email, out _))
        {
            _logger.LogInformation("Email address {Email} of user {User} is not valid", user.Email, user.Id);
            return false;
        }

        return true;
    }

    private async Task<NotificationTemplateDto> GetNotificationTemplateAsync(string templateName)
    {
        var tenantContext = await _systemContext.CreateOrGetTenantContextAsync(_emailConfiguration.NotificationTenant!);
        using var session = await tenantContext.Repository.StartSessionAsync();

        var query = new DataQueryOperation
        {
            FieldFilters = new[]
            {
                new FieldFilter("RtWellKnownName", FieldFilterOperator.Equals, templateName)
            }
        };

        var result = await tenantContext.Repository.GetRtEntitiesByTypeAsync<RtSystemNotificationTemplate>(session, query);

        if (result.TotalCount != 1)
        {
            throw UserEmailInteractionException.TemplateNotFoundOrAmbiguous(templateName);
        }

        var templateEntity = result.Result.Single();

        ValidateTemplate(templateEntity);

        return new NotificationTemplateDto()
        {
            SubjectTemplate = templateEntity.SubjectTemplate,
            BodyTemplate = templateEntity.BodyTemplate,
        };
    }

    private void ValidateTemplate(RtSystemNotificationTemplate template)
    {
        if (string.IsNullOrWhiteSpace(template.SubjectTemplate) || string.IsNullOrWhiteSpace(template.BodyTemplate))
        {
            throw UserEmailInteractionException.TemplateInvalid(template.RtWellKnownName!);
        }
    }

    private bool ShouldSkipRendering(NotificationTemplateDto template)
    {
        if (template.BodyTemplate!.Contains(SkipMarkdownRenderingMark))
        {
            template.BodyTemplate = template.BodyTemplate.Replace(SkipMarkdownRenderingMark, string.Empty);
            return true;
        }

        return false;
    }

    private class EmailConfirmationGrantData
    {
        public string UserId { get; set; } = null!;
        public string ConfirmationToken { get; set; } = null!;
        public string RedirectUrl { get; set; } = null!;
    }
}
