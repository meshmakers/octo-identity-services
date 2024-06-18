using Microsoft.AspNetCore.Identity;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserEmailInteractionException : Exception
{
    public UserEmailInteractionException(string message) : base(message)
    {
        Errors = new List<IdentityError>();
    }

    public UserEmailInteractionException(string message, IEnumerable<IdentityError> errors) : base(message)
    {
        Errors = errors;
    }

    public IEnumerable<IdentityError> Errors { get; }

    public static UserEmailInteractionException TemplateNotFoundOrAmbiguous(string templateName)
    {
        return new UserEmailInteractionException($"Notification template {templateName} not found or ambiguous");
    }

    public static UserEmailInteractionException TemplateInvalid(string templateName)
    {
        return new UserEmailInteractionException($"Notification template {templateName} is invalid");
    }

    public static UserEmailInteractionException InvalidToken()
    {
        return new UserEmailInteractionException("Invalid token");
    }

    public static Exception UnknownUser()
    {
        return new UserEmailInteractionException("Unknown user");
    }
}