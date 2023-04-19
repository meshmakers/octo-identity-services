using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public class UserEmailInteractionException : Exception
{
    public static UserEmailInteractionException TemplateNotFoundOrAmbiguous(string templateName) =>
        new($"Notification template {templateName} not found or ambiguous");

    public static UserEmailInteractionException TemplateInvalid(string templateName) =>
        new($"Notification template {templateName} is invalid");

    public static UserEmailInteractionException InvalidToken() => new("Invalid token");
    

    public UserEmailInteractionException(string message) : base(message)
    {
        Errors = new List<IdentityError>();
    }
    
    public UserEmailInteractionException(string message, IEnumerable<IdentityError> errors) : base(message)
    {
        Errors = errors;
    }
    
    public IEnumerable<IdentityError> Errors { get; }
}
