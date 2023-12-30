using System.Runtime.Serialization;
using Meshmakers.Octo.ConstructionKit.Contracts;

namespace IdentityServerPersistence.SystemStores;

[Serializable]
public class NotExistingException : Exception
{
    public NotExistingException()
    {
    }

    public NotExistingException(string message) : base(message)
    {
    }

    public NotExistingException(string message, Exception inner) : base(message, inner)
    {
    }

    public static Exception UserDoesNotExist(string normalizedEmail)
    {
        return new NotExistingException($"User with normalized email '{normalizedEmail}' does not exist.");
    }

    public static Exception UserWithIdDoesNotExist(OctoObjectId rtId)
    {
        return new NotExistingException($"User with id '{rtId}' does not exist.");
    }

    public static Exception UserTokenDoesNotExist(OctoObjectId userRtId, string loginProvider, string name)
    {
        return new NotExistingException(
            $"User token with user id '{userRtId}', login provider '{loginProvider}' and name '{name}' does not exist.");
    }

    public static Exception UserWithNameDoesNotExist(string normalizedUserName)
    {
        return new NotExistingException($"User with normalized user name '{normalizedUserName}' does not exist.");
    }

    public static Exception RoleWithIdDoesNotExist(OctoObjectId rtId)
    {
        return new NotExistingException($"Role with id '{rtId}' does not exist.");
    }
}