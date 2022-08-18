namespace Naru.UserAppFrontend.Infrastructure.AppleDeveloper.Authentication.Inputs;

public record RevokeTokensInput
{
    public string RefreshToken { get; init; }
}