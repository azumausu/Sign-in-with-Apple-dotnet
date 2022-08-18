namespace Naru.UserAppFrontend.Infrastructure.AppleDeveloper.Authentication.Inputs;

public record GenerateAndValidateTokensInput
{
    public string AuthorizationCode { get; init; }
}