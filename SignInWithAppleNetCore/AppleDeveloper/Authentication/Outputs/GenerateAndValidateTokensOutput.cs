using System.Text.Json.Serialization;

namespace Naru.UserAppFrontend.Infrastructure.AppleDeveloper.Authentication.Outputs;

public record GenerateAndValidateTokensOutput
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; }
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; init; }
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; }
    
    [JsonPropertyName("refresh_token")] 
    public string RefreshToken { get; init; }
    
    [JsonPropertyName("id_token")]
    public string IdToken { get; init; }
}