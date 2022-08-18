using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Naru.UserAppFrontend.Infrastructure.AppleDeveloper.Authentication.Inputs;
using Naru.UserAppFrontend.Infrastructure.AppleDeveloper.Authentication.Outputs;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
/// Apple Developer ApiのAuthentication周りのApiを提供するService
/// </summary>
public class AppleAuthenticationService
{
    private const string APPLE_TEAM_ID = nameof(APPLE_TEAM_ID);
    private const string APPLE_CLIENT_ID = nameof(APPLE_CLIENT_ID);
    private const string APPLE_KEY_ID = nameof(APPLE_KEY_ID);
    
    /// <summary>
    /// .p8をbase64エンコードしたもの
    /// </summary>
    private const string APPLE_AUTH_PRIVATE_KEY = nameof(APPLE_AUTH_PRIVATE_KEY);

    private readonly string _appleTeamId;
    private readonly string _appleClientId;
    private readonly string _appleKeyId;
    private readonly string _appleAuthKey;
    
    public AppleAuthenticationService()
    {
        _appleTeamId = Environment.GetEnvironmentVariable(APPLE_TEAM_ID) 
                       ?? throw new InvalidOperationException($"環境変数{APPLE_TEAM_ID}が存在しません");
        _appleClientId = Environment.GetEnvironmentVariable(APPLE_CLIENT_ID) 
                         ?? throw new InvalidOperationException($"環境変数{APPLE_CLIENT_ID}が存在しません");
        _appleKeyId = Environment.GetEnvironmentVariable(APPLE_KEY_ID) 
                      ?? throw new InvalidOperationException($"環境変数{APPLE_KEY_ID}が存在しません");
        _appleAuthKey = Environment.GetEnvironmentVariable(APPLE_AUTH_PRIVATE_KEY) 
                        ?? throw new InvalidOperationException($"環境変数{APPLE_AUTH_PRIVATE_KEY}が存在しません");
    }
    
    /// <summary>
    /// リフレッシュトークンを作成する
    /// https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
    /// </summary>
    public async ValueTask<GenerateAndValidateTokensOutput> GenerateAndValidateTokens(GenerateAndValidateTokensInput input)
    {
        var clientSecret = GenerateJwt();
        
        var parameters = new Dictionary<string, string>()
        {
            {"code", input.AuthorizationCode},
            {"client_id", _appleClientId},
            {"client_secret", clientSecret},
            {"grant_type", "authorization_code"},
        };
        var client = new HttpClient();
        var response = await client.PostAsync(
            new Uri("https://appleid.apple.com/auth/token"),
            new FormUrlEncodedContent(parameters)
        );
        
        
        if (!response.IsSuccessStatusCode)
        {
            var errorMessage = await response.Content.ReadAsStringAsync() ?? throw new InvalidOperationException(); 
            throw new HttpRequestException($"StatusCode: {response.StatusCode}\nReason: {errorMessage}");
        }

        var body = await response.Content.ReadAsStringAsync() ?? throw new InvalidOperationException();
        var output = JsonSerializer.Deserialize<GenerateAndValidateTokensOutput>(body) ?? throw new InvalidOperationException();

        // Debug
        // Console.WriteLine(body);
        
        return output;
    }

    /// <summary>
    /// リフレッシュトークンを用いてトークンを無効化する
    /// https://developer.apple.com/documentation/sign_in_with_apple/revoke_tokens
    /// </summary>
    /// <returns></returns>
    public async ValueTask RevokeTokens(RevokeTokensInput input)
    {
        var clientSecret = GenerateJwt();
        
        var paramters = new Dictionary<string, string>()
        {
            { "token", input.RefreshToken },
            { "client_id", _appleClientId },
            { "client_secret", clientSecret },
            { "token_type_hint", "refresh_token" },
        };
        var client = new HttpClient();
        var response = await client.PostAsync(
            new Uri("https://appleid.apple.com/auth/revoke"),
            new FormUrlEncodedContent(paramters)
        );
        if (!response.IsSuccessStatusCode)
        {
            var errorMessage = await response.Content.ReadAsStringAsync();
            throw new HttpRequestException($"StatusCode: {response.StatusCode}\nReason: {errorMessage}");
        }
        
        // Debug
        // var body = await response.Content.ReadAsStringAsync() ?? throw new InvalidOperationException();
        // Console.WriteLine(body);
    }
    
    
    private string GenerateJwt()
    {
        var key = GetECDsa();
        var securityKey = new ECDsaSecurityKey(key) { KeyId = _appleKeyId, };
        var credentials = new SigningCredentials(securityKey, "ES256");
        var token = new JwtSecurityToken(
            claims: new[] {new Claim("sub", _appleClientId), },
            issuer: _appleTeamId,
            audience: "https://appleid.apple.com",
            // Refresh Tokenに期限は存在しない。ただし、ユーザーの特定操作で無効になる場合がある。
            // https://developer.apple.com/forums/thread/651237
            expires: DateTime.UtcNow + TimeSpan.FromDays(1),
            signingCredentials: credentials);
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    private ECDsa GetECDsa()
    {
        // もし、.p8をそのまま読み込む場合はこちらを使用する。
        // using TextReader reader = System.IO.File.OpenText("AuthKey_xxxxxxx.p8");
        
        using var stream = new MemoryStream(Convert.FromBase64String(_appleAuthKey));
        using var reader = new StreamReader(stream);
        var ecPrivateKeyParameters =
            (ECPrivateKeyParameters)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
        
        // Windows or Mac
        if (Environment.OSVersion.Platform is PlatformID.MacOSX 
            or PlatformID.Win32S 
            or PlatformID.Win32Windows 
            or PlatformID.Win32NT 
            or PlatformID.WinCE)
        {
            var x = ecPrivateKeyParameters.Parameters.G.AffineXCoord.GetEncoded();
            var y = ecPrivateKeyParameters.Parameters.G.AffineYCoord.GetEncoded();
            var d = ecPrivateKeyParameters.D.ToByteArrayUnsigned();

            var msEcp = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = { X = x, Y = y }, D = d };
            return ECDsa.Create(msEcp);
        }
        // Linux(https://github.com/dotnet/core/issues/2037#issuecomment-436340605)
        else
        {
            var q = ecPrivateKeyParameters.Parameters.G.Multiply (ecPrivateKeyParameters.D).Normalize ();
            var x = q.AffineXCoord.GetEncoded ();
            var y = q.AffineYCoord.GetEncoded ();
            var d = ecPrivateKeyParameters.D.ToByteArrayUnsigned ();
            // Convert the BouncyCastle key to a Native Key.
            var msEcp = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = { X = x, Y = y }, D = d };
            return ECDsa.Create(msEcp);
        }
    }
}
