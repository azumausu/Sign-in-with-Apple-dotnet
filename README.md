# 概要
Sign in with Appleに必要なApple Develoer Apiを.net6から実行するためのコードです。
- [GenerateAndValidateTokens](#https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens)
- [RevokeTokens](#https://developer.apple.com/documentation/sign_in_with_apple/revoke_tokens)

Linux、MacOS、Win全てで動作するように実装しています。
動作を検証したのは、Linux、MaxOSのみです。

# 依存
以下のnugetパッケージに依存してます。
- BouncyCastle.NetCore
- Microsoft.IdentityModel.Tokens
- System.IdentityModel.Tokens.Jwt
