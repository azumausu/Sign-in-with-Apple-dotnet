# 概要
Sign in with Appleで作成されたアカウントを削除するために必要なApple Develoer APIを.net6から実行するためのコードです。
- [GenerateAndValidateTokens](#https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens)
- [RevokeTokens](#https://developer.apple.com/documentation/sign_in_with_apple/revoke_tokens)

Linux、MacOS、Win全てで動作するように実装しています。
動作を検証したのは、Linux、MaxOSのみです。

# How To
AppleAuthenticationService.csがメインです。  
私が使用した時がASP.NET Coreサーバーだったので環境変数から必要な情報を取得する実装になってます。  
下記変数名でそれぞれ環境変数を設定すればそのままで動作します。  
もし、環境変数を使用したくない場合は参照部分を変更すれば動作すると思います。  
APPLE_AUTH_PRIVATE_KEYはAppleで作成した.p8をbase64エンコードしたものを入れる想定で実装しています。  
.p8ファイルをそのまま使用したい場合は、GetECDsa()の中のStreamReaderをコメントアウトして
TextReaderのコメントアウトを外して使用してください。  

- APPLE_TEAM_ID
- APPLE_CLIENT_ID
- APPLE_KEY_ID
- APPLE_AUTH_PRIVATE_KEY

# 依存
以下のnugetパッケージに依存してます。
- BouncyCastle.NetCore
- Microsoft.IdentityModel.Tokens
- System.IdentityModel.Tokens.Jwt
