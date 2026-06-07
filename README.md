# tesla-token

Small Java 21 helper for obtaining a Tesla OAuth refresh token using Tesla's
OAuth PKCE flow.

It opens a native SWT browser, intercepts Tesla's registered
`tesla://auth/callback` redirect, validates the OAuth `state`, exchanges the
authorization code for tokens, prints the refresh token, and copies it to the
clipboard when possible. The program exits after a successful token exchange.

## Requirements

- Java 21
- Maven 3.9+
- A desktop browser backend supported by SWT

Supported SWT profiles are selected automatically for:

- macOS ARM64 / x86_64
- Windows x86_64
- Linux x86_64 / ARM64

Linux additionally needs GTK and WebKitGTK installed by the OS package manager.
Windows may require the Microsoft Edge WebView2 runtime, depending on the SWT
browser backend available on the system.

## Usage

macOS / Linux:

```sh
./tesla-token
```

Windows:

```bat
tesla-token.cmd
```

Options:

```sh
./tesla-token --region cn
./tesla-token --email you@example.com
./tesla-token --debug
```

### Options

`--region global|cn`

Selects the Tesla authentication host. The default is `global`.

- `global`: Non-China accounts using `https://auth.tesla.com`
- `cn`: China accounts using `https://auth.tesla.cn`

`--email EMAIL`

Adds a `login_hint` to the OAuth request so Tesla can pre-fill the login email
field. It is optional and does not change the token scope.

`--debug`

Prints browser navigation events and callback handling details. OAuth codes are
redacted from debug output.

`-h`, `--help`

Prints the command-line help.

## How It Works

The OAuth request uses:

- `client_id=ownerapi`
- `redirect_uri=tesla://auth/callback`
- `scope=openid email offline_access`
- PKCE `code_challenge_method=S256`

The default region is `global`. Europe, North America, and other non-China
accounts authenticate against `https://auth.tesla.com`; China authenticates
against `https://auth.tesla.cn`.

The SWT browser emits `LocationListener.changing(...)` before navigating to the
custom callback URI. The app cancels that navigation, extracts `code` and
`state`, verifies the state, then posts this JSON request to Tesla:

```json
{
  "grant_type": "authorization_code",
  "client_id": "ownerapi",
  "code": "...",
  "code_verifier": "...",
  "redirect_uri": "tesla://auth/callback"
}
```

The returned `refresh_token` is printed to stdout. The browser window then
closes and the process exits.

## Notes

The refresh token is a credential. Do not paste it into logs, issue trackers, or
chat tools.

On macOS, the launcher uses `-XstartOnFirstThread`, which SWT requires for Cocoa.
