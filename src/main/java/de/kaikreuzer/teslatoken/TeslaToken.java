package de.kaikreuzer.teslatoken;

import org.eclipse.swt.SWT;
import org.eclipse.swt.browser.Browser;
import org.eclipse.swt.browser.LocationAdapter;
import org.eclipse.swt.browser.LocationEvent;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TeslaToken {
    private static final String CLIENT_ID = "ownerapi";
    private static final String AUTH_URL_PATH = "/oauth2/v3/authorize";
    private static final String TOKEN_URL_PATH = "/oauth2/v3/token";
    private static final String REDIRECT_URI = "tesla://auth/callback";
    private static final String SCOPES = "openid email offline_access";
    private static final SecureRandom RANDOM = new SecureRandom();

    private TeslaToken() {
    }

    public static void main(String[] args) throws Exception {
        if (Config.containsHelp(args)) {
            Config.printHelp();
            return;
        }

        Config config = Config.parse(args);
        String authHost = authHost(config.region);
        Pkce pkce = Pkce.create();
        String authUrl = buildAuthUrl(authHost, pkce, config.email);

        Display display = new Display();
        Shell shell = new Shell(display);
        shell.setText("Tesla Login");
        shell.setSize(520, 760);
        shell.setLayout(new GridLayout(1, false));

        Label status = new Label(shell, SWT.NONE);
        status.setText("Opening Tesla login...");
        status.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));

        Browser browser = new Browser(shell, SWT.NONE);
        browser.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        AtomicBoolean callbackHandled = new AtomicBoolean();
        ExecutorService tokenExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "tesla-token-exchange");
            thread.setDaemon(true);
            return thread;
        });

        browser.addLocationListener(new LocationAdapter() {
            @Override
            public void changing(LocationEvent event) {
                debug(config, "changing: " + redact(event.location));
                if (event.location != null && event.location.startsWith(REDIRECT_URI)) {
                    event.doit = false;
                    captureCallback(
                            display, shell, browser, status, tokenExecutor, callbackHandled,
                            event.location, authHost, pkce, config);
                }
            }

            @Override
            public void changed(LocationEvent event) {
                debug(config, "changed: " + redact(event.location));
            }
        });

        System.out.println();
        System.out.println("Tesla Authentication");
        System.out.println("============================================================");
        System.out.println("Region:       " + config.region);
        System.out.println("Redirect URI: " + REDIRECT_URI);
        System.out.println("Opening browser...");

        browser.setUrl(authUrl);
        shell.open();

        while (!shell.isDisposed()) {
            if (!display.readAndDispatch()) {
                display.sleep();
            }
        }

        tokenExecutor.shutdownNow();
        display.dispose();
    }

    private static void captureCallback(
            Display display,
            Shell shell,
            Browser browser,
            Label status,
            ExecutorService tokenExecutor,
            AtomicBoolean callbackHandled,
            String callbackUrl,
            String authHost,
            Pkce pkce,
            Config config
    ) {
        if (!callbackHandled.compareAndSet(false, true)) {
            return;
        }

        debug(config, "captured callback: " + redact(callbackUrl));
        status.setText("Captured Tesla callback. Exchanging code...");

        Callback callback;
        try {
            callback = parseCallback(callbackUrl, pkce.state);
        } catch (RuntimeException e) {
            showError(browser, status, "Callback validation failed", e);
            return;
        }

        CompletableFuture
                .supplyAsync(() -> exchangeCode(authHost, callback.code, pkce.codeVerifier), tokenExecutor)
                .whenComplete((tokenResponse, error) -> display.asyncExec(() -> {
                    if (shell.isDisposed()) {
                        return;
                    }
                    if (error != null) {
                        showError(browser, status, "Token exchange failed", unwrap(error));
                    } else {
                        showToken(display, shell, status, tokenResponse.refreshToken);
                    }
                }));
    }

    private static void showToken(
            Display display,
            Shell shell,
            Label status,
            String refreshToken
    ) {
        boolean copied = copyToClipboard(display, refreshToken);
        status.setText(copied ? "Refresh token captured and copied." : "Refresh token captured.");

        System.out.println();
        System.out.println("============================================================");
        System.out.println("Tesla Refresh Token:");
        System.out.println("------------------------------------------------------------");
        System.out.println(refreshToken);
        System.out.println("------------------------------------------------------------");
        System.out.println(copied
                ? "Token copied to clipboard."
                : "Token printed above. Clipboard copy was not available.");

        display.timerExec(500, () -> {
            if (!shell.isDisposed()) {
                shell.dispose();
            }
        });
    }

    private static void showError(Browser browser, Label status, String title, Throwable error) {
        status.setText(title + ": " + error.getMessage());
        System.err.println(title + ": " + error.getMessage());
        browser.setText(statusPage(title, escapeHtml(error.getMessage())));
    }

    private static Throwable unwrap(Throwable error) {
        Throwable cause = error.getCause();
        return cause == null ? error : cause;
    }

    private static String authHost(String region) {
        return switch (region) {
            case "global" -> "https://auth.tesla.com";
            case "cn" -> "https://auth.tesla.cn";
            default -> throw new IllegalArgumentException("Unsupported region: " + region);
        };
    }

    private static String buildAuthUrl(String authHost, Pkce pkce, String email) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_id", CLIENT_ID);
        params.put("code_challenge", pkce.codeChallenge);
        params.put("code_challenge_method", "S256");
        params.put("redirect_uri", REDIRECT_URI);
        params.put("response_type", "code");
        params.put("scope", SCOPES);
        params.put("state", pkce.state);
        if (email != null && !email.isBlank()) {
            params.put("login_hint", email);
        }
        return authHost + AUTH_URL_PATH + "?" + encodeParams(params);
    }

    private static TokenResponse exchangeCode(String authHost, String code, String codeVerifier) {
        try {
            String body = "{"
                    + jsonPair("grant_type", "authorization_code") + ","
                    + jsonPair("client_id", CLIENT_ID) + ","
                    + jsonPair("code", code) + ","
                    + jsonPair("code_verifier", codeVerifier) + ","
                    + jsonPair("redirect_uri", REDIRECT_URI)
                    + "}";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(authHost + TOKEN_URL_PATH))
                    .timeout(Duration.ofSeconds(30))
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient()
                    .send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() != 200) {
                throw new IllegalStateException(
                        "Token exchange failed (HTTP %d): %s".formatted(response.statusCode(), response.body()));
            }

            String refreshToken = jsonString(response.body(), "refresh_token")
                    .orElseThrow(() -> new IllegalStateException("No refresh_token in response: " + response.body()));
            return new TokenResponse(refreshToken);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Callback parseCallback(String callbackUrl, String expectedState) {
        URI uri = URI.create(callbackUrl);
        Map<String, String> params = parseQuery(uri.getRawQuery());

        String error = params.get("error");
        if (error != null && !error.isBlank()) {
            throw new IllegalStateException("Tesla auth error: " + error);
        }

        String code = params.get("code");
        if (code == null || code.isBlank()) {
            throw new IllegalStateException("No auth code in callback URL");
        }

        String returnedState = params.get("state");
        if (!Objects.equals(expectedState, returnedState)) {
            throw new IllegalStateException("CSRF state mismatch");
        }

        return new Callback(code);
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> values = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return values;
        }
        for (String pair : rawQuery.split("&")) {
            int split = pair.indexOf('=');
            String key = split >= 0 ? pair.substring(0, split) : pair;
            String value = split >= 0 ? pair.substring(split + 1) : "";
            values.put(urlDecode(key), urlDecode(value));
        }
        return values;
    }

    private static String encodeParams(Map<String, String> params) {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!query.isEmpty()) {
                query.append('&');
            }
            query.append(urlEncode(entry.getKey()))
                    .append('=')
                    .append(urlEncode(entry.getValue()));
        }
        return query.toString();
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String urlDecode(String value) {
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String jsonPair(String key, String value) {
        return "\"" + escapeJson(key) + "\":\"" + escapeJson(value) + "\"";
    }

    private static String escapeJson(String value) {
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append("\\u%04x".formatted((int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }

    private static Optional<String> jsonString(String json, String key) {
        String needle = "\"" + key + "\"";
        int keyIndex = json.indexOf(needle);
        if (keyIndex < 0) {
            return Optional.empty();
        }
        int colon = json.indexOf(':', keyIndex + needle.length());
        if (colon < 0) {
            return Optional.empty();
        }
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        if (start >= json.length() || json.charAt(start) != '"') {
            return Optional.empty();
        }
        StringBuilder out = new StringBuilder();
        for (int i = start + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                return Optional.of(out.toString());
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (++i >= json.length()) {
                return Optional.empty();
            }
            char escaped = json.charAt(i);
            switch (escaped) {
                case '"', '\\', '/' -> out.append(escaped);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (i + 4 >= json.length()) {
                        return Optional.empty();
                    }
                    String hex = json.substring(i + 1, i + 5);
                    out.append((char) Integer.parseInt(hex, 16));
                    i += 4;
                }
                default -> {
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }

    private static boolean copyToClipboard(Display display, String token) {
        Clipboard clipboard = new Clipboard(display);
        try {
            clipboard.setContents(
                    new Object[]{token},
                    new Transfer[]{TextTransfer.getInstance()});
            return true;
        } catch (RuntimeException e) {
            return false;
        } finally {
            clipboard.dispose();
        }
    }

    private static String statusPage(String title, String message) {
        return """
                <!doctype html>
                <html>
                <head>
                  <meta charset="utf-8">
                  <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; margin: 32px; line-height: 1.45; }
                    pre { white-space: pre-wrap; background: #f5f5f5; padding: 14px; border-radius: 6px; }
                  </style>
                </head>
                <body>
                  <h2>%s</h2>
                  <pre>%s</pre>
                </body>
                </html>
                """.formatted(escapeHtml(title), message);
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static void debug(Config config, String message) {
        if (config.debug) {
            System.out.println("[debug] " + message);
        }
    }

    private static String redact(String value) {
        if (value == null) {
            return null;
        }
        if (!value.startsWith(REDIRECT_URI)) {
            return value;
        }
        URI uri = URI.create(value);
        Map<String, String> params = parseQuery(uri.getRawQuery());
        String code = params.get("code");
        String state = params.get("state");
        return REDIRECT_URI
                + "?code=" + (code == null ? "<missing>" : "<present:" + code.length() + ">")
                + "&state=" + (state == null ? "<missing>" : state);
    }

    private record Pkce(String codeVerifier, String codeChallenge, String state) {
        static Pkce create() throws Exception {
            String verifier = base64Url(randomBytes(32));
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            String challenge = base64Url(sha256.digest(verifier.getBytes(StandardCharsets.UTF_8)));
            String state = base64Url(randomBytes(16));
            return new Pkce(verifier, challenge, state);
        }

        private static byte[] randomBytes(int length) {
            byte[] bytes = new byte[length];
            RANDOM.nextBytes(bytes);
            return bytes;
        }

        private static String base64Url(byte[] bytes) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        }
    }

    private record Callback(String code) {
    }

    private record TokenResponse(String refreshToken) {
    }

    private record Config(String region, String email, boolean debug) {
        static boolean containsHelp(String[] args) {
            for (String arg : args) {
                if ("--help".equals(arg) || "-h".equals(arg)) {
                    return true;
                }
            }
            return false;
        }

        static Config parse(String[] args) {
            String region = "global";
            String email = null;
            boolean debug = false;

            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--region" -> region = normalizeRegion(requireValue(args, ++i, "--region"));
                    case "--email" -> email = requireValue(args, ++i, "--email");
                    case "--debug" -> debug = true;
                    case "-h", "--help" -> {
                    }
                    default -> throw new IllegalArgumentException("Unknown argument: " + args[i]);
                }
            }

            return new Config(region, email, debug);
        }

        static void printHelp() {
            System.out.println("""
                    Usage:
                      tesla-token [options]

                    Options:
                      --region global|cn  Tesla auth region. Default: global.
                                           global uses https://auth.tesla.com.
                                           cn uses https://auth.tesla.cn.
                      --email EMAIL       Pre-fill the Tesla login email field.
                      --debug             Print navigation diagnostics with OAuth codes redacted.
                      -h, --help          Show this help.

                    Behavior:
                      Opens a native SWT browser, intercepts navigation to
                      tesla://auth/callback, verifies state, exchanges the OAuth code,
                      prints the refresh token, copies it to the clipboard when possible,
                      and exits on success.
                    """);
        }

        private static String normalizeRegion(String region) {
            return switch (region.toLowerCase(Locale.ROOT)) {
                case "global" -> "global";
                case "cn" -> "cn";
                default -> throw new IllegalArgumentException("Unsupported region: " + region);
            };
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " requires a value");
            }
            return args[index];
        }
    }
}
