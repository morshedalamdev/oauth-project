import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { randomBytes, createHash } from "crypto";
import { SignJWT, exportJWK, importPKCS8 } from "jose";
import fs from "fs";

// INIT EXPRESS APP
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// IN-MEMORY DATA STORAGE
const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();

// SAMPLE CLIENT
clients.set("demo-client", {
  clientId: "demo-client",
  redirectUris: ["http://localhost:4000/callback"],
});

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtJAIUQnYSO7Sp
P3oKDyafNx7kz5hlsuGGAZNQNyBGIb/uFjYn6tas9Ffp6WA5NoWRSlIlHuQ/UezC
yfg6CLYMcfzkUej3OS6EtsPqNYJm5PBGBc3jg1maRRKLsUfZ1L0ueu7N10H5fOUE
XnY9TJUt/+wkYiNWQjPvJxU+E8myT1kJx4C3S5s5sOkU1Hctc/3K1Fsa+Th3oeS0
R3XN7E/NeUY8botiHfTYMu2K8BhzQTaZN2qhVZlIGRmYwBV7rzyuLuR8a9+GayK5
mQGGtgQHIgJ4Hy/bfXqK/pHR3gz8GX+sz211qd8WWhxOpX+yVeYYf8K0uRoiYD9I
5fKhxEvFAgMBAAECggEAD9mVhSRGacnkcn/4nJYhe37QybKFaX30Lk/TnArH3hO1
3cZTw9i4OVIPAD9YizRGCvRqS7Klw3Qs//H8Ute8Tqxasc4bzRIDg6u1iKnIW8IG
iup6HCNInxpGpdofUT4r6WbgmKBljkDUOE+rdFYf6/ubMwN2560c0v5Zb/rgwn1h
YZzof5zLMZtcSEeg+sOCh5wp3gD9t8MXsByLJV3IvTKJSgeEUsAncuFENvu9YWlJ
zIUF68VTB69IgEZnszbkDPFvv06UGRcGuLgRc4OShllnQq08ceFgASIrhXEzk6iK
iA8operudHKoAIXwMfE1nA0TI6FAIf8wSJe2ZXPlawKBgQDlX59KAfKhsS/70cU2
VlXw5JSvZQiiG/ktwrQHY4VahWWL1coxGxi4BdEIaReuwpHnSh6zelEjMwt6Ikri
INhgszNYjhKNsFz6aj8SBeMj3rW3kh7XnpWbInm9iZpCtdmm1JpStxJaNNHZJ7in
CMxZ1vA/8TM4GNDhQ9MOxemXtwKBgQDBPUsBqx2WB87TdjmXqE8Af6PRmD9TZc0i
wznl8FNeNVq7YSrKneBtDx1Bhh9Qs0fN4IY1syLO69d84EM8HlQ8BE59SOcNiQe+
XuRqHNM3H4eC8T6+pDfR/PYMTbIc+awzMckTcdMigosqgJllORr3PZWawcyu2AcL
lxzgGMZgYwKBgQCC/bfnOPOKmbkQc7zPikCsQK4U+HsUsSr9kirj6Vb32iSi1iYR
IytbtJ6q0fGfcSiH0NF1qA38LyOHzVu8hgtsNgrFsOUxm52NuO1p6ojMLFzUiBMr
CjrgDLE/p/y7ykSRPOsg/8HwWCfbfw65/ZFOYSx1J9cbWzi23NgEoMwFQwKBgHEy
rZipm6hCpKb9L5mmr7jUDKwAKsB49yUxBd6r3LpoOOFhd0bAGzLn0rSKlBebHin9
J8GXUYGzaEUvvlMeVSvfPfdoWGl2Z0HepqF+h0BYSPKszZux6T0qmRv1+6u7mmNW
+7pXSF6D6HAaa0F/pUtGGThR5Mxboizo9bJU8QiPAoGAJwikS3yO5QX/kyuziEr5
ZO6jkpWnmGRLGnSMILZ9KJpo2OFyw+ZGK9w9U/9t1gZspoUzDia1jE3Cn9raBFqd
PJEhJmWxpyScLsHQ8ZHP3jf0aln75r+2OjsHSPTzI+V4Rk2qzRQsJYovOnk99Xdx
COoFVxzVLpv0YLFZg29ZQLo=
-----END PRIVATE KEY-----`;
const ISSUER = "http://localhost:3000";
const KEY_ID = "demo-key-1";

function base64URL(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "=")
    .replace(/=+$/g, "");
}

function sha256Base64URL(str) {
  const hash = createHash("sha256").update(str).digest();
  return base64URL(hash);
}

const generateCode = () => base64URL(randomBytes(32));

function getDemoUser() {
  return {
    sub: "alice",
    name: "Alice Example",
    email: "alice@example.com",
  };
}

app.get("/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = "",
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  // Basic validation
  const client = clients.get(client_id);
  if (!client) return res.status(400).send("Invalid client_id");
  if (!client.redirectUris.includes(redirect_uri))
    return res.status(400).send("Invalid redirect_uri");
  if (response_type !== "code")
    return res.status(400).send("Only response_type=code is supported");
  if (!code_challenge || !code_challenge_method !== "S256")
    return res.status(400).send("PKCE is required with S256 method");

  //   Norammly: show login + consent UI
  const user = getDemoUser();
  const code = generateCode();
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    user,
    codeChallenge: code_challenge,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  const redirect = new URL(redirect_uri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);
  if (state) redirect.searchParams.set("state", state);

  res.redirect(redirect.toString());
});

/**
 * POST /token
 * Supports:
 * - grant_type=authorization_code (with PKCE)
 * - grant_type=refresh_token
 */
app.post("/token", async (req, res) => {
  const { grant_type } = req.body;

  if (grant_type === "authorization_code") {
    const { code, redirect_uri, client_id, code_verifier } = req.body;

    const record = authorizationCodes.get(code);
    if (!record)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid authorization code",
      });
    if (record.clientId !== client_id)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Client ID mismatch",
      });
    if (record.expiresAt < Date.now())
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Authorization code expired",
      });
    if (record.redirectUri !== redirect_uri)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Redirect URI mismatch",
      });

    // PKCE validation
    const computedChallenge = sha256Base64URL(code_verifier);
    if (computedChallenge !== record.codeChallenge)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "PKCE verification failed",
      });

    // One-time use code
    authorizationCodes.delete(code);

    // Generate access token (JWT)
    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    const accessToken = await new SignJWT({
      sub: record.user.sub,
      name: record.user.name,
      email: record.user.email,
    })
      .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
      .setIssuer(ISSUER)
      .setAudience(client_id)
      .setSubject(record.user.sub)
      .setExpirationTime("15m")
      .setIssuedAt()
      .sign(privateKey);

    const refreshToken = generateCode();
    refreshTokens.set(refreshToken, {
      sub: record.user.sub,
      scope: record.scope,
      clientId: client_id,
    });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 900,
      refresh_token: refreshToken,
      scope: record.scope,
    });
  }

  if (grant_type === "refresh_token") {
    const { refresh_token, client_id } = req.body;
    const record = refreshTokens.get(refresh_token);
    if (!record)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Invalid refresh token",
      });
    if (record.clientId !== client_id)
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Client ID mismatch",
      });

    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    const accessToken = await new SignJWT({ scope: record.scope })
      .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
      .setIssuer(ISSUER)
      .setAudience(client_id)
      .setSubject(record.sub)
      .setExpirationTime("15m")
      .setIssuedAt()
      .sign(privateKey);

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 900,
      scope: record.scope,
    });
  }

  res.status(400).json({
    error: "unsupported_grant_type",
    error_description:
      "Only authorization_code and refresh_token are supported",
  });
});

/**
 * JWKS endpoint:
 * Resource servers fetch public keys here to validate JWT signatures.
 */
app.get("/.well-known/jwks.json", async (req, res) => {
  const publicKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
  const jwk = await exportJWK(publicKey);

  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = KEY_ID;

  res.status(200).json({ keys: [jwk] });
});

app.listen(3000, () => {
  console.log("Authorization server running on http://localhost:3000");
});
