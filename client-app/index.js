import express from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import { randomBytes, createHash } from "crypto";

const app = express();
app.use(cookieParser());

const AUTH_SERVER = "http://localhost:3000";
const RESOURCE_SERVER = "http://localhost:6000";

const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:4000/callback";
const PORT = 4000;

// Helpers
function base64url(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function generateVerifier() {
  return base64url(randomBytes(32));
}

function codeChallengeS256(verifier) {
  const hash = createHash("sha256").update(verifier).digest();
  return base64url(hash);
}

function generateState() {
  return base64url(randomBytes(16));
}

app.get("/", (req, res) => {
  res.send(`
    <h2>Client App</h2>
    <p>This app uses Authorization Code + PKCE.</p>
    <a href="/login">Login</a>
  `);
});

app.get("/login", (req, res) => {
  const code_verifier = generateVerifier();
  const code_challenge = codeChallengeS256(code_verifier);
  const state = generateState();

  // Store verifier & state (demo only). In production: server-side session store.
  res.cookie("code_verifier", code_verifier, { httpOnly: true });
  res.cookie("oauth_state", state, { httpOnly: true });

  const authorizeUrl = new URL(`${AUTH_SERVER}/authorize`);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeUrl.searchParams.set("scope", "api.read openid profile email");
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", code_challenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authorizeUrl.toString());
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).send("Missing authorization code");
  }

  if (state !== req.cookies.oauth_state) {
    return res.status(400).send("Invalid state");
  }

  const code_verifier = req.cookies.code_verifier;

  let tokenRes;
  try {
    tokenRes = await axios.post(
      `${AUTH_SERVER}/token`,
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier,
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
    );
  } catch (err) {
    const msg = err?.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    return res.status(500).send(`Token exchange failed: ${msg}`);
  }

  const { access_token, refresh_token } = tokenRes.data;

  res.cookie("access_token", access_token, { httpOnly: true });
  res.cookie("refresh_token", refresh_token, { httpOnly: true });

  // Clean up OAuth-only cookies
  res.clearCookie("code_verifier");
  res.clearCookie("oauth_state");

  // Redirect to normal app route
  res.redirect("/profile");
});

app.get("/profile", async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.redirect("/");

  try {
    const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    res.send(`<pre>${JSON.stringify(apiRes.data, null, 2)}</pre>`);
  } catch (err) {
    const msg = err?.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    res.status(500).send(`API call failed: ${msg}`);
  }
});

app.get("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.redirect("/");

  const tokenRes = await axios.post(
    `${AUTH_SERVER}/token`,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
  );

  res.cookie("access_token", tokenRes.data.access_token, { httpOnly: true });

  res.send(`
    <h3>Refreshed Access Token!</h3>
    <a href="/profile">Call Protected API Again</a>
  `);
});

app.listen(PORT, (err) => {
  if (err) {
    console.error(`Failed to start client app: ${err.message}`);
    process.exit(1);
  }

  console.log(`Client App running on http://localhost:${PORT}`);
});
