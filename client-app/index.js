import express from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import { randomBytes, createHash } from "crypto";

const app = express();
app.use(cookieParser());

const AUTH_SERVER = "http://localhost:3000";
const RESOURCE_SERVER = process.env.RESOURCE_SERVER || "http://localhost:5001";

const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:4000/callback";

// Helpers
function base64URL(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function generateVerifier() {
  return base64URL(randomBytes(32));
}

function codeChallenge(verifier) {
  const hash = createHash("sha256").update(verifier).digest();
  return base64URL(hash);
}

function generateState() {
  return base64URL(randomBytes(16));
}

app.get("/", (req, res) => {
  res.send(`
        <h1>Demo Client</h1>
        <a href="/login">Login with Auth Server</a>
    `);
});

app.get("/login", (req, res) => {
  const verifier = generateVerifier();
  const challenge = codeChallenge(verifier);
  const state = generateState();

  // Store verifier and state in cookies for later verification
  res.cookie("code_verifier", verifier, { httpOnly: true });
  res.cookie("oauth_state", state, { httpOnly: true });

  const authUrl = new URL(`${AUTH_SERVER}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("scope", "api.read");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/callback", async (req, res) => {
  const { code, state } = req.query;

  if (!code) return res.status(400).send("Missing authorization code");
  if (!state) return res.status(400).send("Missing state parameter");

  const code_verifier = req.cookies.code_verifier;

  const tokenRes = await axios.post(
    `${AUTH_SERVER}/token`,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier,
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  const { access_token, refresh_token } = tokenRes.data;

  // Store tokens in cookies
  res.cookie("access_token", access_token, { httpOnly: true });
  res.cookie("refresh_token", refresh_token, { httpOnly: true });

  // Clean up 0Auth-only cookies
  res.clearCookie("code_verifier");
  res.clearCookie("oauth_state");

  // Redirect to normal app route
  res.redirect("/profile");
});

app.get("/profile", async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.redirect("/login");

  try {
    const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    res.send(`<pre>${JSON.stringify(apiRes.data, null, 2)}</pre>`);
  } catch (err) {
    const msg = err?.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    res.status(500).send(`Error fetching profile: ${msg}`);
  }
});

app.get("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.redirect("/login");

  const tokenRes = await axios.post(
    `${AUTH_SERVER}/token`,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  res.cookie("access_token", tokenRes.data.access_token, { httpOnly: true });

  res.send(`
        <h2>Refreshed Access Token</h2>
        <a href="/profile">Call Protected API Again</a>
        `);
});

app.listen(4000, () => {
  console.log("Demo client running on http://localhost:4000");
});
