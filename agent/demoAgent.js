// client/src/demoAgent.js
import { loadEnv, cfg } from "../shared/config.js";  // adjust path if needed
loadEnv();
console.log("[client] mode =>", cfg());

import express from "express";
import crypto from "node:crypto";
import open from "open";
import fs from "node:fs/promises";

const AS = "http://localhost:9092";   // Authorization Server
const RS = "http://localhost:9091";   // Resource Server
const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:9200/callback";

// Request both scopes so we can demo multiple endpoints later
const SCOPE = "tickets:read";

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function sha256(inputStr) {
  return crypto.createHash("sha256").update(inputStr).digest();
}

async function oauthFlow() {
  // PKCE
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(await sha256(verifier));
  const state = base64url(crypto.randomBytes(16));

  // Tiny callback server to catch the code
  const app = express();
  const codePromise = new Promise((resolve, reject) => {
    app.get("/callback", (req, res) => {
      const { code, state: gotState, error, error_description } = req.query;
      if (error) {
        res.status(400).send(`OAuth error: ${error_description || error}`);
        reject(new Error(`OAuth error: ${error}`));
        return;
      }
      if (!code || gotState !== state) {
        res.status(400).send("Missing code or bad state");
        reject(new Error("Missing code or bad state"));
        return;
      }
      res.send("✅ You can close this tab. Returning to the demo…");
      resolve(code);
      setImmediate(() => server.close());
    });

    var server = app.listen(9200, () =>
      console.log("Client callback server on :9200")
    );
  });

  // Build authorize URL & open browser
  const authURL = new URL(`${AS}/authorize`);
  authURL.searchParams.set("response_type", "code");
  authURL.searchParams.set("client_id", CLIENT_ID);
  authURL.searchParams.set("redirect_uri", REDIRECT_URI);
  authURL.searchParams.set("scope", SCOPE);
  authURL.searchParams.set("state", state);
  authURL.searchParams.set("code_challenge_method", "S256");
  authURL.searchParams.set("code_challenge", challenge);

  console.log("Opening browser for consent…");
  await open(authURL.toString());

  // Wait for code
  const code = await codePromise;

  // Exchange code for token
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    code,
    code_verifier: verifier,
  });

  const tokenResp = await fetch(`${AS}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!tokenResp.ok) {
    const t = await tokenResp.text();
    throw new Error(`Token exchange failed: ${t}`);
  }
  const token = await tokenResp.json();
  await fs.writeFile("token.json", JSON.stringify(token, null, 2));
  console.log("🔐 Access token saved to token.json");
  return token.access_token;
}

async function callTickets(accessToken) {
  const r = await fetch(`${RS}/tickets`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (r.status === 403) {
    console.error("❌ insufficient_scope: tickets:read required");
    console.error(await r.text());
    return;
  }
  if (!r.ok) {
    console.error("❌ Tickets call failed:", r.status, await r.text());
    return;
  }
  const data = await r.json();
  console.log("\n🎟️  Tickets:");
  for (const t of data.tickets) {
    console.log(` - ${t.id}: ${t.title} @ ${t.venue} on ${t.date} — $${t.price}`);
  }
}

async function callEcho(accessToken, msg = "hello from the agent") {
  const r = await fetch(`${RS}/echo`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ msg })
  });

  if (r.status === 403) {
    console.error("❌ insufficient_scope: echo:read required");
    console.error(await r.text());
    return;
  }
  if (!r.ok) {
    console.error("❌ Echo call failed:", r.status, await r.text());
    return;
  }
  const data = await r.json();
  console.log("\n🔊 Echo:", data);
}

(async () => {
  try {
    const token = await oauthFlow();
    await callTickets(token);     // needs tickets:read
    await callEcho(token);        // needs echo:read
    console.log("\n✅ Demo complete.");
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();