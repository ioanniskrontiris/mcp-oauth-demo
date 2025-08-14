// node client/scripts/seedDelegation.js
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import fetch from "node-fetch";

const ADP_BASE = process.env.ADP_BASE || "http://localhost:9500";

async function main() {
  // Generate an ephemeral keypair for demo (in real life, user/wallet key)
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const public_jwk = await exportJWK(publicKey);

  // The credential payload the user is “signing”
  const payload = {
    subject: "user-123",
    agentId: "agent-demo",
    toolId: "mcp.echo",
    scopes: ["echo:read"],
    not_after: Math.floor(Date.now()/1000) + 60*60*24*30, // 30 days
    iss: "demo-user-wallet"
  };

  // Sign as a compact JWS
  const jws = await new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256" })
    .sign(privateKey);

  // POST to ADP
  const r = await fetch(`${ADP_BASE}/delegations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jws, public_jwk })
  });

  if (!r.ok) {
    const t = await r.text();
    throw new Error(`/delegations failed ${r.status}: ${t}`);
  }
  console.log("✅ Delegation seeded:", await r.json());
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});