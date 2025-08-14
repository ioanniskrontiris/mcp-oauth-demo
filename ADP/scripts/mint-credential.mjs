import { SignJWT, generateKeyPair, exportJWK } from "jose";

// 1) create a one-off ES256 keypair (for demo)
//    (in prod you'd keep the private key outside and reuse it)
const { publicKey, privateKey } = await generateKeyPair("ES256");
const jwk = await exportJWK(publicKey);
const kid = "test-key-1";
jwk.kid = kid;

// 2) payload: this is the delegation credential the ADP will verify & store
const now = Math.floor(Date.now() / 1000);
const payload = {
  iss: "https://issuer.example", // issuer of the delegation (enterprise)
  sub: "user-123",               // user the delegation is about
  agent_id: "agent-demo",        // agent identity
  tool_id: "mcp.echo",           // tool this applies to
  scopes: ["echo:read"],         // permissions granted
  iat: now,
  exp: now + 60 * 60 * 24 * 30,  // 30 days validity
  jti: "deleg-123"               // optional id
};

// 3) sign it as a compact JWS (JWT)
const jwt = await new SignJWT(payload)
  .setProtectedHeader({ alg: "ES256", kid })
  .sign(privateKey);

// 4) print the JSON the ADP expects: { credential, jwk }
console.log(JSON.stringify({ credential: jwt, jwk }, null, 2));