// gateway/src/crypto.js
import crypto from "node:crypto";

const SECRET = process.env.GW_STATE_SECRET || "dev-secret";

function b64url(buf) {
  return Buffer.isBuffer(buf)
    ? buf.toString("base64url")
    : Buffer.from(String(buf)).toString("base64url");
}

export function signState(payloadObj) {
  const payload = JSON.stringify(payloadObj);
  const p = b64url(payload);
  const sig = crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
  return `${p}.${sig}`; // compact, JWS‑ish
}

export function verifyState(compact) {
  const [p, sig] = String(compact || "").split(".");
  if (!p || !sig) return { ok: false, err: "malformed_state" };
  const exp = crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) {
    return { ok: false, err: "bad_signature" };
  }
  try {
    const json = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    return { ok: true, json };
  } catch {
    return { ok: false, err: "bad_payload" };
  }
}