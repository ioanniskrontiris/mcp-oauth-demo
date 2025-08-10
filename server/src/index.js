import express from "express";
import morgan from "morgan";
import cors from "cors";
import { jwtVerify } from "jose";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

const HMAC_SECRET = new TextEncoder().encode("dev-secret-please-change"); // must match AS
const EXPECTED_ISS = "http://localhost:9092";
const EXPECTED_AUD = "mcp-demo";

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: "https://localhost:9091",
    authorization_servers: ["http://localhost:9092"]
  });
});

// Bearer auth helper
async function verifyBearer(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) throw new Error("no token");
  const token = auth.slice("Bearer ".length);
  const { payload } = await jwtVerify(token, HMAC_SECRET, {
    issuer: EXPECTED_ISS,
    audience: EXPECTED_AUD
  });
  return payload;
}

app.get("/mcp/echo", async (req, res) => {
  try {
    const payload = await verifyBearer(req);
    if (!String(payload.scope || "").includes("echo:read")) {
      return res.status(403).json({ error: "forbidden" });
    }
    const msg = req.query.msg || "hello";
    res.json({ ok: true, echo: String(msg), sub: payload.sub });
  } catch {
    res.set(
      "WWW-Authenticate",
      `Bearer realm="mcp-demo", error="invalid_token", resource_metadata="http://localhost:9091/.well-known/oauth-protected-resource"`
    );
    return res.status(401).json({ error: "missing_or_invalid_token" });
  }
});

app.listen(9091, () => {
  console.log("MCP Resource Server listening on :9091");
});