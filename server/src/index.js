import express from "express";
import morgan from "morgan";
import cors from "cors";

const app = express();
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

/**
 * RFC 9728 Protected Resource Metadata
 * This tells clients where the Authorization Server(s) live.
 */
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  res.json({
    resource: "https://localhost:9091",               // identifier for this resource (demo)
    authorization_servers: [
      "http://localhost:9092"                         // placeholder AS we’ll add later
    ],
    // Optional: document scopes or other hints here
    // "resource_scopes": ["echo:read"]
  });
});

/**
 * Protected MCP tool endpoint (echo).
 * If no/invalid token, respond with 401 and a WWW-Authenticate header that
 * points to our protected resource metadata (per RFC 9728 §5.1).
 */
app.get("/mcp/echo", (req, res) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    res.set(
      "WWW-Authenticate",
      `Bearer realm="mcp-demo", error="invalid_token", resource_metadata="http://localhost:9091/.well-known/oauth-protected-resource"`
    );
    return res.status(401).json({ error: "missing_or_invalid_token" });
  }

  // (We’re not validating the token yet — that’s for Step 2.)
  const msg = req.query.msg || "hello";
  res.json({ ok: true, echo: String(msg) });
});

app.listen(9091, () => {
  console.log("MCP Resource Server listening on :9091");
});