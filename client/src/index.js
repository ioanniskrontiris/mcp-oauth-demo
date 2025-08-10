import fetch from "node-fetch";

async function main() {
  // 1) Call the protected endpoint with no token
  const r1 = await fetch("http://localhost:9091/mcp/echo?msg=hello");
  console.log("Status:", r1.status);

  // 2) Read the WWW-Authenticate header to find resource metadata
  const www = r1.headers.get("www-authenticate") || "";
  console.log("WWW-Authenticate:", www);

  const match = www.match(/resource_metadata="([^"]+)"/);
  if (!match) {
    console.error("No resource_metadata URL in WWW-Authenticate");
    console.log("Body:", await r1.json().catch(() => null));
    return;
  }

  const metadataUrl = match[1];
  console.log("Discovered resource metadata:", metadataUrl);

  // 3) Fetch Protected Resource Metadata (RFC 9728)
  const r2 = await fetch(metadataUrl);
  const meta = await r2.json();
  console.log("Protected Resource Metadata:", meta);

  // 4) Pick an Authorization Server (we’ll build it in the next step)
  const as = Array.isArray(meta.authorization_servers) ? meta.authorization_servers[0] : null;
  console.log("Suggested Authorization Server:", as);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});