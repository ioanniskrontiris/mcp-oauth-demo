// gateway/src/consentHook.js
// super simple: env toggle now; later we’ll plug policy/context
export async function shouldAutoConsent({ scope, aud, toolId, agentId }) {
  const on = String(process.env.GW_AUTO_CONSENT || "true").toLowerCase() === "true";
  return { allow: on, obligations: {} };
}