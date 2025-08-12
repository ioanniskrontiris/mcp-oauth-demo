// shared/config.js
import fs from 'node:fs';

export function loadEnv() {
  // Simple .env parser (no deps)
  if (fs.existsSync('.env')) {
    const text = fs.readFileSync('.env', 'utf8');
    for (const line of text.split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*\S)\s*$/);
      if (m) {
        const [, k, v] = m;
        if (!(k in process.env)) process.env[k] = v;
      }
    }
  }
  // Provide sane defaults
  process.env.AUTH_MODE ??= 'direct';
  process.env.TOKEN_MODE ??= 'jwt';
  process.env.INTROSPECTION_MODE ??= 'direct';
  process.env.POLICY_MODE ??= 'off';
  process.env.AS_BASE ??= 'http://localhost:9092'\;
  process.env.RS_BASE ??= 'http://localhost:9091'\;
  process.env.CLIENT_REDIRECT_URI ??= 'http://localhost:9200/callback'\;
  process.env.CLIENT_ID ??= 'demo-client';
}

export function cfg() {
  return {
    AUTH_MODE: process.env.AUTH_MODE,
    TOKEN_MODE: process.env.TOKEN_MODE,
    INTROSPECTION_MODE: process.env.INTROSPECTION_MODE,
    POLICY_MODE: process.env.POLICY_MODE,
    AS_BASE: process.env.AS_BASE,
    RS_BASE: process.env.RS_BASE,
    CLIENT_REDIRECT_URI: process.env.CLIENT_REDIRECT_URI,
    CLIENT_ID: process.env.CLIENT_ID,
  };
}
