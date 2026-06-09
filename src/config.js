export function loadConfig(env = {}) {
  const issuer = requiredUrl(env.ISSUER, "ISSUER").replace(/\/+$/, "");
  const clientId = required(env.OIDC_CLIENT_ID, "OIDC_CLIENT_ID");
  const clientSecret = optional(env.OIDC_CLIENT_SECRET);
  const redirectUris = required(env.ALLOWED_REDIRECT_URIS, "ALLOWED_REDIRECT_URIS")
    .split(",")
    .map((uri) => uri.trim())
    .filter(Boolean);
  if (redirectUris.length === 0) {
    throw new Error("ALLOWED_REDIRECT_URIS 至少需要一個 redirect_uri");
  }

  return {
    issuer,
    clientId,
    clientSecret,
    redirectUris,
    openaiLoginUrl: optionalUrl(env.OPENAI_LOGIN_URL, "OPENAI_LOGIN_URL"),
    privateJwk: optional(env.PRIVATE_JWK),
    adminToken: optional(env.ADMIN_TOKEN),
    turnstileSiteKey: optional(env.TURNSTILE_SITE_KEY),
    turnstileSecretKey: optional(env.TURNSTILE_SECRET_KEY),
    authorizationCodeTtlSeconds: Number(env.AUTHORIZATION_CODE_TTL_SECONDS ?? 300),
    tokenTtlSeconds: Number(env.TOKEN_TTL_SECONDS ?? 3600)
  };
}

function optional(value) {
  return String(value ?? "").trim();
}

function required(value, name) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    throw new Error(`缺少必要設定：${name}`);
  }
  return normalized;
}

function requiredUrl(value, name) {
  const normalized = required(value, name);
  try {
    return new URL(normalized).toString();
  } catch {
    throw new Error(`${name} 必須是有效 URL`);
  }
}

function optionalUrl(value, name) {
  const normalized = optional(value);
  if (!normalized) {
    return "";
  }
  try {
    return new URL(normalized).toString();
  } catch {
    throw new Error(`${name} 必須是有效 URL`);
  }
}
