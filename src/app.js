import { exportPublicJwk, timingSafeEqual, verifyJwt } from "./crypto.js";
import { InviteService } from "./invite-service.js";
import { OidcService } from "./oidc-service.js";

const TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

export function createApp({ store, config, turnstileFetch = (...args) => globalThis.fetch(...args) }) {
  const inviteService = new InviteService(store);
  const oidcService = new OidcService({ store, config });
  const turnstileService = new TurnstileService({ config, turnstileFetch });

  return {
    async fetch(request) {
      const url = new URL(request.url);
      try {
        if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
          return json(oidcService.getDiscoveryMetadata());
        }
        if (request.method === "GET" && url.pathname === "/") {
          return handleDirectLogin(oidcService, config);
        }
        if (request.method === "GET" && url.pathname === "/jwks.json") {
          return json(
            { keys: [await exportPublicJwk(requirePrivateJwk(config))] },
            { headers: { "content-type": "application/jwk-set+json; charset=utf-8" } }
          );
        }
        if (request.method === "GET" && url.pathname === "/authorize") {
          return handleAuthorize(url, oidcService, config);
        }
        if (request.method === "GET" && url.pathname === "/register") {
          return handleRegisterPage(url, oidcService, config);
        }
        if (request.method === "POST" && url.pathname === "/login") {
          return await handleLogin(request, inviteService, oidcService, turnstileService);
        }
        if (request.method === "POST" && url.pathname === "/register") {
          return await handleRegister(request, inviteService, oidcService, turnstileService);
        }
        if (request.method === "POST" && url.pathname === "/token") {
          return await handleToken(request, oidcService);
        }
        if (request.method === "GET" && url.pathname === "/userinfo") {
          return await handleUserInfo(request, oidcService, config);
        }
        if (url.pathname === "/admin/invite-codes") {
          return await handleInviteCodesAdmin(request, store, config);
        }
        return html("找不到頁面", { status: 404 });
      } catch (error) {
        console.error("Worker 請求處理失敗", {
          path: url.pathname,
          message: getErrorMessage(error)
        });
        return errorResponse(error);
      }
    }
  };
}

function handleAuthorize(url, oidcService, config) {
  const authRequest = oidcService.validateAuthorizeRequest(url.searchParams);
  return html(renderLoginPage(authRequest, config));
}

function handleDirectLogin(_oidcService, config) {
  if (!config.openaiLoginUrl) {
    throw new Error("缺少必要設定：OPENAI_LOGIN_URL");
  }
  return redirectResponse(config.openaiLoginUrl);
}

function handleRegisterPage(url, oidcService, config) {
  const authRequest = oidcService.validateAuthorizeRequest(url.searchParams);
  return html(renderRegisterPage(authRequest, config));
}

async function handleLogin(request, inviteService, oidcService, turnstileService) {
  const { form, authRequest } = await parseLoginForm(request, oidcService);
  await turnstileService.verifyAuthForm(request, form);
  const account = String(form.get("account") ?? "");
  const user = await inviteService.login({ account });
  return issueAuthorizationCode({ user, authRequest, oidcService });
}

async function handleRegister(request, inviteService, oidcService, turnstileService) {
  const { form, authRequest } = await parseLoginForm(request, oidcService);
  await turnstileService.verifyAuthForm(request, form);
  const user = await inviteService.registerWithInvite({
    account: String(form.get("account") ?? ""),
    inviteCode: String(form.get("invite_code") ?? "")
  });
  return issueAuthorizationCode({ user, authRequest, oidcService });
}

async function parseLoginForm(request, oidcService) {
  const form = await request.formData();
  const authRequest = parseAuthRequestForm(form);
  oidcService.validateAuthorizeRequest(
    new URLSearchParams({
      client_id: authRequest.clientId,
      redirect_uri: authRequest.redirectUri,
      response_type: "code",
      scope: authRequest.scope
    })
  );
  return { form, authRequest };
}

function parseAuthRequestForm(form) {
  return {
    clientId: String(form.get("client_id") ?? ""),
    redirectUri: String(form.get("redirect_uri") ?? ""),
    scope: String(form.get("scope") ?? "openid email"),
    state: String(form.get("state") ?? ""),
    nonce: String(form.get("nonce") ?? ""),
    codeChallenge: String(form.get("code_challenge") ?? ""),
    codeChallengeMethod: String(form.get("code_challenge_method") ?? "")
  };
}

async function issueAuthorizationCode({ user, authRequest, oidcService }) {
  const code = await oidcService.createAuthorizationCode({
    user,
    clientId: authRequest.clientId,
    redirectUri: authRequest.redirectUri,
    scope: authRequest.scope,
    nonce: authRequest.nonce,
    codeChallenge: authRequest.codeChallenge,
    codeChallengeMethod: authRequest.codeChallengeMethod
  });
  const redirect = new URL(authRequest.redirectUri);
  redirect.searchParams.set("code", code.code);
  if (authRequest.state) {
    redirect.searchParams.set("state", authRequest.state);
  }
  return redirectResponse(redirect.toString());
}

async function handleToken(request, oidcService) {
  const form = await request.formData();
  const grantType = String(form.get("grant_type") ?? "");
  if (grantType !== "authorization_code") {
    return oauthError("unsupported_grant_type", "只支援 authorization_code", 400);
  }

  const credentials = parseClientCredentials(request, form);
  try {
    const token = await oidcService.exchangeCode({
      code: String(form.get("code") ?? ""),
      clientId: credentials.clientId,
      clientSecret: credentials.clientSecret,
      redirectUri: String(form.get("redirect_uri") ?? ""),
      codeVerifier: String(form.get("code_verifier") ?? "")
    });
    return json(token, {
      headers: { "cache-control": "no-store", pragma: "no-cache" }
    });
  } catch (error) {
    return oauthError("invalid_grant", error.message, 400);
  }
}

async function handleUserInfo(request, oidcService, config) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return json({ error: "缺少 Bearer token" }, { status: 401 });
  }
  const claims = await verifyJwt(match[1], requirePrivateJwk(config));
  const info = await oidcService.getUserInfo(claims.email);
  return json(info);
}

async function handleInviteCodesAdmin(request, store, config) {
  if (!isAdmin(request, config)) {
    return json({ error: "未授權" }, { status: 401 });
  }
  if (request.method === "POST") {
    const body = await request.json();
    const inviteCode = await store.createInviteCode({
      code: body.code,
      maxUses: Number(body.maxUses ?? 100),
      enabled: body.enabled ?? true
    });
    return json(inviteCode, { status: 201 });
  }
  if (request.method === "GET") {
    return json({ message: "請直接查詢 D1，或用 POST 建立邀請碼。" });
  }
  return json({ error: "方法不允許" }, { status: 405 });
}

function parseClientCredentials(request, form) {
  const authorization = request.headers.get("authorization") ?? "";
  const basic = authorization.match(/^Basic\s+(.+)$/i);
  if (basic) {
    const decoded = atob(basic[1]);
    const [clientId, clientSecret] = decoded.split(":");
    return { clientId, clientSecret };
  }
  return {
    clientId: String(form.get("client_id") ?? ""),
    clientSecret: String(form.get("client_secret") ?? "")
  };
}

function isAdmin(request, config) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return Boolean(match && timingSafeEqual(match[1], config.adminToken));
}

function requirePrivateJwk(config) {
  if (!config.privateJwk) {
    throw new Error("缺少必要設定：PRIVATE_JWK");
  }
  return parsePrivateJwk(config.privateJwk);
}

function parsePrivateJwk(value) {
  try {
    const jwk = JSON.parse(value);
    if (!jwk.kid) {
      throw new Error("PRIVATE_JWK 必須包含 kid");
    }
    return jwk;
  } catch (error) {
    if (error.message === "PRIVATE_JWK 必須包含 kid") {
      throw error;
    }
    throw new Error("PRIVATE_JWK 必須是有效的單行 JSON");
  }
}

class TurnstileService {
  constructor({ config, turnstileFetch }) {
    this.config = config;
    this.turnstileFetch = turnstileFetch;
  }

  async verifyAuthForm(request, form) {
    if (!this.config.turnstileSiteKey && !this.config.turnstileSecretKey) {
      return;
    }
    if (!this.config.turnstileSiteKey) {
      throw new Error("缺少必要設定：TURNSTILE_SITE_KEY");
    }
    if (!this.config.turnstileSecretKey) {
      throw new Error("缺少必要設定：TURNSTILE_SECRET_KEY");
    }
    const token = String(form.get("cf-turnstile-response") ?? "").trim();
    if (!token) {
      throw new Error("請先完成 Cloudflare 人機驗證");
    }

    const body = new FormData();
    body.set("secret", this.config.turnstileSecretKey);
    body.set("response", token);
    const remoteIp = getClientIp(request);
    if (remoteIp) {
      body.set("remoteip", remoteIp);
    }

    const response = await this.turnstileFetch(TURNSTILE_SITEVERIFY_URL, {
      method: "POST",
      body
    });
    if (!response.ok) {
      throw new Error("Cloudflare 人機驗證暫時不可用，請稍後再試");
    }

    const result = await response.json();
    if (!result.success) {
      throw new Error("Cloudflare 人機驗證失敗，請重新驗證後再試");
    }
  }
}

function getClientIp(request) {
  return request.headers.get("cf-connecting-ip") ?? request.headers.get("x-forwarded-for") ?? "";
}

function renderLoginPage(request, config) {
  return renderAuthPage({
    title: "OpenAI SSO 登入",
    lead: "請輸入帳號登入。帳號會使用固定信箱域名。",
    formAction: "/login",
    buttonText: "登入",
    fields: accountFields(),
    switchText: "還沒有帳號？",
    switchLabel: "前往註冊",
    switchHref: buildAuthLink("/register", request),
    hiddenFields: toHiddenFields(request),
    turnstileSiteKey: config.turnstileSiteKey,
    turnstileAction: "login"
  });
}

function renderRegisterPage(request, config) {
  return renderAuthPage({
    title: "OpenAI SSO 註冊",
    lead: "請輸入帳號與邀請碼。註冊成功後會直接登入。",
    formAction: "/register",
    buttonText: "註冊並登入",
    fields: [...accountFields(), { label: "邀請碼", name: "invite_code", autocomplete: "one-time-code" }],
    switchText: "已有帳號？",
    switchLabel: "返回登入",
    switchHref: buildAuthLink("/authorize", request),
    hiddenFields: toHiddenFields(request),
    turnstileSiteKey: config.turnstileSiteKey,
    turnstileAction: "register"
  });
}

function renderAuthPage({
  title,
  lead,
  formAction,
  buttonText,
  fields,
  switchText,
  switchLabel,
  switchHref,
  hiddenFields,
  turnstileSiteKey,
  turnstileAction
}) {
  return `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    :root {
      color-scheme: light;
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --bg-page: #f8fafc;
      --bg-card: #ffffff;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --border-color: #e2e8f0;
      --input-border: #cbd5e1;
      --primary: #0f172a;
      --primary-hover: #1e293b;
      --primary-focus: rgba(15, 23, 42, 0.08);
      --accent: #0284c7;
      --shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.04), 0 1px 3px rgba(0, 0, 0, 0.02);
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: var(--bg-page);
      color: var(--text-main);
      font-family: var(--font-sans);
      padding: 20px;
      box-sizing: border-box;
    }

    main {
      width: min(420px, 100%);
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 36px 32px;
      box-shadow: var(--shadow);
    }

    h1 {
      margin: 0 0 8px;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.025em;
      line-height: 1.2;
    }

    p {
      margin: 0 0 24px;
      color: var(--text-muted);
      font-size: 14px;
      line-height: 1.5;
    }

    label, .field-label {
      display: block;
      margin-bottom: 16px;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .account-domain {
      text-transform: none;
      letter-spacing: normal;
      color: var(--accent);
      font-weight: 500;
      margin-left: 4px;
    }

    input {
      box-sizing: border-box;
      width: 100%;
      border: 1px solid var(--input-border);
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 15px;
      margin-top: 6px;
      font-family: var(--font-sans);
      color: var(--text-main);
      background-color: #ffffff;
      transition: all 0.15s ease-in-out;
      font-weight: 400;
      text-transform: none;
      letter-spacing: normal;
    }

    input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px var(--primary-focus);
    }

    button {
      width: 100%;
      border: 0;
      border-radius: 8px;
      padding: 13px 14px;
      margin-top: 8px;
      background: var(--primary);
      color: #ffffff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      font-family: var(--font-sans);
      transition: all 0.15s ease-in-out;
    }

    button:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
    }

    button:active {
      transform: translateY(0);
    }

    .turnstile-widget {
      min-height: 65px;
      margin: 18px 0 14px;
    }

    .hint {
      margin: 24px 0 0;
      text-align: center;
      font-size: 13px;
      color: var(--text-muted);
      text-transform: none;
      letter-spacing: normal;
    }

    a {
      color: var(--primary);
      font-weight: 600;
      text-decoration: none;
      transition: color 0.15s ease;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1px;
    }

    a:hover {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(lead)}</p>
    <form method="post" action="${escapeHtml(formAction)}">
      ${renderHiddenFields(hiddenFields)}
      ${fields
        .map((field) =>
          field.type === "account"
            ? renderAccountField(field)
            : `<label>${escapeHtml(field.label)}
        <input name="${escapeHtml(field.name)}" autocomplete="${escapeHtml(field.autocomplete)}" required>
      </label>`
        )
        .join("")}
      ${renderTurnstile(turnstileSiteKey, turnstileAction)}
      <button type="submit">${escapeHtml(buttonText)}</button>
    </form>
    <p class="hint">${escapeHtml(switchText)} <a href="${escapeHtml(switchHref)}">${escapeHtml(switchLabel)}</a></p>
  </main>
  ${renderTurnstileScript(turnstileSiteKey)}
</body>
</html>`;
}

function accountFields() {
  return [{ type: "account", label: "帳號", name: "account", autocomplete: "username" }];
}

function renderAccountField(field) {
  return `<label class="account-field">${escapeHtml(field.label)}<span class="account-domain">@itc.989567.xyz</span>
          <input name="${escapeHtml(field.name)}" autocomplete="${escapeHtml(field.autocomplete)}" required>
        </label>`;
}

function renderTurnstile(siteKey, action) {
  if (!siteKey) {
    return "";
  }
  return `<div class="turnstile-widget cf-turnstile" data-sitekey="${escapeHtml(siteKey)}" data-action="${escapeHtml(action)}"></div>`;
}

function renderTurnstileScript(siteKey) {
  if (!siteKey) {
    return "";
  }
  return `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`;
}

function renderHiddenFields(hiddenFields) {
  return Object.entries(hiddenFields)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join("");
}

function buildAuthLink(pathname, request) {
  const url = new URL(pathname, "https://sso.local");
  for (const [name, value] of Object.entries(toHiddenFields(request))) {
    if (value) {
      url.searchParams.set(name, value);
    }
  }
  return `${url.pathname}${url.search}`;
}

function toHiddenFields(request) {
  const hiddenFields = {
    client_id: request.clientId,
    redirect_uri: request.redirectUri,
    response_type: request.responseType,
    scope: request.scope,
    state: request.state,
    nonce: request.nonce,
    code_challenge: request.codeChallenge,
    code_challenge_method: request.codeChallengeMethod
  };
  return hiddenFields;
}

function html(body, init = {}) {
  return new Response(body, {
    status: init.status ?? 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...init.headers
    }
  });
}

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...init.headers
    }
  });
}

function redirectResponse(location) {
  return new Response(null, {
    status: 302,
    headers: { location }
  });
}

function oauthError(error, description, status) {
  return json(
    {
      error,
      error_description: description
    },
    { status }
  );
}

function errorResponse(error) {
  const message = getErrorMessage(error);
  return html(
    `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>登入失敗</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    :root {
      --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
      --bg-page: #f8fafc;
      --bg-card: #ffffff;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --border-color: #e2e8f0;
      --danger: #ef4444;
      --shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.04), 0 1px 3px rgba(0, 0, 0, 0.02);
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: var(--bg-page);
      color: var(--text-main);
      font-family: var(--font-sans);
      padding: 20px;
      box-sizing: border-box;
    }
    main {
      width: min(420px, 100%);
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 36px 32px;
      box-shadow: var(--shadow);
      text-align: center;
    }
    h1 {
      margin: 0 0 12px;
      font-size: 22px;
      font-weight: 700;
      color: var(--danger);
    }
    p {
      margin: 0 0 24px;
      color: var(--text-muted);
      font-size: 14px;
      line-height: 1.6;
    }
    a {
      display: inline-block;
      padding: 10px 20px;
      background: #0f172a;
      color: #ffffff;
      border-radius: 6px;
      text-decoration: none;
      font-size: 14px;
      font-weight: 600;
      transition: background 0.15s ease;
    }
    a:hover {
      background: #1e293b;
    }
  </style>
</head>
<body>
  <main>
    <h1>登入失敗</h1>
    <p>${escapeHtml(message)}</p>
    <a href="javascript:history.back()">返回上一頁</a>
  </main>
</body>
</html>`,
    { status: 400 }
  );
}

function getErrorMessage(error) {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  return "登入處理失敗";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
