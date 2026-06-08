import { exportPublicJwk, timingSafeEqual, verifyJwt } from "./crypto.js";
import { InviteService } from "./invite-service.js";
import { OidcService } from "./oidc-service.js";

export function createApp({ store, config }) {
  const inviteService = new InviteService(store);
  const oidcService = new OidcService({ store, config });

  return {
    async fetch(request) {
      const url = new URL(request.url);
      try {
        if (request.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
          return json(oidcService.getDiscoveryMetadata());
        }
        if (request.method === "GET" && url.pathname === "/jwks.json") {
          return json(
            { keys: [await exportPublicJwk(requirePrivateJwk(config))] },
            { headers: { "content-type": "application/jwk-set+json; charset=utf-8" } }
          );
        }
        if (request.method === "GET" && url.pathname === "/authorize") {
          return handleAuthorize(url, oidcService);
        }
        if (request.method === "GET" && url.pathname === "/register") {
          return handleRegisterPage(url, oidcService);
        }
        if (request.method === "POST" && url.pathname === "/login") {
          return await handleLogin(request, inviteService, oidcService);
        }
        if (request.method === "POST" && url.pathname === "/register") {
          return await handleRegister(request, inviteService, oidcService);
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

function handleAuthorize(url, oidcService) {
  const authRequest = oidcService.validateAuthorizeRequest(url.searchParams);
  return html(renderLoginPage(authRequest));
}

function handleRegisterPage(url, oidcService) {
  const authRequest = oidcService.validateAuthorizeRequest(url.searchParams);
  return html(renderRegisterPage(authRequest));
}

async function handleLogin(request, inviteService, oidcService) {
  const { form, authRequest } = await parseLoginForm(request, oidcService);
  const account = String(form.get("account") ?? "");
  const user = await inviteService.login({ account });
  return issueAuthorizationCode({ user, authRequest, oidcService });
}

async function handleRegister(request, inviteService, oidcService) {
  const { form, authRequest } = await parseLoginForm(request, oidcService);
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

function renderLoginPage(request) {
  return renderAuthPage({
    title: "OpenAI SSO 登入",
    lead: "請輸入帳號登入。帳號會使用固定信箱域名。",
    formAction: "/login",
    buttonText: "登入",
    fields: accountFields(),
    switchText: "還沒有帳號？",
    switchLabel: "前往註冊",
    switchHref: buildAuthLink("/register", request),
    hiddenFields: toHiddenFields(request)
  });
}

function renderRegisterPage(request) {
  return renderAuthPage({
    title: "OpenAI SSO 註冊",
    lead: "請輸入帳號與邀請碼。註冊成功後會直接登入。",
    formAction: "/register",
    buttonText: "註冊並登入",
    fields: [...accountFields(), { label: "邀請碼", name: "invite_code", autocomplete: "one-time-code" }],
    switchText: "已有帳號？",
    switchLabel: "返回登入",
    switchHref: buildAuthLink("/authorize", request),
    hiddenFields: toHiddenFields(request)
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
  hiddenFields
}) {
  return `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    :root { color-scheme: light; font-family: Arial, "Noto Sans TC", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f7f7f5; color: #1f2328; }
    main { width: min(430px, calc(100vw - 32px)); background: #fff; border: 1px solid #d9d9d6; border-radius: 8px; padding: 30px; box-shadow: 0 18px 45px rgb(0 0 0 / 8%); }
    h1 { margin: 0 0 16px; font-size: 26px; line-height: 1.25; }
    label, .field-label { display: grid; gap: 8px; margin: 16px 0; font-size: 14px; font-weight: 600; }
    input { box-sizing: border-box; width: 100%; border: 1px solid #c8c8c4; border-radius: 6px; padding: 12px; font-size: 16px; }
    input:focus { outline: 2px solid #111; outline-offset: 2px; }
    .account-field { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; overflow: hidden; border: 1px solid #c8c8c4; border-radius: 6px; background: #fff; }
    .account-field:focus-within { outline: 2px solid #111; outline-offset: 2px; }
    .account-field input { min-width: 0; border: 0; border-radius: 0; }
    .account-field input:focus { outline: 0; }
    .account-domain { align-self: stretch; display: grid; place-items: center; border-left: 1px solid #d9d9d6; padding: 0 12px; color: #5b5f66; background: #fafafa; font-size: 15px; font-weight: 700; white-space: nowrap; }
    button { width: 100%; border: 0; border-radius: 6px; padding: 13px 14px; margin-top: 10px; background: #111; color: #fff; font-size: 16px; font-weight: 700; cursor: pointer; }
    p { margin: 0 0 18px; color: #5b5f66; line-height: 1.6; }
    .hint { margin-top: 18px; text-align: center; font-size: 14px; }
    a { color: #111; font-weight: 700; text-decoration: underline; text-underline-offset: 3px; }
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
      <button type="submit">${escapeHtml(buttonText)}</button>
    </form>
    <p class="hint">${escapeHtml(switchText)} <a href="${escapeHtml(switchHref)}">${escapeHtml(switchLabel)}</a></p>
  </main>
</body>
</html>`;
}

function accountFields() {
  return [{ type: "account", label: "帳號", name: "account", autocomplete: "username" }];
}

function renderAccountField(field) {
  return `<div class="field-label">${escapeHtml(field.label)}
        <div class="account-field">
          <input name="${escapeHtml(field.name)}" autocomplete="${escapeHtml(field.autocomplete)}" required>
          <span class="account-domain">@itc.989567.xyz</span>
        </div>
      </div>`;
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
    `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><title>登入失敗</title></head><body><h1>登入失敗</h1><p>${escapeHtml(message)}</p></body></html>`,
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
