# Cloudflare Workers OpenAI OIDC SSO

這是一個部署於 Cloudflare Workers 的 Custom OIDC SSO Provider，用於對接 OpenAI SSO。使用者登入時只輸入帳號；註冊新帳號時需要輸入邀請碼。系統會把帳號固定轉成 `ACCOUNT_DOMAIN` 指定的信箱域名，邀請碼預設最多建立 100 個新帳號。已建立帳號之後仍可登入，不會再消耗邀請碼。

## 功能

- OIDC discovery：`/.well-known/openid-configuration`
- JWKS：`/jwks.json`
- 授權端點：`/authorize`
- 登入端點：`/login`
- 註冊頁與註冊端點：`/register`
- Token 端點：`/token`
- UserInfo 端點：`/userinfo`
- 邀請碼管理：`/admin/invite-codes`

## 部署前準備

你需要先準備：

- Cloudflare 帳號，並啟用 Workers 與 D1。
- 一個要給 OpenAI 使用的 HTTPS 網域，例如 `https://auth.example.com`。
- 一個要作為使用者信箱尾綴的帳號域名，例如 `example.com`。
- OpenAI SSO 後台提供的 callback URL 與 Tile URL。
- 一組 OIDC Client ID / Client Secret。Client ID 會公開在設定中，Client Secret 必須放到 Workers Secret。
- 一個 RS256 私鑰 JWK，供 `/jwks.json` 與 token 簽章使用。

此專案的 Worker 入口是 `src/index.js`。公開倉庫只提交 `wrangler.example.toml`，真實 `wrangler.toml` 只放在本機並已被 `.gitignore` 忽略。程式碼會從 `env.DB` 讀取 D1，因此 D1 綁定名稱必須是 `DB`。

## 公開倉庫安全設定

不要把真實 `wrangler.toml`、`.env`、Cloudflare token、OIDC secret、私鑰 JWK、D1 database ID、OpenAI callback URL 或任何私有網域設定提交到 GitHub。

本機開發或使用 Wrangler CLI 時，先複製範例檔：

```powershell
Copy-Item wrangler.example.toml wrangler.toml
```

再把 `wrangler.toml` 裡的 D1 binding 占位值改成自己的資料庫設定。`wrangler.toml` 已在 `.gitignore` 中，正常 `git add .` 不會再加入它。正式環境變數請在 Cloudflare Dashboard 的 Variables and Secrets 裡維護，不要寫進 `wrangler.toml` 的 `[vars]`。

若使用 Cloudflare 網頁版 Git 部署，請在 Cloudflare Dashboard 設定 Variables and Secrets 與 D1 綁定，不需要把真實變數提交到倉庫。想要之後仍能在 Cloudflare 介面看到內容的值，請選 Text；真正的密鑰、token 與私鑰才選 Secret。

`wrangler.example.toml` 已設定 `keep_vars = true`。這個設定很重要：使用 `wrangler deploy` 時，Wrangler 不會用本地 `[vars]` 清空或覆蓋 Cloudflare Dashboard 裡已設定的 Variables。若你自己建立新的 `wrangler.toml`，也請保留 `keep_vars = true`。本倉庫預設不使用 `[vars]` 保存私有設定。

`keep_vars = true` 只保護 Dashboard Variables，不代表會自動保留 D1 binding。正式部署仍必須在 Cloudflare Dashboard 或部署時使用的 Wrangler 設定中提供 `DB` 這個 D1 binding。

## OpenAI 設定

在 OpenAI SSO 設定頁選擇 **Custom OIDC**。建議填入：

- Issuer：`https://你的網域`
- Authorization endpoint：`https://你的網域/authorize`
- Token endpoint：`https://你的網域/token`
- JWKS URI：`https://你的網域/jwks.json`
- UserInfo endpoint：`https://你的網域/userinfo`
- Client ID：與 `OIDC_CLIENT_ID` 相同
- Client Secret：與 `OIDC_CLIENT_SECRET` 相同

OpenAI 的實際 callback URL 以 OpenAI 後台顯示為準，並放入 `ALLOWED_REDIRECT_URIS`。若有多個 redirect URI，使用逗號分隔。

## Cloudflare 網頁版部署

建議先建立 D1，再連接 Git 倉庫部署 Worker，這樣第一次部署就能帶上正確的 D1 綁定。

### 1. 建立 D1 資料庫

1. 進入 Cloudflare Dashboard。
2. 到 **Storage & Databases → D1 SQL Database**。
3. 選擇 **Create database**。
4. Database name 建議填 `openai_oidc_sso`。
5. 建立後複製 `database_id`。

本機 CLI 部署時，把 `database_id` 填回本機 `wrangler.toml`。Cloudflare 網頁版部署時，請在 Worker 的 D1 bindings 設定同一個 database，binding 名稱必須是 `DB`。

公開的 `wrangler.example.toml` 不包含真實 D1 binding，避免 Cloudflare Builds 把占位 `database_id` 當真值部署。若你用 `npx wrangler deploy` 自動部署，部署時讀到的設定檔必須包含真實 D1 binding；若使用 Cloudflare Dashboard 部署，請在 Dashboard 綁定 D1。

`binding` 必須維持 `DB`，因為 `src/index.js` 使用 `env.DB` 連線。

### 2. 初始化資料表

1. 在 Cloudflare Dashboard 進入剛建立的 D1 database。
2. 開啟 **Console**。
3. 複製本倉庫的 `schema.sql` 全部內容並貼上。
4. 選擇 **Execute**。
5. 到 **Tables** 確認已建立 `users`、`invite_codes`、`authorization_codes`。

也可以在 Console 執行這段確認：

```sql
SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;
```

初始化只會建立資料表，不會自動建立邀請碼。若暫時不想啟用 `/admin/invite-codes` API，可直接在 D1 Console 建立第一個邀請碼：

```sql
INSERT INTO invite_codes (code, max_uses, used_count, enabled, created_at)
VALUES ('JOIN-2026', 100, 0, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
```

### 3. 連接 Git 倉庫

1. 把程式碼推到 GitHub 或 GitLab。不要提交本機真實 `wrangler.toml`。
2. 在 Cloudflare Dashboard 進入 **Workers & Pages**。
3. 選擇 **Create application**，再選擇連接 Git repository 的部署方式。
4. 選擇此專案倉庫與 production branch。
5. Build settings 建議：
   - Root directory：如果倉庫根目錄就是此專案，留空。
   - Build command：留空，這個 Worker 不需要前端建置。
   - Deploy command：`npx wrangler deploy`。
6. 建立後先完成下方「環境變數與 Secrets」以及 D1 binding 設定，再重新部署。

Cloudflare Workers Builds 會在連接倉庫後部署 Worker。公開倉庫不提交真實 `wrangler.toml`，因此請在 Cloudflare Dashboard 中維護正式環境的 runtime 變數、Secrets 與 D1 綁定。若部署命令使用 `npx wrangler deploy`，請確保部署時讀到的 Wrangler 設定包含 `keep_vars = true`，避免覆蓋 Dashboard 中的 Variables。

若你使用 GitHub Actions 或 Cloudflare Builds 執行 `npx wrangler deploy`，部署時讀到的 Wrangler 設定應包含 `keep_vars = true` 與真實 `DB` D1 binding，但不要包含 `[vars]`。這樣每次推送只部署程式碼，不會把公開倉庫裡的占位值寫回 Cloudflare，也不會清空 Dashboard 裡的 Text 變數。

如果不想在 GitHub 保存 D1 `database_id`，不要讓公開倉庫裡的 `wrangler.example.toml` 帶 `[[d1_databases]]` 占位配置直接部署。可選做法：

- 使用 Cloudflare Dashboard 設定 Worker、Text 變數、Secrets 與 D1 binding，避免用公開 config 覆蓋 Dashboard 設定。
- 在 CI 裡從 GitHub Secrets 產生臨時 Wrangler config，臨時 config 只在構建機存在，包含 `keep_vars = true` 與真實 D1 binding，不包含 `[vars]`。

### 4. 綁定自訂網域

部署完成後，若要使用自己的網域：

1. 進入 Worker 的 **Settings → Domains & Routes**。
2. 選擇 **Add → Custom Domain**。
3. 填入 `auth.example.com` 這類完整主機名稱。
4. 等待 Cloudflare 建立 DNS 記錄與憑證。
5. 將 `ISSUER` 改成這個正式網域，並重新部署。

若先使用 `*.workers.dev` 測試，`ISSUER`、OpenAI OIDC endpoints 與 OpenAI 後台 callback 設定也必須使用同一個測試網域。

## 環境變數與 Secrets

Cloudflare Dashboard 內請到 Worker 的 **Settings → Variables and Secrets** 新增。選擇 **Text** 的值會以明文設定；選擇 **Secret** 的值儲存後不會再顯示。新增或修改後要按 **Deploy** 才會套用到 Worker。

不要把 runtime 變數填到 **Settings → Build → Environment variables**。Build variables 只在 Cloudflare 建置階段可用，Worker 執行時讀不到。

Cloudflare 的 Text 變數可以在 Dashboard 再次查看；Secret 儲存後不能再查看原值。若你需要日後能看回具體值，請設成 Text。Workers 程式讀取 Text 和 Secret 時一樣是 `env.變數名`，不需要改程式碼。

| 名稱 | 建議類型 | 必填 | 說明 |
| --- | --- | --- | --- |
| `ISSUER` | Text | 是 | Worker 對外 URL，不要帶結尾斜線，例如 `https://auth.example.com`。 |
| `OIDC_CLIENT_ID` | Text | 是 | OpenAI Custom OIDC 使用的 Client ID，例如 `openai-sso`。 |
| `ALLOWED_REDIRECT_URIS` | Text | 是 | OpenAI 後台顯示的 callback URL。多個值用逗號分隔。 |
| `ACCOUNT_DOMAIN` | Text | 是 | 使用者帳號的信箱域名，例如 `example.com`。使用者輸入 `neko` 時會變成 `neko@example.com`。 |
| `OPENAI_LOGIN_URL` | Text | 建議 | 直接訪問 `/` 時要跳轉的 OpenAI SSO Tile URL。不能填 OpenAI callback URL。 |
| `AUTHORIZATION_CODE_TTL_SECONDS` | Text 或省略 | 否 | 授權碼有效秒數，預設 `300`。 |
| `TOKEN_TTL_SECONDS` | Text 或省略 | 否 | Access token 與 ID token 有效秒數，預設 `3600`。 |
| `TURNSTILE_SITE_KEY` | Text | 否 | Cloudflare Turnstile 前端公開 Site Key。 |
| `PRIVATE_JWK` | Secret | 是 | RS256 私鑰 JWK，必須是單行 JSON，且包含 `kid`。 |
| `OIDC_CLIENT_SECRET` | Secret | 是 | OpenAI Custom OIDC 使用的 Client Secret。 |
| `ADMIN_TOKEN` | Secret | 否 | 呼叫 `/admin/invite-codes` 建立邀請碼時使用。 |
| `TURNSTILE_SECRET_KEY` | Secret | 否 | Cloudflare Turnstile 後端 Secret Key。設定 Site Key 時也必須設定它。 |

`wrangler.example.toml` 不保存 `[vars]`，避免公開倉庫或自動部署把占位值同步到 Cloudflare。正式部署時請在 Cloudflare Dashboard 確認 runtime 變數是否已正確套用。

若你想在本機保留一份可查看的設定備份，可以複製 `.env.example` 為 `.env`：

```powershell
Copy-Item .env.example .env
```

`.env` 已被 `.gitignore` 忽略，不會提交到 GitHub。注意：`.env` 只是本機備份或本地開發用，不會自動同步到 Cloudflare Dashboard；正式值仍以 Cloudflare Dashboard 為準。

## 產生 RS256 私鑰 JWK

在本機執行：

```powershell
node -e "crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>{j.kid='openai-sso-2026-06-08';j.alg='RS256';j.use='sig';console.log(JSON.stringify(j))})"
```

把輸出整段 JSON 作為 `PRIVATE_JWK` Secret。請保持單行，不要在 Cloudflare Dashboard 內手動換行。

若使用 Wrangler CLI 設定 Secret：

```powershell
pnpm wrangler secret put PRIVATE_JWK
pnpm wrangler secret put OIDC_CLIENT_SECRET
pnpm wrangler secret put ADMIN_TOKEN
pnpm wrangler secret put TURNSTILE_SECRET_KEY
```

## Cloudflare Turnstile

註冊與登入頁支援 Cloudflare Turnstile 人機驗證。

- `TURNSTILE_SITE_KEY`：公開值，設定為 Text。
- `TURNSTILE_SECRET_KEY`：後端驗證密鑰，設定為 Secret。

兩個值都不設定時，系統會停用 Turnstile。只設定其中一個時，登入與註冊會因缺少必要設定而失敗。正式使用建議同時設定兩個值。

## 登入與註冊流程

OpenAI 使用 `/authorize` 作為 authorization endpoint。使用者進入 `/authorize` 後會看到登入頁；若需要建立新帳號，從登入頁點選註冊連結進入 `/register`，OIDC 參數會自動保留。

- 直接入口：訪問 `https://你的網域/` 會跳轉到 `OPENAI_LOGIN_URL`。這必須填 OpenAI SSO 設定頁提供的 Tile URL，例如 `https://chatgpt.com/auth/login?sso=true&connection=conn_...`。不能直接跳 OpenAI callback，否則 OpenAI 端沒有先建立 SSO session，會出現 `client_id_not_found_in_session`。
- 登入頁：只輸入帳號，例如 `neko`。系統會使用 `neko@ACCOUNT_DOMAIN` 登入。
- 註冊頁：輸入帳號與邀請碼。註冊成功後會直接完成 OIDC 登入。

若使用者輸入完整信箱，例如 `neko@example.com`，系統只接受尾綴符合 `ACCOUNT_DOMAIN` 的地址。其他信箱域名會被拒絕。

## 建立邀請碼

若已設定 `ADMIN_TOKEN`，可用管理 API 建立邀請碼：

```powershell
curl -X POST https://你的網域/admin/invite-codes ^
  -H "Authorization: Bearer 你的_ADMIN_TOKEN" ^
  -H "Content-Type: application/json" ^
  -d "{\"code\":\"JOIN-2026\",\"maxUses\":100}"
```

回傳範例：

```json
{
  "code": "JOIN-2026",
  "maxUses": 100,
  "usedCount": 0,
  "enabled": true,
  "createdAt": "2026-06-08T00:00:00.000Z"
}
```

也可以直接在 D1 Console 執行 SQL：

```sql
INSERT INTO invite_codes (code, max_uses, used_count, enabled, created_at)
VALUES ('JOIN-2026', 100, 0, 1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(code) DO UPDATE SET
  max_uses = excluded.max_uses,
  enabled = excluded.enabled;
```

## CLI 部署與資料庫初始化

若偏好使用本機 CLI：

```powershell
pnpm install
Copy-Item wrangler.example.toml wrangler.toml
pnpm wrangler d1 create openai_oidc_sso
```

將 `wrangler d1 create` 回傳的 `database_id` 填入 `wrangler.toml` 後，初始化遠端 D1：

```powershell
pnpm wrangler d1 execute openai_oidc_sso --remote --file .\schema.sql
```

注意：不加 `--remote` 時，Wrangler 只會初始化本機 D1，不會影響 Cloudflare 上的正式資料庫。

部署：

```powershell
pnpm wrangler deploy
```

## 本地驗證

```powershell
pnpm install
pnpm test
pnpm check
```

## 部署後檢查

部署後先開啟：

- `https://你的網域/.well-known/openid-configuration`
- `https://你的網域/jwks.json`

確認兩個端點正常後，再到 OpenAI 後台啟用 Custom OIDC。

若 `/jwks.json` 回報 `缺少必要設定：PRIVATE_JWK`，代表 Secret 未設定或尚未重新部署。若 `/authorize` 回報不允許的 redirect URI，請回到 `ALLOWED_REDIRECT_URIS` 核對 OpenAI 後台顯示的 callback URL。

## Cloudflare 官方參考

- Workers runtime 環境變數與 Secret：https://developers.cloudflare.com/workers/configuration/environment-variables/
- Workers Secret：https://developers.cloudflare.com/workers/configuration/secrets/
- D1 建立、綁定與 Console 初始化：https://developers.cloudflare.com/d1/get-started/
- Workers Git 部署設定：https://developers.cloudflare.com/workers/ci-cd/builds/configuration/
- Workers 自訂網域：https://developers.cloudflare.com/workers/configuration/routing/custom-domains/
