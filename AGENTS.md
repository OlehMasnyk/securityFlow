# AGENTS.md

## Cursor Cloud specific instructions

This repo is an OAuth 2.1 / OIDC / PKCE microservices demo (BFF pattern). See `README.md`
for the architecture, the full flow, and the canonical run/build/test commands. Notes below
are only the non-obvious things a future agent needs to run it here.

### Services (all required for an end-to-end demo)

| Service | Port | How to run (from repo root) |
| --- | --- | --- |
| `authorization-server` (OIDC provider) | 9000 | `./mvnw -pl authorization-server spring-boot:run` |
| `orders-service` (JWT resource server) | 8081 | `./mvnw -pl orders-service spring-boot:run` |
| `profile-service` (JWT resource server) | 8082 | `./mvnw -pl profile-service spring-boot:run` |
| `bff-gateway` (OAuth2 client + gateway) | 8080 | `./mvnw -pl bff-gateway spring-boot:run` |
| `frontend` (React + Vite SPA) | 5173 | `cd frontend && npm run dev -- --host 127.0.0.1` |
| `redis` (BFF session store) | 6379 | `redis-server` (must be running before the BFF) |

Lint/test/build are standard (see `README.md`): `./mvnw clean test` for all Java modules,
`cd frontend && npm run build` for the SPA. There is no separate Java linter configured.

### Non-obvious gotchas

- **Redis must be running on `localhost:6379` before starting `bff-gateway`.** The gateway keeps
  OAuth tokens in Redis-backed sessions. `redis-server` is already installed in this environment.
- **Start `authorization-server` first.** `bff-gateway` reads the OIDC discovery document at
  startup, so the IdP (port 9000) must be up and healthy before the BFF starts. The resource
  servers fetch the JWKS lazily, so their start order is less strict.
- **Run Vite bound to `127.0.0.1`** (`npm run dev -- --host 127.0.0.1`), not the default. The
  registered OAuth redirect URIs are `http://127.0.0.1:5173/...` and `http://127.0.0.1:8080/...`
  (see `AuthorizationServerConfig.java`). The default `npm run dev` binds to `localhost`, which
  resolves to IPv6 `::1` here and is unreachable at `127.0.0.1:5173`; using `localhost:5173` in a
  browser makes the BFF derive an unregistered `localhost` redirect URI and the token exchange
  fails. The Vite dev server proxies `/api`, `/oauth2`, `/login`, `/logout` to the BFF on 8080.
- **Local vs Docker issuer host:** for local runs every service defaults to issuer
  `http://127.0.0.1:9000` (consistent), so you do NOT need the `/etc/hosts` `idp` entry that the
  Docker Compose path requires. Only add `127.0.0.1 idp` if you run via `docker compose`.
- **Demo credentials:** `alice / password` (or `admin / password`).
- **Headless-browser scripting gotcha:** when driving the login flow with a headless browser,
  abort `/favicon.ico` requests. The favicon request hits the protected authorization-server and
  can clobber the saved authorization request, making the post-login `/oauth2/authorize?...`
  step return a 500. A `curl`-driven flow (no favicon) is unaffected.
