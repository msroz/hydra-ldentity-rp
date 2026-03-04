# CLAUDE.md

## General Rules

- コードレビューやプランニングを求められた場合、明示的に依頼されない限りコードを変更しない。レビューとプランは読み取り専用の操作である

## Project Overview

Ory Hydra + Self-hosted Identity Provider + Sample Relying Party で構成された OAuth2/OIDC 学習・検証用プロジェクト。

## Architecture

```
[RP (rp/)] --OAuth2/OIDC--> [Hydra] <--Admin API-- [Identity Provider (identity/)]
                                |
                              [MySQL]
```

- **identity/** — Identity Provider（Go module: `idp`）。Hydra Admin API を呼び出して login/consent/logout フローを処理する
- **rp/** — Relying Party（Go module: `rp`）。OAuth2 Authorization Code Flow を実行するサンプルクライアント
- **hydra/** — Hydra の設定ファイル（hydra.yml）

2つの独立した Go module で構成されている（go.work は使っていない）。

## Tech Stack

Primary languages: Go (backend, OIDC/OAuth), TypeScript (frontend), with HTML/CSS for UI. When making changes, always run `go build ./...` and `go test ./...` for Go, and the appropriate lint/build command for TypeScript projects.

- Go 1.25.4
- Router: go-chi/chi/v5
- Session: gorilla/sessions
- identity: ory/client-go（Hydra Admin API クライアント）, gorilla/csrf
- rp: golang.org/x/oauth2, lestrrat-go/jwx/v2（JWK/JWT）
- Hot reload: air（air.toml）
- Infrastructure: Docker Compose（Hydra v25.4.0, MySQL 8.0.26）

## Services

| Service | Port | Description |
|---------|------|-------------|
| Hydra Public | 8888 | OAuth2/OIDC public endpoint |
| Hydra Admin | 9999 | Hydra admin endpoint |
| Identity Provider | 3000 | Login/Consent/Logout UI |
| Relying Party | 7777 | Sample OAuth2 client |
| MySQL | 5306 (host) | Hydra data store |

## Development

```bash
# Start all services
docker compose up

# identity/ or rp/ の Go コードを変更すると air が自動リロードする
```

## Project Structure

```
identity/
  main.go              # entrypoint
  config/              # configuration
  controllers/         # HTTP handlers (login, consent, logout, hook, home)
  model/               # Hydra service client, user model
  routes/              # chi router setup
  view/                # template service
  templates/           # HTML templates
  static/              # CSS

rp/
  main.go              # entrypoint
  config/              # OAuth2 configuration
  controllers/         # HTTP handlers (auth, home, logout, client)
  model/               # user model
  routes/              # chi router setup
  view/                # template service
  templates/           # HTML templates
  static/              # CSS
  auth/                # private_key_jwt, JWK handling
  keys/                # JWK/PEM key files
  httputil/            # HTTP utilities
  cli/                 # JWK generation CLI

hydra/
  hydra.yml            # Hydra server configuration
```

## Build Verification

ローカルの Go バージョンと go.mod の指定が異なるため、ビルド確認は Docker コンテナ内で行う。

コード修正後は以下の両方が成功することを確認する：

```bash
docker compose run --no-deps --rm identity sh -c "go build -o /dev/null ./... && go vet ./..."
docker compose run --no-deps --rm rp sh -c "go build -o /dev/null ./... && go vet ./..."
```

## Before Implementing Checklist

コードを書く前に以下を確認する：

1. **Pointer dereference** — nil になりうるポインタを参照していないか。特に ory/client-go のレスポンスはポインタ型フィールドが多いため注意
2. **Type assertions** — interface{} からの型アサーションに comma-ok パターン（`v, ok := x.(T)`）を使っているか
3. **Verification steps** — 実装後にどうやって動作確認するかを事前に明確にしておく（ビルド確認、ブラウザでのフロー確認、ログ確認など）

## Go

- ポインタ型と値型（例: `*string` vs `string`）、型アサーションに注意する
- 常に nil チェックを行い、型アサーションには comma-ok パターン（`v, ok := x.(T)`）を使う

## Security / Auth Patterns

- Cookie の命名規則、CSRF オリジンチェック、セキュリティに関わる設定値は、実装前にユーザーに正確なフォーマット・値を確認する。慣習を仮定しない

## Deployment

- Cloudflare Pages へのデプロイは CLI（wrangler deploy）ではなく GitHub 連携を優先する
- Pages と Workers は異なるデプロイモデルであることを区別する

## Conventions

- Commit message: Conventional Commits（`feat:`, `fix:`, `refactor:`, `chore:`, `style:`）
- コードとコミットメッセージは英語
- コード修正後は必ずビルドが通ることを確認する（上記 Build Verification 参照）
- テストは現状なし
