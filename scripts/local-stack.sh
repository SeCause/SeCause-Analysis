#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
export LOCAL_ENV_FILE=${LOCAL_ENV_FILE:-.env}

usage() {
  cat <<'HELP'
Usage: ./scripts/local-stack.sh init|up|down|status|logs|restart|prepare-rag|index-rag|check [args]
  init              Create the ignored .env.local-stack OAuth settings file.
  up                Build and start the full stack; wait for readiness.
  down              Stop this stack; retain DB, RAG, Redis and dependency caches.
  logs [service]    Follow logs (default: analysis-worker).
  restart [service] Restart after code changes (default: analysis-worker).
  prepare-rag       Download OWASP/CWE source documents (no embedding calls).
  index-rag [args]  Index local rag_documents/raw using real embedding API.
  check             Validate config without starting services.

Use sibling SeCause-BE and SeCause-FE checkouts, or set BACKEND_DIR/FRONTEND_DIR.
Keep CLAUDE_API_KEY and OPENAI_API_KEY in Analysis .env (or LOCAL_ENV_FILE).
Run init, then put existing GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in
.env.local-stack. OAuth callback:
http://localhost:3000/login/callback

First run: init, fill OAuth keys, up, prepare-rag, index-rag, then open localhost:3000.
RQ runs inside analysis-worker; it does not need a separate container.
Semgrep is included. CodeQL requires a separate compatible CLI installation.
HELP
}
compose() {
  local env_args=(--env-file "$LOCAL_ENV_FILE")
  if [[ -f "$ROOT/.env.local-stack" ]]; then
    env_args+=(--env-file "$ROOT/.env.local-stack")
  fi
  docker compose "${env_args[@]}" -f "$ROOT/compose.local.yml" "$@"
}
command=${1:-help}
if [[ $# -gt 0 ]]; then shift; fi
case "$command" in
  help|-h|--help) usage; exit 0 ;;
  init)
    if [[ ! -f .env.local-stack ]]; then
      cp .env.local-stack.example .env.local-stack
      chmod 600 .env.local-stack
    fi
    echo 'Fill existing GitHub OAuth credentials in .env.local-stack; existing settings were preserved.'
    exit 0 ;;
  prepare-rag) python3 scripts/local/prepare_rag.py; exit 0 ;;
esac
if [[ ! -f "$LOCAL_ENV_FILE" ]]; then
  echo "Missing $LOCAL_ENV_FILE. Copy .env.example and set real API/OAuth keys." >&2
  exit 1
fi
case "$command" in
  up)
    compose config --quiet
    compose up --build --detach --wait --wait-timeout 900
    echo 'Ready: http://localhost:3000 | Backend: http://localhost:8080 | Analysis: http://localhost:8001/docs'
    echo 'Worker logs: ./scripts/local-stack.sh logs'
    echo 'A fresh DB has no RAG evidence: prepare raw documents and run index-rag before analysis.'
    ;;
  down) compose down ;;
  status) compose ps -a ;;
  logs)
    if [[ $# -eq 0 ]]; then set -- analysis-worker; fi
    compose logs --follow --tail 100 --timestamps "$@" ;;
  restart)
    if [[ $# -eq 0 ]]; then set -- analysis-worker; fi
    compose restart "$@" ;;
  index-rag)
    if [[ ! -f rag_documents/raw/cwe/cwe.xml || ! -d rag_documents/raw/owasp ]]; then
      echo 'Prepare raw sources as described in rag_documents/README.md first.' >&2
      exit 1
    fi
    compose exec -T analysis-api python scripts/index_rag_documents.py "$@"
    ;;
  check) compose config --quiet ;;
  *) usage; exit 1 ;;
esac
