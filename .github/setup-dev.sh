#!/usr/bin/env bash
# setup-dev.sh — Configura el entorno local para contribuir al repo infrafence/infrafence-agent
# Todos los commits y operaciones de GitHub deben realizarse con el usuario infrafence-bot.
#
# Uso: bash .github/setup-dev.sh

set -e

BOT_NAME="infrafence-bot"
BOT_EMAIL="267082224+infrafence-bot@users.noreply.github.com"
REPO_REMOTE="https://github.com/infrafence/infrafence-agent.git"

echo "==> Configurando identidad git local (infrafence-bot)..."
git config user.name  "$BOT_NAME"
git config user.email "$BOT_EMAIL"

echo "==> Remote actual: $(git remote get-url origin)"

# Si el remote no apunta al repo correcto, corregirlo
if ! git remote get-url origin | grep -q "infrafence/infrafence-agent"; then
  git remote set-url origin "$REPO_REMOTE"
  echo "==> Remote actualizado a $REPO_REMOTE"
fi

echo ""
echo "Configuración completada:"
echo "  user.name  = $(git config user.name)"
echo "  user.email = $(git config user.email)"
echo "  origin     = $(git remote get-url origin)"
echo ""
echo "Para push y operaciones gh CLI, exporta el token de infrafence-bot:"
echo "  export GH_TOKEN=<token_de_infrafence-bot>"
echo ""
echo "Flujo de release:"
echo "  1. git commit  (se firmará como infrafence-bot)"
echo "  2. git tag vX.Y.Z"
echo "  3. git push origin main"
echo "  4. GH_TOKEN=<token> git push origin vX.Y.Z"
echo "     → GitHub Actions compila y publica el release como infrafence-bot"
