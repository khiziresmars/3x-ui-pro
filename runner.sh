#!/usr/bin/env bash
# install-and-patch.sh
# Автоматическая установка 3x-ui v2.6.0 + моментальная правка настроек

set -euo pipefail

# ────────────────────────────────────────
# Константы - правь при необходимости
# ────────────────────────────────────────
USERNAME="esmars"
PASSWORD="EsmarsMe13AMS1"
WEB_PORT=8000           # порт панели
WEB_PATH="getkeys"      # без слэшей по краям
SUB_PORT=2096
SUB_PATH="/getkeys/"    # со слэшами
INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh"
DB_PATH="/usr/local/x-ui/x-ui.db"

# ────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Запусти скрипт от root"; exit 1; }

echo "➡  Устанавливаю зависимости (curl, sqlite3)…"
if ! command -v sqlite3 &>/dev/null; then
  if   command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq sqlite3;
  elif command -v yum     &>/dev/null; then yum install -y sqlite;
  elif command -v dnf     &>/dev/null; then dnf install -y sqlite;
  else echo "‼  Не могу поставить sqlite3 — добавь вручную"; exit 1; fi
fi

echo "➡  Скачиваю инсталлер 3x-ui v2.6.0…"
curl -fsSL "$INSTALL_URL" -o /tmp/xui_install.sh
chmod +x /tmp/xui_install.sh

echo "➡  Запускаю официальный install.sh…"
bash /tmp/xui_install.sh

echo "➡  Останавливаю сервис x-ui для правки базы…"
systemctl stop x-ui

if [[ ! -f "$DB_PATH" ]]; then
  echo "‼  База $DB_PATH не найдена. Проверь, где x-ui её создала."; exit 1;
fi

echo "➡  Патчу настройки в базе…"
sqlite3 "$DB_PATH" <<SQL
UPDATE settings
SET username              = '${USERNAME}',
    password              = '${PASSWORD}',
    port                  = ${WEB_PORT},
    webBasePath           = '${WEB_PATH}',
    subPort               = ${SUB_PORT},
    subPath               = '${SUB_PATH}',
    hasDefaultCredential  = 0
WHERE id = 1;
SQL

echo "➡  Перезапускаю x-ui…"
systemctl start x-ui

SERVER_IP=$(curl -s https://api.ipify.org)
echo -e "\n🟢 Готово!\n"
echo "  ▸ Панель:   http://${SERVER_IP}:${WEB_PORT}/${WEB_PATH}/"
echo "  ▸ Логин:    ${USERNAME}"
echo "  ▸ Пароль:   ${PASSWORD}"
echo "  ▸ subPort:  ${SUB_PORT}"
echo -e "\nУдачной работы 🎉"
