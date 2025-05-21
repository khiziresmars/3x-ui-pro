#!/usr/bin/env bash
# runner.sh — авто-инсталляция 3x-ui v2.6.0 + патч БД
set -euo pipefail

# ───── Константы ────────────────────────────────────────────────────
USERNAME="esmars"
PASSWORD="EsmarsMe13AMS1"
WEB_PORT=8000          # порт панели
WEB_PATH="getkeys"     # без слэшей по краям
SUB_PORT=2096
SUB_PATH="/getkeys/"   # со слэшами
INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh"

# ───── Проверки окружения ───────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "Запусти скрипт от root"; exit 1; }

echo "➡  Ставлю зависимости (wget, sqlite3)…"
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wget sqlite3
elif command -v dnf &>/dev/null; then
  dnf install -y -q wget sqlite
elif command -v yum &>/dev/null; then
  yum install -y -q wget sqlite
else
  echo "‼  Не удалось определить пакетный менеджер. Установи wget и sqlite3 вручную."; exit 1;
fi

# ───── Скачиваем и ставим 3x-ui ──────────────────────────────────────
echo "➡  Скачиваю install.sh v2.6.0…"
curl -fsSL "$INSTALL_URL" -o /tmp/xui_install.sh
chmod +x /tmp/xui_install.sh

echo "➡  Запускаю инсталляцию 3x-ui…"
bash /tmp/xui_install.sh

# ───── Определяем путь к базе ───────────────────────────────────────
echo "➡  Ищу x-ui.db…"
DB_PATH=$(find /etc/x-ui /usr/local/x-ui -maxdepth 1 -type f -name "x-ui.db" 2>/dev/null | head -n 1 || true)

if [[ -z "$DB_PATH" ]]; then
  echo "‼  Не удалось найти x-ui.db ни в /etc/x-ui/ ни в /usr/local/x-ui/."; exit 1;
fi
echo "    Найдена база: $DB_PATH"

# ───── Патчим настройки ─────────────────────────────────────────────
echo "➡  Останавливаю сервис x-ui…"
systemctl stop x-ui

echo "➡  Обновляю записи в базе…"
sqlite3 "$DB_PATH" <<SQL
UPDATE settings
SET username             = '${USERNAME}',
    password             = '${PASSWORD}',
    port                 = ${WEB_PORT},
    webBasePath          = '${WEB_PATH}',
    subPort              = ${SUB_PORT},
    subPath              = '${SUB_PATH}',
    hasDefaultCredential = 0
WHERE id = 1;
SQL

# ───── Запуск ────────────────────────────────────────────────────────
echo "➡  Запускаю x-ui заново…"
systemctl start x-ui
systemctl enable x-ui

SERVER_IP=$(curl -s https://api.ipify.org)
echo -e "\n🟢  Установка завершена."
echo "    Панель:   http://${SERVER_IP}:${WEB_PORT}/${WEB_PATH}/"
echo "    Логин:    ${USERNAME}"
echo "    Пароль:   ${PASSWORD}"
echo "    subPort:  ${SUB_PORT}"
echo -e "\n🎉  Удачной работы!"
