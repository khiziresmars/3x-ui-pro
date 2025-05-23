#!/usr/bin/env bash
# runner.sh — Автоматическая настройка 3x-ui:
# - Установка и настройка 3x-ui (панель)
# - Создание inbound'ов (VLESS Reality, Shadowsocks, Trojan WS)
# - Настройка Nginx (опционально, если -nginx true)
# - Настройка SSL (опционально, если -ssl true и есть -domain)
# - Добавление подписок, cron-задач, firewall и т.д.
# 
# Пример запуска:
#   ./runner.sh -domain example.com -ssl true -nginx true -country Germany -reality-sni discord.com
#
# Поддерживаемые флаги (аргументы):
#   -domain <NAME>     : Ваш домен
#   -ssl <true|false>  : Включить/выключить SSL
#   -nginx <true|false>: Включить/выключить Nginx
#   -country <NAME>    : Условное "название страны" (для remark в inbound'ах)
#   -reality-sni <SNI> : SNI для VLESS Reality
#
# Требования: Запуск от root!

set -euo pipefail

# ────────── Константы по умолчанию ──────────
USERNAME="esmars"
PASSWORD="EsmarsMe13AMS1"

# Порт, на котором будет слушать сама панель X-UI
WEB_PORT=8000

# Путь (URL-Path) к панели (по умолчанию "/esmars/")
WEB_PATH="/esmars/"

# Порт для подписок (All-in-One)
SUB_PORT=2096

# Путь (URL-Path) для подписок
SUB_PATH="/getkeys/"

# URL скрипта установки 3x-ui (репозиторий MHSanaei)
INSTALL_URL="https://raw.githubusercontent.com/MHSanaei/3x-ui/refs/tags/v2.6.0/install.sh"

# Настройки SSL и домен (опционально)
DOMAIN=""
ENABLE_SSL="false"
ENABLE_NGINX="false"
COUNTRY="Netherlands"  # по умолчанию
REALITY_SNI="discord.com"  # SNI для Reality

# Порты для inbound'ов
VLESS_REALITY_PORT=443
SHADOWSOCKS_PORT=8388
TROJAN_WS_PORT=8443

# Глобальные переменные, чтобы не таскать их по функциям
declare REALITY_PRIVATE_KEY=""
declare REALITY_PUBLIC_KEY=""
declare VLESS_UUID=""
declare REALITY_SHORT_ID=""
declare SS_PASSWORD=""
declare TROJAN_PASSWORD=""

# ────────── Функции логирования ──────────
log()      { echo -e "\e[37m[$(date '+%H:%M:%S')]\e[0m $1"; }
msg_ok()   { echo -e "\e[1;32m[OK]\e[0m $1"; }
msg_inf()  { echo -e "\e[1;36m[INFO]\e[0m $1"; }
msg_war()  { echo -e "\e[1;33m[WARN]\e[0m $1"; }
error_exit(){ echo -e "\e[1;31m[ERR]\e[0m $1"; exit 1; }

# ────────── Ловушка для очистки временных файлов ──────────
cleanup_installation_scripts() {
    rm -f /tmp/xui_install.sh /tmp/xui_expect.exp 2>/dev/null || true
}
trap cleanup_installation_scripts EXIT ERR INT TERM

# ────────── Функция экранирования строк для sqlite ──────────
escape_sqlite_string() {
    # Заменяем одинарные кавычки на двойные ''
    # чтобы корректно записать в SQL
    echo "${1//\'/\'\'}"
}

# ────────── Получение аргументов из командной строки ──────────
while [[ $# -gt 0 ]]; do
    case $1 in
        -domain)
            DOMAIN="$2"
            ENABLE_SSL="true"
            ENABLE_NGINX="true"
            shift 2
            ;;
        -ssl)
            ENABLE_SSL="$2"
            shift 2
            ;;
        -nginx)
            ENABLE_NGINX="$2"
            shift 2
            ;;
        -country)
            COUNTRY="$2"
            shift 2
            ;;
        -reality-sni)
            REALITY_SNI="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# ────────── Проверка root ──────────
[[ $EUID -ne 0 ]] && error_exit "Запустите скрипт под root"

# ────────── Получение IP адресов ──────────
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-fA-F0-9:]+:+)+[a-fA-F0-9]+"
get_server_ips() {
    IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po 'src \K\S*' || echo "")
    [[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s4 ipv4.icanhazip.com 2>/dev/null || echo "")

    IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po 'src \K\S*' || echo "")
    [[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s6 ipv6.icanhazip.com 2>/dev/null || echo "")
}

# ────────── Установка зависимостей ──────────
install_dependencies() {
    msg_inf "Установка необходимых пакетов..."

    # Проверка и установка `expect` (если нет)
    if ! command -v expect &>/dev/null; then
        msg_inf "Устанавливаем expect..."
        if command -v apt-get &>/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq expect
        elif command -v dnf &>/dev/null; then
            dnf -q -y install expect
        elif command -v yum &>/dev/null; then
            yum -q -y install expect
        else
            msg_war "Не удалось установить expect (неизвестный пакетный менеджер). Продолжаем без expect."
        fi
    fi

    # Основные пакеты
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        PACKAGES="wget curl sqlite3 apache2-utils jq openssl uuid-runtime"
        [[ "$ENABLE_NGINX" == "true" ]] && PACKAGES="$PACKAGES nginx nginx-full"
        [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]] && PACKAGES="$PACKAGES certbot python3-certbot-nginx"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PACKAGES
    elif command -v dnf &>/dev/null; then
        PACKAGES="wget curl sqlite httpd-tools jq openssl util-linux"
        [[ "$ENABLE_NGINX" == "true" ]] && PACKAGES="$PACKAGES nginx"
        [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]] && PACKAGES="$PACKAGES certbot python3-certbot-nginx"
        dnf -q -y install $PACKAGES
    elif command -v yum &>/dev/null; then
        PACKAGES="wget curl sqlite httpd-tools jq openssl util-linux"
        [[ "$ENABLE_NGINX" == "true" ]] && PACKAGES="$PACKAGES nginx"
        [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]] && PACKAGES="$PACKAGES certbot python3-certbot-nginx"
        yum -q -y install $PACKAGES
    else
        error_exit "Не удалось найти подходящий пакетный менеджер (apt, yum, dnf)."
    fi
    msg_ok "Зависимости установлены."
}

# ────────── Настройка SSL сертификата ──────────
setup_ssl() {
    [[ "$ENABLE_SSL" != "true" || -z "$DOMAIN" ]] && return 0

    msg_inf "Настройка SSL для домена $DOMAIN..."
    if systemctl is-active --quiet nginx; then systemctl stop nginx; fi
    fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null || true
    sleep 2

    # Запрос SSL-сертификата
    if ! certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email --cert-name "$DOMAIN" -d "$DOMAIN"; then
        msg_war "Не удалось получить SSL сертификат для $DOMAIN. Отключаем SSL."
        ENABLE_SSL="false"
        return 1
    fi
    msg_ok "SSL сертификат получен. Путь: /etc/letsencrypt/live/$DOMAIN/"
}

# ────────── Настройка Nginx ──────────
setup_nginx() {
    [[ "$ENABLE_NGINX" != "true" ]] && return 0

    msg_inf "Настройка Nginx..."
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /var/www/html
    rm -rf /etc/nginx/default.d 2>/dev/null || true

    # Проверяем, какой пользователь Nginx используется по умолчанию
    nginxusr="www-data"
    id -u "$nginxusr" &>/dev/null || nginxusr="nginx"

    # Создаём базовый nginx.conf
    cat > "/etc/nginx/nginx.conf" <<EOF
user $nginxusr;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 65535;
    use epoll;
    multi_accept on;
}

http {
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    gzip on;
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 4096;
    default_type application/octet-stream;

    include /etc/nginx/mime.types;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Создаём конфиги для домена (если SSL и домен указан) или для IP
    if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
        setup_nginx_domain_config
    else
        setup_nginx_ip_config
    fi

    create_web_pages

    # Удаляем дефолтные конфиги
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true
    systemctl enable nginx >/dev/null 2>&1
    msg_ok "Nginx настроен."
}

setup_nginx_domain_config() {
    msg_inf "Создаём конфиг Nginx для домена $DOMAIN (SSL)"
    cat > "/etc/nginx/sites-available/$DOMAIN" <<EOF
server {
    server_tokens off;
    server_name $DOMAIN;
    listen 80;
    listen [::]:80;
    return 301 https://\$server_name\$request_uri;
}

server {
    server_tokens off;
    server_name $DOMAIN;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    root /var/www/html;
    index index.html;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    # Внимание! При необходимости добавьте ваши ssl_ciphers
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Блок подписок
    location $SUB_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$SUB_PORT$SUB_PATH;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Блок панели (Web UI)
    location $WEB_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$WEB_PORT$WEB_PATH;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Trojan WS
    location /trojan-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$TROJAN_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    error_page 404 /404.html;
    location = /404.html { internal; }
}
EOF

    ln -sf "/etc/nginx/sites-available/$DOMAIN" "/etc/nginx/sites-enabled/$DOMAIN"
}

setup_nginx_ip_config() {
    msg_inf "Создаём конфиг Nginx (без SSL, IP/домен не указан)"
    local server_name_line="server_name _;"
    if [[ -n "$DOMAIN" ]]; then
        server_name_line="server_name $DOMAIN;"
    fi

    cat > "/etc/nginx/sites-available/default_http" <<EOF
server {
    server_tokens off;
    $server_name_line
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html;

    # Подписки
    location $SUB_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$SUB_PORT$SUB_PATH;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Панель
    location $WEB_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$WEB_PORT$WEB_PATH;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Trojan WS
    location /trojan-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$TROJAN_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    error_page 404 /404.html;
    location = /404.html { internal; }
}
EOF

    ln -sf "/etc/nginx/sites-available/default_http" "/etc/nginx/sites-enabled/default_http"
}

create_web_pages() {
    # Главная страница
    mkdir -p /var/www/html
    cat > "/var/www/html/index.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <title>Server Status</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f0f2f5;
      color: #333;
      margin: 40px;
    }
    .container {
      background: #fff;
      padding: 25px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,.1);
      max-width: 600px;
      margin: auto;
    }
    h1 {
      color: #1a73e8;
      display: flex;
      align-items: center;
    }
    h1 svg {
      margin-right: 10px;
      fill: #1a73e8;
    }
    .status {
      color: #34a853;
      font-weight: 700;
    }
    p {
      line-height: 1.6;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" height="24px" viewBox="0 0 24 24" width="24px">
        <path d="M0 0h24v24H0z" fill="none"/>
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 
        10 10 10-4.48 10-10S17.52 2 12 2zm-2 
        15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
      </svg>
      Server Running
    </h1>
    <p class="status">✅ Web server is operational.</p>
    <p>This server is configured for specific proxy services. Public access to this page indicates the web server is working correctly.</p>
    <p><small>Timestamp: <!--#echo var="DATE_LOCAL" --></small></p>
  </div>
</body>
</html>
EOF

    # 404 страница
    cat > "/var/www/html/404.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <title>404 - Not Found</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f0f2f5;
      color: #333;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      text-align: center;
      margin: 0;
    }
    .container {
      background: #fff;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,.1);
    }
    h1 {
      color: #ea4335;
      font-size: 80px;
      margin: 0 0 10px;
      font-weight: 600;
    }
    h2 {
      color: #3c4043;
      font-size: 24px;
      margin: 0 0 20px;
      font-weight: 500;
    }
    p {
      line-height: 1.6;
      font-size: 16px;
    }
    a {
      color: #1a73e8;
      text-decoration: none;
      font-weight: 500;
    }
    a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>404</h1>
    <h2>Page Not Found</h2>
    <p>The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.</p>
    <p><a href="/">Return to homepage</a></p>
  </div>
</body>
</html>
EOF

    # Вставляем реальную дату в index.html (хотя в 404 тоже можно, но не критично)
    sed -i "s|<!--#echo var=\"DATE_LOCAL\" -->|$(date)|g" /var/www/html/index.html
}

# ────────── Настройка cron задач ──────────
setup_cron_jobs() {
    msg_inf "Настройка cron-задач для перезапусков и обновления сертификатов..."
    local current_crontab; current_crontab=$(crontab -l 2>/dev/null || true)

    # Автоперезапуск x-ui в 2 часа ночи
    local cron_cmd="0 2 * * * systemctl restart x-ui > /dev/null 2>&1"
    if ! echo "$current_crontab" | grep -Fq "$cron_cmd"; then
        (echo "$current_crontab"; echo "$cron_cmd") | crontab -
    fi

    # Если Nginx включён, проверяем его конфиг и перезапускаем в 3 часа
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        cron_cmd="0 3 * * * nginx -t && systemctl reload nginx || { pkill nginx; nginx -c /etc/nginx/nginx.conf; } > /dev/null 2>&1"
        if ! echo "$current_crontab" | grep -Fq "$cron_cmd"; then
            (echo "$current_crontab"; echo "$cron_cmd") | crontab -
        fi
    fi

    # Если SSL включён и есть DOMAIN — certbot renew (каждые 60 дней)
    if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
        cron_cmd="0 1 */60 * * certbot renew --nginx --non-interactive --quiet --post-hook \"systemctl reload nginx\" > /dev/null 2>&1"
        if ! echo "$current_crontab" | grep -Fq "$cron_cmd"; then
            (echo "$current_crontab"; echo "$cron_cmd") | crontab -
        fi
    fi

    msg_ok "Cron-задачи настроены."
}

# ────────── Остановка и очистка старых версий x-ui ──────────
cleanup_old_installation() {
    msg_inf "Остановка старых процессов x-ui..."
    systemctl stop x-ui 2>/dev/null || true
    pkill -9 -f "x-ui" 2>/dev/null || true
    sleep 2

    msg_inf "Удаление старых файлов x-ui..."
    rm -rf /etc/x-ui/* 2>/dev/null || true
    if [[ -d /usr/local/x-ui ]]; then
        rm -rf /usr/local/x-ui/*
    fi
    rm -f /usr/local/bin/x-ui 2>/dev/null || true
    msg_ok "Старая установка x-ui (если была) успешно очищена."
}

# ────────── Генерация ключей для Reality ──────────
generate_reality_keys() {
    msg_inf "Генерация Reality ключей..."
    REALITY_PRIVATE_KEY=""
    REALITY_PUBLIC_KEY=""

    local xray_path=""
    if command -v xray &>/dev/null; then
        xray_path="xray"
    elif [[ -f "/usr/local/x-ui/bin/xray-linux-amd64" ]]; then
        xray_path="/usr/local/x-ui/bin/xray-linux-amd64"
    elif [[ -f "/usr/local/bin/xray" ]]; then
        xray_path="/usr/local/bin/xray"
    fi

    if [[ -n "$xray_path" ]]; then
        msg_inf "Используем '$xray_path x25519' для генерации..."
        local key_pair; key_pair=$("$xray_path" x25519 2>/dev/null || echo "")
        if [[ $? -eq 0 && -n "$key_pair" ]]; then
            REALITY_PRIVATE_KEY=$(echo "$key_pair" | awk '/Private key:/{print $3}')
            REALITY_PUBLIC_KEY=$(echo "$key_pair"  | awk '/Public key:/{print $3}')
        fi
    fi

    # fallback, если не удалось сгенерировать через xray
    if [[ -z "$REALITY_PRIVATE_KEY" || -z "$REALITY_PUBLIC_KEY" ]]; then
        msg_war "Не удалось сгенерировать ключи через xray, используем случайные base64."
        REALITY_PRIVATE_KEY=$(openssl rand -base64 32 | tr -d '\n' | tr '/+' '_-' | sed 's/=//g')
        REALITY_PUBLIC_KEY=$(openssl rand -base64 32 | tr -d '\n' | tr '/+' '_-' | sed 's/=//g')
    fi

    msg_ok "Reality Private Key: $REALITY_PRIVATE_KEY"
    msg_ok "Reality Public Key: $REALITY_PUBLIC_KEY"
}

# ────────── Создание inbound'ов VLESS/SS/Trojan в базе x-ui ──────────

create_vless_reality_inbound() {
    msg_inf "Создаём inbound VLESS Reality..."
    VLESS_UUID=$(uuidgen | tr -d '\n')
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    local other_short_id=$(openssl rand -hex 8)

    generate_reality_keys

    local vless_remark="$COUNTRY-vless-reality"

    # json для поля settings
    local vless_settings_json
    vless_settings_json=$(jq -cn --arg uuid "$VLESS_UUID" --arg email "$vless_remark" \
        '{clients: [{id: $uuid, email: $email, flow: "xtls-rprx-vision"}], decryption: "none", fallbacks: []}')

    # json для поля stream_settings
    local reality_json
    reality_json=$(jq -cn \
        --arg sni "$REALITY_SNI" \
        --arg private_key "$REALITY_PRIVATE_KEY" \
        --arg short_id1 "$REALITY_SHORT_ID" \
        --arg short_id2 "$other_short_id" \
        '{show:false, dest: ($sni+":443"), xver:0, serverNames: [$sni,("www." + $sni)], privateKey:$private_key, minClientVer:"", maxClientVer:"", maxTimeDiff:60000, shortIds:[$short_id1, $short_id2]}')

    local vless_stream_settings_json
    vless_stream_settings_json=$(jq -cn --argjson realityCfg "$reality_json" \
        '{network:"tcp", security:"reality", realitySettings:$realityCfg, tcpSettings:{acceptProxyProtocol:false, header:{type:"none"}}}')

    # json для поля sniffing
    local vless_sniffing_json='{"enabled": true, "destOverride": ["http","tls"], "routeOnly": false}'

    sqlite3 "/etc/x-ui/x-ui.db" <<SQL
INSERT INTO inbounds (user_id, port, protocol, settings, stream_settings, tag, remark, sniffing, enable, expiry_time, up, down, total)
VALUES (
    1,
    $VLESS_REALITY_PORT,
    'vless',
    '$(escape_sqlite_string "$vless_settings_json")',
    '$(escape_sqlite_string "$vless_stream_settings_json")',
    '$(escape_sqlite_string "$vless_remark")',
    '$(escape_sqlite_string "$vless_remark")',
    '$(escape_sqlite_string "$vless_sniffing_json")',
    1,
    0,
    0,
    0,
    0
);
SQL

    msg_ok "VLESS Reality inbound создан (порт $VLESS_REALITY_PORT)."
    msg_inf "UUID: $VLESS_UUID"
    msg_inf "SNI: $REALITY_SNI"
    msg_inf "Public Key: $REALITY_PUBLIC_KEY"
    msg_inf "Short ID: $REALITY_SHORT_ID"
}

create_shadowsocks_inbound() {
    msg_inf "Создаём inbound Shadowsocks..."
    SS_PASSWORD=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16)
    local ss_remark="$COUNTRY-shadowsocks"

    # settings
    local ss_settings_json
    ss_settings_json=$(jq -cn --arg pass "$SS_PASSWORD" \
        '{method:"chacha20-ietf-poly1305", password:$pass, network:"tcp,udp"}')

    # stream_settings
    local ss_stream_settings_json='{"network":"tcp","security":"none","tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}'

    # sniffing
    local ss_sniffing_json='{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}'

    sqlite3 "/etc/x-ui/x-ui.db" <<SQL
INSERT INTO inbounds (user_id, port, protocol, settings, stream_settings, tag, remark, sniffing, enable, expiry_time, up, down, total)
VALUES (
    1,
    $SHADOWSOCKS_PORT,
    'shadowsocks',
    '$(escape_sqlite_string "$ss_settings_json")',
    '$(escape_sqlite_string "$ss_stream_settings_json")',
    '$(escape_sqlite_string "$ss_remark")',
    '$(escape_sqlite_string "$ss_remark")',
    '$(escape_sqlite_string "$ss_sniffing_json")',
    1,
    0,
    0,
    0,
    0
);
SQL

    msg_ok "Shadowsocks inbound создан (порт $SHADOWSOCKS_PORT)."
    msg_inf "Пароль: $SS_PASSWORD"
    msg_inf "Метод: chacha20-ietf-poly1305"
}

create_trojan_ws_inbound() {
    msg_inf "Создаём inbound Trojan (WS)..."
    TROJAN_PASSWORD=$(openssl rand -hex 16)
    local trojan_remark="$COUNTRY-trojan-ws"
    local trojan_host="${DOMAIN:-$IP4}"

    # settings
    local trojan_settings_json
    trojan_settings_json=$(jq -cn --arg pass "$TROJAN_PASSWORD" --arg email "$trojan_remark" \
        '{clients:[{password:$pass,email:$email}],fallbacks:[]}')

    # stream_settings
    local trojan_stream_settings_json
    trojan_stream_settings_json=$(jq -cn --arg host "$trojan_host" \
        '{network:"ws","security":"none","wsSettings":{"path":"/trojan-ws","headers":{"Host":$host}}}')

    # sniffing
    local trojan_sniffing_json='{"enabled":true,"destOverride":["http","tls"],"routeOnly":false}'

    sqlite3 "/etc/x-ui/x-ui.db" <<SQL
INSERT INTO inbounds (user_id, port, protocol, settings, stream_settings, tag, remark, sniffing, enable, expiry_time, up, down, total)
VALUES (
    1,
    $TROJAN_WS_PORT,
    'trojan',
    '$(escape_sqlite_string "$trojan_settings_json")',
    '$(escape_sqlite_string "$trojan_stream_settings_json")',
    '$(escape_sqlite_string "$trojan_remark")',
    '$(escape_sqlite_string "$trojan_remark")',
    '$(escape_sqlite_string "$trojan_sniffing_json")',
    1,
    0,
    0,
    0,
    0
);
SQL

    msg_ok "Trojan WS inbound создан (порт $TROJAN_WS_PORT)."
    msg_inf "Пароль: $TROJAN_PASSWORD"
    msg_inf "Путь (WS): /trojan-ws"
    msg_inf "Host (SNI): $trojan_host"
}

create_inbounds() {
    msg_inf "Очищаем все inbound'ы из базы (если были)..."
    sqlite3 "/etc/x-ui/x-ui.db" "DELETE FROM inbounds;" || true

    # Создаём заново 3 inbound'а
    create_vless_reality_inbound
    create_shadowsocks_inbound
    create_trojan_ws_inbound

    local cnt; cnt=$(sqlite3 "/etc/x-ui/x-ui.db" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null || echo 0)
    if [[ "$cnt" -ge 3 ]]; then
        msg_ok "Успешно создано $cnt inbound'ов."
    else
        msg_war "Создано только $cnt inbound'ов. Проверяйте логи!"
    fi
}

# ────────── Первичная настройка (пользователи, настройки панели) ──────────
setup_database() {
    msg_inf "Остановка x-ui для настройки базы..."
    systemctl stop x-ui 2>/dev/null || true
    sleep 2

    local DB_PATH="/etc/x-ui/x-ui.db"
    mkdir -p /etc/x-ui

    # Если база есть — делаем бэкап
    if [[ -f "$DB_PATH" ]]; then
        local backup_ts; backup_ts=$(date +%Y%m%d_%H%M%S)
        msg_inf "Найдена существующая база x-ui. Бэкап: $DB_PATH.backup.$backup_ts"
        cp "$DB_PATH" "$DB_PATH.backup.$backup_ts"
    fi

    rm -f "${DB_PATH}-wal" "${DB_PATH}-shm" 2>/dev/null || true

    # Создаём bcrypt для пароля
    local BCRYPT_RAW; BCRYPT_RAW=$(htpasswd -bnBC 10 "" "$PASSWORD" | tr -d ':\n' | sed "s/\\\$2y\\\$/\\\$2b\\\$/")
    local LOGIN_SECRET; LOGIN_SECRET=$(openssl rand -hex 16)
    local USERNAME_SQL; USERNAME_SQL=$(escape_sqlite_string "$USERNAME")
    local BCRYPT_SQL; BCRYPT_SQL=$(escape_sqlite_string "$BCRYPT_RAW")
    local LOGIN_SECRET_SQL; LOGIN_SECRET_SQL=$(escape_sqlite_string "$LOGIN_SECRET")
    local WEB_PORT_SQL; WEB_PORT_SQL=$(escape_sqlite_string "$WEB_PORT")
    local WEB_BASE_PATH_SQL; WEB_BASE_PATH_SQL=$(escape_sqlite_string "${WEB_PATH#/}") # убираем ведущий слеш
    WEB_BASE_PATH_SQL="${WEB_BASE_PATH_SQL%/}" # убираем конечный слеш
    local SUB_PORT_SQL; SUB_PORT_SQL=$(escape_sqlite_string "$SUB_PORT")
    local SUB_PATH_SQL; SUB_PATH_SQL=$(escape_sqlite_string "$SUB_PATH")

    # Создаём/пересоздаём таблицы и вставляем настройки
    sqlite3 "$DB_PATH" <<EOF
PRAGMA journal_mode = DELETE;

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS inbounds;
DROP TABLE IF EXISTS client_traffics;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  login_secret TEXT NOT NULL DEFAULT '',
  permission TEXT DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL DEFAULT 1,
  up BIGINT NOT NULL DEFAULT 0,
  down BIGINT NOT NULL DEFAULT 0,
  total BIGINT NOT NULL DEFAULT 0,
  remark TEXT NOT NULL DEFAULT '',
  enable INTEGER NOT NULL DEFAULT 1,
  expiry_time BIGINT NOT NULL DEFAULT 0,
  listen TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL UNIQUE,
  protocol TEXT NOT NULL DEFAULT '',
  settings TEXT NOT NULL DEFAULT '{}',
  stream_settings TEXT NOT NULL DEFAULT '{}',
  tag TEXT NOT NULL UNIQUE,
  sniffing TEXT NOT NULL DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  client_stats TEXT
);

DELETE FROM users;
DELETE FROM settings;

INSERT INTO users (id, username, password, login_secret)
VALUES (1, '$USERNAME_SQL', '$BCRYPT_SQL', '$LOGIN_SECRET_SQL');

INSERT INTO settings (key, value) VALUES
('webPort', '$WEB_PORT_SQL'),
('webBasePath', '$WEB_BASE_PATH_SQL'),
('webCertFile', ''),
('webKeyFile', ''),
('webListen', ''),
('tgBotEnable', '0'),
('tgBotToken', ''),
('tgBotChatId', ''),
('tgRunTime', '00:01'),
('tgExpirationDiff', '3'),
('tgTrafficDiff', '10'),
('tgCpu', '80'),
('tgInterval', '10'),
('secretEnable', '0'),
('subEnable', 'true'),
('subPort', '$SUB_PORT_SQL'),
('subPath', '$SUB_PATH_SQL'),
('subListen', ''),
('subUpdates', '24'),
('subDomain', ''),
('xrayTemplateConfig', ''),
('sessionMaxAge', '0'),
('timeLocation', 'Asia/Shanghai'),
('cpuAlert', '0'),
('certMode', 'none'),
('defaultCertPath', ''),
('defaultKeyPath', ''),
('hasDefaultCredential', 'false');

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA integrity_check;
EOF

    if [[ $? -eq 0 ]]; then
        msg_ok "База данных и настройки инициализированы."
    else
        error_exit "Ошибка инициализации базы данных $DB_PATH"
    fi

    chown -R root:root /etc/x-ui/ 2>/dev/null || true
    chmod 700 /etc/x-ui/ 2>/dev/null || true
    chmod 600 "${DB_PATH}"* 2>/dev/null || true
}

# ────────── Установка 3x-ui ──────────
install_3x_ui() {
    msg_inf "Скачиваем скрипт установки 3x-ui..."
    if ! curl -fsSL "$INSTALL_URL" -o /tmp/xui_install.sh; then
        error_exit "Не удалось скачать скрипт 3x-ui по URL: $INSTALL_URL"
    fi
    chmod +x /tmp/xui_install.sh

    # Подготовка expect-файла для автоматизации
    cat > /tmp/xui_expect.exp << 'EEXP'
#!/usr/bin/expect -f
set timeout 300
log_user 0
spawn /tmp/xui_install.sh
expect {
  -nocase -glob "*install/update 3x-ui?*(y/n)*" { send "y\r"; exp_continue }
  -nocase -glob "*modify the listening port*?*(y/n)*" { send "n\r"; exp_continue }
  -nocase -glob "*modify the panel url path*?*(y/n)*" { send "n\r"; exp_continue }
  -nocase -glob "*modify panel username*?*(y/n)*" { send "n\r"; exp_continue }
  -nocase -glob "*modify panel password*?*(y/n)*" { send "n\r"; exp_continue }
  -nocase -glob "*continue?*(y/n)*" { send "y\r"; exp_continue }
  -nocase -glob "*[y/n]*" { send "y\r"; exp_continue }
  -nocase -glob "*press any key*" { send "\r"; exp_continue }
  eof {
    catch wait result
    set ex_st [lindex $result 3]
    if {$ex_st != 0} {
      puts stderr "Установка 3x-ui завершилась с ошибкой: $ex_st"
    }
    exit $ex_st
  }
  timeout {
    puts stderr "Expect таймаут при установке 3x-ui."
    exit 1
  }
}
EEXP

    chmod +x /tmp/xui_expect.exp

    if command -v expect &>/dev/null; then
        msg_inf "Установка 3x-ui через expect..."
        if ! /tmp/xui_expect.exp; then
            msg_war "Скрипт expect завершился с ошибкой."
            error_exit "Ошибка установки 3x-ui с expect."
        fi
    else
        msg_war "expect не найден. Попытка неинтерактивной установки..."
        # Подаём последовательность ответов: (y, n, n, n, n, y, y...)
        if ! (echo -e "y\nn\nn\nn\nn\ny\ny\n" | timeout 300 /tmp/xui_install.sh); then
            error_exit "Ошибка установки 3x-ui (fallback, без expect)."
        fi
    fi

    if systemctl list-unit-files | grep -q "x-ui.service"; then
        msg_ok "3x-ui успешно установлен (служба x-ui обнаружена)."
    else
        msg_war "Служба x-ui.service не найдена. Проверяйте вручную."
    fi
}

# ────────── Настройка Firewall ──────────
setup_firewall() {
    msg_inf "Настройка Firewall..."

    # Список TCP портов
    local -a PORTS_TCP=("22" "80" "$WEB_PORT" "$SUB_PORT" "$VLESS_REALITY_PORT" "$SHADOWSOCKS_PORT" "$TROJAN_WS_PORT")
    # Для SSL-домена ещё 443
    if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
        PORTS_TCP+=("443")
    fi
    # Shadowsocks часто нужен и по UDP
    local -a PORTS_UDP=("$SHADOWSOCKS_PORT")

    # UFW
    if command -v ufw &>/dev/null; then
        msg_inf "Конфигурируем UFW..."
        ufw --force reset >/dev/null 2>&1 || true
        ufw default deny incoming >/dev/null 2>&1
        ufw default allow outgoing >/dev/null 2>&1

        for p in "${PORTS_TCP[@]}"; do
            ufw allow "$p/tcp" >/dev/null 2>&1 || true
        done
        for p in "${PORTS_UDP[@]}"; do
            ufw allow "$p/udp" >/dev/null 2>&1 || true
        done

        ufw --force enable >/dev/null 2>&1
        msg_ok "UFW настроен."
        return 0
    fi

    # Firewalld
    if command -v firewall-cmd &>/dev/null; then
        msg_inf "Конфигурируем firewalld..."
        if ! systemctl is-active --quiet firewalld; then
            systemctl enable firewalld --now >/dev/null 2>&1 || true
        fi
        for p in "${PORTS_TCP[@]}"; do
            firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1 || true
        done
        for p in "${PORTS_UDP[@]}"; do
            firewall-cmd --permanent --add-port="$p/udp" >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
        msg_ok "firewalld настроен."
        return 0
    fi

    # Если ни ufw, ни firewalld нет — минимальные настройки iptables
    msg_inf "Настройка iptables (базово)..."
    iptables -P INPUT ACCEPT
    iptables -F
    iptables -X
    iptables -Z
    # Разрешаем нужные порты (примитивно)
    for p in "${PORTS_TCP[@]}"; do
        iptables -A INPUT -p tcp --dport "$p" -j ACCEPT
    done
    for p in "${PORTS_UDP[@]}"; do
        iptables -A INPUT -p udp --dport "$p" -j ACCEPT
    done
    # Разрешаем localhost и Established
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    # Остальное - drop
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    msg_ok "iptables настроен (базовые правила)."
}

# ────────── Проверка сервисов ──────────
check_services() {
    msg_inf "Проверка статуса X-UI..."

    local service_failed=false

    # Проверяем X-UI (3 попытки)
    for attempt in {1..3}; do
        if systemctl is-active --quiet x-ui; then
            msg_ok "X-UI запущен (попытка $attempt)."
            break
        else
            msg_war "X-UI не запущен, перезапуск ($attempt/3)..."
            systemctl restart x-ui
            sleep 5
            if [[ $attempt -eq 3 ]] && ! systemctl is-active --quiet x-ui; then
                msg_war "Не удалось запустить X-UI."
                journalctl -u x-ui -n 20 --no-pager || true
                service_failed=true
            fi
        fi
    done

    # Проверяем Nginx
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        msg_inf "Проверка Nginx..."
        if nginx -t &>/dev/null; then
            msg_ok "Конфигурация Nginx OK"
            if systemctl is-active --quiet nginx; then
                msg_ok "Nginx запущен."
            else
                msg_war "Nginx не запущен, пытаемся запустить..."
                systemctl restart nginx
                sleep 3
                if systemctl is-active --quiet nginx; then
                    msg_ok "Nginx успешно запущен."
                else
                    msg_war "Не удалось запустить Nginx."
                    journalctl -u nginx -n 10 --no-pager || true
                    service_failed=true
                fi
            fi
        else
            msg_war "Ошибка в конфигурации Nginx."
            nginx -t || true
            service_failed=true
        fi
    fi

    if [[ "$service_failed" == "true" ]]; then
        msg_war "Некоторые сервисы не запущены корректно. Проверьте логи."
    else
        msg_ok "Все основные сервисы (X-UI, Nginx) работают."
    fi
}

# ────────── Генерация ссылок и итоговой информации ──────────
generate_connection_links() {
    msg_inf "Формируем ссылки для подключения..."

    # Чтобы сохранить всё в /root/connection_info.txt
    local INFO_FILE="/root/connection_info.txt"
    rm -f "$INFO_FILE" 2>/dev/null || true

    local srv_addr="${DOMAIN:-$IP4}"

    # Определяем URL панели
    local panel_proto="http://"
    local panel_port_suffix=":$WEB_PORT"
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        # если Nginx включён
        if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
            panel_proto="https://"
            panel_port_suffix=""
        else
            panel_proto="http://"
            panel_port_suffix=""
        fi
    fi
    local panel_url="${panel_proto}${srv_addr}${panel_port_suffix}${WEB_PATH}"

    # URL подписки
    local sub_proto="http://"
    local sub_port_suffix=":$SUB_PORT"
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        sub_proto="http://"
        sub_port_suffix=""
        if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
            sub_proto="https://"
        fi
    fi
    local sub_url="${sub_proto}${srv_addr}${sub_port_suffix}${SUB_PATH}"

    cat > "$INFO_FILE" <<EOF
═══════════════════════════════════════════════════════════════
🔗 ИНФОРМАЦИЯ О ПОДКЛЮЧЕНИИ ($(date '+%Y-%m-%d %H:%M:%S'))
═══════════════════════════════════════════════════════════════
1) Панель управления 3x-ui:
   - URL: $panel_url
   - Логин: $USERNAME
   - Пароль: $PASSWORD

2) Ссылка на подписки (All-in-One):
   $sub_url

3) Сервер: $srv_addr
   Страна (для remark): $COUNTRY
   SSL (через Nginx): $([ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ] && echo "ВКЛ ($DOMAIN)" || echo "ВЫКЛ/по IP")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VLESS Reality:
 - Порт: $VLESS_REALITY_PORT
 - UUID: ${VLESS_UUID:-N/A}
 - SNI: $REALITY_SNI
 - Public Key: ${REALITY_PUBLIC_KEY:-N/A}
 - Short ID: ${REALITY_SHORT_ID:-N/A}
 - Flow: xtls-rprx-vision

Shadowsocks:
 - Порт: $SHADOWSOCKS_PORT
 - Пароль: ${SS_PASSWORD:-N/A}
 - Метод: chacha20-ietf-poly1305

Trojan (WS):
 - Порт: $TROJAN_WS_PORT
 - Пароль: ${TROJAN_PASSWORD:-N/A}
 - Путь (WS): /trojan-ws
 - Host (SNI): $srv_addr

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Управление сервисами:
 - systemctl {start|stop|restart|status} x-ui
 - При включённом Nginx: systemctl {start|stop|restart|status|reload} nginx
 - Файл с информацией: $INFO_FILE

EOF
    msg_ok "Информация о подключении сохранена в $INFO_FILE"
}

# ────────── Оптимизация sysctl и ulimit ──────────
optimize_system() {
    msg_inf "Применяем сетевые оптимизации sysctl..."

    cat > /etc/sysctl.d/99-network-optimization.conf <<EOF
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 10000
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
fs.file-max = 1000000
fs.nr_open = 2000000
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
EOF

    if sysctl --system >/dev/null 2>&1; then
        msg_ok "sysctl применён."
    else
        msg_war "Не удалось автоматически загрузить sysctl --system. Попробуйте вручную."
    fi

    # Настройка лимитов
    msg_inf "Настройка ulimit..."
    cat > /etc/security/limits.d/99-vpn-limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 65535
* hard nproc 65535
root soft nofile 1000000
root hard nofile 1000000
root soft nproc 65535
root hard nproc 65535
EOF
    msg_ok "Лимиты ресурсов настроены (может потребоваться перезагрузка)."
}

# ────────── Утилитный скрипт xui-manager ──────────
create_management_script() {
    msg_inf "Создаём скрипт 'xui-manager' для управления..."

    cat > "/usr/local/bin/xui-manager" <<'XEOF'
#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/root/connection_info.txt"

check_root(){
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Нужны права root.${NC}"
        exit 1
    fi
}

show_status(){
    echo -e "${YELLOW}== СТАТУС СЕРВИСОВ ==${NC}"
    if systemctl is-active --quiet x-ui; then
        echo -e "${GREEN}✅ X-UI: Запущен${NC}"
    else
        echo -e "${RED}❌ X-UI: Остановлен${NC}"
    fi

    if systemctl list-unit-files 2>/dev/null | grep -q "nginx.service"; then
        if systemctl is-active --quiet nginx; then
            echo -e "${GREEN}✅ Nginx: Запущен${NC}"
        else
            echo -e "${RED}❌ Nginx: Остановлен${NC}"
        fi
    fi
}

show_info(){
    if [[ -f "$LOG_FILE" ]]; then
        cat "$LOG_FILE"
    else
        echo -e "${RED}Файл ${LOG_FILE} не найден.${NC}"
    fi
}

restart_services(){
    check_root
    echo -e "${YELLOW}Перезапуск сервисов...${NC}"

    systemctl restart x-ui
    if systemctl list-unit-files 2>/dev/null | grep -q "nginx.service"; then
        if nginx -t &>/dev/null; then
            systemctl restart nginx
        else
            echo -e "${RED}Ошибка в конфиге Nginx.${NC}"
            nginx -t || true
        fi
    fi
    echo -e "${GREEN}Выполнено.${NC}"
}

show_logs(){
    local srv="x-ui"
    local lines="50"

    if [[ "$2" == "nginx" ]]; then
        srv="nginx"
    elif [[ "$2" =~ ^[0-9]+$ ]]; then
        lines="$2"
    fi

    if [[ "$3" =~ ^[0-9]+$ ]]; then
        lines="$3"
    fi

    echo -e "${YELLOW}ЛОГИ $srv (последние $lines строк):${NC}"
    journalctl -u "$srv" -n "$lines" --no-pager --output cat
}

update_ssl_certs(){
    check_root
    if [[ ! -d "/etc/letsencrypt/live" || -z "$(command -v certbot)" ]]; then
        echo -e "${RED}Certbot/SSL не установлены или каталог не найден.${NC}"
        return 1
    fi
    echo -e "${YELLOW}Обновляем SSL...${NC}"
    certbot renew --nginx --non-interactive --quiet --post-hook "systemctl reload nginx"
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}SSL обновлены (если срок подходил).${NC}"
    else
        echo -e "${RED}Ошибка обновления SSL.${NC}"
    fi
}

show_help(){
    echo "Использование: xui-manager [команда]"
    echo "Команды:"
    echo "  status               - Показать статус сервисов"
    echo "  info                 - Показать информацию из $LOG_FILE"
    echo "  restart              - Перезапустить x-ui (и Nginx, если есть)"
    echo "  logs [x-ui|nginx N]  - Показать логи (по умолчанию x-ui, 50 строк)"
    echo "  ssl-renew            - Обновить/проверить SSL-сертификаты (certbot renew)"
    echo "  help                 - Показать справку"
}

case "$1" in
  status|st)
    show_status
    ;;
  info|i)
    show_info
    ;;
  restart|r)
    restart_services
    ;;
  logs|l)
    show_logs "$@"
    ;;
  ssl-renew|ssl)
    update_ssl_certs
    ;;
  help|h|--help|-h|"")
    show_help
    ;;
  *)
    echo -e "${RED}Неизвестная команда: $1${NC}"
    show_help
    exit 1
    ;;
esac
XEOF

    chmod +x "/usr/local/bin/xui-manager"
    msg_ok "Скрипт xui-manager создан (использование: xui-manager help)."
}

# ────────── Итоговый отчёт ──────────
final_report() {
    echo ""
    msg_ok "УСТАНОВКА 3x-ui ЗАВЕРШЕНА!"
    msg_inf "Для просмотра сведений:   cat /root/connection_info.txt"
    msg_inf "Для управления:           xui-manager help"
    echo ""
}

# ────────── Основная функция ──────────
main() {
    clear
    msg_inf "🚀 Запуск автоматической настройки 3x-ui..."

    get_server_ips
    msg_inf "IPv4: ${IP4:-N/A} | IPv6: ${IP6:-N/A} | Домен: ${DOMAIN:-нет}"
    echo ""

    install_dependencies

    # SSL
    if [[ "$ENABLE_SSL" == "true" && -n "$DOMAIN" ]]; then
        setup_ssl
    elif [[ "$ENABLE_SSL" == "true" && -z "$DOMAIN" ]]; then
        msg_war "SSL включён, но домен не указан — отключаем SSL."
        ENABLE_SSL="false"
    fi

    # Nginx
    if [[ "$ENABLE_NGINX" == "true" ]]; then
        setup_nginx
        # Попытка запустить Nginx
        if ! systemctl restart nginx; then
            msg_war "Не удалось запустить Nginx. Смотрите логи."
            journalctl -u nginx -n 20 --no-pager || true
        else
            msg_ok "Nginx запущен."
        fi
    fi

    cleanup_old_installation
    install_3x_ui
    setup_database
    create_inbounds

    msg_inf "Включаем автозагрузку и перезапускаем X-UI..."
    systemctl enable x-ui >/dev/null 2>&1
    if ! systemctl restart x-ui; then
        msg_war "Не удалось запустить X-UI. Смотрите логи."
        journalctl -u x-ui -n 20 --no-pager || true
        error_exit "X-UI не стартовал после конфигурации!"
    fi

    setup_cron_jobs
    setup_firewall
    optimize_system
    create_management_script
    check_services
    generate_connection_links

    final_report
    log "Скрипт завершён."
}

main "$@"
