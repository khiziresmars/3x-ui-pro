#!/bin/bash
#################### x-ui-pro v11.8.4 @ github.com/GFW4Fun ##############################################
[[ $EUID -ne 0 ]] && { echo "not root!"; exec sudo "$0" "$@"; }

######################################## Цветные сообщения ##############################################
msg()     { echo -e "\e[1;37;40m $1 \e[0m"; }
msg_ok()  { echo -e "\e[1;32;40m $1 \e[0m"; }
msg_err() { echo -e "\e[1;31;40m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;36;40m $1 \e[0m"; }
msg_war() { echo -e "\e[1;33;40m $1 \e[0m"; }
hrline()  { printf '\033[1;35;40m%s\033[0m\n' "$(printf '%*s' "${COLUMNS:-$(tput cols)}" '' | tr ' ' "${1:--}")"; }

######################################## Шапка ##########################################################
echo
msg_inf ' _     _ _     _ _____      _____   ______   _____ '
msg_inf '  \___/  |     |   |   ___ |_____] |_____/  |     |'
msg_inf ' _/   \_ |_____| __|__     |       |     \_ |_____|'
hrline

######################################## Cлучайности / константы #######################################
mkdir -p "${HOME}/.cache"
Pak=$(command -v apt || echo dnf)

# ---- Панель X-UI (Глобальные значения, используемые для обновления БД) ----
FixedPanelPath="/esmars" # Фиксированный путь панели (без слешей, add_slashes добавит)
RNDSTR2=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n1)") #  второй путь (для v2rayA)

# ---- Порт панели (Генерируется случайно, используется для обновления БД) ----
while true; do
  Generated_XUI_PORT=$((RANDOM%30000 + 30000)); nc -z 127.0.0.1 "$Generated_XUI_PORT" &>/dev/null || break
done
Current_XUI_Port=${Generated_XUI_PORT} # Используем это значение для UPDATE_XUIDB

######################################## Переменные скрипта ############################################
XUIDB="/etc/x-ui/x-ui.db"
domain=""
reality_domain="" # Для REALITY домена
UNINSTALL="x"
PNLNUM=1
CFALLOW="off"
NOPATH=""
RNDTMPL="n"
CLIMIT="#"
WarpCfonCountry=""
WarpLicKey=""
CleanKeyCfon=""
TorCountry=""
Secure="no" # По умолчанию 'no', значит SecureNginxAuth будет "#"
ENABLEUFW=""
VERSION="last"
CountryAllow="XX"
Random_country=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)
TorRandomCountry=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)

ActualPanelPort=""
ActualPanelPath=""
PanelUser=""
PanelPass="EsmarsMe13AMS1"
XrayInstallPath="/usr/local/bin/xray" # Стандартный путь после установки Xray

######################################## Аргументы CLI #################################################
while [ "$#" -gt 0 ]; do
  case "$1" in
    -country)             CountryAllow="$2"; shift 2 ;;
    -xuiver)              VERSION="$2"; shift 2 ;;
    -ufw)                 ENABLEUFW="$2"; shift 2 ;;
    -secure)              Secure="$2"; shift 2 ;; # Если 'yes', SecureNginxAuth будет ""
    -TorCountry)          TorCountry="$2"; shift 2 ;;
    -WarpCfonCountry)     WarpCfonCountry="$2"; shift 2 ;;
    -WarpLicKey)          WarpLicKey="$2"; shift 2 ;;
    -CleanKeyCfon)        CleanKeyCfon="$2"; shift 2 ;;
    -RandomTemplate)      RNDTMPL="$2"; shift 2 ;;
    -Uninstall)           UNINSTALL="$2"; shift 2 ;;
    -panel)               PNLNUM="$2"; shift 2 ;;
    -subdomain)           domain="$2"; shift 2 ;;
    -realitydomain)       reality_domain="$2"; shift 2 ;;
    -cdn)                 CFALLOW="$2"; shift 2 ;;
    *)                    shift 1 ;;
  esac
done

#############################################################################################################
service_enable() {
for service_name in "$@"; do
	systemctl is-active --quiet "$service_name" && systemctl stop "$service_name" > /dev/null 2>&1
	systemctl daemon-reload	> /dev/null 2>&1
	systemctl enable "$service_name" > /dev/null 2>&1
	systemctl start "$service_name" > /dev/null 2>&1
done
}
####################################UFW Rules################################################################
if [[ -n "$ENABLEUFW" ]]; then
	sudo $Pak -y install ufw && sudo ufw reset && echo ssh ftp http https mysql 53 2052 2053 2082 2083 2086 2087 2095 2096 3389 5900 8443 8880 | xargs -n 1 sudo ufw allow && sudo ufw --force enable
	msg_inf "UFW settings changed and UFW enabled!"; exit 1
fi
##############################TOR Change Region Country #####################################################
if [[ -n "$TorCountry" ]]; then
	TorCountry=$(echo "$TorCountry" | tr '[:lower:]' '[:upper:]')
	[[ "$TorCountry" == "XX" ]] || [[ ! "$TorCountry" =~ ^[A-Z]{2}$ ]] && TorCountry=$TorRandomCountry
	TorCountry=$(echo "$TorCountry" | tr '[:upper:]' '[:lower:]')
	sudo cp -f /etc/tor/torrc /etc/tor/torrc.bak
	if grep -q "^ExitNodes" /etc/tor/torrc; then
		sudo sed -i "s/^ExitNodes.*/ExitNodes {$TorCountry}/" /etc/tor/torrc
	else
		echo "ExitNodes {$TorCountry}" | sudo tee -a /etc/tor/torrc
	fi
	if grep -q "^StrictNodes" /etc/tor/torrc; then
		sudo sed -i "s/^StrictNodes.*/StrictNodes 1/" /etc/tor/torrc
	else
		echo "StrictNodes 1" | sudo tee -a /etc/tor/torrc
	fi
	systemctl restart tor
	msg "\nEnter after 10 seconds:\ncurl --socks5-hostname 127.0.0.1:9050 https://ipapi.co/json/\n"
	msg_inf "Tor settings changed!"
	exit 1
fi
##############################WARP/Psiphon Change Region Country ############################################
if [[ -n "$WarpCfonCountry" || -n "$WarpLicKey" || -n "$CleanKeyCfon" ]]; then
WarpCfonCountry=$(echo "$WarpCfonCountry" | tr '[:lower:]' '[:upper:]')
cfonval=" --cfon --country $WarpCfonCountry";
[[ "$WarpCfonCountry" == "XX" ]] && cfonval=" --cfon --country ${Random_country}"
[[ "$WarpCfonCountry" =~ ^[A-Z]{2}$ ]] || cfonval="";
wrpky=" --key $WarpLicKey";[[ -n "$WarpLicKey" ]] || wrpky="";
[[ -n "$CleanKeyCfon" ]] && { cfonval=""; wrpky=""; }

cat > /etc/systemd/system/warp-plus.service << EOF
[Unit]
Description=warp-plus service
After=network.target nss-lookup.target

[Service]
WorkingDirectory=/etc/warp-plus/
ExecStart=/etc/warp-plus/warp-plus --scan${cfonval}${wrpky}
ExecStop=/bin/kill -TERM \$MAINPID
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF
rm -rf ~/.cache/warp-plus
service_enable "warp-plus";
msg "\nEnter after 10 seconds:\ncurl --socks5-hostname 127.0.0.1:8086 https://ipapi.co/json/\n"
msg_inf "warp-plus settings changed!"
exit 1
fi
##############################Random Fake Site############################################################
if [[ ${RNDTMPL} == *"y"* ]]; then
cd "$HOME" || exit 1
if [[ ! -d "randomfakehtml-master" ]]; then
    wget https://github.com/GFW4Fun/randomfakehtml/archive/refs/heads/master.zip
    unzip master.zip && rm -f master.zip
fi
cd randomfakehtml-master || exit 1
rm -rf assets ".gitattributes" "README.md" "_config.yml"
RandomHTML=$(for i in *; do echo "$i"; done | shuf -n1 2>&1)
msg_inf "Random template name: ${RandomHTML}"
if [[ -d "${RandomHTML}" && -d "/var/www/html/" ]]; then
	rm -rf /var/www/html/*
	cp -a "${RandomHTML}"/. "/var/www/html/"
	msg_ok "Template extracted successfully!" && exit 1
else
	msg_err "Extraction error!" && exit 1
fi
fi
##############################Uninstall##################################################################
if [[ "${UNINSTALL}" == *"y"* ]]; then
	echo "python3-certbot-nginx nginx nginx-full nginx-core nginx-common nginx-extras tor" | xargs -n 1 $Pak -y remove --purge
	for service in nginx tor x-ui warp-plus v2raya xray; do # Added xray here as it might be standalone
		systemctl stop "$service" > /dev/null 2>&1
		systemctl disable "$service" > /dev/null 2>&1
        rm -f "/etc/systemd/system/${service}.service" # Remove service files
	done
    systemctl daemon-reload
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge > /dev/null 2>&1
 	printf 'n' | bash <(wget -qO- https://github.com/v2rayA/v2rayA-installer/raw/main/uninstaller.sh) > /dev/null 2>&1
 	rm -rf /etc/warp-plus/ /etc/nginx/ /var/www/html/ /usr/local/etc/xray /usr/local/share/xray /var/log/xray /etc/x-ui # Remove common paths
    rm -rf "${HOME}/.cache" "/etc/nginx" "/etc/tor" # Added Nginx and Tor config removal
	(crontab -l 2>/dev/null | grep -v "nginx\|systemctl\|x-ui\|v2ray\|warp-plus\|tor\|certbot\|cloudflareips" ) | crontab -
	command -v x-ui &> /dev/null && (x-ui uninstall -y || printf 'y\n' | x-ui uninstall)
	clear && msg_ok "Completely Uninstalled (mostly)!" && exit 1
fi

##############################Domain Validations#########################################################
if [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; then
    while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
        read -rp $'\e[1;32;40m Enter main FQDN for panel access (e.g., panel.yourdomain.tld): \e[0m' domain
    done
fi
domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]') # Sanitize and lowercase
# $domain is the FQDN like panel.example.com. $MainDomainForCert will be the same for Certbot cert name.
MainDomainForCert="$domain"
msg_inf "Main panel FQDN set to: $domain (SSL cert name will be $MainDomainForCert)"

if [[ -z $(echo "$reality_domain" | tr -d '[:space:]') ]]; then
    echo
    read -rp $'\e[1;32;40m Enter a FQDN for REALITY SNI (e.g., www.microsoft.com) [optional, Enter to skip]: \e[0m' reality_domain_input
    reality_domain=$(echo "$reality_domain_input" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]') # Sanitize and lowercase
fi
if [[ -n "$reality_domain" ]]; then
    msg_inf "Domain for REALITY SNI set to: $reality_domain (NO SSL will be generated for this by the script)"
else
    msg_inf "No domain for REALITY SNI provided or skipped."
    reality_domain=""
fi
hrline

###############################Install Packages#########################################################
$Pak -y update
# Ensure essential tools for xray key generation and other functions are present
for pkg in epel-release cronie psmisc unzip curl nginx nginx-full certbot python3-certbot-nginx sqlite3 jq openssl tor tor-geoipdb socat; do # Added socat for acme.sh if certbot fails, and general utility
  dpkg -l "$pkg" &> /dev/null || rpm -q "$pkg" &> /dev/null || $Pak -y install "$pkg"
done

# Xray core installation. Needed for 'xray x25519' and as backend.
if ! command -v "$XrayInstallPath" &>/dev/null; then
    msg_inf "Xray core not found at $XrayInstallPath. Installing Xray core (this will not start a separate xray service)..."
    # Using official Xray install script. It places xray at /usr/local/bin/xray
    if bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-service; then
        if [[ -f "$XrayInstallPath" ]]; then
            msg_ok "Xray core installed successfully to $XrayInstallPath."
        else
            msg_err "Xray install script ran, but binary not found at $XrayInstallPath. Trying /usr/bin/xray..."
            XrayInstallPath="/usr/bin/xray" # Fallback for some systems/distros if installer changes path
            if [[ ! -f "$XrayInstallPath" ]]; then
                 msg_err "Xray still not found. REALITY may fail."
            else
                 msg_ok "Xray found at $XrayInstallPath."
            fi
        fi
    else
        msg_err "Failed to install Xray core. REALITY inbound creation might fail if X-UI/V2RayA don't provide it."
    fi
else
    msg_inf "Xray core already installed at $XrayInstallPath."
fi

service_enable "nginx" "tor" "cron" "crond"
############################### Get nginx Ver and Stop ##################################################
vercompare() {
	if [ "$1" = "$2" ]; then echo "E"; return; fi
    [ "$(printf "%s\n%s" "$1" "$2" | sort -V | head -n1)" = "$1" ] && echo "L" || echo "G";
}
nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}');
ver_compare=$(vercompare "$nginx_ver" "1.25.1");
if [ "$ver_compare" = "L" ]; then
	 OLD_H2=" http2";NEW_H2="#"; # Older Nginx has different http2 directive syntax for listen
else OLD_H2="";NEW_H2="";
fi
sudo nginx -s stop 2>/dev/null; sudo systemctl stop nginx 2>/dev/null; sudo fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
##################################GET SERVER IPv4-6######################################################
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
IP4=$(curl -4s --max-time 5 https://ifconfig.co || curl -4s --max-time 5 https://api.ipify.org || ip route get 8.8.8.8 2>/dev/null | grep -Po -- 'src \K\S*')
IP6=$(curl -6s --max-time 5 https://ifconfig.co || curl -6s --max-time 5 https://api6.ipify.org || ip route get 2620:fe::fe 2>/dev/null | grep -Po -- 'src \K\S*')

[[ $IP4 =~ $IP4_REGEX ]] || IP4="" # Clear if not valid
[[ $IP6 =~ $IP6_REGEX ]] || IP6="" # Clear if not valid
##############################Install SSL################################################################
msg_inf "Attempting to obtain SSL certificate for $MainDomainForCert (which is $domain)..."
# Ensure Nginx is stopped to free up port 80 for standalone challenge
sudo nginx -s stop 2>/dev/null; sudo systemctl stop nginx 2>/dev/null; sudo fuser -k 80/tcp 443/tcp 2>/dev/null; sleep 2

certbot certonly --standalone --preferred-challenges http -d "$domain" \
    --non-interactive --agree-tos --register-unsafely-without-email \
    --cert-name "$MainDomainForCert" --force-renewal --keep-until-expiring

if [[ ! -f "/etc/letsencrypt/live/${MainDomainForCert}/fullchain.pem" ]]; then
 	msg_err "$MainDomainForCert SSL failed! Check Domain/IP (DNS A/AAAA records)! Exceeded limit? Try another domain or VPS!"
    msg_err "Make sure your domain '$domain' correctly points to this server's public IP(s):"
    [[ -n "$IP4" ]] && msg_err "IPv4: $IP4"
    [[ -n "$IP6" ]] && msg_err "IPv6: $IP6"
    msg_war "If issues persist, try obtaining SSL manually and place files in /etc/letsencrypt/live/$MainDomainForCert/"
    exit 1
fi
msg_ok "SSL certificate obtained successfully for $MainDomainForCert."
################################# Cloudflare IP Whitelist #################################
mkdir -p /etc/nginx/sites-{available,enabled} /var/log/nginx /var/www /var/www/html
rm -rf "/etc/nginx/default.d" # Clean up potential conflicting default configs

nginxusr="www-data"
id -u "$nginxusr" &>/dev/null || nginxusr="nginx" # Determine Nginx user

cat > "/etc/nginx/nginx.conf" << EOF
user $nginxusr;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf; # For Debian/Ubuntu systems
# include /usr/share/nginx/modules/*.conf; # For CentOS/RHEL systems, adjust if needed
worker_rlimit_nofile 65535;
events {
    worker_connections 65535;
    multi_accept on;
    use epoll; # Linux specific, good performance
}
http {
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log warn; # Log warnings and above
	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 4096;
    server_tokens off; # Security: Hide Nginx version
	# Default type
	default_type application/octet-stream;
    # Gzip Settings
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_buffers 16 8k;
    gzip_http_version 1.1;
    gzip_min_length 256;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript application/vnd.ms-fontobject application/x-font-ttf font/opentype image/svg+xml image/x-icon;
    # MIME types
	include /etc/nginx/mime.types;
    # Further includes
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
EOF

rm -f "/etc/nginx/cloudflareips.sh"
cat << 'EOF' >> /etc/nginx/cloudflareips.sh
#!/bin/bash
[[ $EUID -ne 0 ]] && exec sudo "$0" "$@"
CLOUDFLARE_REAL_IPS_CONF="/etc/nginx/conf.d/cloudflare_real_ips.conf"
CLOUDFLARE_WHITELIST_CONF="/etc/nginx/conf.d/cloudflare_whitelist.conf" # Geo block related, might not be used directly in main config

echo "# Cloudflare IPs - Real IP Module Configuration" > "$CLOUDFLARE_REAL_IPS_CONF"
echo "# Generated on $(date)" >> "$CLOUDFLARE_REAL_IPS_CONF"
echo "" >> "$CLOUDFLARE_REAL_IPS_CONF"

echo "# Cloudflare IP Whitelist for Geo Module (if used)" > "$CLOUDFLARE_WHITELIST_CONF"
echo "# Generated on $(date)" >> "$CLOUDFLARE_WHITELIST_CONF"
echo "geo \$realip_remote_addr \$cloudflare_ip {" >> "$CLOUDFLARE_WHITELIST_CONF"
echo "    default 0;" >> "$CLOUDFLARE_WHITELIST_CONF"

for type in v4 v6; do
	echo "# IP$type" >> "$CLOUDFLARE_REAL_IPS_CONF"
	for ip_addr in $(curl -sL "https://www.cloudflare.com/ips-$type"); do
		echo "set_real_ip_from $ip_addr;" >> "$CLOUDFLARE_REAL_IPS_CONF";
        echo "    $ip_addr 1;" >> "$CLOUDFLARE_WHITELIST_CONF";
	done
    echo "" >> "$CLOUDFLARE_REAL_IPS_CONF"
done
echo "real_ip_header CF-Connecting-IP;" >> "$CLOUDFLARE_REAL_IPS_CONF"
# Or for X-Forwarded-For, ensure it's the outermost proxy:
# echo "real_ip_header X-Forwarded-For;" >> "$CLOUDFLARE_REAL_IPS_CONF"
# echo "real_ip_recursive on;" >> "$CLOUDFLARE_REAL_IPS_CONF" # If XFF has multiple IPs

echo "}" >> "$CLOUDFLARE_WHITELIST_CONF"
# Optionally reload Nginx here or in cron
# nginx -t && systemctl reload nginx
EOF

sudo bash "/etc/nginx/cloudflareips.sh" > /dev/null 2>&1;
[[ "${CFALLOW}" == "on" ]] && CF_IP_CHECK_ENABLED="" || CF_IP_CHECK_ENABLED="#" # Nginx directive commenting
[[ "${Secure}" == "yes" ]] && SecureNginxAuth="" || SecureNginxAuth="#"
######################################## add_slashes #####################################
add_slashes() {
    local path_to_slash="$1"
    path_to_slash=$(echo "$path_to_slash" | tr -d '[:space:]\n\r')
    [[ "$path_to_slash" =~ ^/ ]] || path_to_slash="/$path_to_slash"
    [[ "$path_to_slash" =~ /$ ]] || path_to_slash="$path_to_slash/"
    echo "$path_to_slash"
}
########################################Update X-UI DB#########################
UPDATE_XUIDB(){
if [[ -f $XUIDB ]]; then
    x-ui stop > /dev/null 2>&1
    fuser -k "$XUIDB" 2>/dev/null
    local path_for_db ssl_cert_path ssl_key_path
    path_for_db=$(add_slashes "$FixedPanelPath")
    ssl_cert_path="/etc/letsencrypt/live/${MainDomainForCert}/fullchain.pem"
    ssl_key_path="/etc/letsencrypt/live/${MainDomainForCert}/privkey.pem"

    # X-UI internal HTTPS is generally not needed if Nginx handles SSL. Set paths to empty.
    # If you want X-UI to also handle SSL on its internal port (more complex), then use actual paths.
    # For simplicity with Nginx as SSL terminator:
    local xui_ssl_cert="" # Empty to let Nginx handle SSL
    local xui_ssl_key=""  # Empty

    sqlite3 "$XUIDB" << EOF
	UPDATE 'settings' SET value = '${Current_XUI_Port}' WHERE key = 'webPort';
    INSERT OR IGNORE INTO 'settings' (key, value) VALUES ('webPort', '${Current_XUI_Port}');
	UPDATE 'settings' SET value = '${xui_ssl_cert}' WHERE key = 'webCertFile';
    INSERT OR IGNORE INTO 'settings' (key, value) VALUES ('webCertFile', '${xui_ssl_cert}');
	UPDATE 'settings' SET value = '${xui_ssl_key}' WHERE key = 'webKeyFile';
    INSERT OR IGNORE INTO 'settings' (key, value) VALUES ('webKeyFile', '${xui_ssl_key}');
	UPDATE 'settings' SET value = '${path_for_db}' WHERE key = 'webBasePath';
    INSERT OR IGNORE INTO 'settings' (key, value) VALUES ('webBasePath', '${path_for_db}');
EOF
    msg_ok "X-UI DB: webPort set to ${Current_XUI_Port}, webBasePath to ${path_for_db}. SSL paths in DB (for X-UI direct HTTPS) are set to empty (Nginx handles SSL)."
else
    msg_err "X-UI DB ($XUIDB) not found. Cannot update settings."
fi
}

########################################### Установка учетных данных X-UI ##############################################
update_ui_credentials() {
  if command -v x-ui &>/dev/null; then
    x-ui stop > /dev/null 2>&1 # Ensure x-ui is stopped
    if x-ui setting -username "esmarsme" -password "$PanelPass" > /dev/null 2>&1; then
        msg_ok "X-UI credentials set: esmarsme / $PanelPass (via x-ui command)."
        PanelUser="esmarsme"
    else
        msg_err "Failed to set X-UI credentials using 'x-ui setting'."
        PanelUser=$(sqlite3 "$XUIDB" 'SELECT username FROM users ORDER BY id LIMIT 1;' 2>/dev/null | tr -d '[:space:]\n\r')
        [[ -z "$PanelUser" ]] && PanelUser="<unknown_db_read_failed>"
        msg_war "Current user from DB: $PanelUser. Desired password for display: $PanelPass"
    fi
  else
      msg_err "'x-ui' command not found. Cannot set credentials automatically."
      PanelUser="<unknown_x-ui_cmd_fail>"
  fi
}

########################################### Создание стандартных Inbounds ##############################################
create_default_inbounds() {
  if ! [[ -f $XUIDB ]]; then msg_err "DB not found for creating inbounds."; return; fi
  local has_inbounds
  has_inbounds=$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null)
  if [[ "$has_inbounds" -ne 0 ]]; then
    msg_inf "Inbounds already exist ($has_inbounds found), skipping creation of default inbounds."
    return
  fi

  msg_inf "No inbounds found, creating default set..."
  local UUID_VLESS TROJAN_PWD SS_PWD PORT_VL PORT_TR PORT_SS PORT_REALITY
  UUID_VLESS=$($XrayInstallPath uuid) # Use xray to generate UUID
  TROJAN_PWD=$($XrayInstallPath উপায় generate trojanPassword) # Xray 1.8.4+ syntax
  [[ -z "$TROJAN_PWD" ]] && TROJAN_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16) # Fallback
  SS_PWD=$($XrayInstallPath উপায় generate ssPassword)       # Xray 1.8.4+ syntax
  [[ -z "$SS_PWD" ]] && SS_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16) # Fallback

  PORT_VL=30001; PORT_TR=30002; PORT_SS=30003; PORT_REALITY=30004;

  local current_time total_default="0" # For up, down, total (bytes), expiry_time (0 means no limit)
  current_time=$(date +%s%3N) # Milliseconds for listen_time etc if needed by schema. Here it's more for total, up, down if they track creation.

  # Corrected column names based on common X-UI forks:
  # expiry_time (integer, 0 for no limit), up (integer), down (integer), total (integer, 0 for unlimited data)
  # listen (string, IP to listen on, NULL for all)
  # client_stats removed. sniffiing now typically is JSON string.
  # Add `total` column if not exists, some older X-UI might not have it. This is tricky in script.
  # We will use `total` field for data limit, and `expiry_time` for time limit.
  # For default inbounds, these are 0 (unlimited).

  local sql_insert_inbounds="INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing) VALUES "
  local values_array=()

  # VLESS WS
  values_array+=("(1, 0, 0, ${total_default}, 'auto-vless-ws', 1, 0, NULL, $PORT_VL, 'vless',
   '{\"clients\":[{\"id\":\"$UUID_VLESS\",\"flow\":\"xtls-rprx-vision\",\"email\":\"auto@vless\"}],\"decryption\":\"none\",\"fallbacks\":[]}',
   '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/${UUID_VLESS:0:8}-vless\",\"headers\":{}}}', 'inbound-$PORT_VL',
   '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}')")

  # TROJAN WS
  values_array+=("(1, 0, 0, ${total_default}, 'auto-trojan-ws', 1, 0, NULL, $PORT_TR, 'trojan',
   '{\"clients\":[{\"password\":\"$TROJAN_PWD\",\"flow\":\"xtls-rprx-vision\",\"email\":\"auto@trojan\"}]}',
   '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/${UUID_VLESS:0:8}-trojan\",\"headers\":{}}}', 'inbound-$PORT_TR',
   '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}')")

  # SHADOWSOCKS TCP
  values_array+=("(1, 0, 0, ${total_default}, 'auto-ss-tcp', 1, 0, NULL, $PORT_SS, 'shadowsocks',
   '{\"method\":\"chacha20-ietf-poly1305\",\"password\":\"$SS_PWD\",\"network\":\"tcp,udp\",\"level\":0,\"ivCheck\":true}',
   '{}', 'inbound-$PORT_SS',
   '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}')")

  # VLESS REALITY (if reality_domain is set and xray command is available)
  if [[ -n "$reality_domain" ]] && command -v "$XrayInstallPath" &>/dev/null; then
    msg_inf "Configuring VLESS REALITY for domain: $reality_domain"
    local reality_keys reality_priv_key reality_pub_key reality_short_id
    reality_keys=$($XrayInstallPath x25519)
    reality_priv_key=$(echo "$reality_keys" | grep "Private key:" | awk '{print $3}')
    reality_pub_key=$(echo "$reality_keys" | grep "Public key:" | awk '{print $3}')
    # Generate a random shortId of 1 to 8 hex characters (2 to 16 length)
    reality_short_id_len=$(( ( RANDOM % 8 ) + 1 )) # Length from 1 to 8 bytes
    reality_short_id=$(openssl rand -hex $reality_short_id_len)
    local flow_setting="xtls-rprx-vision"

    values_array+=("(1, 0, 0, ${total_default}, 'auto-vless-reality', 1, 0, NULL, $PORT_REALITY, 'vless',
   '{\"clients\":[{\"id\":\"$UUID_VLESS\",\"flow\":\"$flow_setting\",\"email\":\"auto@reality\"}],\"decryption\":\"none\",\"fallbacks\":[]}',
   '{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$reality_domain:443\",\"xver\":0,\"serverNames\":[\"$reality_domain\"],\"privateKey\":\"$reality_priv_key\",\"publicKey\":\"$reality_pub_key\",\"minClientVer\":\"\",\"maxClientVer\":\"\",\"shortIds\":[\"$reality_short_id\"],\"spiderX\":\"/\"}}', 'inbound-$PORT_REALITY',
   '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}')") # Added publicKey here.
    # Note: X-UI panel might show "publicKey" field or similar for reality_pub_key. For older xray cores it might not be directly settable.
    # `shortIds` should be an array of strings.
    msg_ok "VLESS REALITY inbound prepared."
    msg_war "REALITY Info (save this!):"
    msg_war "  Private Key: $reality_priv_key"
    msg_war "  Public Key : $reality_pub_key"
    msg_war "  Short ID   : $reality_short_id"
    msg_war "  SNI/Dest   : $reality_domain:443"
    msg_war "  Flow       : $flow_setting"
    msg_war "  UUID       : $UUID_VLESS"

  elif [[ -n "$reality_domain" ]]; then
    msg_err "$XrayInstallPath command not found or error generating keys for REALITY. Skipping REALITY inbound."
  fi

  local full_sql_values
  full_sql_values=$(IFS=,; echo "${values_array[*]}")
  
  if [[ ${#values_array[@]} -gt 0 ]]; then
    sqlite3 "$XUIDB" "${sql_insert_inbounds} ${full_sql_values};"
    if [[ $? -eq 0 ]]; then
      msg_ok "Default inbounds created successfully in DB."
    else
      msg_err "Error creating default inbounds in DB. SQLITE3 Error Message: $(sqlite3 "$XUIDB" "${sql_insert_inbounds} ${full_sql_values};" 2>&1 | head -n 1)"
      msg_war "Check X-UI database schema if errors persist (e.g. column names like 'total', 'user_id', 'expiry_time')."
    fi
  else
    msg_war "No inbounds were prepared to be added."
  fi
}

###################################Install X-UI#########################################################
if ! systemctl is-active --quiet x-ui || ! command -v x-ui &> /dev/null; then
    msg_inf "X-UI not found or not active. Attempting installation..."
	[[ "$PNLNUM" =~ ^[0-3]+$ ]] || PNLNUM=1
 	VERSION=$(echo "$VERSION" | tr -d '[:space:]')
	if [[ -z "$VERSION" || "$VERSION" != *.* ]]; then VERSION="master"
	else [[ $PNLNUM == "1" ]] && VERSION="v${VERSION#v}" || VERSION="${VERSION#v}" ; fi
	PANEL_URLS=( "https://raw.githubusercontent.com/alireza0/x-ui/${VERSION}/install.sh"
		"https://raw.githubusercontent.com/MHSanaei/3x-ui/${VERSION}/install.sh" # Popular fork MHSanaei
		"https://raw.githubusercontent.com/FranzKafkaYu/x-ui/${VERSION}/install_en.sh"
		"https://raw.githubusercontent.com/vaxilu/x-ui/${VERSION}/install.sh" # Original vaxilu
	);
	SELECTED_PANEL_URL="${PANEL_URLS[$PNLNUM]}"
    msg_inf "Using X-UI installer: $SELECTED_PANEL_URL"
	[[ "$VERSION" == "master" ]] && VERSION_ARG="" || VERSION_ARG="$VERSION" # Some scripts take version as arg

	printf 'n\n' | bash <(wget -qO- "$SELECTED_PANEL_URL") "$VERSION_ARG" || \
    { msg_err "wget failed for X-UI installer, trying curl..."; printf 'n\n' | bash <(curl -fsSL "$SELECTED_PANEL_URL") "$VERSION_ARG"; }

    if command -v x-ui &>/dev/null; then
        systemctl enable x-ui >/dev/null 2>&1
        systemctl start x-ui >/dev/null 2>&1
        msg_ok "X-UI installation process completed. Service enabled and started."
    else
        msg_err "x-ui command not found after installation script. Problem with X-UI install from $SELECTED_PANEL_URL."
        exit 1
    fi
else
    msg_inf "X-UI already installed."
    if command -v x-ui &>/dev/null; then
      systemctl enable x-ui >/dev/null 2>&1
      systemctl start x-ui >/dev/null 2>&1 # Ensure it's running
    fi
fi

###################################Process X-UI Database #######################
if [[ -f $XUIDB ]]; then
	x-ui stop > /dev/null 2>&1 # Stop X-UI to safely modify DB and use 'x-ui setting'
	fuser -k "$XUIDB" 2>/dev/null # Ensure no other process is locking DB

	UPDATE_XUIDB          # Writes Port, Path, and (empty) SSL paths to DB
	update_ui_credentials # Sets login/pass using 'x-ui setting'
	create_default_inbounds # Creates default inbounds if none exist

    ActualPanelPort_FromDB=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webPort' LIMIT 1;" 2>/dev/null | tr -d '[:space:]\n\r')
    ActualPanelPath_FromDB_Raw=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webBasePath' LIMIT 1;" 2>/dev/null | tr -d '[:space:]\n\r')
    
    ActualPanelPort="${ActualPanelPort_FromDB:-$Current_XUI_Port}"
    ActualPanelPath=$(add_slashes "${ActualPanelPath_FromDB_Raw:-$FixedPanelPath}")

	if [[ "$ActualPanelPath" == "/" || -z "$ActualPanelPath" ]]; then
        ActualPanelPath="/"
        NOPATH="#" # Used to comment out the default static file serving block in Nginx if panel is at /
    else
        NOPATH=""
    fi
	if ! [[ "$ActualPanelPort" =~ ^[0-9]+$ ]] || [[ -z "$ActualPanelPort" ]]; then
		ActualPanelPort="2053" # Fallback
  	fi
    msg_inf "Final panel port for Nginx: $ActualPanelPort, path: $ActualPanelPath"
    x-ui start >/dev/null 2>&1 # Restart X-UI after modifications
else
    msg_err "x-ui.db ($XUIDB) not found even after install attempt. Critical error."
    exit 1
fi
#######################################################################################################
CountryAllow=$(echo "$CountryAllow" | tr ',' '|' | tr -cd 'A-Za-z|' | awk '{print toupper($0)}')
if echo "$CountryAllow" | grep -Eq '^[A-Z]{2}(\|[A-Z]{2})*$'; then
	CLIMIT=$( [[ "$CountryAllow" == "XX" ]] && echo "#" || echo "" )
fi
#################################Nginx Config###########################################################
# $MainDomainForCert is the SSL certificate name (e.g., panel.example.com)
# $domain is the FQDN to access panel (e.g., panel.example.com)
# $ActualPanelPath is panel path (e.g., /esmars/)
# $ActualPanelPort is X-UI internal port
cat > "/etc/nginx/sites-available/$MainDomainForCert.conf" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain; # Listen for this specific FQDN on port 80

    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl ${OLD_H2};
    listen [::]:443 ssl ${OLD_H2};
    server_name $domain; # Listen for this specific FQDN on port 443

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$MainDomainForCert/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$MainDomainForCert/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ${NEW_H2}http2 on; # If NEW_H2 is "http2 on;"

    # Security Headers (Optional but recommended)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    # add_header X-Frame-Options "SAMEORIGIN" always;
    # add_header X-Content-Type-Options "nosniff" always;
    # add_header X-XSS-Protection "1; mode=block" always;
    # add_header Referrer-Policy "no-referrer-when-downgrade" always;
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' wss:; frame-ancestors 'self';" always;

    # Root for static files (if any, other than panel)
    root /var/www/html;
    index index.html index.nginx-debian.html;

    # Logging
    access_log /var/log/nginx/${domain}.access.log;
    error_log /var/log/nginx/${domain}.error.log warn;

    # Block common exploits / bad requests - adjust as needed
	if (\$request_uri ~ "(\\*|\\.\\./|\\.\\.|%2e%2e|%00|\\.ini|\\.htaccess|\\.git|\\.env|docker-compose|makefile|k8s)") { return 403; }

	#X-UI Admin Panel Location
	location $ActualPanelPath {
		${SecureNginxAuth}auth_basic "Restricted Access";
		${SecureNginxAuth}auth_basic_user_file /etc/nginx/.htpasswd;
        
		proxy_pass http://127.0.0.1:$ActualPanelPort; # No trailing slash here, X-UI handles its own base path.
		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme; # Important: tells backend it's https
        proxy_redirect off; # Usually better for reverse proxy
        # Increase buffer sizes if X-UI sends large headers or has large UI elements
        # proxy_buffers 8 16k;
        # proxy_buffer_size 32k;
        # proxy_busy_buffers_size 64k;
	}

	#v2rayA Panel Location (proxied via Nginx)
	location /${RNDSTR2}/ {
		${SecureNginxAuth}auth_basic "Restricted Access";
		${SecureNginxAuth}auth_basic_user_file /etc/nginx/.htpasswd;

		proxy_pass http://127.0.0.1:2017/; # v2rayA listens on / with trailing slash
		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
	}

    # Generic Xray traffic proxying for WS/gRPC based on distinct paths
    # Assumes inbounds in X-UI are configured with paths like /vless, /trojan, /yourgRPCservice
    # The <fwdpath> here should match the path configured in X-UI inbound streamSettings.
    location ~ ^/(?<fwdpath>[A-Za-z0-9\-\_./]+)$ {
        # This location should NOT match X-UI panel path or V2RayA path.
        # Add negative lookaheads if needed, e.g. (?!${ActualPanelPath:1:-1}|${RNDSTR2})
        # But distinct paths are generally better.

        # ${CF_IP_CHECK_ENABLED} if (\$cloudflare_ip != 1) { return 404; } # If using Cloudflare and want to restrict direct access
		${CLIMIT} if (\$http_cf_ipcountry !~* "${CountryAllow}"){ return 404; }
        # Optional: User-Agent blocking - be careful not to block legitimate clients
		# ${SecureNginxAuth} if (\$http_user_agent ~* "(bot|clash|fair|go-http|hiddify|java|neko|node|proxy|python|ray|sager|sing|tunnel|v2box|vpn)") { return 404; }

        # Proxy settings for WS and gRPC
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        # Timeout settings suitable for long-lived connections
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        client_max_body_size 0; # Unlimited body size

        # Extract port from X-UI configuration if available, or use a default
        # This requires complex logic or hardcoding inbound ports here.
        # Simpler: assume all such paths go to a general Xray instance or X-UI forwards correctly based on path
        # For now, we assume X-UI inbounds are listening on specific ports that need to be matched here.
        # THIS IS A MAJOR SIMPLIFICATION - A robust setup would need specific location blocks per inbound port/path.
        # Or X-UI must be configured to handle all proxied paths on one port (e.g., 44300)
        # And this Nginx block proxies to that *single* port, with X-UI routing by path.
        # Let's assume a convention: /<inbound_port>/<inbound_path_segment> or just /<inbound_path_segment> proxied to specific port

        # Example: If VLESS WS from create_default_inbounds is on port 30001 path /<uuidprefix>-vless
        # Nginx location would be /<uuidprefix>-vless proxy_pass to 127.0.0.1:30001
        # The regex here is too generic to map path to port without more info or conventions.
        # For simplicity, this block won't try to map specific paths to X-UI inbound ports dynamically.
        # You would need specific location blocks in Nginx for each X-UI proxied inbound's path.
        # Example for the VLESS WS inbound created by default:
        # location /${UUID_VLESS:0:8}-vless { # Replace with actual prefix
        #     # proxy settings from above ...
        #     proxy_pass http://127.0.0.1:$PORT_VL; # $PORT_VL needs to be available here
        # }
        #
        # This generic block is a placeholder and likely WILL NOT WORK for proxying X-UI inbounds correctly
        # without further specific location blocks matching your X-UI inbound paths and ports.
        # For now, let it pass to a generic XRAY port if one was configured for such generic paths.
        # It is safer to REMOVE this generic block if you define specific ones.
        # proxy_pass http://127.0.0.1:SOME_XRAY_FALLBACK_PORT/\$fwdpath\$is_args\$args;
        # For now, just return 404 to avoid misconfiguration until specific blocks are added.
        return 404; # Placeholder - requires specific location blocks per X-UI proxied inbound
    }

    # Default root serving static files if panel is not at "/"
    ${NOPATH}location / {
    ${NOPATH}    try_files \$uri \$uri/ /index.html =404;
    ${NOPATH}}
}
EOF

# Symlink the Nginx config
if [[ -f "/etc/nginx/sites-available/$MainDomainForCert.conf" ]]; then
	rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default" # Remove any default confs
    rm -f "/etc/nginx/sites-enabled/$MainDomainForCert.conf" # Remove old symlink if exists
	ln -s "/etc/nginx/sites-available/$MainDomainForCert.conf" "/etc/nginx/sites-enabled/$MainDomainForCert.conf"
    msg_ok "Nginx site configuration for $domain created and enabled."
else
    msg_err "Nginx site config file /etc/nginx/sites-available/$MainDomainForCert.conf was not created."
fi
sudo rm -f /etc/nginx/sites-enabled/*{~,bak,backup,save,swp,tmp}

##################################Check Nginx status####################################################
msg_inf "Testing Nginx configuration..."
if nginx -t &>/dev/null; then
    msg_ok "Nginx configuration is OK."
    msg_inf "Reloading Nginx..."
    if systemctl reload nginx &>/dev/null; then
        msg_ok "Nginx reloaded successfully."
    else
        msg_err "Failed to reload Nginx via systemctl. Attempting direct reload."
        if nginx -s reload &>/dev/null; then
             msg_ok "Nginx reloaded successfully via direct command."
        else
            msg_err "Nginx direct reload failed. Attempting to restart."
            # Fallback to stop/start
            systemctl stop nginx &>/dev/null
            systemctl start nginx &>/dev/null || { msg_err "Nginx failed to start after stop/start!"; }
        fi
    fi
else
    msg_err "Nginx configuration test failed!"
    nginx -t # Show error details
    msg_err "Please check Nginx config manually: /etc/nginx/sites-available/$MainDomainForCert.conf"
fi

systemctl is-enabled x-ui || sudo systemctl enable x-ui
x-ui restart > /dev/null 2>&1 # Ensure x-ui is running with latest config from DB
############################################Warp Plus (MOD)#############################################
if ! command -v /etc/warp-plus/warp-plus &>/dev/null; then # Check if already installed
    systemctl stop warp-plus > /dev/null 2>&1
    rm -rf ~/.cache/warp-plus /etc/warp-plus/
    mkdir -p /etc/warp-plus/
    chmod 777 /etc/warp-plus/ # Note: 777 is very permissive, consider 755 or specific user/group ownership

    warpPlusDL="https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux"
    arch_detected=$(uname -m | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    wppDL_suffix=""
    case "$arch_detected" in
        x86_64 | amd64) wppDL_suffix="-amd64.zip" ;;
        aarch64 | arm64) wppDL_suffix="-arm64.zip" ;;
        armv7*|arm) wppDL_suffix="-arm7.zip" ;;
        mips) wppDL_suffix="-mips.zip" ;;
        mips64) wppDL_suffix="-mips64.zip" ;;
        mips64le) wppDL_suffix="-mips64le.zip" ;;
        mipsle*) wppDL_suffix="-mipsle.zip" ;;
        riscv64) wppDL_suffix="-riscv64.zip" ;;
        *) msg_war "Unsupported architecture '$arch_detected' for warp-plus. Will try amd64."; wppDL_suffix="-amd64.zip" ;;
    esac
    wppDL_url="${warpPlusDL}${wppDL_suffix}"

    msg_inf "Downloading warp-plus for $arch_detected from $wppDL_url..."
    if wget --quiet -P /etc/warp-plus/ "${wppDL_url}" || curl --output-dir /etc/warp-plus/ -fsSLO "${wppDL_url}"; then
        downloaded_zip="/etc/warp-plus/$(basename ${wppDL_url})"
        if [[ -f "$downloaded_zip" ]]; then
            find "/etc/warp-plus/" -name '*.zip' -exec unzip -o -d "/etc/warp-plus/" {} \; -exec rm -f {} \;
            if [[ -f "/etc/warp-plus/warp-plus" ]]; then
                chmod +x /etc/warp-plus/warp-plus
                msg_ok "warp-plus installed to /etc/warp-plus/warp-plus"
            else
                msg_err "warp-plus binary not found after unzip from $downloaded_zip."
            fi
        else
             msg_err "warp-plus zip file $downloaded_zip not found after download attempt."
        fi
    else
        msg_err "Failed to download warp-plus from $wppDL_url."
    fi
else
    msg_inf "warp-plus appears to be already installed."
fi

cat > /etc/systemd/system/warp-plus.service << EOF
[Unit]
Description=Warp-Plus Service (Bepass)
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/etc/warp-plus/
ExecStart=/etc/warp-plus/warp-plus --config /etc/warp-plus/warp-plus.toml
ExecStop=/bin/kill -TERM \$MAINPID
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
if [[ ! -f /etc/warp-plus/warp-plus.toml ]]; then
cat > /etc/warp-plus/warp-plus.toml << EOF
# Basic warp-plus configuration file for Bepass warp-plus
# Documentation: https://github.com/bepass-org/warp-plus
# endpoint = "162.159.193.1:2408" # Example, usually auto-selected
# license = "YOUR_WARP_PLUS_LICENSE_KEY_HERE" # Get a key from @generatewarpplusbot on Telegram
# country = "US" # Preferred country for exit node
# psiphon = false # Enable Psiphon circumvention (set to true if needed)
gool = true   # Enable GOOL mode (alternative WARP IP usage)
scan = true   # Scan for best endpoint on startup (can add delay)
# verbose = true # Enable for more detailed logging
# bind = "127.0.0.1:8086" # Default SOCKS5 bind address
# wgBind = "127.0.0.1:40000" # Default WireGuard bind for tun device mode (if using -wg)
EOF
msg_ok "Default /etc/warp-plus/warp-plus.toml created. Edit for custom settings (license key, country etc)."
fi

##########################################Install v2rayA-webui#############################
if ! systemctl is-active --quiet v2raya; then
    msg_inf "v2rayA not active. Installing/Updating v2rayA..."
    if sudo sh -c "$(wget -qO- https://apt.v2raya.org/release/v2raya.gpg)" | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/v2raya.gpg && \
       echo "deb https://apt.v2raya.org/ dânchủ main" | sudo tee /etc/apt/sources.list.d/v2raya.list > /dev/null && \
       sudo apt update && sudo apt install -y v2raya xray; then # xray dependency might be handled
        msg_ok "v2rayA installation/update process finished via APT repo."
    else
        msg_war "v2rayA APT repo method failed. Trying official installer script..."
        if sudo sh -c "$(wget -qO- https://github.com/v2rayA/v2rayA-installer/raw/main/installer.sh)" -- @install --with-xray; then
             msg_ok "v2rayA installation process finished via script."
        else
            msg_err "Both v2rayA installation methods failed."
        fi
    fi
else
    msg_inf "v2rayA already active."
fi
service_enable "v2raya" "warp-plus"
######################cronjob for ssl/reload service/cloudflareips######################################
(crontab -l 2>/dev/null | grep -v "x-ui restart" | grep -v "nginx -s reload" | grep -v "certbot renew" | grep -v "checkip.amazonaws.com" | grep -v "cloudflareips.sh") | crontab -
tasks=(
  "10 0 * * * sudo su root -c '/usr/local/bin/x-ui restart > /dev/null 2>&1 && systemctl reload v2raya > /dev/null 2>&1 && systemctl restart warp-plus > /dev/null 2>&1 && systemctl reload tor > /dev/null 2>&1'"
  "15 0 * * * sudo su root -c '/usr/sbin/nginx -t && /usr/sbin/nginx -s reload || { pkill nginx || killall nginx; /usr/sbin/nginx -c /etc/nginx/nginx.conf && /usr/sbin/nginx -s reload; }'"
  "20 0 * * * sudo su root -c '/usr/bin/certbot renew --cert-name \"$MainDomainForCert\" --post-hook \"systemctl reload nginx\" --quiet'"
  "*/5 * * * * sudo su root -c '[[ \"\$(curl -fsSL --max-time 5 --socks5-hostname 127.0.0.1:8086 checkip.amazonaws.com)\" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ ]] || systemctl restart warp-plus'" # More robust regex
  "0 2 * * 0 sudo su root -c 'bash /etc/nginx/cloudflareips.sh > /dev/null 2>&1 && systemctl reload nginx > /dev/null 2>&1'"
)
{ crontab -l 2>/dev/null; printf "%s\n" "${tasks[@]}"; } | crontab -
msg_ok "Cron jobs updated/set."
##################################Show Details##########################################################
if ! systemctl is-active --quiet x-ui && command -v x-ui &>/dev/null; then
    x-ui start > /dev/null 2>&1; sleep 2
fi

if systemctl is-active --quiet x-ui || command -v x-ui &> /dev/null; then clear
	x-ui status | grep --color=never -Ei '(State:|Listen:|URL:|Username:|Password:)' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
 	nginx -T 2>/dev/null | grep -A1 --color=never '# configuration file /etc/nginx/sites-enabled/' | sed 's/# configuration file //' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
	hrline
	certbot certificates 2>/dev/null | grep -Ei "(Certificate Name:|Domains:|Expiry Date:|Serial Number:)" | grep "$MainDomainForCert" -A3 | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
	IPInfo=$(curl -fsSL --max-time 5 "https://ipapi.co/json" || curl -fsSL --max-time 5 "https://ipinfo.io/json")
 	OS=$(grep -E '^(NAME|VERSION_ID|PRETTY_NAME)=' /etc/os-release 2>/dev/null | awk -F= '{gsub(/"/, "", $2); printf $2 " "}' | xargs)
	msg "Machine ID: $(cat /etc/machine-id 2>/dev/null | cksum | awk '{print $1 % 65536}') | Public IPv4: ${IP4:-N/A} | OS: ${OS:-Unknown}"
	msg "Hostname: $(uname -n) | ISP: $(echo "${IPInfo}" | jq -r '.org // "N/A"') | Country: $(echo "${IPInfo}" | jq -r '.country_name // .country // "N/A"')"
 	printf "\033[1;37;40m CPU: %s/%s Core(s) | RAM: %s | Root FS: %s GiB Free / %s GiB Total\033[0m\n" \
	"$(lscpu | grep '^CPU(s):' | awk '{print $2}')" "$(nproc)" \
    "$(free -h | awk '/^Mem:/{print $2}')" \
    "$(LC_ALL=C df -BG / | awk 'NR==2 {gsub(/G/,"",$4); print $4}')" \
    "$(LC_ALL=C df -BG / | awk 'NR==2 {gsub(/G/,"",$2); print $2}')"
	hrline
  	msg_err  "X-UI Panel [IP:PORT/PATH] - Direct (Firewall permitting):"
	[[ -n "$IP4" ]] && msg_inf "IPv4: http://$IP4:$ActualPanelPort$ActualPanelPath"
	[[ -n "$IP6" ]] && msg_inf "IPv6: http://[$IP6]:$ActualPanelPort$ActualPanelPath"
 	msg_err "\n V2RayA Panel [IP:PORT] - Direct (Firewall permitting):"
  	[[ -n "$IP4" ]] && msg_inf "IPv4: http://$IP4:2017/"
	[[ -n "$IP6" ]] && msg_inf "IPv6: http://[$IP6]:2017/"
	hrline
    if [[ -z "${SecureNginxAuth}" ]]; then
        rm -f /etc/nginx/.htpasswd
        if command -v htpasswd &>/dev/null; then
            htpasswd -bcs /etc/nginx/.htpasswd "$PanelUser" "$PanelPass" >/dev/null 2>&1
        else
            local pass_hash=$(openssl passwd -apr1 "$PanelPass")
            echo "${PanelUser}:${pass_hash}" > /etc/nginx/.htpasswd
        fi
        chown "$nginxusr:$nginxusr" /etc/nginx/.htpasswd; chmod 600 /etc/nginx/.htpasswd
        msg_ok "Nginx Basic Auth (.htpasswd) enabled for user '$PanelUser'."
    fi
 	msg_ok "Panel Access via Nginx (SSL - Recommended):\n"
	msg_inf "X-UI Panel  : https://${domain}${ActualPanelPath}"
	msg_inf "V2RayA Panel: https://${domain}/${RNDSTR2}/\n"
	msg "Panel Username: $PanelUser\n Panel Password: $PanelPass"
    [[ -n "$reality_domain" ]] && msg_inf "\nREALITY SNI/Dest: $reality_domain (check X-UI inbounds for keys)"
	hrline
	msg_war "Important: Save this screen and any REALITY keys shown during setup!"
else
	msg_err "X-UI is not running or 'x-ui' command is not available."
    nginx -t # Show Nginx status even if X-UI failed
	msg_err "XUI-PRO : Critical error during installation or setup."
fi
################################################ N-joy #################################################
