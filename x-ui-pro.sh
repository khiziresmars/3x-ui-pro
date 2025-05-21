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
reality_domain="" # <--- НОВАЯ ПЕРЕМЕННАЯ ДЛЯ REALITY ДОМЕНА
UNINSTALL="x"
PNLNUM=1
CFALLOW="off"
NOPATH="" # Будет установлен позже в зависимости от $ActualPanelPath
RNDTMPL="n"
CLIMIT="#"
WarpCfonCountry=""
WarpLicKey=""
CleanKeyCfon=""
TorCountry=""
Secure="no"
ENABLEUFW=""
VERSION="last"
CountryAllow="XX"
Random_country=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)
TorRandomCountry=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)

# Переменные, которые будут заполнены из БД X-UI для использования в Nginx и отображении
ActualPanelPort=""
ActualPanelPath="" # Будет, например, /esmars/
PanelUser=""
PanelPass="EsmarsMe13AMS1" # Предполагаемый пароль для отображения

######################################## Аргументы CLI #################################################
while [ "$#" -gt 0 ]; do
  case "$1" in
    -country)             CountryAllow="$2"; shift 2 ;;
    -xuiver)              VERSION="$2"; shift 2 ;;
    -ufw)                 ENABLEUFW="$2"; shift 2 ;;
    -secure)              Secure="$2"; shift 2 ;;
    -TorCountry)          TorCountry="$2"; shift 2 ;;
    -WarpCfonCountry)     WarpCfonCountry="$2"; shift 2 ;;
    -WarpLicKey)          WarpLicKey="$2"; shift 2 ;;
    -CleanKeyCfon)        CleanKeyCfon="$2"; shift 2 ;;
    -RandomTemplate)      RNDTMPL="$2"; shift 2 ;;
    -Uninstall)           UNINSTALL="$2"; shift 2 ;;
    -panel)               PNLNUM="$2"; shift 2 ;;
    -subdomain)           domain="$2"; shift 2 ;;
    -realitydomain)       reality_domain="$2"; shift 2 ;; # Аргумент для Reality домена
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
	sudo $(command -v apt || echo dnf) -y install ufw && ufw reset && echo ssh ftp http https mysql 53 2052 2053 2082 2083 2086 2087 2095 2096 3389 5900 8443 8880 | xargs -n 1 sudo ufw allow && sudo ufw enable
	msg_inf "UFW settings changed!"; exit 1
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
######
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
######
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
	echo "python3-certbot-nginx nginx nginx-full nginx-core nginx-common nginx-extras tor" | xargs -n 1 $Pak -y remove
	for service in nginx tor x-ui warp-plus v2raya xray; do
		systemctl stop "$service" > /dev/null 2>&1
		systemctl disable "$service" > /dev/null 2>&1
	done
	#bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
 	printf 'n' | bash <(wget -qO- https://github.com/v2rayA/v2rayA-installer/raw/main/uninstaller.sh)
 	rm -rf /etc/warp-plus/ /etc/nginx/sites-enabled/*
	crontab -l | grep -v "nginx\|systemctl\|x-ui\|v2ray" | crontab -
	command -v x-ui &> /dev/null && printf 'y\n' | x-ui uninstall

	clear && msg_ok "Completely Uninstalled!" && exit 1
fi

##############################Domain Validations#########################################################
# Запрос основного домена
if [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; then
    while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
        read -rp $'\e[1;32;40m Enter main subdomain for panel access (e.g., panel.yourdomain.tld): \e[0m' domain
    done
fi
domain=$(echo "$domain" | tr -d '[:space:]')
SubDomain=$(echo "$domain" | sed 's/^[^ ]* \|\..*//g') # This logic might be flawed if domain is just example.com
MainDomain=$(echo "$domain" | sed 's/.*\.\([^.]*\..*\)$/\1/')
if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]] || [[ "$SubDomain" == "$MainDomain" ]] ; then # Improved check
	MainDomain=${domain}
fi
msg_inf "Main panel domain set to: $domain (SSL will be for $MainDomain)"


# ЗАПРОС ВТОРОГО ДОМЕНА ДЛЯ REALITY (опционально, если не передан через аргумент)
if [[ -z $(echo "$reality_domain" | tr -d '[:space:]') ]]; then
    echo # пустая строка для отступа
    read -rp $'\e[1;32;40m Enter a different valid domain for REALITY (e.g., www.google.com) [optional, press Enter to skip]: \e[0m' reality_domain_input
    reality_domain=$(echo "$reality_domain_input" | tr -d '[:space:]')
fi

if [[ -n "$reality_domain" ]]; then
    msg_inf "Domain for REALITY usage set to: $reality_domain"
else
    msg_inf "No domain for REALITY provided or skipped."
    reality_domain="" # Убедимся, что переменная пуста
fi
hrline # Добавим разделитель для наглядности


###############################Install Packages#########################################################
$Pak -y update
for pkg in epel-release cronie psmisc unzip curl nginx nginx-full certbot python3-certbot-nginx sqlite sqlite3 jq openssl tor tor-geoipdb; do
  dpkg -l "$pkg" &> /dev/null || rpm -q "$pkg" &> /dev/null || $Pak -y install "$pkg"
done
# Xray core нужен для 'xray x25519', поэтому устанавливаем его здесь, если нет.
if ! command -v xray &>/dev/null; then
    msg_inf "Installing Xray core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-service
    # Мы не хотим, чтобы этот xray запускался как сервис, т.к. x-ui/v2raya управляют своим
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
	 OLD_H2=" http2";NEW_H2="#";
else OLD_H2="";NEW_H2="";
fi
####### Stop nginx
sudo nginx -s stop 2>/dev/null
sudo systemctl stop nginx 2>/dev/null
sudo fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null
##################################GET SERVER IPv4-6######################################################
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*')
IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*')
[[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com);
[[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com);
##############################Install SSL################################################################
msg_inf "Attempting to obtain SSL certificate for $MainDomain (which might be $domain)..."
certbot certonly --standalone --non-interactive --force-renewal --agree-tos --register-unsafely-without-email --cert-name "$MainDomain" -d "$domain"
# If domain=sub.example.com, MainDomain could be sub.example.com. If domain=example.com, MainDomain=example.com
if [[ ! -d "/etc/letsencrypt/live/${MainDomain}/" ]]; then
 	systemctl start nginx >/dev/null 2>&1
	msg_err "$MainDomain SSL failed! Check Domain/IP (DNS A/AAAA records)! Exceeded limit? Try another domain or VPS!"
    msg_err "Make sure your domain '$domain' correctly points to this server's IP: $IP4"
    [[ -n "$IP6" ]] && msg_err "and/or IPv6: $IP6"
    exit 1
fi
msg_ok "SSL certificate obtained successfully for $MainDomain."
################################# Access to configs only with cloudflare#################################
mkdir -p /etc/nginx/sites-{available,enabled} /var/log/nginx /var/www /var/www/html
rm -rf "/etc/nginx/default.d"

nginxusr="www-data"
id -u "$nginxusr" &>/dev/null || nginxusr="nginx"

cat > "/etc/nginx/nginx.conf" << EOF
user $nginxusr;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
worker_rlimit_nofile 65535;
events { worker_connections 65535; use epoll; multi_accept on; }
http {
	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;
	gzip on;sendfile on;tcp_nopush on;
	types_hash_max_size 4096;
	default_type application/octet-stream;
	include /etc/nginx/*.types;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
EOF

rm -f "/etc/nginx/cloudflareips.sh"
cat << 'EOF' >> /etc/nginx/cloudflareips.sh
#!/bin/bash
[[ $EUID -ne 0 ]] && exec sudo "$0" "$@"
rm -f "/etc/nginx/conf.d/cloudflare_real_ips.conf" "/etc/nginx/conf.d/cloudflare_whitelist.conf"
CLOUDFLARE_REAL_IPS_PATH=/etc/nginx/conf.d/cloudflare_real_ips.conf
CLOUDFLARE_WHITELIST_PATH=/etc/nginx/conf.d/cloudflare_whitelist.conf
echo "# Cloudflare IPs" > $CLOUDFLARE_REAL_IPS_PATH
echo "# Generated on $(date)" >> $CLOUDFLARE_REAL_IPS_PATH
echo "" >> $CLOUDFLARE_REAL_IPS_PATH
echo "geo \$realip_remote_addr \$cloudflare_ip {" > $CLOUDFLARE_WHITELIST_PATH
echo "    default 0;" >> $CLOUDFLARE_WHITELIST_PATH
echo "# Cloudflare Whitelist IPs" >> $CLOUDFLARE_WHITELIST_PATH
echo "# Generated on $(date)" >> $CLOUDFLARE_WHITELIST_PATH
echo "" >> $CLOUDFLARE_WHITELIST_PATH

for type in v4 v6; do
	# echo "# IP$type" # Optional comment in files
	for ip_addr in $(curl -sL https://www.cloudflare.com/ips-$type); do
		echo "set_real_ip_from $ip_addr;" >> $CLOUDFLARE_REAL_IPS_PATH;
		echo "    $ip_addr 1;" >> $CLOUDFLARE_WHITELIST_PATH;
	done
done
echo "" >> $CLOUDFLARE_REAL_IPS_PATH
echo "real_ip_header CF-Connecting-IP;" >> $CLOUDFLARE_REAL_IPS_PATH
# echo "real_ip_header X-Forwarded-For;" >> $CLOUDFLARE_REAL_IPS_PATH # Alternative or additional
echo "}" >> $CLOUDFLARE_WHITELIST_PATH
EOF

sudo bash "/etc/nginx/cloudflareips.sh" > /dev/null 2>&1;
[[ "${CFALLOW}" == *"on"* ]] && CF_IP="" || CF_IP="#"
[[ "${Secure}" == *"yes"* ]] && SecureNginxAuth="" || SecureNginxAuth="#"
######################################## add_slashes /webBasePath/ #####################################
add_slashes() {
    local path_to_slash="$1"
    path_to_slash=$(echo "$path_to_slash" | tr -d '[:space:]\n\r') # Очистка
    [[ "$path_to_slash" =~ ^/ ]] || path_to_slash="/$path_to_slash"
    [[ "$path_to_slash" =~ /$ ]] || path_to_slash="$path_to_slash/"
    echo "$path_to_slash"
}
########################################Update X-UI Port/Path for first INSTALL#########################
UPDATE_XUIDB(){
if [[ -f $XUIDB ]]; then
    x-ui stop > /dev/null 2>&1
    fuser -k "$XUIDB" 2>/dev/null
    local path_for_db
    path_for_db=$(add_slashes "$FixedPanelPath") # Используем FixedPanelPath ("/esmars" -> "/esmars/")
    sqlite3 "$XUIDB" << EOF
	DELETE FROM 'settings' WHERE key IN ('webPort', 'webCertFile', 'webKeyFile', 'webBasePath');
	INSERT INTO 'settings' (key, value) VALUES ('webPort', '${Current_XUI_Port}'),('webCertFile', '/etc/letsencrypt/live/${MainDomain}/fullchain.pem'),('webKeyFile', '/etc/letsencrypt/live/${MainDomain}/privkey.pem'),('webBasePath', '${path_for_db}');
EOF
    msg_ok "X-UI DB: webPort set to ${Current_XUI_Port}, webBasePath to ${path_for_db}. Web SSL cert/key paths also updated."
else
    msg_err "X-UI DB ($XUIDB) not found. Cannot update settings."
fi
}

########################################### Установка учетных данных X-UI ##############################################
update_ui_credentials() {
  if command -v x-ui &>/dev/null; then
    x-ui stop > /dev/null 2>&1 # Ensure x-ui is stopped
    # x-ui setting работает с базой данных напрямую, сервис может быть остановлен
    x-ui setting -username "esmarsme" -password "EsmarsMe13AMS1" > /dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        msg_ok "X-UI credentials set to: esmarsme / EsmarsMe13AMS1 (via x-ui command)."
        PanelUser="esmarsme"
    else
        msg_err "Failed to set X-UI credentials using 'x-ui setting'. Panel might retain default or previous credentials."
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
    msg_inf "Inbounds already exist, skipping creation of default inbounds."
    return
  fi

  msg_inf "No inbounds found, creating default set..."
  local UUID_VLESS TROJAN_PWD SS_PWD PORT_VL PORT_TR PORT_SS PORT_REALITY
  UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
  TROJAN_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  SS_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  PORT_VL=30001; PORT_TR=30002; PORT_SS=30003; PORT_REALITY=30004;

  # Start building SQL
  local sql_insert_inbounds="INSERT INTO inbounds (enable, remark, listen, port, protocol, settings, stream_settings, sniffing, client_stats, up, down, total, expiry_time, client_ip_limit) VALUES "
  local values_array=()

  # VLESS WS
  values_array+=("(1, 'auto-vless-ws', NULL, $PORT_VL, 'vless',
 '{\"clients\":[{\"id\":\"$UUID_VLESS\",\"flow\":\"xtls-rprx-vision\",\"email\":\"auto@vless\"}],\"decryption\":\"none\",\"fallbacks\":[]}',
 '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/${UUID_VLESS:0:8}-vless\",\"headers\":{}}}',
 '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}', '[]',0,0,0,0,0)")

  # TROJAN WS
  values_array+=("(1, 'auto-trojan-ws', NULL, $PORT_TR, 'trojan',
 '{\"clients\":[{\"password\":\"$TROJAN_PWD\",\"flow\":\"xtls-rprx-vision\",\"email\":\"auto@trojan\"}]}',
 '{\"network\":\"ws\",\"security\":\"none\",\"wsSettings\":{\"path\":\"/${UUID_VLESS:0:8}-trojan\",\"headers\":{}}}',
 '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}', '[]',0,0,0,0,0)")

  # SHADOWSOCKS TCP (original has it with no streamSettings, which is typical for SS)
  values_array+=("(1, 'auto-ss-tcp', NULL, $PORT_SS, 'shadowsocks',
 '{\"method\":\"chacha20-ietf-poly1305\",\"password\":\"$SS_PWD\",\"network\":\"tcp,udp\",\"level\":0,\"ivCheck\":true}',
 '{}',
 '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}', '[]',0,0,0,0,0)")

  # VLESS REALITY (if reality_domain is set)
  if [[ -n "$reality_domain" ]] && command -v xray &>/dev/null; then
    msg_inf "Configuring VLESS REALITY for domain: $reality_domain"
    local reality_keys reality_priv_key reality_pub_key reality_short_id
    reality_keys=$(xray x25519)
    reality_priv_key=$(echo "$reality_keys" | grep "Private key:" | awk '{print $3}')
    reality_pub_key=$(echo "$reality_keys" | grep "Public key:" | awk '{print $3}')
    reality_short_id=$(openssl rand -hex 8) # Random shortId
    local flow_setting="xtls-rprx-vision" # Default flow for Reality

    values_array+=("(1, 'auto-vless-reality', NULL, $PORT_REALITY, 'vless',
   '{\"clients\":[{\"id\":\"$UUID_VLESS\",\"flow\":\"$flow_setting\",\"email\":\"auto@reality\"}],\"decryption\":\"none\",\"fallbacks\":[]}',
   '{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"dest\":\"$reality_domain:443\",\"xver\":0,\"serverNames\":[\"$reality_domain\"],\"privateKey\":\"$reality_priv_key\",\"publicKey\":\"$reality_pub_key\",\"shortId\":\"$reality_short_id\",\"spiderX\":\"/\",\"minClientVer\":\"\",\"maxClientVer\":\"\"}}',
   '{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\"]}', '[]',0,0,0,0,0)")
    msg_ok "VLESS REALITY inbound prepared."
    msg_war "REALITY Private Key: $reality_priv_key"
    msg_war "REALITY Public Key: $reality_pub_key"
    msg_war "REALITY Short ID: $reality_short_id"
    msg_war "REALITY ServerName/SNI: $reality_domain"
    msg_war "REALITY Dest: $reality_domain:443"
    msg_war "REALITY Flow: $flow_setting"

  elif [[ -n "$reality_domain" ]]; then
    msg_err "xray command not found. Cannot generate keys for REALITY. Skipping REALITY inbound."
  fi

  # Combine all values and execute SQL
  local full_sql_values
  full_sql_values=$(IFS=,; echo "${values_array[*]}")
  
  if [[ ${#values_array[@]} -gt 0 ]]; then
    sqlite3 "$XUIDB" "${sql_insert_inbounds} ${full_sql_values};"
    if [[ $? -eq 0 ]]; then
      msg_ok "Default inbounds created successfully in DB."
    else
      msg_err "Error creating default inbounds in DB."
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
	PANEL=( "https://raw.githubusercontent.com/alireza0/x-ui/${VERSION}/install.sh"
		"https://raw.githubusercontent.com/mhsanaei/3x-ui/${VERSION}/install.sh"
		"https://raw.githubusercontent.com/FranzKafkaYu/x-ui/${VERSION}/install_en.sh"
		"https://raw.githubusercontent.com/AghayeCoder/tx-ui/${VERSION}/install.sh"
	);
	[[ "$VERSION" == "master" ]] && VERSION=""
	printf 'n\n' | bash <(wget -qO- "${PANEL[$PNLNUM]}") "$VERSION" ||  { printf 'n\n' | bash <(curl -Ls "${PANEL[$PNLNUM]}") "$VERSION"; }
	# service_enable "x-ui" # x-ui install script should handle enabling/starting
    if command -v x-ui &>/dev/null; then
        systemctl enable x-ui >/dev/null 2>&1
        systemctl start x-ui >/dev/null 2>&1
        msg_ok "X-UI installation process completed. Service enabled and started."
    else
        msg_err "x-ui command not found after installation script. Problem with X-UI install."
    fi
else
    msg_inf "X-UI already installed and potentially active."
    # Ensure it is enabled and started if it was previously stopped by script
    if command -v x-ui &>/dev/null; then
      systemctl enable x-ui >/dev/null 2>&1
      systemctl start x-ui >/dev/null 2>&1
    fi
fi

###################################Process X-UI Database (Update/Setttings/Credentials)#######################
if [[ -f $XUIDB ]]; then
	x-ui stop > /dev/null 2>&1 # Stop X-UI to safely modify DB and use 'x-ui setting'
	fuser -k "$XUIDB" 2>/dev/null

	UPDATE_XUIDB          # Writes Current_XUI_Port, "/esmars/", and SSL paths to DB
	update_ui_credentials # Sets login/pass using 'x-ui setting'
	create_default_inbounds # Creates default inbounds if none exist

    # Read back actual values from DB for Nginx and display
    ActualPanelPort_FromDB=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webPort' LIMIT 1;" 2>/dev/null | tr -d '[:space:]\n\r')
    ActualPanelPath_FromDB_Raw=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webBasePath' LIMIT 1;" 2>/dev/null | tr -d '[:space:]\n\r') # Cleaned raw output
    
    ActualPanelPort="${ActualPanelPort_FromDB:-$Current_XUI_Port}"
    ActualPanelPath=$(add_slashes "${ActualPanelPath_FromDB_Raw:-$FixedPanelPath}") # Use FixedPanelPath as fallback for path

    # PanelUser is set within update_ui_credentials
    # PanelPass is a fixed string for display: "EsmarsMe13AMS1"

	if [[ "$ActualPanelPath" == "/" || -z "$ActualPanelPath" ]]; then
        ActualPanelPath="/"
        NOPATH="#"
    else
        NOPATH=""
    fi

	if ! [[ "$ActualPanelPort" =~ ^[0-9]+$ ]] || [[ -z "$ActualPanelPort" ]]; then # Only positive integers
		ActualPanelPort="2053"
  	fi
    msg_inf "Final panel port for Nginx: $ActualPanelPort, path: $ActualPanelPath"
    x-ui start >/dev/null 2>&1 # Restart X-UI after modifications
else
    msg_err "x-ui.db ($XUIDB) not found. X-UI installation likely failed or path is incorrect."
    msg_war "Using fallback settings for display/Nginx. Panel may not be functional."
	ActualPanelPort="${Current_XUI_Port}"
    ActualPanelPath=$(add_slashes "$FixedPanelPath") # /esmars/
    PanelUser="esmarsme" # Intended
    if [[ "$ActualPanelPath" == "/" ]]; then NOPATH="#"; else NOPATH=""; fi
fi
#######################################################################################################
CountryAllow=$(echo "$CountryAllow" | tr ',' '|' | tr -cd 'A-Za-z|' | awk '{print toupper($0)}')
if echo "$CountryAllow" | grep -Eq '^[A-Z]{2}(\|[A-Z]{2})*$'; then
	CLIMIT=$( [[ "$CountryAllow" == "XX" ]] && echo "#" || echo "" )
fi
#################################Nginx Config###########################################################
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
	server_tokens off;
	server_name $domain *.$domain; # Listen for the exact domain and any subdomains of it for panel cert. $MainDomain for certbot name.
	listen 80;
	listen [::]:80;
	listen 443 ssl${OLD_H2} default_server; # Ensure this is default for SSL
	listen [::]:443 ssl${OLD_H2} default_server; # Ensure this is default for SSL
	${NEW_H2}http2 on; # http3 on; # QUIC/HTTP3 often needs more setup. Disable for now.
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
	ssl_prefer_server_ciphers off; # Let client choose
	ssl_certificate /etc/letsencrypt/live/$MainDomain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$MainDomain/privkey.pem;
    
    # Strict Host Check (ensure domain matches, otherwise return 444)
    # if (\$host !~* ^($(echo $domain | sed 's/\./\\./g')|www\.$(echo $domain | sed 's/\./\\./g'))\$ ) { return 444; } # Example if you want www also
    if (\$host !~* ^$(echo $domain | sed 's/\./\\./g')\$ ) {
         return 444; # Silently drop connection if host does not match panel domain
    }

	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^$(echo $domain | sed 's/\./\\./g')\$ ) {set \$safe "\${safe}0"; } # Check SNI
	if (\$safe = 10){return 444;} # If HTTPS but SNI doesn't match
	
    if (\$request_uri ~ "(\\"|'|\`|~|,|:|--|;|%|\\$|&&|\\?\\?|0x00|0X00|\\||\\\\|\\{|\\}|\\[|\\]|<|>|\\.\\.\\.|\\.\\.\\/|\\/\\/\\/)"){set \$hack 1;}
	error_page 400 401 402 403 500 501 502 503 504 =404 /404.html; # Custom 404 page
    # Create a simple /var/www/html/404.html if you want a custom page
    # location = /404.html { internal; }
	proxy_intercept_errors on;

	#X-UI Admin Panel (path from ActualPanelPath, e.g. /esmars/)
	location $ActualPanelPath {
		${SecureNginxAuth}auth_basic "Restricted Access";
		${SecureNginxAuth}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_pass http://127.0.0.1:$ActualPanelPort;
		proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
		proxy_redirect off;
		break;
	}

	#v2ray-ui (path from RNDSTR2, e.g. /randompath/)
	location /${RNDSTR2}/ {
		${SecureNginxAuth}auth_basic "Restricted Access";
		${SecureNginxAuth}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_pass http://127.0.0.1:2017/; # Standard v2rayA port
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
		proxy_redirect off;
		break;
	}

	# Subscription Path (simple/encode/json/fragment) for X-UI inbounds - path must match inbound settings
    # Example: if X-UI inbound path is /vlsub, location should be ~ ^/(?<fwdport>\d+)/vlsub
	location ~ ^/(?<fwdport>\d+)/(sub|json|fragment)/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
		proxy_pass http://127.0.0.1:\$fwdport/\$2/\$fwdpath\$is_args\$args; # \$2 is (sub|json|fragment)
		proxy_redirect off;
		break;
	}

	# Xray Generic Config Path (for WS/gRPC not directly on ports 80/443, but proxied via Nginx)
    # Assumes X-UI inbounds are configured with specific paths like /vless, /trojan, /grpcservicename
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>[A-Za-z0-9\-\_]+)\$ {
		if (\$hack = 1) {return 404;}
		# ${CF_IP}if (\$cloudflare_ip != 1) {return 404;} # Cloudflare IP check - re-evaluate if this makes sense with direct access for panel too.
		${CLIMIT}if (\$http_cf_ipcountry !~* "${CountryAllow}"){ return 404; }
		# ${SecureNginxAuth}if (\$http_user_agent ~* "(bot|clash|fair|go-http|hiddify|java|neko|node|proxy|python|ray|sager|sing|tunnel|v2box|vpn)") { return 404; } # This might block legitimate clients

		client_max_body_size 0; # Allow large file uploads if necessary for some protocols
        client_body_timeout 1d; # Long timeout
        proxy_read_timeout 1d;  # Long timeout for streaming
        proxy_send_timeout 1d;  # Long timeout

		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host; # Important for WS
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_buffering off; # Good for streaming, reduces latency
		proxy_request_buffering off; # Good for streaming
		# proxy_socket_keepalive on; # Might be useful for gRPC

        # Differentiate gRPC based on Content-Type (more robust than path segment)
		if (\$content_type = "application/grpc" ) {
            # grpc_socket_keepalive on; # Not a standard nginx directive. Use proxy_socket_keepalive for underlying TCP
			grpc_pass grpc://127.0.0.1:\$fwdport; # Pass to the gRPC service on its port.
                                                # \$fwdpath might be the gRPC service name IF x-ui/xray uses it like that for routing.
                                                # Often, gRPC doesn't use a path in the proxy_pass this way unless for multi-service setup on one port.
                                                # If \$fwdpath IS the service name, it would be part of the gRPC call, not the proxy_pass URL path.
                                                # For simple gRPC on its own port in x-ui, this is fine.
			break;
		}
        # Default to HTTP proxy for WS or other HTTP-based protocols
		proxy_pass http://127.0.0.1:\$fwdport/\$fwdpath\$is_args\$args; # Passes /<port>/<path> to backend as /<path>
		break;
	}
	
    # Default location for unmatched requests on this server block.
    # If NOPATH is empty (meaning $ActualPanelPath is not "/"), this will serve static files or 404.
    # If NOPATH is "#" (meaning $ActualPanelPath IS "/"), this location is effectively commented out and
    # the location / { ... X-UI proxy ...} block above will handle it.
	$NOPATH location / {
    $NOPATH     try_files \$uri \$uri/ /index.html =404; # Serve static files if they exist
    $NOPATH }

    # Add HSTS header if SSL is used (optional but recommended)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
EOF

if [[ -f "/etc/nginx/sites-available/$MainDomain" ]]; then
	unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
	rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
	ln -fs "/etc/nginx/sites-available/$MainDomain" "/etc/nginx/sites-enabled/$MainDomain" 2>/dev/null # Ensure link name is also specific
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
        msg_err "Failed to reload Nginx. Attempting to restart."
        pkill -9 nginx || killall -9 nginx
        systemctl start nginx &>/dev/null || { msg_err "Nginx failed to start after pkill!"; }
    fi
else
    msg_err "Nginx configuration test failed!"
    nginx -t # Show error details
    msg_err "Please check Nginx config manually: /etc/nginx/sites-available/$MainDomain"
    msg_war "Attempting to start Nginx with potentially flawed config (last resort)..."
    pkill -9 nginx || killall -9 nginx
    systemctl start nginx &>/dev/null || { msg_err "Nginx failed to start!"; }
fi

systemctl is-enabled x-ui || sudo systemctl enable x-ui
x-ui restart > /dev/null 2>&1 # Ensure x-ui is running with latest config from DB
############################################Warp Plus (MOD)#############################################
systemctl stop warp-plus > /dev/null 2>&1
rm -rf ~/.cache/warp-plus /etc/warp-plus/
mkdir -p /etc/warp-plus/
chmod 777 /etc/warp-plus/
## Download Cloudflare Warp Mod (wireguard)
warpPlusDL="https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux"
arch=$(uname -m | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
case "$arch" in
	x86_64 | amd64) wppDL="${warpPlusDL}-amd64.zip" ;;
	aarch64 | arm64) wppDL="${warpPlusDL}-arm64.zip" ;;
	armv7*|arm) wppDL="${warpPlusDL}-arm7.zip" ;; # Catch armv7l, armv7, etc.
	mips) wppDL="${warpPlusDL}-mips.zip" ;;
	mips64) wppDL="${warpPlusDL}-mips64.zip" ;;
	mips64le) wppDL="${warpPlusDL}-mips64le.zip" ;;
	mipsle*) wppDL="${warpPlusDL}-mipsle.zip" ;;
	riscv64) wppDL="${warpPlusDL}-riscv64.zip" ;; # Fixed from riscv*
	*) msg_war "Unsupported architecture '$arch' for warp-plus. Falling back to amd64."; wppDL="${warpPlusDL}-amd64.zip" ;;
esac

msg_inf "Downloading warp-plus for $arch from $wppDL..."
wget --quiet -P /etc/warp-plus/ "${wppDL}" || curl --output-dir /etc/warp-plus/ -fsSLO "${wppDL}" # Use -fsSLO for curl
if [[ ! -f "/etc/warp-plus/$(basename ${wppDL})" ]]; then
    msg_err "Failed to download warp-plus."
else
    find "/etc/warp-plus/" -name '*.zip' | xargs -I {} sh -c 'unzip -o -d "$(dirname "{}")" "{}" && rm -f "{}"'
    if [[ ! -f "/etc/warp-plus/warp-plus" ]]; then
        msg_err "warp-plus binary not found after unzip."
    else
        chmod +x /etc/warp-plus/warp-plus
        msg_ok "warp-plus installed."
    fi
fi

cat > /etc/systemd/system/warp-plus.service << EOF
[Unit]
Description=Warp-Plus Service (Bepass)
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/warp-plus/
ExecStart=/etc/warp-plus/warp-plus --config /etc/warp-plus/warp-plus.toml
# Default config uses endpoint 162.159.193.10:2408 and Binds to 127.0.0.1:8086 (SOCKS5) / 127.0.0.1:40000 (WireGuard)
# Create /etc/warp-plus/warp-plus.toml for custom settings
# Example warp-plus.toml:
# license = "YOUR_WARP_PLUS_LICENSE_KEY"
# country = "US"
# psiphon = true
# verbose = true
# bind = "0.0.0.0:8086" # If you want to expose SOCKS5, not recommended for security

ExecStop=/bin/kill -TERM \$MAINPID
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
# Create a basic warp-plus.toml if it doesn't exist, to ensure service starts
if [[ ! -f /etc/warp-plus/warp-plus.toml ]]; then
cat > /etc/warp-plus/warp-plus.toml << EOF
# Basic warp-plus configuration
# scan = true # Enable scan for better endpoint, can take time on start
gool = true # Use WARP endpoint not Cloudflare's normal IP for some checks
verbose = true
EOF
fi

##########################################Install v2ray-core + v2rayA-webui#############################
# Check if v2rayA is already installed and running its service
if ! systemctl is-active --quiet v2raya; then
    msg_inf "v2rayA not active. Installing/Updating v2rayA..."
    sudo sh -c "$(wget -qO- https://github.com/v2rayA/v2rayA-installer/raw/main/installer.sh)" -- @install --with-xray # Ensure latest Xray
    msg_ok "v2rayA installation process finished."
else
    msg_inf "v2rayA already active."
fi
service_enable "v2raya" "warp-plus"
######################cronjob for ssl/reload service/cloudflareips######################################
(crontab -l 2>/dev/null | grep -v "x-ui restart" | grep -v "nginx -s reload" | grep -v "certbot renew" | grep -v "checkip.amazonaws.com" | grep -v "cloudflareips.sh") | crontab -
tasks=(
  "10 0 * * * sudo su -c 'x-ui restart > /dev/null 2>&1 && systemctl reload v2raya > /dev/null 2>&1 && systemctl restart warp-plus > /dev/null 2>&1 && systemctl reload tor > /dev/null 2>&1'"
  "15 0 * * * sudo su -c 'nginx -s reload 2>&1 | grep -q error && { pkill nginx || killall nginx; nginx -c /etc/nginx/nginx.conf; nginx -s reload; }'" # Check for error specifically
  "20 0 1 * * sudo su -c 'certbot renew --nginx --force-renewal --non-interactive --post-hook \"systemctl reload nginx\" > /dev/null 2>&1'" # use systemctl reload
  "* * * * * sudo su -c '[[ \"\$(curl -s --max-time 5 --socks5-hostname 127.0.0.1:8086 checkip.amazonaws.com)\" =~ ^((([0-9]{1,3}\.){3}[0-9]{1,3})|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))\$ ]] || systemctl restart warp-plus'"
  "0 2 * * 0 sudo bash /etc/nginx/cloudflareips.sh > /dev/null 2>&1 && systemctl reload nginx > /dev/null 2>&1" # Reload nginx after updating IPs
)
{ crontab -l 2>/dev/null; printf "%s\n" "${tasks[@]}"; } | crontab -
msg_ok "Cron jobs updated/set."
##################################Show Details##########################################################
# Ensure x-ui is running before trying to get status or other info
if ! systemctl is-active --quiet x-ui && command -v x-ui &>/dev/null; then
    x-ui start > /dev/null 2>&1
    sleep 2 # Give it a moment to start
fi

if systemctl is-active --quiet x-ui || command -v x-ui &> /dev/null; then clear
	x-ui status | grep --color=never -i ':' | awk '{print "\033[1;37;40m" $0 "\033[0m"}' # Use x-ui status
	hrline
 	nginx -T 2>/dev/null | grep -A1 --color=never '# configuration file /etc/nginx/sites-enabled/' | sed 's/# configuration file //' | tr -d ':' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
	hrline
	certbot certificates 2>/dev/null | grep -Ei '(Certificate Name:|Domains:|Expiry Date:|Serial Number:)' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
	IPInfo=$(curl -Ls --max-time 5 "https://ipapi.co/json" || curl -Ls --max-time 5 "https://ipinfo.io/json")
 	OS=$(grep -E '^(NAME|VERSION_ экспедиционная (CODENAME)?)=' /etc/*release 2>/dev/null | awk -F= '{gsub(/"/, "", $2); printf $2 " "}' | xargs)
	msg "Machine ID: $(cat /etc/machine-id 2>/dev/null | cksum | awk '{print $1 % 65536}') | Public IPv4: ${IP4} | OS: ${OS}"
	msg "Hostname: $(uname -n) | ISP Info: $(echo "${IPInfo}" | jq -r '.org, .country_name' | paste -sd' / ')"
 	printf "\033[1;37;40m CPU: %s/%s Core | RAM: %s | SSD Root: %s GiB\033[0m\n" \
	"$(arch)" "$(nproc)" "$(free -h | awk '/^Mem:/{print $2}')" "$( LC_ALL=C df -BG / | awk 'NR==2 {gsub(/G/, "", $2); print $2}')"
	hrline
  	msg_err  "X-UI Panel [IP:PORT/PATH]"
    # $ActualPanelPort and $ActualPanelPath are the values from DB or fallbacks
	[[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4 Access: http://$IP4:$ActualPanelPort$ActualPanelPath"
	[[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6 Access: http://[$IP6]:$ActualPanelPort$ActualPanelPath"
 	msg_err "\n V2RayA Panel [IP:PORT]"
  	[[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4 Access: http://$IP4:2017/"
	[[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6 Access: http://[$IP6]:2017/"
	hrline
    # Create/Update .htpasswd for Nginx Basic Auth if SecureNginxAuth is enabled
    if [[ -z "${SecureNginxAuth}" ]]; then # SecureNginxAuth is empty if -secure yes
        rm -f /etc/nginx/.htpasswd # Remove old file to ensure single entry
        if command -v htpasswd &>/dev/null; then
            htpasswd -bcs /etc/nginx/.htpasswd "$PanelUser" "$PanelPass" >/dev/null 2>&1
        else
            local pass_hash
            pass_hash=$(openssl passwd -apr1 "$PanelPass")
            echo "${PanelUser}:${pass_hash}" > /etc/nginx/.htpasswd
        fi
        chown "$nginxusr:$nginxusr" /etc/nginx/.htpasswd
        chmod 600 /etc/nginx/.htpasswd
        msg_ok "Nginx Basic Auth (.htpasswd) created/updated for user '$PanelUser'."
    fi
 	msg_ok "Admin Panel [SSL Access - Recommended]:\n"
    # $domain is the user-provided domain, $ActualPanelPath is path from DB (e.g. /esmars/), $RNDSTR2 is random for v2rayA
	msg_inf "X-UI Panel: https://${domain}${ActualPanelPath}"
	msg_inf "V2RayA Panel: https://${domain}/${RNDSTR2}/\n"
	msg "Panel Username: $PanelUser\n Panel Password: $PanelPass"
    [[ -n "$reality_domain" ]] && msg_inf "\nREALITY SNI/Dest Domain: $reality_domain (check X-UI inbounds for keys/config)"
	hrline
	msg_war "Important: Save This Screen and any REALITY keys shown during setup!"
else
	msg_err "X-UI is not running or 'x-ui' command is not available."
    nginx -t # Still try to show nginx status if x-ui failed
	msg_err "XUI-PRO : Critical error during installation or setup."
fi
################################################ N-joy #################################################
