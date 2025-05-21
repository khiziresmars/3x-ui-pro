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
RNDSTR="/esmars"            #  <-- фиксированная точка входа панели (без слеша в конце, add_slashes добавит)
RNDSTR2=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n1)") #  второй путь (для v2rayA)
# ---- Порт панели (Генерируется случайно, используется для обновления БД) ----
while true; do
  Current_Generated_PORT=$((RANDOM%30000 + 30000)); nc -z 127.0.0.1 "$Current_Generated_PORT" &>/dev/null || break
done
PORT=${Current_Generated_PORT} # Используем это значение для UPDATE_XUIDB

######################################## Переменные скрипта ############################################
XUIDB="/etc/x-ui/x-ui.db"
domain=""
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
Secure="no"
ENABLEUFW=""
VERSION="last"
CountryAllow="XX"
Random_country=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1) # Из оригинального скрипта
TorRandomCountry=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1) # Из оригинального скрипта


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
while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
	read -rp $'\e[1;32;40m Enter available subdomain (sub.domain.tld): \e[0m' domain
done

domain=$(echo "$domain" 2>&1 | tr -d '[:space:]' )
SubDomain=$(echo "$domain" 2>&1 | sed 's/^[^ ]* \|\..*//g')
MainDomain=$(echo "$domain" 2>&1 | sed 's/.*\.\([^.]*\..*\)$/\1/')

if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]] ; then
	MainDomain=${domain}
fi
###############################Install Packages#########################################################
$Pak -y update
for pkg in epel-release cronie psmisc unzip curl nginx nginx-full certbot python3-certbot-nginx sqlite sqlite3 jq openssl tor tor-geoipdb; do
  dpkg -l "$pkg" &> /dev/null || rpm -q "$pkg" &> /dev/null || $Pak -y install "$pkg"
done
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
certbot certonly --standalone --non-interactive --force-renewal --agree-tos --register-unsafely-without-email --cert-name "$MainDomain" -d "$domain"
if [[ ! -d "/etc/letsencrypt/live/${MainDomain}/" ]]; then
 	systemctl start nginx >/dev/null 2>&1
	msg_err "$MainDomain SSL failed! Check Domain/IP! Exceeded limit!? Try another domain or VPS!" && exit 1
fi
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
echo "geo \$realip_remote_addr \$cloudflare_ip {
	default 0;" >> $CLOUDFLARE_WHITELIST_PATH
for type in v4 v6; do
	echo "# IP$type"
	for ip in `curl https://www.cloudflare.com/ips-$type`; do
		echo "set_real_ip_from $ip;" >> $CLOUDFLARE_REAL_IPS_PATH;
		echo "	$ip 1;" >> $CLOUDFLARE_WHITELIST_PATH;
	done
done
echo "real_ip_header X-Forwarded-For;" >> $CLOUDFLARE_REAL_IPS_PATH
echo "}" >> $CLOUDFLARE_WHITELIST_PATH
EOF

sudo bash "/etc/nginx/cloudflareips.sh" > /dev/null 2>&1;
[[ "${CFALLOW}" == *"on"* ]] && CF_IP="" || CF_IP="#"
[[ "${Secure}" == *"yes"* ]] && Secure="" || Secure="#"
######################################## add_slashes /webBasePath/ #####################################
add_slashes() {
    local path_to_slash="$1"
    [[ "$path_to_slash" =~ ^/ ]] || path_to_slash="/$path_to_slash"
    [[ "$path_to_slash" =~ /$ ]] || path_to_slash="$path_to_slash/"
    echo "$path_to_slash"
}
########################################Update X-UI Port/Path for first INSTALL#########################
# RNDSTR (path) and PORT are global variables defined at the start of the script.
# RNDSTR is e.g. "/esmars" (fixed), PORT is random for this run.
# UPDATE_XUIDB uses these global variables to update the database.
UPDATE_XUIDB(){
if [[ -f $XUIDB ]]; then
    x-ui stop > /dev/null 2>&1
    fuser -k "$XUIDB" 2>/dev/null # Use -k to kill processes using the file
    local RNDSTRSLASH # Local variable for slashed path
    RNDSTRSLASH=$(add_slashes "$RNDSTR") # Uses global RNDSTR (e.g. "/esmars" -> "/esmars/")
    sqlite3 "$XUIDB" << EOF
	DELETE FROM 'settings' WHERE key IN ('webPort', 'webCertFile', 'webKeyFile', 'webBasePath');
	INSERT INTO 'settings' (key, value) VALUES ('webPort', '${PORT}'),('webCertFile', ''),('webKeyFile', ''),('webBasePath', '${RNDSTRSLASH}');
EOF
fi
}

########################################### НОВАЯ ФУНКЦИЯ ###############################################
update_ui_credentials() {
  # username = esmarsme, password = EsmarsMe13AMS1
  local user_row_count
  user_row_count=$(sqlite3 "$XUIDB" "SELECT COUNT(id) FROM users;" 2>/dev/null)

  if [[ "$user_row_count" -eq 0 ]]; then
    # No users, insert the new one
    sqlite3 "$XUIDB" "INSERT INTO users (username, password,permission) VALUES ('esmarsme', 'EsmarsMe13AMS1','');"
    msg_inf "Created new user: esmarsme"
  elif [[ "$user_row_count" -ge 1 ]]; then
    # Update the first user (ORDER BY id LIMIT 1 implies this)
    sqlite3 "$XUIDB" "UPDATE users SET username='esmarsme', password='EsmarsMe13AMS1' WHERE id = (SELECT id FROM users ORDER BY id LIMIT 1);"
    msg_inf "Updated existing user to: esmarsme"
  else
    msg_err "Could not determine user to update/create."
  fi
}

########################################### НОВАЯ ФУНКЦИЯ ###############################################
create_default_inbounds() {
  # Проверяем, если там уже есть хоть один inbound — выходим.
  local has_inbounds
  has_inbounds=$(sqlite3 "$XUIDB" "SELECT COUNT(*) FROM inbounds;" 2>/dev/null)
  if [[ "$has_inbounds" -ne 0 ]]; then # Ensure it's exactly 0, not just non-gt-0
    msg_inf "Inbounds already exist, skipping creation of default inbounds."
    return
  fi

  msg_inf "No inbounds found, creating default set..."
  # Генерация значений
  UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
  TROJAN_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
  SS_PWD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)

  # Порты внутрь (за nginx) – можно менять при желании
  PORT_VL=30001
  PORT_TR=30002
  PORT_SS=30003

  sqlite3 "$XUIDB" <<EOF
INSERT INTO inbounds
(enable, remark, listen, port, protocol, settings, stream_settings, sniffing, client_stats, up, down, total, expiry_time, client_ip_limit)
VALUES
-- VLESS WS
(1, 'auto-vless', NULL, $PORT_VL, 'vless',
 '{"clients":[{"id":"$UUID_VLESS","email":"auto@vless"}],"decryption":"none","fallbacks":[]}',
 '{"network":"ws","security":"none","wsSettings":{"path":"/vless"}}',
 '{"enabled":true,"destOverride":["http","tls","quic"]}', '[]',0,0,0,0,0),

-- TROJAN WS
(1, 'auto-trojan', NULL, $PORT_TR, 'trojan',
 '{"clients":[{"password":"$TROJAN_PWD","email":"auto@trojan"}]}',
 '{"network":"ws","security":"none","wsSettings":{"path":"/trojan"}}',
 '{"enabled":true,"destOverride":["http","tls","quic"]}', '[]',0,0,0,0,0),

-- SHADOWSOCKS TCP
(1, 'auto-ss', NULL, $PORT_SS, 'shadowsocks',
 '{"method":"chacha20-ietf-poly1305","password":"$SS_PWD","network":"tcp,udp","level":0,"ivCheck":true}',
 '{}',
 '{"enabled":true,"destOverride":["http","tls","quic"]}', '[]',0,0,0,0,0);
EOF
  msg_ok "Default inbounds (VLESS, Trojan, SS) created successfully."
}

###################################Install X-UI#########################################################
if ! systemctl is-active --quiet x-ui || ! command -v x-ui &> /dev/null; then
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
	service_enable "x-ui" # This enables and starts x-ui
    # UPDATE_XUIDB and other modifications will happen in the next block
fi

###################################Process X-UI Database (Update/Setttings/Credentials)#######################
if [[ -f $XUIDB ]]; then
	x-ui stop > /dev/null 2>&1 # Ensure x-ui is stopped for DB operations
	fuser -k "$XUIDB" 2>/dev/null

	UPDATE_XUIDB          # Uses global RNDSTR="/esmars" and global random PORT to set DB.
	update_ui_credentials # Sets fixed username/password.
	create_default_inbounds # Adds default inbounds if none exist.

    # Read back the PORT and RNDSTR from the database that were just set/updated.
    # This ensures the script uses the actual values from DB for Nginx and display.
    # Note: The global variable 'PORT' defined at the start holds the value used by UPDATE_XUIDB.
    # The global variable 'RNDSTR' (e.g. "/esmars") is used by UPDATE_XUIDB (after add_slashes).
    # Here we re-assign script's PORT and RNDSTR vars with values from DB to confirm.

    PORT_FROM_DB=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webPort' LIMIT 1;" 2>&1)
    RNDSTR_FROM_DB=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webBasePath' LIMIT 1;" 2>&1)

    # Update script's PORT and RNDSTR variables for Nginx config and display.
    PORT="$PORT_FROM_DB"
    RNDSTR=$(add_slashes "$RNDSTR_FROM_DB" | tr -d '[:space:]') # Ensure it's like /path/

	XUIUSER=$(sqlite3 "${XUIDB}" 'SELECT "username" FROM users ORDER BY id LIMIT 1;' 2>&1) # Should be 'esmarsme'
	XUIPASS=$(sqlite3 "${XUIDB}" 'SELECT "password" FROM users ORDER BY id LIMIT 1;' 2>&1) # Should be 'EsmarsMe13AMS1' (but we show it as a var)

	if [[ "$RNDSTR" == "/" ]]; then
        NOPATH="#"
    else
        NOPATH="" # RNDSTR is not "/", so NOPATH is empty
    fi

	if [[ -z "${PORT}" ]] || ! [[ "${PORT}" =~ ^-?[0-9]+$ ]]; then
		PORT="2053" # Fallback, though UPDATE_XUIDB should have set it.
  	fi
    # x-ui will be started later by service_enable or systemctl start nginx sequence
else
    # XUIDB not found, even after potential install attempt.
    msg_err "x-ui.db not found. X-UI installation may have failed."
    msg_war "Using default fallback settings for display/Nginx config, but panel may not be functional."
	# PORT remains the initially generated random port
	# RNDSTR remains the initial "/esmars", format it with slashes for nginx.
    RNDSTR=$(add_slashes "$RNDSTR" | tr -d '[:space:]')
	XUIUSER="esmarsme" # Intended username
    XUIPASS="EsmarsMe13AMS1" # Intended password
    if [[ "$RNDSTR" == "/" ]]; then NOPATH="#"; else NOPATH=""; fi
fi
#######################################################################################################
CountryAllow=$(echo "$CountryAllow" | tr ',' '|' | tr -cd 'A-Za-z|' | awk '{print toupper($0)}')
if echo "$CountryAllow" | grep -Eq '^[A-Z]{2}(\|[A-Z]{2})*$'; then
	CLIMIT=$( [[ "$CountryAllow" == "XX" ]] && echo "#" || echo "" )
fi
#################################Nginx Config###########################################################
# $RNDSTR here should be the path read from DB (e.g., /esmars/)
# $RNDSTR2 is the random path for v2rayA
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
	server_tokens off;
	server_name $MainDomain *.$MainDomain;
	listen 80;
	listen [::]:80;
	listen 443 ssl${OLD_H2};
	listen [::]:443 ssl${OLD_H2};
	${NEW_H2}http2 on; http3 on;
	index index.html index.htm index.php index.nginx-debian.html;
	root /var/www/html/;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$MainDomain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$MainDomain/privkey.pem;
	if (\$host !~* ^(.+\.)?$MainDomain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$MainDomain\$ ) {set \$safe "\${safe}0"; }
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\\"|'|\`|~|,|:|--|;|%|\\$|&&|\\?\\?|0x00|0X00|\\||\\\\|\\{|\\}|\\[|\\]|<|>|\\.\\.\\.|\\.\\.\\/|\\/\\/\\/)"){set \$hack 1;}
	error_page 400 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;
	#X-UI Admin Panel (path from RNDSTR, e.g. /esmars/)
	location $RNDSTR {
		${Secure}auth_basic "Restricted Access";
		${Secure}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:$PORT; # PORT is the panel port from DB
		break;
	}
	#v2ray-ui (path from RNDSTR2, e.g. /randompath/)
	location /${RNDSTR2}/ {
		${Secure}auth_basic "Restricted Access";
		${Secure}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:2017/; # Standard v2rayA port
		break;
	}
	#Subscription Path (simple/encode)
	location ~ ^/(?<fwdport>\d+)/sub/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:\$fwdport/sub/\$fwdpath\$is_args\$args;
		break;
	}
	#Subscription Path (json/fragment)
	location ~ ^/(?<fwdport>\d+)/json/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:\$fwdport/json/\$fwdpath\$is_args\$args;
		break;
	}
	#Xray Config Path
	location ~ ^/(?<fwdport>\d+)/(?<fwdpath>.*)\$ {
		if (\$hack = 1) {return 404;}
		${CF_IP}if (\$cloudflare_ip != 1) {return 404;}
		${CLIMIT}if (\$http_cf_ipcountry !~* "${CountryAllow}"){ return 404; }
		${Secure}if (\$http_user_agent ~* "(bot|clash|fair|go-http|hiddify|java|neko|node|proxy|python|ray|sager|sing|tunnel|v2box|vpn)") { return 404; }
		client_max_body_size 0;
		client_body_timeout 1d;
		grpc_read_timeout 1d;
		grpc_socket_keepalive on;
		proxy_read_timeout 1d;
		proxy_http_version 1.1;
		proxy_buffering off;
		proxy_request_buffering off;
		proxy_socket_keepalive on;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		if (\$content_type ~* "GRPC") { grpc_pass grpc://127.0.0.1:\$fwdport\$is_args\$args; break; }
		proxy_pass http://127.0.0.1:\$fwdport\$is_args\$args;
		break;
	}
	$NOPATH location / { try_files \$uri \$uri/ =404; }
}
EOF
if [[ -f "/etc/nginx/sites-available/$MainDomain" ]]; then
	unlink "/etc/nginx/sites-enabled/default" >/dev/null 2>&1
	rm -f "/etc/nginx/sites-enabled/default" "/etc/nginx/sites-available/default"
	ln -fs "/etc/nginx/sites-available/$MainDomain" "/etc/nginx/sites-enabled/" 2>/dev/null
fi
sudo rm -f /etc/nginx/sites-enabled/*{~,bak,backup,save,swp,tmp}
##################################Check Nginx status####################################################
if ! systemctl start nginx > /dev/null 2>&1 || ! nginx -t &>/dev/null || nginx -s reload 2>&1 | grep -q error; then
	pkill -9 nginx || killall -9 nginx
	nginx -c /etc/nginx/nginx.conf
	nginx -s reload
fi
systemctl is-enabled x-ui || sudo systemctl enable x-ui # Ensure x-ui is enabled
x-ui start > /dev/null 2>&1 # Ensure x-ui is started after all DB/Nginx changes
############################################Warp Plus (MOD)#############################################
systemctl stop warp-plus > /dev/null 2>&1
rm -rf ~/.cache/warp-plus /etc/warp-plus/
mkdir -p /etc/warp-plus/
chmod 777 /etc/warp-plus/
## Download Cloudflare Warp Mod (wireguard)
warpPlusDL="https://github.com/bepass-org/warp-plus/releases/latest/download/warp-plus_linux"

case "$(uname -m | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
	x86_64 | amd64) wppDL="${warpPlusDL}-amd64.zip" ;;
	aarch64 | arm64) wppDL="${warpPlusDL}-arm64.zip" ;;
	armv*) wppDL="${warpPlusDL}-arm7.zip" ;;
	mips) wppDL="${warpPlusDL}-mips.zip" ;;
	mips64) wppDL="${warpPlusDL}-mips64.zip" ;;
	mips64le) wppDL="${warpPlusDL}-mips64le.zip" ;;
	mipsle*) wppDL="${warpPlusDL}-mipsle.zip" ;;
	riscv*) wppDL="${warpPlusDL}-riscv64.zip" ;;
	*) wppDL="${warpPlusDL}-amd64.zip" ;;
esac

wget --quiet -P /etc/warp-plus/ "${wppDL}" || curl --output-dir /etc/warp-plus/ -LOs "${wppDL}"
find "/etc/warp-plus/" -name '*.zip' | xargs -I {} sh -c 'unzip -o -d "$0" "{}" && rm -f "{}"' "/etc/warp-plus/" # Added -o to overwrite
cat > /etc/systemd/system/warp-plus.service << EOF
[Unit]
Description=warp-plus service
After=network.target nss-lookup.target

[Service]
WorkingDirectory=/etc/warp-plus/
ExecStart=/etc/warp-plus/warp-plus
ExecStop=/bin/kill -TERM \$MAINPID
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF
##########################################Install v2ray-core + v2rayA-webui#############################
#bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install # Original commented this out if v2rayA provides it
sudo sh -c "$(wget -qO- https://github.com/v2rayA/v2rayA-installer/raw/main/installer.sh)" @install --with-xray # Fixed typo @ --with-xray to @install --with-xray
service_enable "v2raya" "warp-plus"
######################cronjob for ssl/reload service/cloudflareips######################################
tasks=(
  "0 0 * * * sudo su -c 'x-ui restart > /dev/null 2>&1 && systemctl reload v2raya warp-plus tor'"
  "0 0 * * * sudo su -c 'nginx -s reload 2>&1 | grep -q error && { pkill nginx || killall nginx; nginx -c /etc/nginx/nginx.conf; nginx -s reload; }'"
  "0 0 1 * * sudo su -c 'certbot renew --nginx --force-renewal --non-interactive --post-hook \"nginx -s reload\" > /dev/null 2>&1'"
  "* * * * * sudo su -c '[[ \"\$(curl -s --socks5-hostname 127.0.0.1:8086 checkip.amazonaws.com)\" =~ ^((([0-9]{1,3}\.){3}[0-9]{1,3})|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))\$ ]] || systemctl restart warp-plus'"
  "0 0 * * 0 sudo bash /etc/nginx/cloudflareips.sh > /dev/null 2>&1"
)
crontab -l | grep -qE "x-ui" || { printf "%s\n" "${tasks[@]}" | crontab -; }
##################################Show Details##########################################################
if systemctl is-active --quiet x-ui || command -v x-ui &> /dev/null; then clear
	printf '0\n' | x-ui | grep --color=never -i ':' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
 	nginx -T 2>/dev/null | grep -i 'configuration file /etc/nginx/sites-enabled/'  | sed 's/.*configuration file //'  | tr -d ':' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
	hrline
	certbot certificates 2>/dev/null | grep -i 'Path:\|Domains:\|Expiry Date:' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
	hrline
	IPInfo=$(curl -Ls "https://ipapi.co/json" || curl -Ls "https://ipinfo.io/json")
 	OS=$(grep -E '^(NAME|VERSION)=' /etc/*release 2>/dev/null | awk -F= '{printf $2 " "}' | xargs)
	msg "ID: $(cat /etc/machine-id 2>/dev/null | cksum | awk '{print $1 % 65536}') | IP: ${IP4} | OS: ${OS}"
	msg "Hostname: $(uname -n) | $(echo "${IPInfo}" | jq -r '.org, .country_name' | paste -sd' | ')" # Used country_name
 	printf "\033[1;37;40m CPU: %s/%s Core | RAM: %s | SSD: %s Gi\033[0m\n" \
	"$(arch)" "$(nproc)" "$(free -h | awk '/^Mem:/{print $2}')" "$( LC_ALL=C df / | awk 'NR==2 {printf "%.0f", $2 / 1024 / 1024}')" # Ensure consistent df output
	hrline
  	msg_err  "XrayUI Panel [IP:PORT/PATH]"
    # $PORT and $RNDSTR here are the values read back from DB or fallbacks
	[[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4: http://$IP4:$PORT$RNDSTR"
	[[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6: http://[$IP6]:$PORT$RNDSTR"
 	msg_err "\n V2rayA Panel [IP:PORT]"
  	[[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4: http://$IP4:2017/"
	[[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6: http://[$IP6]:2017/"
	hrline
    # Create/Update .htpasswd for Nginx Basic Auth if Secure=yes
    if [[ "${Secure}" == "" ]]; then # Secure is empty if -secure yes
        rm -f /etc/nginx/.htpasswd # Remove old file to ensure single entry
        if command -v htpasswd &>/dev/null; then
            htpasswd -bcs /etc/nginx/.htpasswd "$XUIUSER" "$XUIPASS" # Use htpasswd if available
        else
            # Fallback to openssl passwd if htpasswd not found (less ideal for managing multiple users but ok for one)
            echo -n "${XUIUSER}:" > /etc/nginx/.htpasswd
            openssl passwd -apr1 "${XUIPASS}" >> /etc/nginx/.htpasswd
        fi
        chown "$nginxusr:$nginxusr" /etc/nginx/.htpasswd
        chmod 600 /etc/nginx/.htpasswd
    fi
 	msg_ok "Admin Panel [SSL]:\n"
    # $domain is the user-provided domain, $RNDSTR is path from DB (e.g. /esmars/), $RNDSTR2 is random for v2rayA
	msg_inf "XrayUI: https://${domain}${RNDSTR}"
	msg_inf "V2rayA: https://${domain}/${RNDSTR2}/\n"
	msg "Username: $XUIUSER\n Password: $XUIPASS" # These are from DB now: esmarsme/EsmarsMe13AMS1
	hrline
	msg_war "Note: Save This Screen!"
else
	nginx -t && printf '0\n' | x-ui | grep --color=never -i ':'
	msg_err "XUI-PRO : Installation error..."
fi
################################################ N-joy #################################################
