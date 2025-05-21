#!/bin/bash
#################### x-ui-pro v11.8.4 @ github.com/GFW4Fun ##############################################
[[ $EUID -ne 0 ]] && { echo "not root!"; exec sudo "$0" "$@"; }

msg()     { echo -e "\e[1;37;40m $1 \e[0m"; }
msg_ok()  { echo -e "\e[1;32;40m $1 \e[0m"; }
msg_err() { echo -e "\e[1;31;40m $1 \e[0m"; }
msg_inf() { echo -e "\e[1;36;40m $1 \e[0m"; }
msg_war() { echo -e "\e[1;33;40m $1 \e[0m"; }
hrline()  { printf '\033[1;35;40m%s\033[0m\n' "$(printf '%*s' "${COLUMNS:-$(tput cols)}" '' | tr ' ' "${1:--}")"; }

echo
msg_inf ' _     _ _     _ _____      _____   ______   _____ '
msg_inf '  \___/  |     |   |   ___ |_____] |_____/  |     |'
msg_inf ' _/   \_ |_____| __|__     |       |     \_ |_____|'
hrline

##################################Random Port and Fixed Path############################################
mkdir -p "${HOME}/.cache"
Pak=$(command -v apt||echo dnf);

# Жёстко прописанный путь к панели: /esmars/
RNDSTR="/esmars/"          
# Случайный путь для v2rayA
RNDSTR2=$(tr -dc A-Za-z0-9 </dev/urandom | head -c "$(shuf -i 6-12 -n1)");

# Случайный порт для X-UI
while true; do
  PORT=$((RANDOM%30000+30000))
  nc -z 127.0.0.1 "$PORT" &>/dev/null || break
done

Random_country=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)
TorRandomCountry=$(echo ATBEBGBRCACHCZDEDKEEESFIFRGBHRHUIEINITJPLVNLNOPLPTRORSSESGSKUAUS | fold -w2 | shuf -n1)

##################################Variables##############################################################
XUIDB="/etc/x-ui/x-ui.db";domain="";reality_domain=""
UNINSTALL="x";PNLNUM=1;CFALLOW="off";NOPATH="";RNDTMPL="n";CLIMIT="#"
WarpCfonCountry="";WarpLicKey="";CleanKeyCfon="";TorCountry="";Secure="no";ENABLEUFW=""
VERSION="last";CountryAllow="XX"

# Логин/пароль X-UI 
XUIUSER="esmarsme"
XUIPASS="EsmarsMe13AMS1"

################################Get arguments###########################################################
while [ "$#" -gt 0 ]; do
  case "$1" in
    -country) CountryAllow="$2"; shift 2;;
    -xuiver)  VERSION="$2"; shift 2;;
    -ufw)     ENABLEUFW="$2"; shift 2;;
    -secure)  Secure="$2"; shift 2;;
    -TorCountry) TorCountry="$2"; shift 2;;
    -WarpCfonCountry) WarpCfonCountry="$2"; shift 2;;
    -WarpLicKey) WarpLicKey="$2"; shift 2;;
    -CleanKeyCfon) CleanKeyCfon="$2"; shift 2;;
    -RandomTemplate) RNDTMPL="$2"; shift 2;;
    -Uninstall) UNINSTALL="$2"; shift 2;;
    -panel)    PNLNUM="$2"; shift 2;;
    -subdomain) domain="$2"; shift 2;;
    -realitydomain) reality_domain="$2"; shift 2;;
    -cdn) CFALLOW="$2"; shift 2;;
    *) shift 1;;
  esac
done

########################################################################################################
service_enable() {
for service_name in "$@"; do
  systemctl is-active --quiet "$service_name" && systemctl stop "$service_name" >/dev/null 2>&1
  systemctl daemon-reload         >/dev/null 2>&1
  systemctl enable "$service_name" >/dev/null 2>&1
  systemctl start "$service_name"  >/dev/null 2>&1
done
}

####################################UFW Rules################################################################
if [[ -n "$ENABLEUFW" ]]; then
  sudo "$Pak" -y install ufw
  ufw reset
  echo ssh ftp http https mysql 53 2052 2053 2082 2083 2086 2087 2095 2096 3389 5900 8443 8880 \
    | xargs -n 1 sudo ufw allow
  sudo ufw enable
  msg_inf "UFW settings changed!"
  exit 1
fi

##############################TOR/WARP/RandomHTML/Uninstall ... (без изменений)###########################
# ... [здесь блоки Tor / Warp / RandomTemplate / Uninstall] ...

##############################Domain Validations#########################################################
while [[ -z $(echo "$domain" | tr -d '[:space:]') ]]; do
  read -rp $'\e[1;32;40m Enter available subdomain (e.g. sub.domain.tld): \e[0m' domain
done
domain=$(echo "$domain" | tr -d '[:space:]')

# Спрашиваем reality_domain (SNI) - опционально
if [[ -z "$reality_domain" ]]; then
  read -rp $'\e[1;32;40m Enter domain for REALITY SNI (optional, press Enter to skip): \e[0m' reality_domain
fi
reality_domain=$(echo "$reality_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')

# Суб-домен/Главный
SubDomain=$(echo "$domain"  | sed 's/^[^ ]* \|\..*//g')
MainDomain=$(echo "$domain" | sed 's/.*\.\([^.]*\..*\)$/\1/')
if [[ "${SubDomain}.${MainDomain}" != "${domain}" ]]; then
  MainDomain=${domain}
fi

###############################Install Packages (Debian/Ubuntu)#########################################
$Pak -y update
for pkg in cronie psmisc unzip curl nginx nginx-full certbot python3-certbot-nginx sqlite3 jq openssl tor tor-geoipdb; do
  dpkg -l "$pkg" &>/dev/null || rpm -q "$pkg" &>/dev/null || $Pak -y install "$pkg"
done
service_enable "nginx" "tor" "cron" "crond"

############################### Stop Nginx and free 80/443 for certbot ##################################
vercompare() {
  if [ "$1" = "$2" ]; then echo "E"; return; fi
  [ "$(printf "%s\n%s" "$1" "$2" | sort -V | head -n1)" = "$1" ] && echo "L" || echo "G"
}
nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
ver_compare=$(vercompare "$nginx_ver" "1.25.1")
if [ "$ver_compare" = "L" ]; then
  OLD_H2=" http2"; NEW_H2="#"
else
  OLD_H2=""; NEW_H2=""
fi
sudo nginx -s stop 2>/dev/null
sudo systemctl stop nginx 2>/dev/null
sudo fuser -k 80/tcp 80/udp 443/tcp 443/udp 2>/dev/null

##################################GET SERVER IPv4-6######################################################
IP4_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
IP6_REGEX="([a-f0-9:]+:+)+[a-f0-9]+"
IP4=$(ip route get 8.8.8.8 2>&1 | grep -Po -- 'src \K\S*')
IP6=$(ip route get 2620:fe::fe 2>&1 | grep -Po -- 'src \K\S*')
[[ $IP4 =~ $IP4_REGEX ]] || IP4=$(curl -s ipv4.icanhazip.com)
[[ $IP6 =~ $IP6_REGEX ]] || IP6=$(curl -s ipv6.icanhazip.com)

##############################Install SSL################################################################
certbot certonly --standalone --non-interactive --force-renewal --agree-tos \
  --register-unsafely-without-email --cert-name "$MainDomain" -d "$domain"
if [[ ! -d "/etc/letsencrypt/live/${MainDomain}/" ]]; then
  systemctl start nginx >/dev/null 2>&1
  msg_err "$MainDomain SSL failed! Check Domain/IP!"
  exit 1
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
CLOUDFLARE_REAL_IPS_CONF="/etc/nginx/conf.d/cloudflare_real_ips.conf"
CLOUDFLARE_WHITELIST_CONF="/etc/nginx/conf.d/cloudflare_whitelist.conf"

echo "# Cloudflare IPs - Real IP Module Configuration" > "$CLOUDFLARE_REAL_IPS_CONF"
echo "# Generated on $(date)" >> "$CLOUDFLARE_REAL_IPS_CONF"
echo "" >> "$CLOUDFLARE_REAL_IPS_CONF"

echo "# Cloudflare IP Whitelist for Geo Module" > "$CLOUDFLARE_WHITELIST_CONF"
echo "# Generated on $(date)" >> "$CLOUDFLARE_WHITELIST_CONF"
echo "geo \$realip_remote_addr \$cloudflare_ip {" >> "$CLOUDFLARE_WHITELIST_CONF"
echo "    default 0;" >> "$CLOUDFLARE_WHITELIST_CONF"

for type in v4 v6; do
  for ip_addr in $(curl -sL "https://www.cloudflare.com/ips-$type"); do
    echo "set_real_ip_from $ip_addr;" >> "$CLOUDFLARE_REAL_IPS_CONF"
    echo "    $ip_addr 1;" >> "$CLOUDFLARE_WHITELIST_CONF"
  done
done

echo "real_ip_header X-Forwarded-For;" >> "$CLOUDFLARE_REAL_IPS_CONF"
echo "}" >> "$CLOUDFLARE_WHITELIST_CONF"
EOF

sudo bash "/etc/nginx/cloudflareips.sh" > /dev/null 2>&1
[[ "${CFALLOW}" == *"on"* ]] && CF_IP="" || CF_IP="#"
[[ "${Secure}" == *"yes"* ]] && Secure="" || Secure="#"

########################################### !!! /esmars/ !!! ###########################################
# Здесь путь к панели всегда /esmars/

########################################Update X-UI DB##################################################
UPDATE_XUIDB(){
if [[ -f $XUIDB ]]; then
  x-ui stop > /dev/null 2>&1
  fuser "$XUIDB" 2>/dev/null
  sqlite3 "$XUIDB" << EOF
DELETE FROM 'settings' WHERE key IN ('webPort','webCertFile','webKeyFile','webBasePath');
INSERT INTO 'settings' (key, value) VALUES
('webPort','${PORT}'),
('webCertFile',''),
('webKeyFile',''),
('webBasePath','/esmars/');
EOF
fi
}

###################################Install X-UI#########################################################
if ! systemctl is-active --quiet x-ui || ! command -v x-ui &> /dev/null; then
  [[ "$PNLNUM" =~ ^[0-3]+$ ]] || PNLNUM=1
  VERSION=$(echo "$VERSION" | tr -d '[:space:]')
  if [[ -z "$VERSION" || "$VERSION" != *.* ]]; then
    VERSION="master"
  else
    if [[ $PNLNUM == 1 ]]; then
      VERSION="v${VERSION#v}"
    else
      VERSION="${VERSION#v}"
    fi
  fi
  PANEL=(
    "https://raw.githubusercontent.com/alireza0/x-ui/${VERSION}/install.sh"
    "https://raw.githubusercontent.com/mhsanaei/3x-ui/${VERSION}/install.sh"
    "https://raw.githubusercontent.com/FranzKafkaYu/x-ui/${VERSION}/install_en.sh"
    "https://raw.githubusercontent.com/AghayeCoder/tx-ui/${VERSION}/install.sh"
  )
  [[ "$VERSION" == "master" ]] && VERSION=""
  printf 'n\n' | bash <(wget -qO- "${PANEL[$PNLNUM]}") "$VERSION" \
   || { printf 'n\n' | bash <(curl -Ls "${PANEL[$PNLNUM]}") "$VERSION"; }

  service_enable "x-ui"
  UPDATE_XUIDB
fi

###################################Get Installed XUI Port/Path##########################################
if [[ -f $XUIDB ]]; then
  x-ui stop > /dev/null 2>&1
  fuser "$XUIDB" 2>/dev/null
  PORT=$(sqlite3 "${XUIDB}" "SELECT value FROM settings WHERE key='webPort' LIMIT 1;" 2>&1)
  # Путь принудительно /esmars/
  RNDSTR="/esmars/"
  NOPATH=""
  # Логин/пароль берем свои
  XUIUSER="esmarsme"
  XUIPASS="EsmarsMe13AMS1"
  # Запишем их в БД
  #md5
  pass_hash=$(echo -n "$XUIPASS" | md5sum | awk '{print $1}')
  sqlite3 "$XUIDB" "DELETE FROM users;"
  sqlite3 "$XUIDB" "INSERT INTO users (username,password) VALUES ('$XUIUSER','$pass_hash');"
  x-ui start >/dev/null 2>&1
  # Если PORT пуст, ставим 2053
  [[ -z "$PORT" || ! "${PORT}" =~ ^[0-9]+$ ]] && PORT="2053"
else
  PORT="2053"
  RNDSTR="/esmars/"
  NOPATH=""
  XUIUSER="esmarsme"
  XUIPASS="EsmarsMe13AMS1"
fi

##############################country allow
CountryAllow=$(echo "$CountryAllow" | tr ',' '|' | tr -cd 'A-Za-z|' | awk '{print toupper($0)}')
if echo "$CountryAllow" | grep -Eq '^[A-Z]{2}(\|[A-Z]{2})*$'; then
	CLIMIT=$( [[ "$CountryAllow" == "XX" ]] && echo "#" || echo "" )
fi

#################################Nginx Config ( /esmars/ )############################################
cat > "/etc/nginx/sites-available/$MainDomain" << EOF
server {
	server_tokens off;
	server_name $MainDomain *.$MainDomain;
	listen 80;
	listen [::]:80;
	listen 443 ssl${OLD_H2};
	listen [::]:443 ssl${OLD_H2};
	${NEW_H2}http2 on; http3 on;
	index index.html index.nginx-debian.html;
	root /var/www/html;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers HIGH:!aNULL:!eNULL:!MD5:!DES:!RC4:!ADH:!SSLv3:!EXP:!PSK:!DSS;
	ssl_certificate /etc/letsencrypt/live/$MainDomain/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/$MainDomain/privkey.pem;

	if (\$host !~* ^(.+\.)?$MainDomain\$ ){return 444;}
	if (\$scheme ~* https) {set \$safe 1;}
	if (\$ssl_server_name !~* ^(.+\.)?$MainDomain\$ ) {set \$safe "\${safe}0";}
	if (\$safe = 10){return 444;}
	if (\$request_uri ~ "(\"|'|\`|~|,|:|--|;|%|\\\$|&&|\?\?|0x00|0X00|\||\\|\{|\}|<|>|\.\.\.|\.\.\/|\/\/\/)"){return 404;}
	error_page 400 402 403 500 501 502 503 504 =404 /404;
	proxy_intercept_errors on;

	location /esmars/ {
		${Secure}auth_basic "Restricted Access";
		${Secure}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:$PORT;
	}

	location /${RNDSTR2}/ {
		${Secure}auth_basic "Restricted Access";
		${Secure}auth_basic_user_file /etc/nginx/.htpasswd;
		proxy_redirect off;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_pass http://127.0.0.1:2017/;
	}

	${NOPATH} location / { try_files \$uri \$uri/ =404; }
}
EOF

ln -fs "/etc/nginx/sites-available/$MainDomain" "/etc/nginx/sites-enabled/$MainDomain" 2>/dev/null
rm -f /etc/nginx/sites-enabled/default 2>/dev/null
rm -f /etc/nginx/sites-enabled/*{~,bak,backup,save,swp,tmp} 2>/dev/null

if ! systemctl start nginx >/dev/null 2>&1 || ! nginx -t &>/dev/null || nginx -s reload 2>&1 | grep -q error; then
  pkill -9 nginx || killall nginx
  nginx -c /etc/nginx/nginx.conf
  nginx -s reload
fi

systemctl is-enabled x-ui || systemctl enable x-ui
x-ui start >/dev/null 2>&1

############################################ Warp Plus (MOD) ###########################################
# ... (без изменений)...

###################### cronjob for ssl/reload service/cloudflareips #####################################
tasks=(
  "0 0 * * * sudo su -c 'x-ui restart > /dev/null 2>&1 && systemctl reload v2raya warp-plus tor'"
  "0 0 * * * sudo su -c 'nginx -s reload 2>&1 | grep -q error && { pkill nginx || killall nginx; nginx -c /etc/nginx/nginx.conf; nginx -s reload; }'"
  "0 0 1 * * sudo su -c 'certbot renew --nginx --force-renewal --non-interactive --post-hook \"nginx -s reload\" > /dev/null 2>&1'"
  "* * * * * sudo su -c '[[ \"\$(curl -s --socks5-hostname 127.0.0.1:8086 checkip.amazonaws.com)\" =~ ^((([0-9]{1,3}\.){3}[0-9]{1,3})|(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}))\$ ]] || systemctl restart warp-plus'"
  "0 0 * * 0 sudo bash /etc/nginx/cloudflareips.sh > /dev/null 2>&1"
)
(crontab -l 2>/dev/null | grep -q "x-ui" ) || {
  ( crontab -l 2>/dev/null; printf "%s\n" "${tasks[@]}" ) | crontab -
}

################################## Show Details ########################################################
if systemctl is-active --quiet x-ui || command -v x-ui &> /dev/null; then
  clear
  printf '0\n' | x-ui | grep --color=never -i ':' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
  hrline
  nginx -T | grep -i 'configuration file /etc/nginx/sites-enabled/' | sed 's/.*configuration file //' \
    | tr -d ':' | awk '{print "\033[1;32;40m" $0 "\033[0m"}'
  hrline
  certbot certificates | grep -i 'Path:\|Domains:\|Expiry Date:' | awk '{print "\033[1;37;40m" $0 "\033[0m"}'
  hrline

  # Проверим валидность IPInfo
  IPInfo=$(curl -Ls "https://ipapi.co/json" || curl -Ls "https://ipinfo.io/json")
  if ! echo "$IPInfo" | jq . >/dev/null 2>&1; then
    IPInfo='{"org":"N/A","country":"N/A"}'
  fi

  OS=$(grep -E '^(NAME|VERSION)=' /etc/*release 2>/dev/null | awk -F= '{printf $2 " "}' | xargs)
  msg "ID: $(cat /etc/machine-id | cksum | awk '{print $1 % 65536}') | IP: ${IP4} | OS: ${OS}"
  msg "Hostname: $(uname -n) | $(echo "$IPInfo" | jq -r '.org'), $(echo "$IPInfo" | jq -r '.country')"

  printf "\033[1;37;40m CPU: %s/%s Core | RAM: %s | SSD: %s Gi\033[0m\n" \
    "$(arch)" "$(nproc)" "$(free -h | awk '/^Mem:/{print $2}')" \
    "$(df / | awk 'NR==2 {printf "%.2f", $2 / 1024 / 1024}')"
  hrline

  msg_err "XrayUI Panel [IP:PORT/PATH]"
  [[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4: http://$IP4:$PORT/esmars/"
  [[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6: http://[$IP6]:$PORT/esmars/"

  hrline
  msg_err "V2rayA Panel [IP:PORT]"
  [[ -n "$IP4" && "$IP4" =~ $IP4_REGEX ]] && msg_inf "IPv4: http://$IP4:2017/"
  [[ -n "$IP6" && "$IP6" =~ $IP6_REGEX ]] && msg_inf "IPv6: http://[$IP6]:2017/"

  hrline
  # Логин/пароль BasicAuth => esmarsme / EsmarsMe13AMS1
  rm -f /etc/nginx/.htpasswd
  if command -v htpasswd &>/dev/null; then
    htpasswd -bcs /etc/nginx/.htpasswd "esmarsme" "EsmarsMe13AMS1"
  else
    pass_hash=$(openssl passwd -apr1 "EsmarsMe13AMS1")
    echo "esmarsme:${pass_hash}" >/etc/nginx/.htpasswd
  fi

  msg_ok "Admin Panel [SSL]:\n"
  msg_inf "XrayUI: https://${domain}/esmars/"
  msg_inf "V2rayA: https://${domain}/${RNDSTR2}/\n"
  msg "Username: esmarsme\n Password: EsmarsMe13AMS1"

  # Reality SNI
  if [[ -n "$reality_domain" ]]; then
    hrline
    msg_ok "REALITY (SNI): $reality_domain"
    msg_inf "Include this domain as SNI in your Reality inbound config"
  fi

  hrline
  msg_war "Note: Save This Screen!"
else
  nginx -t
  printf '0\n' | x-ui | grep --color=never -i ':'
  msg_err "XUI-PRO : Installation error..."
fi

################################################ N-joy #################################################
