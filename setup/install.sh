#!/bin/bash

# Run as root:
# sudo ./install.sh [maildomain.com]

INSTALLDIR=`pwd`

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

HOSTNAME="$1"

if [ -z "$HOSTNAME" ]
  then
    PUBLIC_IP=`curl -s https://api.ipify.org`
    if [ ! -z "$PUBLIC_IP" ]; then
        HOSTNAME=`dig +short -x $PUBLIC_IP | sed 's/\.$//'`
        HOSTNAME="${HOSTNAME:-$PUBLIC_IP}"
    fi
    HOSTNAME="${HOSTNAME:-`hostname`}"
fi

MAILDOMAIN="${2:-$HOSTNAME}"

if lsof -Pi :25 -sTCP:LISTEN -t >/dev/null ; then
    echo "Error: SMTP server already running on port 25"
    exit 1
fi

if lsof -Pi :587 -sTCP:LISTEN -t >/dev/null ; then
    echo "Error: SMTP server already running on port 587"
    exit 1
fi

if lsof -Pi :993 -sTCP:LISTEN -t >/dev/null ; then
    echo "Error: IMAP server already running on port 993"
    exit 1
fi

if lsof -Pi :995 -sTCP:LISTEN -t >/dev/null ; then
    echo "Error: POP3 server already running on port 995"
    exit 1
fi

WILDDUCK_COMMIT="a38cebd538ed161cf086d515f8fe679e689043cf"
ZONEMTA_COMMIT="v1.0.4" # zone-mta-template
WEBMAIL_COMMIT="221783539bd4382917d750989bb2ab425804f80a"
WILDDUCK_ZONEMTA_COMMIT="e58db2e431669cf63454c530620176b6d387b364"
WILDDUCK_HARAKA_COMMIT="92eba398676dd2418a0830256aa554efd09fb546"
HARAKA_VERSION="2.8.18"

# stop on first error
set -e

export DEBIAN_FRONTEND=noninteractive

function hook_script {
    echo "#!/bin/bash
git --git-dir=/var/opt/$1.git --work-tree=\"/opt/$1\" checkout "\$3" -f
cd \"/opt/$1\"
rm -rf package-lock.json
npm install --production --progress=false
sudo $SYSTEMCTL_PATH restart $1 || echo \"Failed restarting service\"" > "/var/opt/$1.git/hooks/update"
    chmod +x "/var/opt/$1.git/hooks/update"
}

function hook_script_bower {
    echo "#!/bin/bash
git --git-dir=/var/opt/$1.git --work-tree=\"/opt/$1\" checkout "\$3" -f
cd \"/opt/$1\"
rm -rf package-lock.json
npm install --progress=false
npm run bowerdeps
sudo $SYSTEMCTL_PATH restart $1 || echo \"Failed restarting service\"" > "/var/opt/$1.git/hooks/update"
    chmod +x "/var/opt/$1.git/hooks/update"
}

# create user for running applications
useradd wildduck || echo "User wildduck already exists"

# create user for deploying code
useradd deploy || echo "User deploy already exists"

mkdir -p /home/deploy/.ssh
# add your own key to the authorized_keys file
echo "# Add your public key here
" >> /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy

NODE_PATH=`which node`
SYSTEMCTL_PATH=`which systemctl`

SRS_SECRET=`pwgen 12 -1`
DKIM_SECRET=`pwgen 12 -1`
ZONEMTA_SECRET=`pwgen 12 -1`
DKIM_SELECTOR=`$NODE_PATH -e 'console.log(Date().toString().substr(4, 3).toLowerCase() + new Date().getFullYear())'`

node -v
redis-server -v
mongod --version
echo "HOSTNAME: $HOSTNAME"

# remove old sudoers file
rm -rf /etc/sudoers.d/wildduck

####### WILD DUCK #######

# clear previous install
if [ -f "/etc/systemd/system/wildduck.service" ]
then
    $SYSTEMCTL_PATH stop wildduck || true
    $SYSTEMCTL_PATH disable wildduck || true
    rm -rf /etc/systemd/system/wildduck.service
fi
rm -rf /var/opt/wildduck.git
rm -rf /opt/wildduck
rm -rf /etc/wildduck

# fresh install
cd /var/opt
git clone --bare git://github.com/Lee182/wildduck.git

# create update hook so we can later deploy to this location
hook_script wildduck

# allow deploy user to restart wildduck service
echo "deploy ALL = (root) NOPASSWD: $SYSTEMCTL_PATH restart wildduck" >> /etc/sudoers.d/wildduck

# checkout files from git to working directory
mkdir -p /opt/wildduck
git --git-dir=/var/opt/wildduck.git --work-tree=/opt/wildduck checkout "$WILDDUCK_COMMIT"
cp -r /opt/wildduck/config /etc/wildduck
mv /etc/wildduck/default.toml /etc/wildduck/wildduck.toml

# enable example message
sed -i -e 's/"disabled": true/"disabled": false/g' /opt/wildduck/emails/00-example.json

# update ports
sed -i -e "s/999/99/g;s/localhost/$HOSTNAME/g" /etc/wildduck/imap.toml
sed -i -e "s/999/99/g;s/localhost/$HOSTNAME/g" /etc/wildduck/pop3.toml

echo "enabled=true
port=24
disableSTARTTLS=true" > /etc/wildduck/lmtp.toml

# make sure that DKIM keys are not stored to database as cleartext
#echo "secret=\"$DKIM_SECRET\"
#cipher=\"aes192\"" >> /etc/wildduck/dkim.toml

echo "user=\"wildduck\"
group=\"wildduck\"
emailDomain=\"$MAILDOMAIN\"" | cat - /etc/wildduck/wildduck.toml > temp && mv temp /etc/wildduck/wildduck.toml

sed -i -e "s/localhost:3000/$HOSTNAME/g;s/localhost/$HOSTNAME/g;s/2587/587/g" /etc/wildduck/wildduck.toml

cd /opt/wildduck
npm install --unsafe-perm --production

chown -R deploy:deploy /var/opt/wildduck.git
chown -R deploy:deploy /opt/wildduck

echo "[Unit]
Description=WildDuck Mail Server
Conflicts=cyrus.service dovecot.service
After=redis.service

[Service]
Environment=\"NODE_ENV=production\"
WorkingDirectory=/opt/wildduck
ExecStart=$NODE_PATH server.js --config=\"/etc/wildduck/wildduck.toml\"
ExecReload=/bin/kill -HUP \$MAINPID
Type=simple
Restart=always
SyslogIdentifier=wildduck-server

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/wildduck.service

$SYSTEMCTL_PATH enable wildduck.service

####### HARAKA #######

# clear previous install
if [ -f "/etc/systemd/system/haraka.service" ]
then
    $SYSTEMCTL_PATH stop haraka || true
    $SYSTEMCTL_PATH disable haraka || true
    rm -rf /etc/systemd/system/haraka.service
fi
rm -rf /var/opt/haraka-plugin-wildduck.git
rm -rf /opt/haraka

# fresh install
cd /var/opt
git clone --bare git://github.com/nodemailer/haraka-plugin-wildduck.git
echo "#!/bin/bash
git --git-dir=/var/opt/haraka-plugin-wildduck.git --work-tree=/opt/haraka/plugins/wildduck checkout "\$3" -f
cd /opt/haraka/plugins/wildduck
rm -rf package-lock.json
npm install --production --progress=false
sudo $SYSTEMCTL_PATH restart haraka || echo \"Failed restarting service\"" > "/var/opt/haraka-plugin-wildduck.git/hooks/update"
chmod +x "/var/opt/haraka-plugin-wildduck.git/hooks/update"

# allow deploy user to restart wildduck service
echo "deploy ALL = (root) NOPASSWD: $SYSTEMCTL_PATH restart haraka" >> /etc/sudoers.d/wildduck

cd
npm install --unsafe-perm -g Haraka@$HARAKA_VERSION
haraka -i /opt/haraka
cd /opt/haraka
npm install --unsafe-perm --save haraka-plugin-rspamd Haraka@$HARAKA_VERSION

# Haraka WIldDuck plugin. Install as separate repo as it can be edited more easily later
mkdir -p plugins/wildduck
git --git-dir=/var/opt/haraka-plugin-wildduck.git --work-tree=/opt/haraka/plugins/wildduck checkout "$WILDDUCK_HARAKA_COMMIT"

cd plugins/wildduck
npm install --unsafe-perm --production --progress=false

cd /opt/haraka
mv config/plugins config/plugins.bak

echo "26214400" > config/databytes
echo "$HOSTNAME" > config/me
echo "WildDuck MX" > config/smtpgreeting

echo "spf

## ClamAV is disabled by default. Make sure freshclam has updated all
## virus definitions and clamav-daemon has successfully started before
## enabling it.
#clamd

rspamd
tls
#dkim_verify

# WildDuck plugin handles recipient checking and queueing
wildduck" > config/plugins

cat 
echo "key=/root/letsencrypt/etc/live/$HOSTNAME/privkey.pem
cert=/root/letsencrypt/etc/live/$HOSTNAME/fullchain.pem" > config/tls.ini

echo 'host = localhost
port = 11333
add_headers = always
[dkim]
enabled = true
[header]
bar = X-Rspamd-Bar
report = X-Rspamd-Report
score = X-Rspamd-Score
spam = X-Rspamd-Spam
[check]
authenticated=true
private_ip=true
[reject]
spam = false
[soft_reject]
enabled = true
[rmilter_headers]
enabled = true
[spambar]
positive = +
negative = -
neutral = /' > config/rspamd.ini

echo 'clamd_socket = /var/run/clamav/clamd.ctl
[reject]
virus=true
error=false' > config/clamd.ini

cp plugins/wildduck/config/wildduck.yaml config/wildduck.yaml
sed -i -e "s/secret value/$SRS_SECRET/g" config/wildduck.yaml

echo '[Unit]
Description=Haraka MX Server
After=redis.service

[Service]
Environment="NODE_ENV=production"
WorkingDirectory=/opt/haraka
ExecStart=/usr/bin/node ./node_modules/.bin/haraka -c .
Type=simple
Restart=always
SyslogIdentifier=haraka

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/haraka.service

echo 'user=wildduck
group=wildduck' >> config/smtp.ini

chown -R deploy:deploy /opt/haraka
chown -R deploy:deploy /var/opt/haraka-plugin-wildduck.git

# ensure queue folder for Haraka
mkdir -p /opt/haraka/queue
chown -R wildduck:wildduck /opt/haraka/queue

$SYSTEMCTL_PATH enable haraka.service

#### ZoneMTA ####

# clear previous install
if [ -f "/etc/systemd/system/zone-mta.service" ]
then
    $SYSTEMCTL_PATH stop zone-mta || true
    $SYSTEMCTL_PATH disable zone-mta || true
    rm -rf /etc/systemd/system/zone-mta.service
fi
rm -rf /var/opt/zone-mta.git
rm -rf /var/opt/zonemta-wildduck.git
rm -rf /opt/zone-mta
rm -rf /etc/zone-mta

# fresh install
cd /var/opt
git clone --bare git://github.com/zone-eu/zone-mta-template.git zone-mta.git
git clone --bare git://github.com/nodemailer/zonemta-wildduck.git

# create update hooks so we can later deploy to this location
hook_script zone-mta
echo "#!/bin/bash
git --git-dir=/var/opt/zonemta-wildduck.git --work-tree=/opt/zone-mta/plugins/wildduck checkout "\$3" -f
cd /opt/zone-mta/plugins/wildduck
rm -rf package-lock.json
npm install --production --progress=false
sudo $SYSTEMCTL_PATH restart zone-mta || echo \"Failed restarting service\"" > "/var/opt/zonemta-wildduck.git/hooks/update"
chmod +x "/var/opt/zonemta-wildduck.git/hooks/update"

# allow deploy user to restart zone-mta service
echo "deploy ALL = (root) NOPASSWD: $SYSTEMCTL_PATH restart zone-mta" >> /etc/sudoers.d/zone-mta

# checkout files from git to working directory
mkdir -p /opt/zone-mta
git --git-dir=/var/opt/zone-mta.git --work-tree=/opt/zone-mta checkout "$ZONEMTA_COMMIT"

mkdir -p /opt/zone-mta/plugins/wildduck
git --git-dir=/var/opt/zonemta-wildduck.git --work-tree=/opt/zone-mta/plugins/wildduck checkout "$WILDDUCK_ZONEMTA_COMMIT"

cp -r /opt/zone-mta/config /etc/zone-mta
sed -i -e 's/port=2525/port=587/g;s/host="127.0.0.1"/host="0.0.0.0"/g;s/authentication=false/authentication=true/g' /etc/zone-mta/interfaces/feeder.toml
rm -rf /etc/zone-mta/plugins/dkim.toml
echo '# @include "/etc/wildduck/dbs.toml"' > /etc/zone-mta/dbs-production.toml
echo 'user="wildduck"
group="wildduck"' | cat - /etc/zone-mta/zonemta.toml > temp && mv temp /etc/zone-mta/zonemta.toml

echo "[[default]]
address=\"0.0.0.0\"
name=\"$HOSTNAME\"" > /etc/zone-mta/pools.toml

echo "[\"modules/zonemta-loop-breaker\"]
enabled=\"sender\"
secret=\"$ZONEMTA_SECRET\"
algo=\"md5\"" > /etc/zone-mta/plugins/loop-breaker.toml

echo '["modules/zonemta-onion"]
enabled=["sender"]
["modules/zonemta-onion".proxy]
host="127.0.0.1"
port=9050' > /etc/zone-mta/plugins/onion.toml

echo "[\"wildduck\"]
enabled=[\"receiver\", \"sender\"]

# which interfaces this plugin applies to
interfaces=[\"feeder\"]

# optional hostname to be used in headers
# defaults to os.hostname()
hostname=\"$HOSTNAME\"

# How long to keep auth records in log
authlogExpireDays=30

# SRS settings for forwarded emails

[srs]
    # Handle rewriting of forwarded emails
    enabled=true
    # SRS secret value. Must be the same as in the MX side
    secret=\"$SRS_SECRET\"
    # SRS domain, must resolve back to MX
    rewriteDomain=\"$MAILDOMAIN\"

[dkim]
# share config with WildDuck installation
# @include \"/etc/wildduck/dkim.toml\"
" > /etc/zone-mta/plugins/wildduck.toml

cd /opt/zone-mta/keys
openssl genrsa -out "$MAILDOMAIN-dkim.pem" 2048
chmod 400 "$MAILDOMAIN-dkim.pem"
openssl rsa -in "$MAILDOMAIN-dkim.pem" -out "$MAILDOMAIN-dkim.cert" -pubout
DNS_ADDRESS="v=DKIM1;p=$(grep -v -e '^-' $MAILDOMAIN-dkim.cert | tr -d "\n")"

DKIM_JSON=`DOMAIN="$MAILDOMAIN" SELECTOR="$DKIM_SELECTOR" node -e 'console.log(JSON.stringify({
  domain: process.env.DOMAIN,
  selector: process.env.SELECTOR,
  description: "Default DKIM key for "+process.env.DOMAIN,
  privateKey: fs.readFileSync("/opt/zone-mta/keys/"+process.env.DOMAIN+"-dkim.pem", "UTF-8")
}))'`

cd /opt/zone-mta
npm install --unsafe-perm --production
npm install zonemta-onion --save

cd /opt/zone-mta/plugins/wildduck
npm install --unsafe-perm --production

chown -R deploy:deploy /var/opt/zone-mta.git
chown -R deploy:deploy /var/opt/zonemta-wildduck.git
chown -R deploy:deploy /opt/zone-mta

echo '[Unit]
Description=Zone Mail Transport Agent
Conflicts=sendmail.service exim.service postfix.service
After=redis.service

[Service]
Environment="NODE_ENV=production"
WorkingDirectory=/opt/zone-mta
ExecStart=/usr/bin/node index.js --config="/etc/zone-mta/zonemta.toml"
ExecReload=/bin/kill -HUP $MAINPID
Type=simple
Restart=always
SyslogIdentifier=zone-mta

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/zone-mta.service

$SYSTEMCTL_PATH enable zone-mta.service

#### WWW ####
####
# clear previous install
if [ -f "/etc/systemd/system/wildduck-webmail.service" ]
then
    $SYSTEMCTL_PATH stop wildduck-webmail || true
    $SYSTEMCTL_PATH disable wildduck-webmail || true
    rm -rf /etc/systemd/system/wildduck-webmail.service
fi
rm -rf /var/opt/wildduck-webmail.git
rm -rf /opt/wildduck-webmail

# fresh install
cd /var/opt
git clone --bare git://github.com/nodemailer/wildduck-webmail.git

# create update hook so we can later deploy to this location
hook_script_bower wildduck-webmail
chmod +x /var/opt/wildduck-webmail.git/hooks/update

# allow deploy user to restart zone-mta service
echo "deploy ALL = (root) NOPASSWD: $SYSTEMCTL_PATH restart wildduck-webmail" >> /etc/sudoers.d/wildduck-webmail

# checkout files from git to working directory
mkdir -p /opt/wildduck-webmail
git --git-dir=/var/opt/wildduck-webmail.git --work-tree=/opt/wildduck-webmail checkout "$WEBMAIL_COMMIT"
cp /opt/wildduck-webmail/config/default.toml /etc/wildduck/wildduck-webmail.toml

sed -i -e "s/localhost/$HOSTNAME/g;s/999/99/g;s/2587/587/g;s/proxy=false/proxy=true/g" /etc/wildduck/wildduck-webmail.toml

cd /opt/wildduck-webmail

chown -R deploy:deploy /var/opt/wildduck-webmail.git
chown -R deploy:deploy /opt/wildduck-webmail

# we need to run bower which reject root
HOME=/home/deploy sudo -u deploy npm install
HOME=/home/deploy sudo -u deploy npm run bowerdeps

echo '[Unit]
Description=Wildduck Webmail
After=wildduck.service

[Service]
Environment="NODE_ENV=production"
WorkingDirectory=/opt/wildduck-webmail
ExecStart=/usr/bin/node server.js --config="/etc/wildduck/wildduck-webmail.toml"
ExecReload=/bin/kill -HUP $MAINPID
Type=simple
Restart=always
SyslogIdentifier=wildduck-www

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/wildduck-webmail.service

$SYSTEMCTL_PATH enable wildduck-webmail.service

ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 25/tcp
ufw allow 587/tcp
ufw allow 993/tcp
ufw allow 995/tcp
ufw --force enable

#### SSL CERTS ####

curl https://get.acme.sh | sh

echo "cert='/root/letsencrypt/etc/live/$HOSTNAME/fullchain.pem'
key='/root/letsencrypt/etc/live/$HOSTNAME/privkey.pem' > /etc/wildduck/tls.toml

sed -i -e "s/key=/#key=/g;s/cert=/#cert=/g" /etc/zone-mta/interfaces/feeder.toml
echo '# @include "../../wildduck/tls.toml"' >> /etc/zone-mta/interfaces/feeder.toml

# vanity script as first run should not restart anything
echo '#!/bin/bash
echo "OK"' > /usr/local/bin/reload-services.sh
chmod +x /usr/local/bin/reload-services.sh

# /root/.acme.sh/acme.sh --issue --nginx \
#     -d "$HOSTNAME" \
#     --key-file       /etc/wildduck/certs/privkey.pem  \
#     --fullchain-file /etc/wildduck/certs/fullchain.pem \
#     --reloadcmd     "/usr/local/bin/reload-services.sh" \
#     --force || echo "Warning: Failed to generate certificates, using self-signed certs"

# # Update site config, make sure ssl is enabled
# echo "server {
#     listen 80;
#     listen [::]:80;
#     listen 443 ssl http2;
#     listen [::]:443 ssl http2;

#     server_name $HOSTNAME;

#     ssl_certificate /etc/wildduck/certs/fullchain.pem;
#     ssl_certificate_key /etc/wildduck/certs/privkey.pem;

#     location / {
#         proxy_set_header X-Real-IP \$remote_addr;
#         proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
#         proxy_set_header HOST \$http_host;
#         proxy_set_header X-NginX-Proxy true;
#         proxy_pass http://127.0.0.1:3000;
#         proxy_redirect off;
#     }
# }" > "/etc/nginx/sites-available/$HOSTNAME"
# $SYSTEMCTL_PATH reload nginx

# update reload script for future updates
echo "#!/bin/bash
$SYSTEMCTL_PATH reload wildduck
$SYSTEMCTL_PATH restart zone-mta
$SYSTEMCTL_PATH restart haraka
$SYSTEMCTL_PATH restart wildduck-webmail" > /usr/local/bin/reload-services.sh
chmod +x /usr/local/bin/reload-services.sh

### start services ####

$SYSTEMCTL_PATH start mongod
$SYSTEMCTL_PATH start wildduck
$SYSTEMCTL_PATH start haraka
$SYSTEMCTL_PATH start zone-mta
$SYSTEMCTL_PATH start wildduck-webmail

cd "$INSTALLDIR"

echo "DEPLOY SETUP

1. Add your ssh key to /home/deploy/.ssh/authorized_keys

2. Clone application code
\$ git clone deploy@$HOSTNAME:/var/opt/wildduck.git
\$ git clone deploy@$HOSTNAME:/var/opt/zone-mta.git
\$ git clone deploy@$HOSTNAME:/var/opt/wildduck-webmail.git
\$ git clone deploy@$HOSTNAME:/var/opt/haraka-plugin-wildduck.git
\$ git clone deploy@$HOSTNAME:/var/opt/zonemta-wildduck.git

3. After making a change in local copy deploy to server
\$ git push origin master
(you might need to use -f when pushing first time)

NAMESERVER SETUP
================

MX
--
Add this MX record to the $MAILDOMAIN DNS zone:

$MAILDOMAIN. IN MX 5 $HOSTNAME.

SPF
---
Add this TXT record to the $MAILDOMAIN DNS zone:

$MAILDOMAIN. IN TXT \"v=spf1 a:$HOSTNAME ~all\"

DKIM
----
Add this TXT record to the $MAILDOMAIN DNS zone:

$DKIM_SELECTOR._domainkey.$MAILDOMAIN. IN TXT \"$DNS_ADDRESS\"

PTR
---
Make sure that your public IP has a PTR record set to $HOSTNAME.
If your hosting provider does not allow you to set PTR records but has
assigned their own hostname, then edit /etc/zone-mta/pools.toml and replace
the hostname $HOSTNAME with the actual hostname of this server.

(this text is also stored to $INSTALLDIR/$MAILDOMAIN-nameserver.txt)" > "$INSTALLDIR/$MAILDOMAIN-nameserver.txt"

printf "Waiting for the server to start up.."

until $(curl --output /dev/null --silent --fail http://localhost:8080/users); do
    printf '.'
    sleep 2
done
echo "."

# Ensure DKIM key
echo "Registering DKIM key for $MAILDOMAIN"
echo $DKIM_JSON

curl -i -XPOST http://localhost:8080/dkim \
-H 'Content-type: application/json' \
-d "$DKIM_JSON"

echo ""
cat "$INSTALLDIR/$MAILDOMAIN-nameserver.txt"
echo ""
echo "All done, open https://$HOSTNAME/:3000 in your browser"
