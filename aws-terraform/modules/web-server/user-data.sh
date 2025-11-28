#!/bin/bash
(
echo "qwe123"
echo "qwe123"
) | passwd --stdin root

sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
sed -i "s/^#PermitRootLogin yes/PermitRootLogin yes/g" /etc/ssh/sshd_config
service sshd restart

hostnamectl --static set-hostname ${hostname}

cat <<'EOT' > /etc/profile.d/prompt.sh
export PS1="[\[\e[1;31m\]\u\[\e[m\]@\[\e[1;32m\]\h\[\e[m\]: \[\e[1;36m\]\w\[\e[m\]]#"
EOT
source /etc/profile

# Install web server packages
dnf -y install php php-cli php-mysqlnd
dnf -y install httpd php-fpm mariadb105-client cronie
systemctl enable --now httpd php-fpm crond

# Create index page
echo "<h1>CloudNet@ FullLab - ${region} - Websrv${server_number}</h1>" > /var/www/html/index.html

# Download and configure ping checker
curl -o /opt/pingcheck.sh https://cloudneta-book.s3.ap-northeast-2.amazonaws.com/chapter8/pingchecker.sh
chmod +x /opt/pingcheck.sh

cat <<EOT>> /etc/crontab
*/3 * * * * root /opt/pingcheck.sh
EOT
systemctl restart crond

# Create health check file
echo "1" > /var/www/html/HealthCheck.txt