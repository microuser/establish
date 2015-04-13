#!/bin/sh

#https://www.howtoforge.com/perfect-server-centos-7-apache2-mysql-php-pureftpd-postfix-dovecot-and-ispconfig3-p3

yum update
yum -y install dialog

yum -y install nano wget net-tools NetowrkManager-tui bzip2




systemctl stop firewalld.service
systemctl disable firewalld.service

iptables -L 
firewall-cmd --state


#Disable SELinux

if [ `cat /etc/selinux/config | grep 'SELINUX=enforcing' | wc -l ` == 1 ] ; then
    sed -i 's#^SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config
    reboot
fi


#Enable Additional Repositores
rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY*

#This may need updating
rpm -ivh http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm    

yum -y install yum-priorities perl
    #search and replace multiline version
    perl -0777 -pi -e "s/enabled=1\ngpgcheck=1/enabled=1\npriority=10\ngpgcheck=1/g" /etc/yum.repos.d/epel.repo

yum update

yum -y groupinstall 'Development Tools'
yum -y install quota

#Append rootflags=uquota,gquota to grub
sed -i 's#GRUB_CMDLINE_LINUX="rd.lvm.lv=centos/root rd.lvm.lv=centos/swap crashkernel=auto rhgb quiet"#GRUB_CMDLINE_LINUX="rd.lvm.lv=centos/root rd.lvm.lv=centos/swap crashkernel=auto rhgb quiet rootflags=uquota,gquota"#g' /etc/default/grub

cp -v /boot/grub2/grub.cfg /boot/grub2/grub.cfg_bk
grub2-mkconfig -o /boot/grub2/grub.cfg
reboot

quotacheck -avugm

quotaon -avug

yum -y install ntp httpd mod_ssl mariadb-server php php-mysql php-mbstring phpmyadmin

yum -y install dovecot dovecot-mysql dovecot-pigeonhole


touch /etc/dovecot/dovecot-sql.conf
ln -s /etc/dovecot/dovecot-sql.conf /etc/dovecot-sql.conf

systemctl enable dovecot

systemctl start dovecot
yum -y install postfix
systemctl enable mariadb.service
systemctl start mariadb.service
systemctl stop sendmail.service
systemctl disable sendmail.service
systemctl enable postfix.service
systemctl restart postfix.service
yum -y install getmail


mysql_secure_installation

#nano /etc/httpd/conf.d/phpMyAdmin.conf

    perl -0777 -pi -e "s&<Directory /usr/share/phpMyAdmin/>\n   AddDefaultCharset UTF-8\n\n   <IfModule mod_authz_core.c>\n     # Apache 2.4\n     <RequireAny>\n       Require ip 127.0.0.1\n       Require ip ::1\n     </RequireAny>&<Directory /usr/share/phpMyAdmin/>\n   AddDefaultCharset UTF-8\n\n   <IfModule mod_authz_core.c>\n     # Apache 2.4\n     <RequireAny>\n       #Require ip 127.0.0.1\n       #Require ip ::1\n        Require all granted\n     </RequireAny>&g" /etc/httpd/conf.d/phpMyAdmin.conf

    sed -i "s#     = 'cookie'#     = 'http'#g" /etc/phpMyAdmin/config.inc.php


systemctl enable  httpd.service
systemctl restart  httpd.service



yum -y install amavisd-new spamassassin clamav clamd clamav-update unzip bzip2 unrar perl-DBD-mysql




sed -i "s@^Example@#Example@g" /etc/freshclam.conf
sa-update
freshclam 
systemctl enable amavisd.service




yum -y install php php-devel php-gd php-imap php-ldap php-mysql php-odbc php-pear php-xml php-xmlrpc php-pecl-apc php-mbstring php-mcrypt php-mssql php-snmp php-soap php-tidy curl curl-devel perl-libwww-perl ImageMagick libxml2 libxml2-devel mod_fcgid php-cli httpd-devel php-fpm


sed -i 's/^error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/error_reporting = E_ALL \& ~E_NOTICE \& ~E_DEPRECATED \& ~E_STRICT/g' /etc/php.ini


sed -i 's#date.timezone = 'Europe/Berlin'#date.timezone = 'America/Chicago'#g' /etc/php.ini

cd /usr/local/src
wget http://suphp.org/download/suphp-0.7.2.tar.gz
tar zxvf suphp-0.7.2.tar.gz

wget -O suphp.patch https://lists.marsching.com/pipermail/suphp/attachments/20130520/74f3ac02/attachment.patch
patch -Np1 -d suphp-0.7.2 < suphp.patch
cd suphp-0.7.2
autoreconf -if

./configure --prefix=/usr/ --sysconfdir=/etc/ --with-apr=/usr/bin/apr-1-config --with-apache-user=apache --with-setid-mode=owner --with-logfile=/var/log/httpd/suphp_log
make
make install

echo "LoadModule suphp_module modules/mod_suphp.so" >> /etc/httpd/conf.d/suphp.conf

echo "[global]" >/etc/suphp.conf
echo ";Path to logfile" >>/etc/suphp.conf
echo "logfile=/var/log/httpd/suphp.log" >>/etc/suphp.conf
echo ";Loglevel" >>/etc/suphp.conf
echo "loglevel=info" >>/etc/suphp.conf
echo ";User Apache is running as" >>/etc/suphp.conf
echo "webserver_user=apache" >>/etc/suphp.conf
echo ";Path all scripts have to be in" >>/etc/suphp.conf
echo "docroot=/" >>/etc/suphp.conf
echo ";Path to chroot() to before executing script" >>/etc/suphp.conf
echo ";chroot=/mychroot" >>/etc/suphp.conf
echo "; Security options" >>/etc/suphp.conf
echo "allow_file_group_writeable=true" >>/etc/suphp.conf
echo "allow_file_others_writeable=false" >>/etc/suphp.conf
echo "allow_directory_group_writeable=true" >>/etc/suphp.conf
echo "allow_directory_others_writeable=false" >>/etc/suphp.conf
echo ";Check wheter script is within DOCUMENT_ROOT" >>/etc/suphp.conf
echo "check_vhost_docroot=true" >>/etc/suphp.conf
echo ";Send minor error messages to browser" >>/etc/suphp.conf
echo "errors_to_browser=false" >>/etc/suphp.conf
echo ";PATH environment variable" >>/etc/suphp.conf
echo "env_path=/bin:/usr/bin" >>/etc/suphp.conf
echo ";Umask to set, specify in octal notation" >>/etc/suphp.conf
echo "umask=0077" >>/etc/suphp.conf
echo "; Minimum UID" >>/etc/suphp.conf
echo "min_uid=100" >>/etc/suphp.conf
echo "; Minimum GID" >>/etc/suphp.conf
echo "min_gid=100" >>/etc/suphp.conf
echo "" >>/etc/suphp.conf
echo "[handlers]" >>/etc/suphp.conf
echo ';Handler for php-scripts' >>/etc/suphp.conf
echo 'x-httpd-suphp="php:/usr/bin/php-cgi"' >>/etc/suphp.conf
echo ";Handler for CGI-scripts" >>/etc/suphp.conf
echo 'x-suphp-cgi="execute:!self"' >>/etc/suphp.conf


cp /etc/httpd/conf.d/php.conf /etc/httpd/conf.d/php.conf.bk
echo '#' > /etc/httpd/conf.d/php.conf
echo '# Cause the PHP interpreter to handle files with a .php extension.' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '<Directory /usr/share>' >> /etc/httpd/conf.d/php.conf
echo '<FilesMatch \.php$>' >> /etc/httpd/conf.d/php.conf
echo '    SetHandler application/x-httpd-php' >> /etc/httpd/conf.d/php.conf
echo '</FilesMatch>' >> /etc/httpd/conf.d/php.conf
echo '</Directory>' >> /etc/httpd/conf.d/php.conf
echo '' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '# Allow php to handle Multiviews' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo 'AddType text/html .php' >> /etc/httpd/conf.d/php.conf
echo '' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '# Add index.php to the list of files that will be served as directory' >> /etc/httpd/conf.d/php.conf
echo '# indexes.' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo 'DirectoryIndex index.php' >> /etc/httpd/conf.d/php.conf
echo '' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '# Uncomment the following lines to allow PHP to pretty-print .phps' >> /etc/httpd/conf.d/php.conf
echo '# files as PHP source code:' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '#<FilesMatch \.phps$>' >> /etc/httpd/conf.d/php.conf
echo '#    SetHandler application/x-httpd-php-source' >> /etc/httpd/conf.d/php.conf
echo '#</FilesMatch>' >> /etc/httpd/conf.d/php.conf
echo '' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo '# Apache specific PHP configuration options' >> /etc/httpd/conf.d/php.conf
echo '# those can be override in each configured vhost' >> /etc/httpd/conf.d/php.conf
echo '#' >> /etc/httpd/conf.d/php.conf
echo 'php_value session.save_handler "files"' >> /etc/httpd/conf.d/php.conf
echo 'php_value session.save_path    "/var/lib/php/session"' >> /etc/httpd/conf.d/php.conf



systemctl start php-fpm.service
systemctl enable php-fpm.service
systemctl enable httpd.service 
systemctl restart httpd.service 


yum -y install python-devel

wget http://dist.modpython.org/dist/mod_python-3.5.0.tgz
tar xfz mod_python-3.5.0.tgz
cd mod_python-3.5.0
./configure
make
make install
echo 'LoadModule python_module modules/mod_python.so' > /etc/httpd/conf.modules.d/10-python.conf
systemctl restart httpd.service 
yum -y install pure-ftpd
systemctl enable pure-ftpd.service
systemctl start pure-ftpd.service



yum install openssl
sed -i 's/# TLS                      1/TLS                      2/g' /etc/pure-ftpd/pure-ftpd.conf
mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem 

chmod 600 /etc/ssl/private/pure-ftpd.pem
systemctl restart pure-ftpd.service

yum -y install bind bind-utils
cp /etc/named.conf /etc/named.conf_bak
cat /dev/null > /etc/named.conf

echo '' >> /etc/named.conf
echo '//' >> /etc/named.conf
echo '// named.conf' >> /etc/named.conf
echo '//' >> /etc/named.conf
echo '// Provided by Red Hat bind package to configure the ISC BIND named(8) DNS' >> /etc/named.conf
echo '// server as a caching only nameserver (as a localhost DNS resolver only).' >> /etc/named.conf
echo '//' >> /etc/named.conf
echo '// See /usr/share/doc/bind*/sample/ for example named configuration files.' >> /etc/named.conf
echo '//' >> /etc/named.conf
echo 'options {' >> /etc/named.conf
echo '        listen-on port 53 { any; };' >> /etc/named.conf
echo '        listen-on-v6 port 53 { any; };' >> /etc/named.conf
echo '        directory       "/var/named";' >> /etc/named.conf
echo '        dump-file       "/var/named/data/cache_dump.db";' >> /etc/named.conf
echo '        statistics-file "/var/named/data/named_stats.txt";' >> /etc/named.conf
echo '        memstatistics-file "/var/named/data/named_mem_stats.txt";' >> /etc/named.conf
echo '        allow-query     { any; };' >> /etc/named.conf
echo '				allow-recursion {"none";};' >> /etc/named.conf
echo '        recursion no;' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo 'logging {' >> /etc/named.conf
echo '        channel default_debug {' >> /etc/named.conf
echo '                file "data/named.run";' >> /etc/named.conf
echo '                severity dynamic;' >> /etc/named.conf
echo '        };' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo 'zone "." IN {' >> /etc/named.conf
echo '        type hint;' >> /etc/named.conf
echo '        file "named.ca";' >> /etc/named.conf
echo '};' >> /etc/named.conf
echo 'include "/etc/named.conf.local";' >> /etc/named.conf

touch /etc/named.conf.local

systemctl enable named.service
systemctl start named.service

yum -y install webalizer awstats perl-DateTime-Format-HTTP perl-DateTime-Format-Builder

cd /tmp
wget http://olivier.sessink.nl/jailkit/jailkit-2.17.tar.gz
tar xvfz jailkit-2.17.tar.gz
cd jailkit-2.17
./configure
make
make install
cd ..
rm -rf jailkit-2.17*



yum -y install fail2ban 


yum -y install rkhunter

yum -y install mailman


touch /var/lib/mailman/data/aliases
/usr/lib/mailman/bin/newlist mailman

echo '## mailman mailing list' >> /etc/aliases
echo 'mailman:              "|/usr/lib/mailman/mail/mailman post mailman"' >> /etc/aliases
echo 'mailman-admin:        "|/usr/lib/mailman/mail/mailman admin mailman"' >> /etc/aliases
echo 'mailman-bounces:      "|/usr/lib/mailman/mail/mailman bounces mailman"' >> /etc/aliases
echo 'mailman-confirm:      "|/usr/lib/mailman/mail/mailman confirm mailman"' >> /etc/aliases
echo 'mailman-join:         "|/usr/lib/mailman/mail/mailman join mailman"' >> /etc/aliases
echo 'mailman-leave:        "|/usr/lib/mailman/mail/mailman leave mailman"' >> /etc/aliases
echo 'mailman-owner:        "|/usr/lib/mailman/mail/mailman owner mailman"' >> /etc/aliases
echo 'mailman-request:      "|/usr/lib/mailman/mail/mailman request mailman"' >> /etc/aliases
echo 'mailman-subscribe:    "|/usr/lib/mailman/mail/mailman subscribe mailman"' >> /etc/aliases
echo 'mailman-unsubscribe:  "|/usr/lib/mailman/mail/mailman unsubscribe mailman"' >> /etc/aliases


newaliases
systemctl restart postfix.service

perl -0777 -pi -e "s&ScriptAlias /mailman/ /usr/lib/mailman/cgi-bin/\n<Directory /usr/lib/mailman/cgi-bin/>&ScriptAlias /mailman/ /usr/lib/mailman/cgi-bin/\nScriptAlias /cgi-bin/mailman/ /usr/lib/mailman/cgi-bin/\n<Directory /usr/lib/mailman/cgi-bin/>&g" /etc/httpd/conf.d/mailman.conf


echo '#' > /etc/httpd/conf.d/mailman.conf
echo '#  httpd configuration settings for use with mailman.' >> /etc/httpd/conf.d/mailman.conf
echo '#' >> /etc/httpd/conf.d/mailman.conf
echo '' >> /etc/httpd/conf.d/mailman.conf
echo 'ScriptAlias /mailman/ /usr/lib/mailman/cgi-bin/' >> /etc/httpd/conf.d/mailman.conf
echo 'ScriptAlias /cgi-bin/mailman/ /usr/lib/mailman/cgi-bin/' >> /etc/httpd/conf.d/mailman.conf
echo '<Directory /usr/lib/mailman/cgi-bin/>' >> /etc/httpd/conf.d/mailman.conf
echo '    AllowOverride None' >> /etc/httpd/conf.d/mailman.conf
echo '    Options ExecCGI' >> /etc/httpd/conf.d/mailman.conf
echo '    Order allow,deny' >> /etc/httpd/conf.d/mailman.conf
echo '    Allow from all' >> /etc/httpd/conf.d/mailman.conf
echo '</Directory>' >> /etc/httpd/conf.d/mailman.conf
echo '' >> /etc/httpd/conf.d/mailman.conf
echo '' >> /etc/httpd/conf.d/mailman.conf
echo '#Alias /pipermail/ /var/lib/mailman/archives/public/' >> /etc/httpd/conf.d/mailman.conf
echo 'Alias /pipermail /var/lib/mailman/archives/public/' >> /etc/httpd/conf.d/mailman.conf
echo '<Directory /var/lib/mailman/archives/public>' >> /etc/httpd/conf.d/mailman.conf
echo '    Options Indexes MultiViews FollowSymLinks' >> /etc/httpd/conf.d/mailman.conf
echo '    AllowOverride None' >> /etc/httpd/conf.d/mailman.conf
echo '    Order allow,deny' >> /etc/httpd/conf.d/mailman.conf
echo '    Allow from all' >> /etc/httpd/conf.d/mailman.conf
echo '    AddDefaultCharset Off' >> /etc/httpd/conf.d/mailman.conf
echo '</Directory>' >> /etc/httpd/conf.d/mailman.conf
echo '' >> /etc/httpd/conf.d/mailman.conf
echo '# Uncomment the following line, to redirect queries to /mailman to the' >> /etc/httpd/conf.d/mailman.conf
echo '# listinfo page (recommended).' >> /etc/httpd/conf.d/mailman.conf
echo '' >> /etc/httpd/conf.d/mailman.conf
echo '# RedirectMatch ^/mailman[/]*$ /mailman/listinfo' >> /etc/httpd/conf.d/mailman.conf


systemctl restart httpd.service

systemctl enable mailman.service
systemctl start mailman.service
yum -y install roundcubemail


echo '#                 ' > /etc/httpd/conf.d/roundcubemail.conf
echo '# Round Cube Webmail is a browser-based multilingual IMAP client' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo 'Alias /roundcubemail /usr/share/roundcubemail' >> /etc/httpd/conf.d/roundcubemail.conf
echo 'Alias /webmail /usr/share/roundcubemail' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '# Define who can access the Webmail' >> /etc/httpd/conf.d/roundcubemail.conf
echo '# You can enlarge permissions once configured' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#<Directory /usr/share/roundcubemail/>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    <IfModule mod_authz_core.c>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        # Apache 2.4' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Require local' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    </IfModule>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    <IfModule !mod_authz_core.c>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        # Apache 2.2' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Order Deny,Allow' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Deny from all' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Allow from 127.0.0.1' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Allow from ::1' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    </IfModule>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '<Directory /usr/share/roundcubemail/>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        Options none' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        AllowOverride Limit' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        Require all granted' >> /etc/httpd/conf.d/roundcubemail.conf
echo '</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '# Define who can access the installer' >> /etc/httpd/conf.d/roundcubemail.conf
echo '# keep this secured once configured' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#<Directory /usr/share/roundcubemail/installer/>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    <IfModule mod_authz_core.c>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        # Apache 2.4' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Require local' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    </IfModule>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    <IfModule !mod_authz_core.c>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        # Apache 2.2' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Order Deny,Allow' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Deny from all' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Allow from 127.0.0.1' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#        Allow from ::1' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#    </IfModule>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '#</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '<Directory /usr/share/roundcubemail/installer>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        Options none' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        AllowOverride Limit' >> /etc/httpd/conf.d/roundcubemail.conf
echo '        Require all granted' >> /etc/httpd/conf.d/roundcubemail.conf
echo '</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '' >> /etc/httpd/conf.d/roundcubemail.conf
echo '# Those directories should not be viewed by Web clients.' >> /etc/httpd/conf.d/roundcubemail.conf
echo '<Directory /usr/share/roundcubemail/bin/>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '    Order Allow,Deny' >> /etc/httpd/conf.d/roundcubemail.conf
echo '    Deny from all' >> /etc/httpd/conf.d/roundcubemail.conf
echo '</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '<Directory /usr/share/roundcubemail/plugins/enigma/home/>' >> /etc/httpd/conf.d/roundcubemail.conf
echo '    Order Allow,Deny' >> /etc/httpd/conf.d/roundcubemail.conf
echo '    Deny from all' >> /etc/httpd/conf.d/roundcubemail.conf
echo '</Directory>' >> /etc/httpd/conf.d/roundcubemail.conf


systemctl restart httpd.service


##Ask user for round cube password
password="dcdpro200"
mysql -u root -p -e "CREATE DATABASE roundcubedb;"
mysql -u root -p -e "CREATE USER roundcubeuser@localhost IDENTIFIED BY 'dcdpro200';"
mysql -u root -p -e "GRANT ALL PRIVILEGES on roundcubedb.* to roundcubeuser@localhost ;"
mysql -u root -p -e "FLUSH PRIVILEGES;"

password="dca8i943waqlkcdj"
mysql -u root -p -e "CREATE DATABASE roundcubedb; CREATE USER roundcubeuser@localhost IDENTIFIED BY '$password'; GRANT ALL PRIVILEGES on roundcubedb.* to roundcubeuser@localhost ;FLUSH PRIVILEGES;"


#Connect to your IP

ip addr

##http://192.168.1.100/roundcubemail/installer
#Click Next if all is OK
#Set your MySQL info you just set

echo '<?php' > /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '/* Local configuration for Roundcube Webmail */' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// SQL DATABASE' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// Database connection string (DSN) for read+write operations' >> /etc/roundcubemail/config.inc.php
echo '// Format (compatible with PEAR MDB2): db_provider://user:password@host/database' >> /etc/roundcubemail/config.inc.php
echo '// Currently supported db_providers: mysql, pgsql, sqlite, mssql or sqlsrv' >> /etc/roundcubemail/config.inc.php
echo '// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php' >> /etc/roundcubemail/config.inc.php
echo '// NOTE: for SQLite use absolute path: sqlite:////full/path/to/sqlite.db?mode=0646' >> /etc/roundcubemail/config.inc.php
echo '$config["db_dsnw"] = "mysql://roundcubeuser:dcdpro200@localhost/roundcubedb";' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// IMAP' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// The mail host chosen to perform the log-in.' >> /etc/roundcubemail/config.inc.php
echo '// Leave blank to show a textbox at login, give a list of hosts' >> /etc/roundcubemail/config.inc.php
echo '// to display a pulldown menu or set one host as string.' >> /etc/roundcubemail/config.inc.php
echo '// To use SSL/TLS connection, enter hostname with prefix ssl:// or tls://' >> /etc/roundcubemail/config.inc.php
echo '// Supported replacement variables:' >> /etc/roundcubemail/config.inc.php
echo '// %n - hostname ($_SERVER["SERVER_NAME"])' >> /etc/roundcubemail/config.inc.php
echo '// %t - hostname without the first part' >> /etc/roundcubemail/config.inc.php
echo '// %d - domain (http hostname $_SERVER["HTTP_HOST"] without the first part)' >> /etc/roundcubemail/config.inc.php
echo '// %s - domain name after the "@" from e-mail address provided at login screen' >> /etc/roundcubemail/config.inc.php
echo '// For example %n = mail.domain.tld, %t = domain.tld' >> /etc/roundcubemail/config.inc.php
echo '// WARNING: After hostname change update of mail_host column in users table is' >> /etc/roundcubemail/config.inc.php
echo '//          required to match old user data records with the new host.' >> /etc/roundcubemail/config.inc.php
echo '$config["default_host"] = "localhost";' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// SMTP' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// SMTP server host (for sending mails).' >> /etc/roundcubemail/config.inc.php
echo '// To use SSL/TLS connection, enter hostname with prefix ssl:// or tls://' >> /etc/roundcubemail/config.inc.php
echo '// If left blank, the PHP mail() function is used' >> /etc/roundcubemail/config.inc.php
echo '// Supported replacement variables:' >> /etc/roundcubemail/config.inc.php
echo '// %h - users IMAP hostname' >> /etc/roundcubemail/config.inc.php
echo '// %n - hostname ($_SERVER["SERVER_NAME"])' >> /etc/roundcubemail/config.inc.php
echo '// %t - hostname without the first part' >> /etc/roundcubemail/config.inc.php
echo '// %d - domain (http hostname $_SERVER["HTTP_HOST"] without the first part)' >> /etc/roundcubemail/config.inc.php
echo '// %z - IMAP domain (IMAP hostname without the first part)' >> /etc/roundcubemail/config.inc.php
echo '// For example %n = mail.domain.tld, %t = domain.tld' >> /etc/roundcubemail/config.inc.php
echo '$config["smtp_server"] = "ssl://smtp.mq.savedgames.net";' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// provide an URL where a user can get support for this Roundcube installation' >> /etc/roundcubemail/config.inc.php
echo '// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!' >> /etc/roundcubemail/config.inc.php
echo '$config["support_url"] = ""; ' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// this key is used to encrypt the users imap password which is stored' >> /etc/roundcubemail/config.inc.php
echo '// in the session record (and the client cookie if remember password is enabled).' >> /etc/roundcubemail/config.inc.php
echo '// please provide a string of exactly 24 chars.' >> /etc/roundcubemail/config.inc.php
echo '$config["des_key"] = "jvQX5q%ODd_zKop!XoH=Gj?8";' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// PLUGINS' >> /etc/roundcubemail/config.inc.php
echo '// ----------------------------------' >> /etc/roundcubemail/config.inc.php
echo '// List of active plugins (in plugins/ directory)' >> /etc/roundcubemail/config.inc.php
echo '$config["plugins"] = array();' >> /etc/roundcubemail/config.inc.php
echo '' >> /etc/roundcubemail/config.inc.php
echo '// Set the spell checking engine. Possible values:' >> /etc/roundcubemail/config.inc.php
echo '// - googie  - the default (also used for connecting to Nox Spell Server, see "spellcheck_uri" setting)' >> /etc/roundcubemail/config.inc.php
echo '// - pspell  - requires the PHP Pspell module and aspell installed' >> /etc/roundcubemail/config.inc.php
echo '// - enchant - requires the PHP Enchant module' >> /etc/roundcubemail/config.inc.php
echo '// - atd     - install your own After the Deadline server or check with the people at http\://www.afterthedeadline.com before using their API' >> /etc/roundcubemail/config.inc.php
echo '// Since Google shut down their public spell checking service, the default settings' >> /etc/roundcubemail/config.inc.php
echo '// connect to http://spell.roundcube.net which is a hosted service provided by Roundcube.' >> /etc/roundcubemail/config.inc.php
echo '// You can connect to any other googie-compliant service by setting spellcheck_uri accordingly.' >> /etc/roundcubemail/config.inc.php
echo '$config["spellcheck_engine"] = "pspell";' >> /etc/roundcubemail/config.inc.php



####Remove Installation folder

