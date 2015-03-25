#!/bin/sh

chjail_user(){
username=$1
domainname=$2

#http://khmel.org/?p=624
#http://superuser.com/questions/370953/how-to-not-allow-user-outside-of-home-directory-with-sftp
###http://askubuntu.com/questions/134425/how-can-i-chroot-sftp-only-ssh-users-into-their-homes

mkdir -p /home/$username
echo "$username" > /home/$username/THIS_USER_IS_CHROOTED
useradd -d /home/$username -M -N -g uploaders $username
usermod -s "/usr/libexec/openssh/sftp-server" $username
chown root:root /home/$username
chmod 755 /home/$username
#ln -s /srv/www/$domainname /home/$username/public_html


bindString="/srv/www/$domainname /home/$username/public_html none bind"
if [ "`grep "$bindString" /etc/ssh/sshd_config | wc -l `" == "0" ]; then
    mkdir -p /home/$username/public_html
    chown -h $username:uploaders /home/$username/public_html
    chmod 755 /home/$username/public_html
    echo  fstab entry
    echo "$bindString" >> /etc/fstab;
    mount -a
fi

passwd $username

#If "Subsystem sftp /usr/lib/openssh/sftp-server" starts the line, then comment out and replace "Subsystem sftp internal-sftp"
sed -i 's&^Subsystem\tsftp\t/usr/libexec/openssh/sftp-server&#Subsystem\tsftp\t/usr/libexec/openssh/sftp-server\nSubsystem sftp internal-sftp&g' /etc/ssh/sshd_config

#Check to see if we already have a username entry, if not then add one
#userExists=`grep "Match User $username" /etc/ssh/sshd_config | wc -l `
groupExists=`grep "Match group uploaders" /etc/ssh/sshd_config | wc -l `
if [ "$groupExists" == "0" ]; then
    echo "Adding Entry to /etc/ssh/sshd_config/"
    echo "Match group uploaders" >> /etc/ssh/sshd_config
    echo "     ChrootDirectory /home/%u" >> /etc/ssh/sshd_config
    echo "     ForceCommand internal-sftp" >> /etc/ssh/sshd_config
    echo "     AllowTCPForwarding no" >> /etc/ssh/sshd_config
    echo "     X11Forwarding no" >> /etc/ssh/sshd_config
    echo "" >> /etc/ssh/sshd_config
fi


}

add_host(){
    hostname=$1
    port=$2
    shift; shift;

    ##hostname is not null
    if [ -n "$hostname" ]; then
        filepathhttp="/etc/httpd/sites.d/$hostname-80.conf"
        filepathhttps="/etc/httpd/sites.d/$hostname-443.conf"
	rootpath="/srv/www/$hostname"
        #If domain is subdomain, no redirect, if isnot, make non-www redirect to www.domain.com
        if [[ $domainname =~ ^.+\..+\..+ ]]; then
            ##This domain is a subdomain, don't redirect
            servername="$hostname"    

        else
            ##This domain has a non-www redirect to www.domain.com
            servername="www.$hostname"
        fi
        
        echo "<VirtualHost *:$port>"                                            > $filepathhttp
        echo "    ServerAdmin webmaster@$hostname"                              >> $filepathhttp
        echo "    DocumentRoot $rootpath"                                       >> $filepathhttp
        echo "    ServerName $servername"                                       >> $filepathhttp
        echo "    #ServerAlias $servername"                                     >> $filepathhttp
        echo "    ErrorLog $rootpath/error_log "                                >> $filepathhttp
        echo "    CustomLog $rootpath/access_log common "                       >> $filepathhttp
        echo "</VirtualHost> "                                                  >> $filepathhttp	

        if [ "$servername" != "$hostname" ]; then
            echo "<VirtualHost *:$port>"                                        >> $filepathhttp
            echo "    ServerName $hostname"                                     >> $filepathhttp
            echo "    Redirect permanent / http://www.$hostname"                >> $filepathhttp
            echo "</VirtualHost> "                                              >> $filepathhttp	
        fi

        echo "<VirtualHost *:443>"	 					> $filepathhttps
        echo "    ServerAdmin webmaster@$hostname" 				>> $filepathhttps
        echo "    DocumentRoot $rootpath/html"                                  >> $filepathhttps
        echo "    ServerName $servername"					>> $filepathhttps
        echo "    #ServerAlias $servername"					>> $filepathhttps
        echo "    ErrorLog $rootpath/ssl_error_log "                    	>> $filepathhttps
        echo "    TransferLog $rootpath/ssl_transfer_log"	  		>> $filepathhttps
        echo "    CustomLog $rootpath/ssl_access_log common "                   >> $filepathhttps
        echo "    LogLevel warn "						>> $filepathhttps
        echo "    SSLEngine on "		 				>> $filepathhttps
        echo "    SSLProtocol all -SSLv2"	 				>> $filepathhttps
        echo '    SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW'>> $filepathhttps
        echo "    SSLCertificateFile /etc/httpd/ssl/$hostname/apache.crt" 	>> $filepathhttps
        echo "    SSLCertificateKeyFile /etc/httpd/ssl/$hostname/apache.key"    >> $filepathhttps
        echo "    #SSLCertificateChainFile /etc/httpd/ssl/$hostname/DigiCertCA.crt" >> $filepathhttps
        echo '    <Files ~ "\.(cgi|shtml|phtml|php3?)$">'			>> $filepathhttps
        echo "            SSLOptions +StdEnvVars" 				>> $filepathhttps
        echo "    </Files>"			 				>> $filepathhttps
        echo "    <Directory \"$rootpath/cgi-bin\">"                            >> $filepathhttps
        echo "            SSLOptions +StdEnvVars"		 		>> $filepathhttps
        echo "    </Directory>"                                                 >> $filepathhttps
        echo '    SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0'>> $filepathhttps
        echo "</VirtualHost> "                                                  >> $filepathhttps	

        if [ "$servername" != "$hostname" ]; then
            echo "<VirtualHost *:443>"                                          >> $filepathhttps
            echo "    ServerName $hostname"                                     >> $filepathhttps
            echo "    Redirect permanent / https://www.$hostname"               >> $filepathhttps
            echo "    LogLevel warn "						>> $filepathhttps
            echo "    SSLEngine on "		 				>> $filepathhttps
            echo "    SSLProtocol all -SSLv2"	 				>> $filepathhttps
            echo '    SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW'>> $filepathhttps
            echo "    SSLCertificateFile /etc/httpd/ssl/$hostname/apache.crt" 	>> $filepathhttps
            echo "    SSLCertificateKeyFile /etc/httpd/ssl/$hostname/apache.key">> $filepathhttps
            echo "    #SSLCertificateChainFile /etc/httpd/ssl/$hostname/DigiCertCA.crt" >> $filepathhttps
            echo '    <Files ~ "\.(cgi|shtml|phtml|php3?)$">'			>> $filepathhttps
            echo "            SSLOptions +StdEnvVars" 				>> $filepathhttps
            echo "    </Files>"			 				>> $filepathhttps
            echo "    <Directory \"$rootpath/cgi-bin\">"		 	>> $filepathhttps
            echo "            SSLOptions +StdEnvVars"		 		>> $filepathhttps
            echo "    </Directory>"			 			>> $filepathhttps
            echo '    SetEnvIf User-Agent ".*MSIE.*" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0'>> $filepathhttps
            echo "</VirtualHost> "                                              >> $filepathhttps	
        fi


	dialog --title "$filepathhttps" --textbox "$filepathhttps" 20 80
        dialog --title "$filepathhttp" --textbox "$filepathhttp" 20 80
	mkdir -pv $rootpath
	mkdir -pv $rootpath/html
	mkdir -pv $rootpath/cgi-bin
	echo "<html><body><h1>$hostname</h1></body></html>" > $rootpath/html/index.html
	echo "Error Log" >> $rootpath/error_log
	echo "Access Log" >> $rootpath/access_log
	echo "SSL Error Log" >> $rootpath/ssl_error_log
	echo "SSL Access Log" >> $rootpath/ssl_access_log
	echo "SSL Transfer Log" >> $rootpath/ssl_transfer_log
	chown -Rv apache:uploaders $rootpath
	chmod -Rv 770 $rootpath
	service httpd reload
  fi
}

yum -y install dialog
dialog --backtitle "\Z1WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING "\
        --colors \
        --title "\Z7 Establish - CentOS6 Webserver Deployment"\
        --yesno "\Z1    Establish is a system configuration script which will assist in initial\
 web server configuration of the traditional LAMP stack. It assumes a clean image of CentOS 6\
 with no prior changes.\n    It will configure apache for hosting of multiple php applictions\
 with http and https configurations using self signed certificates. Creating of domains with\
 www.domain.com as well as subdomains are supported. \n\
    At the end of the process the script will look through creation of domains for which it will\
 write VirtualHost definations for www redirects for non-subdomain hosts as well as http and https\
 accessability. This program can be run multiple times reasonably safely, It is suggested that you\
 backup your own files, not that there should be any to backup since it is only to be ran on a server\
 with zero-configuration, straight from the system install. Project URL: https://github.com/microuser/establish\n\
\Zb\Z0Features: Apache with SSL Certificates, PHP5.5 with Modules, MYSQL, SSH Account Creation for uploads, \
VirtualHost Wizard for multiple creating multiple sites on a single IP.\n\
    \ZB\Z1          Select YES to continue with installation"\
        21 78

if [ $? != 0 ]; then #0 means yes
    exit 0
fi


##http://www.rackspace.com/knowledge_center/article/installing-mysql-server-on-centos
yum -y update
yum -y install nano

dialog 	--title "Make a developers group" --yesno "Make a developers group and /srv/www folder" 7 60
if [ $? == 0 ]; then #0 means yes
    groupadd developers
    groupadd uploaders

    #Add developers group sudo access
    echo "%developers        ALL=(ALL)       NOPASSWD: ALL" > /etc/sudoers.d/developers 
    mkdir -pv /srv
    mkdir -pv /srv/www/
    chown -Rv apache:uploaders /srv
    chmod -Rv 770 /srv

    #Add apache to group
    usermod -a -G uploaders apache
    usermod -a -G uploaders developers
fi




dialog 	--title "Make SSH Sudo User of group Developers" --yesno "" 7 60
if [ $? == 0 ]; then #0 means yes
    touch /tmp/form
    while [ -f "/tmp/form" ]
    do
        dialog 	--title "Add a SSH User" --yesno "Make SSH Sudo User of group Developers, part of uploaders group for use at /srv/www" 7 60
        if [ $? == 0 ]; then #0 means yes
            echo "" > /tmp/form
            user=""
            dialog --ok-label "Submit" \
                --backtitle "Add a SSH User" \
                --title "Host a SSH User" \
                --form "This SSH user will be part of the developers group which can login remotly to upload files to the /srv/www/ directory. Note that you can create user accounts with upload access limited specific to the domain later on during virtualhost configuration" \
                15 80 0 \
                "Username:" 	1 1	"$user" 	1 15 50 0 \
                2>/tmp/form
            confirmed=$?
            if [ $confirmed == "0" ]; then
                user=`sed -n '1p' /tmp/form`
                #Add the ssh user
                useradd $user
                passwd $user
                usermod -a -G developers $user	
            else
                #stop the loop by removing the response file
                rm -f /tmp/form
            fi
        else
            #stop the loop by removing the response file
            rm -f /tmp/form
        fi
    done
fi




dialog 	--title "Install PHP 5.5" --yesno "Install php 5.5 and its modules?" 7 60
if [ $? == 0 ]; then #0 means yes
    rpm -Uvh https://mirror.webtatic.com/yum/el6/latest.rpm

    yum -y install php55w php55w-opcache
    #installs mod_php, php55w-zts

    yum -y install php55w-bcmath
    #installs bcmath

    yum -y install php55w-cli
    #installs  php-cgi, php-pcntl, php-readline

    yum -y install php55w-common
    #installs php-api, php-bz2, php-calendar, php-ctype, php-curl, php-date, php-exif, php-fileinfo, php-ftp, php-gettext, php-gmp, php-hash, php-iconv, php-json, php-libxml, php-openssl, php-pcre, php-pecl-Fileinfo, php-pecl-phar, php-pecl-zip, php-reflection, php-session, php-shmop, php-simplexml, php-sockets, php-spl, php-tokenizer, php-zend-abi, php-zip, php-zlib

    ##php55w-dba 	
    ##php55w-devel 	
    ####php55w-embedded 	php-embedded-devel
    ##php55w-enchant 	
    ##php55w-fpm 	
    yum -y install php55w-gd 	
    ##php55w-imap 	
    ##php55w-interbase 	php_database, php-firebird
    ##php55w-intl 	
    ##php55w-ldap 	
    ##php55w-mbstring 	
    ##php55w-mcrypt 	
    ##php55w-mssql 	
    ##php55w-mysql 	php-mysqli, php_database
    ##php55w-mysqlnd 	php-mysqli, php_database
    ##php55w-odbc 	php-pdo_odbc, php_database
    ##php55w-opcache 	php55w-pecl-zendopcache
    yum -y install php55w-pdo 	
    ##php55w-pecl-gearman 	
    ##php55w-pecl-geoip 	
    ##php55w-pecl-memcache 	
    ##php55w-pecl-xdebug 	
    ##php55w-pgsql 	php-pdo_pgsql, php_database
    ##php55w-process 	php-posix, php-sysvmsg, php-sysvsem, php-sysvshm
    ##php55w-pspell 	
    ##php55w-recode 	
    ###php55w-snmp 	
    ##php55w-soap 	
    ##php55w-tidy 	
    ##php55w-xml 	php-dom, php-domxml, php-wddx, php-xsl
    ##php55w-xmlrpc 	
fi




dialog 	--title "Install Mysql" --yesno "Install mysql?" 7 60
if [ $? == 0 ]; then #0 means yes
    yum -y install mysql-server
    /sbin/service mysqld start
    /usr/bin/mysql_secure_installation

    #Make mysql run at startup
    chkconfig mysqld on
fi



dialog 	--title "Configure Apache & SSL" --yesno "Configure Apache & SSL" 7 60
if [ $? == 0 ]; then #0 means yes
    chkconfig mysqld on

    yum install mod_ssl
    mkdir -pv /etc/httpd/ssl
    mkdir -pv /etc/httpd/sites.d
    #mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.bk
    echo "LoadModule ssl_module modules/mod_ssl.so" > /etc/httpd/conf.d/ssl.conf
    echo "Listen 443" >> /etc/httpd/conf.d/ssl.conf
    echo "NameVirtualHost *:443" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLPassPhraseDialog  builtin" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLSessionCache         shmcb:/var/cache/mod_ssl/scache(512000)" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLSessionCacheTimeout  300" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLMutex default" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLRandomSeed startup file:/dev/urandom  256" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLRandomSeed connect builtin" >> /etc/httpd/conf.d/ssl.conf
    echo "SSLCryptoDevice builtin" >> /etc/httpd/conf.d/ssl.conf
    echo "" >> /etc/httpd/conf.d/ssl.conf
    echo "Include sites.d/*-443.conf" >> /etc/httpd/conf.d/ssl.conf
    echo "" >> /etc/httpd/conf.d/ssl.conf
    echo "" >> /etc/httpd/conf.d/ssl.conf
    echo "" >> /etc/httpd/conf.d/ssl.conf

    #Setting NameVirtualHost allows multiple on port 80. 
    sed -i 's/^Listen 80/#Listen 80/g' /etc/httpd/conf/httpd.conf

    ##We enable http port 80 connections 
    echo "Listen 80" > /etc/httpd/conf.d/http.conf
    echo "NameVirtualHost *:80" >> /etc/httpd/conf.d/http.conf
    echo "Include sites.d/*-80.conf" >> /etc/httpd/conf.d/http.conf
fi




touch /tmp/form
while [ -f "/tmp/form" ]
do
    dialog 	--title "Add a domain name" --yesno "Add a domain name" 7 60
    if [ $? == 0 ]; then #0 means yes

        domainname=""
        port="80"
        dialog --ok-label "Submit" \
                  --backtitle "Add an apache virtual host" \
                  --title "Host Add" \
                  --form "Add an apache virtual host" \
        15 80 0 \
                "DomainName:" 	1 1	"$domainname" 	1 15 50 0 \
                "Port:"    	2 1	"$port"  	2 15 50 0 \
        2>/tmp/form

        domainname=`sed -n '1p' /tmp/form | sed 's/^www\.//g'`
        port=`sed -n '2p' /tmp/form`
        
        # Add domain if the variable isn't empty
        add_host $domainname $port

        dialog 	--title "SSL Self Signed Certificate" --yesno "Install SSL Self Signed Certificate?" 7 60
        if [ $? == 0 ]; then #0 means yes
            mkdir -pv /etc/httpd/ssl/$domainname
            sslCert="/etc/httpd/ssl/$domainname/apache.crt"
            sslKey="/etc/httpd/ssl/$domainname/apache.key"
            sslSkip="0"

            if [ -e "$sslCert" ] && [ -e "$sslKey" ]; then
                dialog 	--title "A SSL Cert Already Exists." --yesno "A SSL Cert Already Exits. SKIP the creation, and use the existing one?" 7 60
                if [ $? == 0 ]; then
                    sslSkip="1"
                fi
            fi
            if [ "$sslSkip" == "0" ]; then
                #create the certificate and the key to protect it
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $sslKey -out $sslCert
            fi
        fi
        dialog --title "Add uploader account" --yesno "Add uploader account. This creates a system user with access to only the domain folder for SFTP. The user is jailed to this folder" 7 60
        if [ $? == 0 ]; then
            rm /tmp/form
            touch /tmp/form
            dialog --ok-label "Submit" \
                  --backtitle "Add an apache virtual host" \
                  --title "Host Add" \
                  --form "Add an apache virtual host" \
                15 80 0 \
                "Username:" 	1 1	"$domainname" 	1 15 50 0 \
                2>/tmp/form

            user=`sed -n '1p' /tmp/form`
            chjail_user $user $domainname

        fi
    
    else
        service httpd restart
        httpd -S
        #stop the loop by removing the response file
        rm -f /tmp/form
    fi
done
exit 0

