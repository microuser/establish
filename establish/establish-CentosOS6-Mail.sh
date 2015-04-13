#!/bin/sh
#https://www.rosehosting.com/blog/mailserver-with-virtual-users-and-domains-using-postfix-and-dovecot-on-a-centos-6-vps/



if ! type -path "dig" > /dev/null 2>&1; then yum install bind-utils -y; fi

 DOMAIN=mydomain.com
 NSHOSTS=( "$(dig @4.2.2.2 +short MX ${DOMAIN}|sort -n|cut -d' ' -f2)" )
 for NS in ${NSHOSTS[@]}; do printf "%-15s => %-s\n" "$(dig @4.2.2.2 +short A ${NS})" "${NS}"; done
 unset DOMAIN NSHOSTS

## screen -U -S mailserver-screen
## yum update

groupadd vmail -g 2222
yum remove exim sendmail
yum install postfix cronie

cp /etc/postfix/main.cf{,.orig}


#$ nano /etc/postfix/main.cf
#[Edit]     #myhostname = host.domain.tld
#            myhostname = mail.savedgames.net

#
#[Same] queue_directory = /var/spool/postfix
#[Same] command_directory = /usr/sbin
#[Same] daemon_directory = /usr/libexec/postfix
#[Same] data_directory = /var/lib/postfix
#[Same] mail_owner = postfix
#[Same] unknown_local_recipient_reject_code = 550
#[Edit] alias_maps = hash:/etc/postfix/aliases      
#        From alias_maps = hash:/etc/aliases
#        To  alias_maps = hash:/etc/postfix/aliases
#[Edit] From:   alias_database = hash:/etc/aliases
#       To:     alias_database = $alias_maps
#[Edit] From:   inet_interfaces = localhost
#       To:     inet_interfaces = all
#       From    inet_protocols = all
#       To      inet_protocols = ipv4

#[Same] mydestination = $myhostname, localhost.$mydomain, localhost
#[Same] debug_peer_level = 2
#[Same] debugger_command =         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin         ddd $daemon_directory/$process_name $process_id & sleep 5
#[Smae] sendmail_path = /usr/sbin/sendmail.postfix

#Append all the following:
    #relay_domains = *
    #virtual_alias_maps=hash:/etc/postfix/vmail_aliases
    #virtual_mailbox_domains=hash:/etc/postfix/vmail_domains
    #virtual_mailbox_maps=hash:/etc/postfix/vmail_mailbox

    #virtual_mailbox_base = /var/vmail
    #virtual_minimum_uid = 2222
    #virtual_transport = virtual
    #virtual_uid_maps = static:2222
    #virtual_gid_maps = static:2222

    #smtpd_sasl_auth_enable = yes
    #smtpd_sasl_type = dovecot
    #smtpd_sasl_path = /var/run/dovecot/auth-client
    #smtpd_sasl_security_options = noanonymous
    #smtpd_sasl_tls_security_options = $smtpd_sasl_security_options
    #smtpd_sasl_local_domain = $mydomain
    #broken_sasl_auth_clients = yes

    #smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
    #smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

## nano /etc/postfix/vmail_domains
#[Append Following]
#        savedgames.net            OK
#        iusethis.org             OK

## vim /etc/postfix/vmail_mailbox
#[Append Following]
# info@mydomain.com           mydomain.com/info/
# info@my-otherdomain.com     my-otherdomain.com/info/

## vim /etc/postfix/vmail_aliases
#[Append Following]
# info@mydomain.com           info@mydomain.com
# info@my-otherdomain.com     foo@bar.tld

#uncomment /etc/postfix/master.cf
#            #submission inet n       -       n       -       -       smtpd
#            submission inet n       -       n       -       -       smtpd
#                   -o smtpd_tls_security_level=encrypt
#                 -o smtpd_sasl_auth_enable=yes
#                 -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#                    -o milter_macro_daemon_name=ORIGINATING



yum install dovecot
cp /etc/dovecot/dovecot.conf{,.orig}

nano /etc/dovecot/dovecot.conf
#[Repalce entire file with..]

        listen = *
        ssl = no
        protocols = imap lmtp
        disable_plaintext_auth = no
        auth_mechanisms = plain login
        mail_access_groups = vmail
        default_login_user = vmail
        first_valid_uid = 2222
        first_valid_gid = 2222
        #mail_location = maildir:~/Maildir
        mail_location = maildir:/var/vmail/%d/%n

        passdb {
            driver = passwd-file
            args = scheme=SHA1 /etc/dovecot/passwd
        }
        userdb {
            driver = static
            args = uid=2222 gid=2222 home=/var/vmail/%d/%n allow_all_users=yes
        }
        service auth {
            unix_listener auth-client {
              group = postfix
              mode = 0660
              user = postfix
            }

            unix_listener auth-master {
              group = vmail
              mode = 0660
              user = vmail
            }

        }
        service imap-login {
          process_min_avail = 1
          user = vmail
        }







touch /etc/dovecot/passwd
doveadm pw -s sha1 | cut -d '}' -f2

nano /etc/dovecot/passwd
    info@savedgames.net:WOqG6WQG6oxxkDQNwFYEEHtEemk=
    info@iusethis.org:WOqG6WQG6oxxkDQNwFYEEHtEemk=

## chown root: /etc/dovecot/passwd
## chmod 600 /etc/dovecot/passwd


## chkconfig postfix on
## chkconfig dovecot on
## service postfix restart
## service dovecot restart



