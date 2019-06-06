# Author praveenkumar.hosanagappaamarkumar@microfocus.com
# Platform Centos
#!/bin/sh
# set kernel parameters
cat > /etc/sysctl.d/custom-sysctl.conf <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
EOF


sleep 5
echo # After Creating  /etc/sysctl.d/custom-sysctl.conf
echo ###########################################################
cat /etc/sysctl.d/custom-sysctl.conf
echo ############################################################

echo # Set Password Expiry
echo " Before modifying /etc/login.defs"
echo ############################################################
echo ####Taking backup /etc/login.defs ##########################
cp /etc/login.defs /etc/"login.defs-Backup.$(date +"%F %T")"
ls -ltrh /etc/login.defs-Backup*

echo #############################################################
cat /etc/login.defs | grep -i PASS_MAX_DAYS
cat /etc/login.defs | grep -i PASS_MIN_DAYS
cat /etc/login.defs | grep -i PASS_WARN_AGE
cat /etc/login.defs | grep -i PASS_MIN_LEN
echo ############################################################
echo ############ modifying /etc/login.defs #####################

sed -i '/PASS_MAX_DAYS/s/[0-9]\+/365/g' /etc/login.defs
sed -i '/PASS_MIN_DAYS/s/[0-9]\+/1/g' /etc/login.defs
sed -i '/PASS_MIN_LEN/s/[0-9]\+/8/g' /etc/login.defs
sed -i '/PASS_WARN_AGE/s/[0-9]\+/7/g' /etc/login.defs
echo ############################################################
sleep 5
echo ######### After modifying /etc/login.defs ##################
cat /etc/login.defs | grep -i PASS_MAX_DAYS
cat /etc/login.defs | grep -i PASS_MIN_DAYS
cat /etc/login.defs | grep -i PASS_WARN_AGE
cat /etc/login.defs | grep -i PASS_MIN_LEN
echo ############################################################

echo ##### Configuring OpenSSH server ############################
echo ####### Taking back-up of /etc/ssh/sshd_config ##############
cp /etc/ssh/sshd_config /etc/ssh/"sshd_config-backup.$(date +"%F %T")"
echo ############# values Before modifying /etc/ssh/sshd_config #####
echo ################################################################
echo "Before modifying Changes in /etc/ssh/sshd_config "
cat /etc/ssh/sshd_config | grep -i LogLevel
cat /etc/ssh/sshd_config | grep -i X11Forwarding
cat /etc/ssh/sshd_config | grep -i X11Forwarding
cat /etc/ssh/sshd_config | grep -i MaxAuthTries
cat /etc/ssh/sshd_config | grep -i IgnoreRhosts
cat /etc/ssh/sshd_config | grep -i HostbasedAuthentication
cat /etc/ssh/sshd_config | grep -i PermitEmptyPasswords
cat /etc/ssh/sshd_config | grep -i PermitUserEnvironment
cat /etc/ssh/sshd_config | grep -i ClientAliveInterval
cat /etc/ssh/sshd_config | grep -i ClientAliveCountMax
cat /etc/ssh/sshd_config | grep -i LoginGraceTime
cat /etc/ssh/sshd_config | grep -i Ciphers
echo #############################################################
echo ##### Changing sshd_config ##################################
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/.*# Ciphers and keying*/&\n Ciphers aes256-ctr,aes192-ctr,aes128-ctr/' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i 's|#Banner none|Banner /etc/ssh/warningtext|g' /etc/ssh/sshd_config
echo ############### Setting Up Banner ###############################
sleep 5
touch /etc/ssh/warningtext
echo #################################################################
sleep 2
cat > /etc/ssh/warningtext <<EOF
###################################################################
#               Authorized access only!                           #
#  Disconnect IMMEDIATELY if you are not an authorized user!!!    #
#   All actions Will be monitored and recorded by Micro Focus     #
#                  Approved By PSDC CCoE                          #
###################################################################
EOF
sleep 2
service sshd restart
chmod 600 /etc/ssh/warningtext
echo ###################################################################################

echo "After  modifying Changes in /etc/ssh/sshd_config "

cat /etc/ssh/sshd_config | grep -i LogLevel
cat /etc/ssh/sshd_config | grep -i X11Forwarding
cat /etc/ssh/sshd_config | grep -i X11Forwarding
cat /etc/ssh/sshd_config | grep -i MaxAuthTries
cat /etc/ssh/sshd_config | grep -i IgnoreRhosts
cat /etc/ssh/sshd_config | grep -i HostbasedAuthentication
cat /etc/ssh/sshd_config | grep -i PermitEmptyPasswords
cat /etc/ssh/sshd_config | grep -i PermitUserEnvironment
cat /etc/ssh/sshd_config | grep -i ClientAliveInterval
cat /etc/ssh/sshd_config | grep -i ClientAliveCountMax
cat /etc/ssh/sshd_config | grep -i LoginGraceTime
cat /etc/ssh/sshd_config | grep -i Ciphers
cat /etc/ssh/sshd_config | grep -i Banner
cat /etc/ssh/warningtext
echo #############################################################

# set permissions on /tmp
chmod 1777 /tmp

# Remove Uncessary / Unneeded Packages / Programs
yum erase mcstrans > /dev/null 2>&1
yum erase telnet-server > /dev/null 2>&1
yum erase telnet > /dev/null 2>&1
yum erase rsh-server > /dev/null 2>&1
yum erase rsh > /dev/null 2>&1
yum erase ypbind > /dev/null 2>&1
yum erase ypserv > /dev/null 2>&1
yum erase tftp > /dev/null 2>&1
yum erase tftp-server > /dev/null 2>&1
yum erase talk > /dev/null 2>&1
yum erase talk-server > /dev/null 2>&1
yum erase xinetd > /dev/null 2>&1
yum erase dhcp > /dev/null 2>&1
yum erase openldap-servers > /dev/null 2>&1
yum erase openldap-clients > /dev/null 2>&1
yum erase bind > /dev/null 2>&1
yum erase vsftpd > /dev/null 2>&1
yum erase httpd > /dev/null 2>&1
yum erase dovecot > /dev/null 2>&1
yum erase samba > /dev/null 2>&1
yum erase squid > /dev/null 2>&1
yum erase net-snmp > /dev/null 2>&1
yum erase setroubleshoot > /dev/null 2>&1
# Disable unnecessary Packages
chkconfig autofs off > /dev/null 2>&1
chkconfig avahi-daemon off > /dev/null 2>&1
chkconfig avahi-dnsconfd off > /dev/null 2>&1
chkconfig bluetooth off > /dev/null 2>&1
chkconfig cups off > /dev/null 2>&1
chkconfig dhcdbd off > /dev/null 2>&1
chkconfig gpm off > /dev/null 2>&1
chkconfig haldaemon off > /dev/null 2>&1
chkconfig isdn off > /dev/null 2>&1
chkconfig irda off > /dev/null 2>&1
chkconfig irqbalance off > /dev/null 2>&1
chkconfig kdump off > /dev/null 2>&1
chkconfig kudzu off > /dev/null 2>&1
chkconfig mcstrans off > /dev/null 2>&1
chkconfig microcode_ctl off > /dev/null 2>&1
chkconfig multipathd off > /dev/null 2>&1
chkconfig netconsole off > /dev/null 2>&1
chkconfig netfs off > /dev/null 2>&1
chkconfig netplugd off > /dev/null 2>&1
chkconfig nfs off > /dev/null 2>&1
chkconfig nfslock off > /dev/null 2>&1
chkconfig nscd off > /dev/null 2>&1
chkconfig pcscd off > /dev/null 2>&1
chkconfig portmap off > /dev/null 2>&1
chkconfig rhnsd off > /dev/null 2>&1
chkconfig restorecond off > /dev/null 2>&1
chkconfig rpcgssd off > /dev/null 2>&1
chkconfig rpcidmapd off > /dev/null 2>&1
chkconfig rpcsvcgssd off > /dev/null 2>&1
chkconfig sendmail off > /dev/null 2>&1
chkconfig smartd off > /dev/null 2>&1
chkconfig winbind off > /dev/null 2>&1
chkconfig wpa_supplicant off > /dev/null 2>&1
chkconfig xfs off > /dev/null 2>&1
chkconfig ypbind off > /dev/null 2>&1
chkconfig yum-updatesd off > /dev/null 2>&1
