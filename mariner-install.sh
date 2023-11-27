#!/bin/bash
# TODO: Move user and group properly away from id's Login Enterprise expects
# TODO: Fix shell scripts (incl trim)

temp_dir="/install/mariner-install"
tar_file="appliance.tar.gz"
username="admin"

# Need 2CPU
# Need 4GB RAM
# Need 26 GB Free Space
echo "----------------------------------------------------------------"
echo "### Checking Pre-Reqs ###"
echo "----------------------------------------------------------------"

if [ -f /etc/selinux/config ]; then
     SELINUXSTATUS=$(getenforce)
     if [ $SELINUXSTATUS != "Disabled" ]; then
          echo "----------------------------------------------------------------"
          echo "### WARNING: SELinux must be disabled! ###"
          echo "----------------------------------------------------------------"
          exit 1
     fi
fi

echo "----------------------------------------------------------------"
echo "### Checking if script is run as root ###"
echo "----------------------------------------------------------------"
if [ $USER != 'root' ]; then
   echo "----------------------------------------------------------------"
   echo "### This script must be run as root! ###"
   echo "----------------------------------------------------------------"
   exit 1
fi

echo "----------------------------------------------------------------"
echo "### Checking Diskspace ###"
echo "----------------------------------------------------------------"
FREE=`df -k / --output=avail "$PWD" | tail -n1`   # df -k not df -h
if [ $FREE -lt 27262976 ]; then # 26G = 26*1024*1024k 
     # less than 26GBs free!
     echo "----------------------------------------------------------------"
     echo "### The installation requires 26 GB Free on the root partition (/)! ###"
     echo "----------------------------------------------------------------"
     exit 1
fi

echo "----------------------------------------------------------------"
echo "### Checking CPUs ###"
echo "----------------------------------------------------------------"
CPUS=`getconf _NPROCESSORS_ONLN`
if [ $CPUS -lt 2 ]; then
     echo "----------------------------------------------------------------"
     echo "### WARNING: 2 CPUS Required! ###"
     echo "----------------------------------------------------------------"
     exit 1
fi

echo "----------------------------------------------------------------"
echo "### Checking RAM ###"
echo "----------------------------------------------------------------"
RAM=`free -m | grep "Mem*" | awk '{s+=$2} END {print $2}'`
if [ ${#RAM} != 0 ]; then
     if [ $RAM -lt 4 ]; then
          echo "----------------------------------------------------------------"
          echo "### WARNING: 4 GB RAM Required! ###"
          echo "----------------------------------------------------------------"
          exit 1
     fi
else
     RAM=`free -m | grep "Mem*" | awk '{s+=$2} END {print $2}'`
          if [ $RAM -lt 4096 ]; then
          echo "----------------------------------------------------------------"
          echo "### WARNING: 4096 MB RAM Required! ###"
          echo "----------------------------------------------------------------"
          exit 1
     fi
fi

echo "----------------------------------------------------------------"
echo "### Build Swapfile ###"
echo "----------------------------------------------------------------"
dd if=/dev/zero of=/swapfile count=4096 bs=1MB
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile swap swap defailts 0 0'| tee -a /etc/fstab

#TODO: FIX ADMIN CHECK
if id -u "admin" >/dev/null 2>&1; then
  admincheck=$(id -u admin)
else
  admincheck=""
fi

if [ $admincheck == "" ]; then
     echo "----------------------------------------------------------------"
     echo "### Create Admin Account ###"
     echo "----------------------------------------------------------------"
     useradd -u 1000 -m admin
     usermod -aG sudo admin
elif [ $admincheck == 1000 ]; then
     echo "----------------------------------------------------------------"
     echo "### READY: Admin user already exists and is id 1000! ###"
     echo "----------------------------------------------------------------"
     usermod -aG sudo admin
else
     echo "----------------------------------------------------------------"
     echo "### WARNING: UID 1000 is already in use. Admin will use a different UID ###"
     echo "----------------------------------------------------------------"
     useradd -m admin
     usermod -aG sudo admin
     admin_uid=$(id -u "admin")
     #exit 1
fi

groupcheck=$(getent group loginenterprise | cut -d: -f1)
gidcheck=$(getent group 1002 | cut -d: -f1)

if [ $groupcheck ] && [ $gidcheck ]; then
     echo "----------------------------------------------------------------"
     echo "### WARNING: loginenterprise group already exists! ###"
     echo "----------------------------------------------------------------"
else
     echo "----------------------------------------------------------------"
     echo "### Create loginenterprise group ###"
     echo "----------------------------------------------------------------"
     groupadd -g 1002 loginenterprise
fi

if [ -f /etc/sysctl.conf ]; then
     echo "----------------------------------------------------------------"
     echo "### /etc/sysctl.conf already exists ###"
     echo "----------------------------------------------------------------"
     #exit 1
else
     echo "----------------------------------------------------------------"
     echo "### Create /etc/sysctl.conf ###"
     echo "----------------------------------------------------------------"
     touch /etc/sysctl.conf
fi

while :
do
     echo ""
     read -ersp "Please enter a new password for $username: " password
     echo ""
     read -ersp "Please confirm the new password: " password2
     echo ""
     if [ "$password" != "$password2" ]; then
          echo "Passwords do not match, try again..."
     elif [[ "$password" == *[\"]* ]]; then
          echo "Password cannot contain a double quote (\") character"
     elif [[ "$password" == "" ]]; then
          echo "Password cannot be empty"
     else
          echo "admin:$password" | chpasswd
          echo "Password updated successfully"
          break
     fi
done

echo "----------------------------------------------------------------"
echo "### Fix FSTRIM ###"
echo "----------------------------------------------------------------"
echo '[Unit]
Description=Discard unused blocks on filesystems from /etc/fstab
Documentation=man:fstrim(8)
ConditionVirtualization=!container

[Service]
Type=oneshot
ExecStart=/usr/sbin/fstrim -A
PrivateDevices=no
PrivateNetwork=yes
PrivateUsers=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@default @file-system @basic-io @system-service' > /etc/systemd/system/fstrim.service

echo '[Unit]
Description=Discard unused blocks once a week
Documentation=man:fstrim
ConditionVirtualization=!container

[Timer]
OnCalendar=weekly
AccuracySec=1h
Persistent=true
RandomizedDelaySec=6000

[Install]
WantedBy=timers.target' > /etc/systemd/system/fstrim.timer

sudo systemctl enable fstrim.timer

echo "----------------------------------------------------------------"
echo "### Allow ssh Password Authentication ###"
echo "----------------------------------------------------------------"
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd

echo "----------------------------------------------------------------"
echo "### Set Defaults (sysctl.conf) ###"
echo "----------------------------------------------------------------"
echo "
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.ip_forward = 1
" >>/etc/sysctl.conf

echo "----------------------------------------------------------------"
echo "### Set Defaults ###"
echo "----------------------------------------------------------------"
# remove/purge python2
yum remove python2 -y

# create python to python3 symbolic link
ln -s /usr/bin/python3 /usr/bin/python

echo "----------------------------------------------------------------"
echo "### Install Packages ###"
echo "----------------------------------------------------------------"
yum update -qq -y
yum install -y \
     ca-certificates \
     curl \
     gnupg \
     lsb-release \
     unzip \
     nano \
     libicu

echo "----------------------------------------------------------------"
echo "### Download install files ###"
echo "----------------------------------------------------------------"
curl -o $tar_file https://prodcampapispec.s3.us-west-1.amazonaws.com/appliance-5.5.2.tar.gz

echo "----------------------------------------------------------------"
echo "### Unzipping arhive and installing files ###"
echo "----------------------------------------------------------------"
mkdir -p $temp_dir
tar -zxvf $tar_file -C $temp_dir
cp -R $temp_dir/appliance/loginvsi /
cp -R $temp_dir/appliance/usr /
cp -f $temp_dir/appliance/etc/systemd/system/loginvsid.service /etc/systemd/system/
cp -f $temp_dir/appliance/etc/systemd/system/pi_guard.service /etc/systemd/system/
systemctl enable pi_guard
systemctl enable loginvsid

mv $temp_dir/appliance/usr/bin/pdmenu /usr/bin/pdmenu

chmod -R +x /loginvsi/bin/*
chmod +x /usr/bin/loginvsid
chown root:root /usr/bin/loginvsid

echo "----------------------------------------------------------------"
echo "### Download and Install PDMENU ###"
echo "----------------------------------------------------------------"
curl -o $temp_dir/appliance/pdmenu-1.3.2-3.2.x86_64.rpm https://download.opensuse.org/repositories/shells/CentOS_5/x86_64/pdmenu-1.3.2-3.2.x86_64.rpm
rpm -ivh --nodeps $temp_dir/appliance/*.rpm


echo "----------------------------------------------------------------"
echo "### Uninstalling Docker ###"
echo "----------------------------------------------------------------"
yum update -y

sh -c "$(curl -fsSL https://get.docker.com)"
yum module remove -y container-tools

yum remove -y docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine

yum install -y yum-utils

echo "----------------------------------------------------------------"
echo "### Installing Docker (Moby) ###"
echo "----------------------------------------------------------------"
tdnf install -y moby-engine moby-cli

echo "----------------------------------------------------------------"
echo "### Starting Docker ###"
echo "----------------------------------------------------------------"
systemctl start docker
systemctl enable docker

echo "----------------------------------------------------------------"
echo "### Initiating docker swarm... ###"
echo "----------------------------------------------------------------"
docker swarm init
docker load -i $temp_dir/appliance/images/*

echo "$password" | base64 >/home/admin/.password

echo "----------------------------------------------------------------"
echo "### Fix firstrun ###"
echo "----------------------------------------------------------------"
sed -i '\|echo "Resetting SSH keys..."|d' /loginvsi/bin/firstrun
sed -i '\|etc/init.d/ssh stop|d' /loginvsi/bin/firstrun
sed -i '\|rm -f /etc/ssh/ssh_host_*|d' /loginvsi/bin/firstrun
sed -i '\|/etc/init.d/ssh start|d' /loginvsi/bin/firstrun
sed -i '\|dpkg-reconfigure -f noninteractive openssh-server|d' /loginvsi/bin/firstrun
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/bin/firstrun
sed -i 's/update-ca-certificate/update-ca-trust/g' /loginvsi/bin/firstrun

echo "----------------------------------------------------------------"
echo "### Fix Appliance Guard Url ###"
echo "----------------------------------------------------------------"
sed -i 's/APPLIANCE_GUARD_URL=192.168.126.1:8080/APPLIANCE_GUARD_URL=172.18.0.1:8080/g' /loginvsi/.env

echo "----------------------------------------------------------------"
echo "### Prevent Cloud Init changing hostname ###"
echo "----------------------------------------------------------------"
if [ -f /etc/cloud/cloud.cfg ]; then
     sed -i '/preserve_hostname: false,preserve_hostname: true/g' /etc/cloud/cloud.cfg
     sed -i 's/- set_hostname/#- set_hostname/g' /etc/cloud/cloud.cfg
     sed -i 's/- update_hostname/#- set_hostname/g' /etc/cloud/cloud.cfg
     sed -i 's/- update_etc_hosts/#- set_hostname/g' /etc/cloud/cloud.cfg
fi

echo "----------------------------------------------------------------"
echo "### Fix SSL Cert Paths in compose ###"
echo "----------------------------------------------------------------"
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/compose/InternalDB/docker-compose.yml
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/compose/InternalDB/docker-compose.migration.yml
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/compose/Infra/docker-compose.yml
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/compose/ExternalDB/docker-compose.yml
sed -i 's#/usr/local/share/ca-certificates:/#/etc/pki/ca-trust/source/anchors:/#g' /loginvsi/compose/ExternalDB/docker-compose.migration.yml

echo "----------------------------------------------------------------"
echo "### Copy CA to Cert Path ###"
echo "----------------------------------------------------------------"
cp /certificates/CA.crt /etc/pki/ca-trust/source/anchors
update-ca-trust

#Docker does not have access to symlinks to certificates, so we copy the ca bundle back
unlink /etc/ssl/certs/ca-certificates.crt
cp /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/certs/ca-certificates.crt

# echo "----------------------------------------------------------------"
# echo "### Set permissions masks ###"
# echo "----------------------------------------------------------------"
# #-- Directories
# # Set /loginvsi
# chmod -R 755 /loginvsi
# chown -R admin:admin /loginvsi

# # Set /loginvsi/bin/grafana
# chmod -R 555 /loginvsi/bin/grafana
# chown -R root:root /loginvsi/bin/grafana

# # Set /loginvsi/content/zip
chmod 775 /loginvsi/content/zip
chown -R admin:loginenterprise /loginvsi/content/zip

# #Set /loginvsi/logs
chmod -R 755 /loginvsi/logs
chown -R root:loginenterprise /loginvsi/logs

# #Set /loginvsi/settings
# chmod -R 755 /loginvsi/settings
# chown -R 999:loginenterprise /loginvsi/settings

# #--- Files
# #Set /loginvsi/.env /loginvsi/.title
chmod 644 /loginvsi/.env /loginvsi/.title
chown root:root /loginvsi/.env /loginvsi/.title

# #Set /loginvsi/bin/firstrun
chmod 755 /loginvsi/bin/firstrun
chown root:root /loginvsi/bin/firstrun

# #Set /loginvsi/bin/start/trimfilesystem
chmod 555 /loginvsi/bin/start/trimfilesystem
chown root:root /loginvsi/bin/start/trimfilesystem

# #Set /loginvsi/bin/start/cleanupdockerimages
chmod 555 /loginvsi/bin/start/cleanupdockerimages
chown root:root /loginvsi/bin/start/cleanupdockerimages

# #Set /loginvsi/content/CA.crt
chmod 644 /loginvsi/content/CA.crt
#chown admin:admin /loginvsi/content/CA.crt

# #Set /loginvsi/first_run.chk
chmod 644 /loginvsi/first_run.chk
chown root:root /loginvsi/first_run.chk

# #Set /loginvsi/second_run.chk
chmod 644 /loginvsi/second_run.chk
chown root:root /loginvsi/second_run.chk

# #Set /loginvsi/settings/appsettings.all.json
chmod 664 /loginvsi/settings/appsettings.all.json
chown root:loginenterprise /loginvsi/settings/appsettings.all.json

# #Set /loginvsi/content/zip/secured/logon.zip
chmod 664 /loginvsi/content/zip/secured/logon.zip
chown admin:loginenterprise /loginvsi/content/zip/secured/logon.zip

chmod -R +x /loginvsi/bin/*

chmod 755 /usr/bin/loginvsid
chown root:root /usr/bin/loginvsid

chmod 755 /etc/systemd/system/loginvsid.service
chown root:root /etc/systemd/system/loginvsid.service

chmod 755 /etc/systemd/system/pi_guard.service
chown root:root /etc/systemd/system/pi_guard.service

sed -i "s#:/home/admin:/bin/bash#:/home/admin:/usr/bin/startmenu#" /etc/passwd

echo "----------------------------------------------------------------"
echo "### completing firstrun ###"
echo "----------------------------------------------------------------"
touch -f /loginvsi/first_run.chk

echo "----------------------------------------------------------------"
echo "Installation is complete, but we need to configure some things."
echo "As root, run the following commands:"
echo "domainname <yourdnssuffix ie: westus.cloudapp.azure.com>"
echo "bash /loginvsi/bin/firstrun"
echo ""
echo "----------------------------------------------------------------"