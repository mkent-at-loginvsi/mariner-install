#!/bin/bash
while getopts r: flag
do
  case "${flag}" in 
    r) resumedir=${OPTARG};;
  esac
done 

echo "----------------------------------------------------------------"
echo "The script you are running has basename $( basename -- "$0"; ), dirname $( dirname -- "$0"; )";
echo "The present working directory is $( pwd; )";
echo "----------------------------------------------------------------"
export WORK_DIR="$PWD"
export OUTPUT_DIR=$WORK_DIR/..

echo "----------------------------------------------------------------"
echo "Install Archive will be written to $OUTPUT_DIR"
echo "----------------------------------------------------------------"
# Disk space check
FREE=`df -k / --output=avail "$PWD" | tail -n1`   # df -k not df -h
if [ $FREE -lt 38990768 ]; then               # 40G = 26*1024*1024k (Kibibyte)
     # less than 26GBs free!
     echo "----------------------------------------------------------------"
     echo "The installation requires 40GB Free on the root partition (/)"
     echo "----------------------------------------------------------------"
     #exit
fi

echo "----------------------------------------------------------------"
echo "### Install Packages ###"
echo "----------------------------------------------------------------"
yum update -qq -y
yum install -y unzip libguestfs-tools

if [ -z "$resumedir" ]; then
# Create Build Directory
echo "----------------------------------------------------------------"
echo "Creating Build Directory"
echo "----------------------------------------------------------------"
dir="build-$(date +%Y_%m_%d_%H_%M_%S)"
export BUILD_DIR="$PWD/$dir"
out_dir="appliance"

mkdir $dir
echo "----------------------------------------------------------------"
echo "Relative Build Direcory: $dir"
echo "Full Path Build Directory: $BUILD_DIR"
echo "----------------------------------------------------------------"
else

# Resume Build, Set Build Directory
echo "----------------------------------------------------------------"
echo "Resuming Build in Directory"
echo "----------------------------------------------------------------"
dir=$resumedir
export BUILD_DIR="$PWD/$dir"
out_dir="appliance"
echo "----------------------------------------------------------------"
echo "Relative Build Direcory: $dir"
echo "Full Path Build Directory: $BUILD_DIR"
echo "----------------------------------------------------------------"
fi

# Download ISO
isoFile="LoginEnterprise-5.4.6.iso"
echo "----------------------------------------------------------------"
echo "Downloading Update ISO to $BUILD_DIR/$isoFile"
echo "----------------------------------------------------------------"

if ! [ -f $BUILD_DIR/$isoFile ]; then
  curl -o $BUILD_DIR/$isoFile https://loginvsidata.s3.eu-west-1.amazonaws.com/LoginPI3_ISO/public/$isoFile
fi

# Mount ISO
echo "----------------------------------------------------------------"
echo "Check if ISO is mounted"
echo "----------------------------------------------------------------"
if ! [ -d /media/iso ]; then
  sudo mkdir /media/iso
fi

if ! [ -d /media/iso/update ]; then
  sudo mount $BUILD_DIR/$isoFile /media/iso -o loop
fi

# Fail if ISO doesn't exist
echo "----------------------------------------------------------------"
echo "Checking if ISO Mounted"
echo "----------------------------------------------------------------"
if ! [ -d /media/iso/update ]; then
  echo "Mount failed"
  exit 1
fi

# Download Appliance VHD zip
applianceFileZip="AZ-VA-LoginEnterprise-5.4.6.zip"
applianceFileVhd="AZ-VA-LoginEnterprise-5.4.6.vhd"
echo "----------------------------------------------------------------"
echo "Downloading Virtual Appliance to $BUILD_DIR/$applianceFileZip"
echo "----------------------------------------------------------------"

if ! [ -f $BUILD_DIR/$applianceFileZip ]; then
  curl -o $BUILD_DIR/$applianceFileZip https://loginvsidata.s3.eu-west-1.amazonaws.com/LoginEnterprise/VirtualAppliance/$applianceFileZip
fi

# Unzip VHD
echo "----------------------------------------------------------------"
echo "Unzipping Virtual Appliance VHD $BUILD_DIR/$applianceFileZip"
echo "----------------------------------------------------------------"
if ! [ -f $BUILD_DIR/$applianceFileVhd ]; then
  unzip -d $BUILD_DIR $BUILD_DIR/$applianceFileZip
fi

# Mount VHD
echo "----------------------------------------------------------------"
echo "Mounting Virtual Hard Drive"
echo "----------------------------------------------------------------"
sudo mkdir /mnt/vhd
sudo chmod 777 /mnt/vhd

mountpath="$BUILD_DIR"
LIBGUESTFS_BACKEND=direct
export LIBGUESTFS_BACKEND

if ! [ -d /mnt/vhd/loginvsi ]; then
  guestmount --add $mountpath/AZ-VA-LoginEnterprise-5.4.6.vhd --ro /mnt/vhd/ -m /dev/sda1
fi

# Fail if VHD doesn't exist
echo "----------------------------------------------------------------"
echo "Checking if VHD Mounted"
echo "----------------------------------------------------------------"
if ! [ -d /mnt/vhd/loginvsi ]; then
  echo "Mount failed"
  exit 1
fi

# Copy Files and Directories to output dir
echo "----------------------------------------------------------------"
echo "Copying Files to archive"
echo "----------------------------------------------------------------"
build_out=$BUILD_DIR/$out_dir
mkdir $build_out

# Copy Login Enterprise Installation
cp -r /mnt/vhd/loginvsi $build_out/

# Copy Login Enterprise Service
mkdir -p $build_out/etc/systemd/system/
cp -f /mnt/vhd/etc/systemd/system/loginvsid.service $build_out/etc/systemd/system/loginvsid.service

# Copy Docker Images
imageFile="images.tar.gz"
mkdir -p $build_out/images
cp -r /media/iso/$imageFile $build_out/images/

#Copy Login Enterprise Service Watcher
cp -f /mnt/vhd/etc/systemd/system/pi_guard.service $build_out/etc/systemd/system/pi_guard.service

echo "----------------------------------------------------------------"
echo "Downloading pdmenu to $BUILD_DIR/rpms"
echo "----------------------------------------------------------------"
# Download pdmenu for rhel/centos
pdmenuSourceUrl="https://download.opensuse.org/repositories/shells/CentOS_5/x86_64/pdmenu-1.3.2-3.2.x86_64.rpm"
cd $BUILD_DIR
curl -L -O $pdmenuSourceUrl

#Copy firstrun, daemon and Menuing
mkdir -p $build_out/usr/bin
cp -f /mnt/vhd/usr/bin/loginvsid $build_out/usr/bin/loginvsid
cp -f /mnt/vhd/usr/bin/pdmenu $build_out/usr/bin/pdmenu
curl -o $build_out/usr/bin/pdmenu https://github.com/mkent-at-loginvsi/rhel-install/raw/main/pdmenu/pdmenu.rhel

#zip up appliance build
echo "----------------------------------------------------------------"
echo "Packaging Archive"
echo "----------------------------------------------------------------"
cd $BUILD_DIR
tar -czvf $out_dir.tar.gz $out_dir
mv -v $out_dir.tar.gz $OUTPUT_DIR
cd $WORK_DIR

#Unmount vhd
echo "----------------------------------------------------------------"
echo "Cleaning up"
echo "----------------------------------------------------------------"
#sudo guestunmount /mnt/vhd
#sudo umount /media/iso
#sh clean.sh
unset BUILD_DIR
unset WORK_DIR
unset OUTPUT_DIR

echo "----------------------------------------------------------------"
echo "Build Complete"
echo "----------------------------------------------------------------"
