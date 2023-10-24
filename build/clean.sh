
if [ -f /mnt/vhd/loginvsi ]; then
  sudo guestunmount /mnt/vhd
fi

unset BUILD_DIR
sudo rm -rf */
