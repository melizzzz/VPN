sudo apt update
sudo apt install python3-setuptools
sudo apt install python3-scapy
sudo ip link delete tun0
sudo ip link delete tun1
cd ./pytun
sudo python3 setup.py build
sudo systemctl stop apparmor
sudo python3 setup.py install
sudo modprobe tun
sudo lsof -i :5000

