#! /bin/bash
ROOT=`pwd`
dpdk_nic_bind=$ROOT/dpdk/usertools/dpdk-devbind.py
nic_filter="Eth.*Copper"

cfg_file="sample_swlb_2port_1WT.cfg"
tc_file="sample_swlb_2port_2WT.tc"

pci_list=`lspci | grep "$nic_filter" | cut -d ' ' -f 1  | tr "\n" " "`
echo $pci_list
sudo $dpdk_nic_bind -b igb_uio $pci_list
sudo $dpdk_nic_bind --status

gdb --args $ROOT/VNFs//vCGNAPT/build/vCGNAPT -p 0x3 -f $cfg_file  -s $tc_file

