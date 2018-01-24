#! /bin/bash
ROOT=`pwd`
dpdk_nic_bind=$ROOT/dpdk/usertools/dpdk-devbind.py
#nic_filter="Eth.*Copper"
nic_filter="Netronome Systems"

#cfg_file="sample_swlb_2port_1WT.cfg"
cfg_file="acc_swlb_2port_2WT.cfg"
#tc_file="sample_swlb_2port_2WT.tc"
tc_file="./acc_swlb_2000_flow.tc"
./gen-flow-common.sh >  $tc_file
./gen-2000-flow.sh   >> $tc_file

pci_list=`lspci | grep "$nic_filter" | cut -d ' ' -f 1  | tr "\n" " "`
echo $pci_list
sudo $dpdk_nic_bind -b igb_uio $pci_list
sudo $dpdk_nic_bind --status

sudo gdb --args $ROOT/VNFs/vCGNAPT/build/vCGNAPT -p 0x3 -f $cfg_file  -s $tc_file

