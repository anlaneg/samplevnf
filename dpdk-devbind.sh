#! /bin/bash
ROOT=`pwd`
dpdk_nic_bind=$ROOT/dpdk/usertools/dpdk-devbind.py

function get_pci_list_by_vendor()
{
	vendor_finger_print="$1"
        pci_list=`lspci | grep "$vendor_finger_print" | cut -d ' ' -f 1  | tr "\n" " "`
        echo "$pci_list"
}

function do_dpdk_nic_bind()
{
	pci_list="$1"
	echo $pci_list
	sudo $dpdk_nic_bind -b igb_uio $pci_list
	sudo $dpdk_nic_bind --status
}


MYVM_FILTER="Eth.*Copper"
NETRONOME_FILTER="Netronome Systems"
CAVIUM_FILTER="Cavium, Inc."

function get_env_name()
{
	my_vm=`get_pci_list_by_vendor $MYVM_FILTER`
        netronome=`get_pci_list_by_vendor $NETRONOME_FILTER`
        cavium=`get_pci_list_by_vendor $CAVIUM_FILTER`

	if [ ! -z "$my_vm" ];
	then
		do_dpdk_nic_bind "$my_vm"
		echo "ENV:myvm"
        elif [ ! -z "$netronome" ];
	then
		do_dpdk_nic_bind "$netronome"
		echo "ENV:netronome"
	elif [ ! -z "$cavium" ];
	then
		do_dpdk_nic_bind "$cavium"
		echo "ENV:cavium";
	else
		echo "ENV:unkown"
	fi;
}

env_name=`get_env_name|grep "^ENV:"|cut -d':' -f 2`
cfg_file="./$env_name/acc_swlb_2port_2WT.cfg"
tc_file="./acc_swlb_2000_flow.tc"
./$env_name/gen-flow-common.sh $env_name >  $tc_file
./gen-2000-flow.sh   $env_name >> $tc_file

echo "use config file: $cfg_file"
echo "use testcasse file: $tc_file"
sudo gdb --args $ROOT/VNFs/vCGNAPT/build/vCGNAPT -p 0x3 -f $cfg_file  -s $tc_file

