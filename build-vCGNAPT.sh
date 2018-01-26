export VNF_CORE=`pwd`
DPDK_DIR=/home/cgnat/workspace/dpdk_17_05/dpdk
export RTE_SDK=$DPDK_DIR
export RTE_TARGET=x86_64-native-linuxapp-gcc
make clean
make EXTRA_CFLAGS="-O0 -g" || { echo -e "\nVNF: Make failed\n"; }

