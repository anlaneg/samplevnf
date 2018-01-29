#! /bin/bash
if [ ! `id -u` -eq  0 ];
then
    echo "Checking for user permission.. Password-less sudo user must run this script"
    exit 1
fi;
./tools/vnf_build.sh -s -d=17.05
