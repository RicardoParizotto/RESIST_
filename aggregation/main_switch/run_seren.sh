#!/bin/bash

#Kill any running switch
pkill switchd

#Set environment vars
source /root/bin/set_sde.sh


bf-p4c serene.p4
cp_p4 serene


#Launch the switch
$SDE/run_switchd.sh -p serene &

#Wait to it to get setup
sleep 60

#Add the ports
$SDE/run_bfshell.sh -b $SDE/port_setup.py
