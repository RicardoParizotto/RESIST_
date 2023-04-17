#!/bin/bash
ifconfig enp1s0np1 down
ifconfig enp1s0np1 up
ip neighbor add 10.50.1.6 lladdr b8:59:9f:df:07:cb dev enp1s0np1 nud permanent
ip neighbor add 10.50.1.16 lladdr b8:59:9f:df:07:d1 dev enp1s0np1 nud permanent
ip neighbor add 10.50.1.100 lladdr b8:59:9f:df:07:cb dev enp1s0np1 nud permanent

