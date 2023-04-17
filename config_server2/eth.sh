#!/bin/bash

ip neighbor add 10.50.0.1 lladdr 00:15:4d:12:11:a8 dev enp101s0f0 nud permanent
ip neighbor add 10.50.0.5 lladdr b8:59:9f:df:07:f1 dev enp101s0f0 nud permanent
ip neighbor add 10.50.0.15 lladdr b8:59:9f:df:08:00 dev enp101s0f0 nud permanent
