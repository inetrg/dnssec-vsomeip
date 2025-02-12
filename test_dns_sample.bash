#!/usr/bin/bash
# launch x instances of the dns_sample program to test parallel requests
dns_sample="/home/vm-user/workspace/mininet-vsomeip-evaluation/vsomeip/build/examples/dns-sample"
nsd_base_dir="/home/vm-user/workspace/mininet-vsomeip-evaluation/"
cwd=$(pwd)
num_instances=$1
if [ ! -d dns_sample_log ]; then
    mkdir dns_sample_log/
else
    rm dns_sample_log/*
fi
eth0_ip=$(ip addr show eth0 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1)
sed -i -E "s/.* # mininet-host-ip/    ip-address: ${eth0_ip} # mininet-host-ip/" $nsd_base_dir/nsd/nsd.conf
sed -i -E "s/ns\.service\.         IN    A    .*/ns.service.         IN    A    $eth0_ip/" $nsd_base_dir/zones/service.zone
sed -i -E "s/ns\.client\.         IN    A    .*/ns.client.         IN    A    $eth0_ip/" $nsd_base_dir/zones/client.zone
nsd-control-setup
nsd -c $nsd_base_dir/nsd/nsd.conf

for i in $(seq 1 $num_instances)
do
    $dns_sample "$i" > dns_sample_log/dns_sample_$i.log 2>&1 &
done
wait

nsd-control stop
