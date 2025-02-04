#!/usr/bin/bash
# launch x instances of the dns_sample program to test parallel requests
dns_sample="/home/vm-user/workspace/mininet-vsomeip-evaluation/vsomeip/build/examples/dns-sample"
num_instances=$1
rm dns_sample_log/*
for i in $(seq 1 $num_instances)
do
    $dns_sample 50 "$i" > dns_sample_log/dns_sample_$i.log 2>&1 &
done
wait
