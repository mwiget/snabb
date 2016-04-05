# Tuning the performance of the lwaftr

## Adjust CPU frequency governor

Set the CPU frequency governor to _'performance'_:

```bash
for CPUFREQ in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
   [ -f $CPUFREQ ] || continue;
   echo -n performance > $CPUFREQ;
done
```
## Avoid fragmentation

Make sure that MTUs are set such that fragmentation is rare.


## NUMA

Each NIC is associated with a NUMA node.  For systems with multiple NUMA
nodes, usually if you have more than one socket, you will need to ensure
that the processes that access NICs do so from the right NUMA node.

For example if you are going to be working with NICs `0000:01:00.0`,
`0000:01:00.1`, `0000:02:00.0`, and `0000:02:00.1`, check:

```bash
$ for device in 0000:0{1,2}:00.{0,1}; do \
    echo $device; cat /sys/bus/pci/devices/$device/numa_node; \
  done
0000:01:00.0
0
0000:01:00.1
0
0000:02:00.0
0
0000:02:00.1
0
```

So all of these are on NUMA node 0.  Then check your CPUs:

```
$ numactl -H | grep cpus
node 0 cpus: 0 1 2 3 4 5
node 1 cpus: 6 7 8 9 10 11
```

So for these we should run our binaries under `taskset -c CPU` to bind
them to CPUs in the NUMA node 0.

## Isolate CPUs

Force the Linux kernel to use a limited amount of CPUs to schedule its
processes, leaving all the other CPUs for running Snabb.

To isolate CPUs, boot your Linux kernel with the `isolcpus` parameter.
Under NixOS, edit `/etc/nixos/configuration.nix` to add this parameter:

```
boot.kernelParams = [ "hugepagesz=1G" "hugepages=10" "isolcpus=1-5,7-11" ];
```

The line above prevents the kernel to schedule processes in CPUs ranging from
1 to 5 and 7 to 11. That leaves CPUs 0 and 6 for the Linux kernel.

After adding the `isolcpus` flag run `nixos-rebuild switch` and then reboot 
your workstation to enable the changes.
