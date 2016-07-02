#!/bin/bash
#

qemu=/usr/local/bin/qemu-system-x86_64
snabb=/usr/local/bin/snabb

VCPMEM="4000"     # default memory for vRE/VCP in kBytes
VFPMEM="16000"     # default memory for vPFE/VFP in kBytes
VCPCPU="1"        # default cpu count for vRE/VCP
VFPCPU="6"        # default cpu count for vPFE/VFP

#---------------------------------------------------------------------------
function show_help {
  cat <<EOF
Usage:

docker run --name <name> --rm -v \$PWD:/u:ro \\
   --privileged -i -t marcelwiget/vmxl2tpv3[:version] \\
   -c <junos_config_file> -i identity [-l license_file] \\
   [-m <kbytes>] [-M <kBytes>] [-V <cores>] [-W <cores>] \\
   [-u <user_data_file> ] [-y yang files] \\
   <image> <pci-address/core> [<pci-address/core> ...]

   <image>          vmx tar file or directory name (for occam images)

[:version]       Container version. Defaults to :latest

 -v \$PWD:/u:ro   Required to access a file in the current directory
                 docker is executed from (ro forces read-only access)
                 The file will be copied from this location

 -l  license_file to be loaded at startup (requires user snabbvmx with ssh
     private key given via option -i)

 -i  ssh private key for user snabbvmx 
     (required to access lwaftr config via netconf)

 -m  Specify the amount of memory for the vRE/VCP (default $VCPMEM kB)
 -M  Specify the amount of memory for the vPFE/VFP (default $VFPMEM kB)

 -V  number of vCPU's to assign to the vRE/VCP (default $VCPCPU)
 -W  number of vCPU's to assign to vPFE/VFP (default $VFPCPU)

 -d  launch debug shell before launching vMX

 -P  cpu list for vPFE
 -R  cpu list for vRE

 -u  Userdata file for non-vMX mode

 -y  YANG modules to load, comma separated

<pci-address/core>  PCI Address of the Intel 825999 based 10GE port with
                    core to pin snabb on.
                    Multiple ports can be specified, space separated

Example:
docker run --name lwaftr1 --rm --privileged -v \$PWD:/u:ro \\
  -i -t marcelwiget/vmxl2tpv3 -c lwaftr1.txt -i snabbvmx.key \\
  jinstall64-vrr-14.2R5.8-domestic.img 0000:05:00.0/7 0000:05:00.0/8

EOF
}

#---------------------------------------------------------------------------
function cleanup {

  set +e
  trap - EXIT SIGINT SIGTERM

  echo ""
  echo ""
  echo "vMX terminated."

  pkill qemu

  echo "waiting for qemu to terminate ..."
  while  true;
  do
    if [ "1" == "`ps ax|grep qemu|wc -l`" ]; then
      break
    fi
    sleep 5
    echo "force kill of qemu required ..."
    pkill -9 qemu
  done

  exit 0

}
#---------------------------------------------------------------------------

function addif_to_bridge {
  ip link set master $1 dev $2
}

function create_tap_if {
  ip tuntap add dev $1 mode tap
  ip link set $1 up promisc on
}

function create_mgmt_bridge {
# Requires network isolation (without --net=host). 
# Create local bridge br0 for MGMT and place eth0 in it
bridge="br0"
myip=`ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p'`
gateway=`ip -4 route list 0/0 |cut -d' ' -f3`
ip addr flush dev eth0
ip link add name $bridge type bridge
ip link set up $bridge
ip addr add $myip/16 dev $bridge
route add default gw $gateway
ip link set master $bridge dev eth0
echo $bridge
}

function create_int_bridge {
  bridge="brint"
  tap="tapint"
  # need to create a tap interface, so the bridge
  # will use its mac address 
  ip tuntap add dev $tap mode tap
  ip link set $tap up
  ip link add name $bridge type bridge
  ip link set master $bridge dev $tap
  ip link set up $bridge
  ip addr add 128.0.0.100/16 dev $bridge
  echo $bridge
}

function create_bridge {
  bridge=$1
  ip link add name $bridge type bridge
  ip link set up $bridge
}

function mount_hugetables {
  >&2 echo "mounting hugepages ..."
  # mount hugetables, remove directory if this isn't possible due
  # to lack of privilege level. A check for the diretory is done further down
  mkdir /hugetlbfs && mount -t hugetlbfs none /hugetlbfs || rmdir /hugetlbfs

  # check that we are called with enough privileges and env variables set
  if [ ! -d "/hugetlbfs" ]; then
    >&2 echo "Can't access /hugetlbfs. Did you specify --privileged ?"
    exit 1
  fi

  hugepages=`cat /proc/sys/vm/nr_hugepages`
  if [ "0" -gt "$hugepages" ]; then
    >&2 echo "No hugepages found. Did you specify --privileged ?"
    exit 1
  fi
}

function create_vmxhdd {
  >&2 echo "Creating empty vmxhdd.img for vRE ..."
  qemu-img create -f qcow2 /tmp/vmxhdd.img 2G >/dev/null
  echo "/tmp/vmxhdd.img"
}

# prepare cloud-init config drive for non-vMX mode
function create_cloud_init {
  echo "create_cloud_init called"
  mkdir config_drive
  mkdir -p config_drive/openstack/2012-08-10
  ln -s 2012-08-10 config_drive/openstack/latest
  cat > config_drive/openstack/latest/meta_data.json << EOF
{
  "uuid": "$VMIMAGE",
  "files": [
{
  "content_path": "/latest/user_data",
  "path": "/etc/network/interfaces"
}
]
}
EOF

  echo "cloud-init userdata file: $USERDATA"

  if [ -f "/u/$USERDATA" ]; then
   echo "creating user_data ..."
   cat /u/$USERDATA > config_drive/openstack/latest/user_data
  fi
  mkisofs -R -V config-2 -o disk.config config_drive
}

function create_config_drive {
  >&2 echo "Creating config drive (metadata.img) ..."
  mkdir config_drive
  mkdir config_drive/boot
  mkdir config_drive/var
  mkdir config_drive/var/db
  mkdir config_drive/var/db/vmm
  mkdir config_drive/var/db/vmm/etc
  mkdir config_drive/var/db/vmm/vmxl2tpv3
  mkdir config_drive/config
  mkdir config_drive/config/license
  cat > config_drive/boot/loader.conf <<EOF
vmchtype="vmx"
vm_retype="RE-VMX"
vm_instance="0"
EOF
  if [ -f "/u/$LICENSE" ]; then
    >&2 echo "copying $LICENSE"
    cp /u/$LICENSE config_drive/config/license/
  fi
  if [ ! -z "$YANG" ]; then
     yangfiles="${YANG//,/ }"
     yangcmd=""
     for file in $yangfiles; do 
        if [ -f "/u/$file" ]; then
           >&2 echo "YANG file $file"
           yangcmd="$yangcmd -m /var/db/vmm/vmxl2tpv3/$file"
           cp /u/$file config_drive/var/db/vmm/vmxl2tpv3
        fi
     done
    cat > config_drive/var/db/vmm/etc/rc.vmm <<EOF
echo "YANG import started"
ls /var/db/vmm/vmxl2tpv3
echo "arg=$yangcmd"
/bin/sh /usr/libexec/ui/yang-pkg add -X -i vmxlwafr-yang $yangcmd
echo "YANG import completed"
EOF
#    cli -c "request system yang add $yangmodules package vmxl2tpv3-yang"
    chmod a+rx config_drive/var/db/vmm/etc/rc.vmm
  fi
  cp /u/$CONFIG config_drive/config/juniper.conf
  # placing license files on the config drive isn't supported yet
  # but it is assumed, this is how it will work.
#  if [ -f *.lic ]; then
#    for f in *.lic; do
#      cp $f config_drive/config/license
#    done
#  fi
  cd config_drive
  tar zcf vmm-config.tgz *
  rm -rf boot config var
  cd ..
  # Create our own metadrive image, so we can use a junos config file
  # 100MB should be enough.
  dd if=/dev/zero of=metadata.img bs=1M count=100 >/dev/null 2>&1
  mkfs.vfat metadata.img >/dev/null 
  mount -o loop metadata.img /mnt
  cp config_drive/vmm-config.tgz /mnt
  umount /mnt
}

#==================================================================
# main()

echo "Juniper Networks vMX lwaftr Docker Container (unsupported prototype)"
echo ""

while getopts "h?c:m:l:i:V:W:M:P:R:tdu:y:" opt; do
  case "$opt" in
    h|\?)
      show_help
      exit 1
      ;;
    V)  VCPCPU=$OPTARG
      ;;
    W)  VFPCPU=$OPTARG
      ;;
    m)  VCPMEM=$OPTARG
      ;;
    M)  VFPMEM=$OPTARG
      ;;
    c)  CONFIG=$OPTARG
      ;;
    l)  LICENSE=$OPTARG
      ;;
    i)  IDENTITY=$OPTARG
      ;;
    u)  USERDATA=$OPTARG
      ;;
    y)  YANG=$OPTARG
      ;;
    P)  QEMUVFPCPUS=$OPTARG
      ;;
    R)  QEMUVCPCPUS=$OPTARG
      ;;
    d)  DEBUG=1
      ;;
  esac
done

shift "$((OPTIND-1))"

# first parameter is the vMX image
image=$1
shift

if [ -d "/u/$image" ]; then
   echo "Using directory $image for VCP and VFP images"
elif [ ! -f "/u/$image" ]; then
  echo "Error: Can't find image $image"
  exit 1
fi 
# find numanode to use based on PCI list.
# It will simply use the numanode of the last PCI.
# Using cards on different Nodes is not recommended 
for DEV in $@; do # ============= loop thru interfaces start
  PCI=${DEV%/*} 
  if [ "tap" == "$PCI" ]; then
    NUMANODE=0
 else
    CPU=$(cat /sys/class/pci_bus/${PCI%:*}/cpulistaffinity | cut -d'-' -f1 | cut -d',' -f1)
    NODE=$(numactl -H | grep "cpus: $CPU" | cut -d " " -f 2)
    if [ -z "$NUMANODE" ]; then
      NUMANODE=$NODE
    fi
    if [ "$NODE" != "$NUMANODE" ]; then 
      echo "WARNING: Interface $PCI is on numa node $NODE, but request is for node $NUMANODE"
    else
      echo "Interface $PCI is on node $NODE"
    fi
  fi
done

mkdir /var/run/snabb
numactl --membind=$NUMANODE mount -t tmpfs -o rw,nosuid,nodev,noexec,relatime,size=4M tmpfs /var/run/snabb

if [ -d "/u/$image" ]; then
  cp /u/$image/images/junos-vmx-*.qcow2 /tmp/
  VCPIMAGE=$(ls /tmp/junos-vmx-*.qcow2)
  cp /u/$image/images/vFPC-*.img /tmp/
  VFPIMAGE=$(ls /tmp/vFPC-*.img)
  echo "Occam VCPIMAGE=$VCPIMAGE VFPIMAGE=$VFPIMAGE"
elif [[ "$image" =~ \.tgz$ ]]; then
  echo "extracting VMs from $image ..."
  tar -zxf /u/$image -C /tmp/ --wildcards vmx*/images/vFPC*img --wildcards vmx*/images/jinstall*img --wildcards vmx*/images/vFPC-2*img --wildcards vmx*/images/vPFE-2*img
  VCPIMAGE=$(ls /tmp/vmx*/images/jinstall64-vmx*img)
  mv $VCPIMAGE /tmp
  VCPIMAGE="/tmp/$(basename $VCPIMAGE)"
  VFPIMAGE="`ls /tmp/vmx*/images/vFPC*img 2>/dev/null`"
  if [ -z "$VFPIMAGE" ]; then
    echo "checking for pre 15.1 VFP image .."
    VFPIMAGE="`ls /tmp/vmx*/images/vPFE-2*img 2>/dev/null`"
  fi
  mv $VFPIMAGE /tmp
  VFPIMAGE="/tmp/$(basename $VFPIMAGE)"
  rm -rf /tmp/vmx*
else
  echo "Using $image in non-vMX mode"
  cp /u/$image /tmp
  VMIMAGE="/tmp/$image"
  $(mount_hugetables)
  $(create_cloud_init)
fi

if [ ! -z "$VCPIMAGE" ]; then
  if [ ! -f "/u/$IDENTITY" ]; then
    echo "Error: Can't find private key file $identity"
    exit 1
  fi

  cp /u/$IDENTITY .
  IDENTITY="/$(basename $IDENTITY)"
  HDDIMAGE=$(create_vmxhdd)
  MGMTIP="128.0.0.1"
  $(mount_hugetables)
  $(create_config_drive)
fi

BRMGMT=$(create_mgmt_bridge)
BRINT=$(create_int_bridge)
# Create unique 4 digit ID used for this vMX in interface names
ID=$(printf '%02x%02x%02x' $[RANDOM%256] $[RANDOM%256] $[RANDOM%256])
# Create tap interfaces for mgmt
VCPMGMT="vcpm$ID"
VCPINT="vcpi$ID"
VFPMGMT="vfpm$ID"
VFPINT="vfpi$ID"
$(create_tap_if $VCPMGMT)
$(create_tap_if $VFPMGMT)
$(addif_to_bridge $BRMGMT $VCPMGMT)
$(addif_to_bridge $BRMGMT $VFPMGMT)
$(create_tap_if $VCPINT)
$(create_tap_if $VFPINT)
$(addif_to_bridge $BRINT $VCPINT)
$(addif_to_bridge $BRINT $VFPINT)


cat <<EOF

  vRE/VCP=$VCPIMAGE with ${VCPMEM}kB and ${VCPCPU} cores
  vPFE/VFP=$VFPIMAGE with ${VFPMEM}kB and ${VFPCPU} cores
  VMIMAGE=$VMIMAGE
  mgmt bridge $BRMGMT with interfaces $VCPMGMT and $VFPMGMT
  internal interface $VCPMGMT IP $MGMTIP BRMGMT $BRMGMT
  config=$CONFIG license=$LICENSE identity=$IDENTITY

EOF

set -e	#  Exit immediately if a command exits with a non-zero status.
trap cleanup EXIT SIGINT SIGTERM

echo "Building virtual interfaces and bridges for $@ ..."

INTNR=0	# added to each tap interface to make them unique
INTID="xe"

MACP=$(printf "02:%02X:%02X:%02X:%02X" $[RANDOM%256] $[RANDOM%256] $[RANDOM%256] $[RANDOM%256])

CPULIST=""  # collect cores given to PCIDEVS
for DEV in $@; do # ============= loop thru interfaces start

   # 0000:05:00.0/7 -> PCI=0000:05:00.0, CORE=7
   CORE=${DEV#*/}
   PCI=${DEV%/*} 
   if [ -z "$CPULIST" ]; then
      CPULIST=$CORE
   else
      CPULIST="$CPULIST,$CORE"
   fi

   echo "PCI=$PCI CORE=$CORE CPULIST=$CPULIST"
   # add PCI to list
   PCIDEVS="$PCIDEVS $PCI"
   # create persistent mac address based on host-name in junos config file
   h=$(grep host-name /u/$CONFIG |md5sum)
   if [ "tap" == "$PCI" ]; then
      macaddr="02:${h:0:2}:${h:2:2}:${h:4:2}:00:0$INTNR"
   else
      macaddr="02:${h:0:2}:${h:2:2}:${h:4:2}:${PCI:5:2}:0${PCI:11:1}"
   fi
   INT="${INTID}${INTNR}"
   INTLIST="$INTLIST $INT"
   echo "$PCI/$CORE" > /tmp/pci_$INT
   echo "$macaddr" > /tmp/mac_$INT

  if [ "tap" == "$PCI" ]; then
     if [ -z "$(lsmod|grep 8021q)" ]; then
        echo "ERROR: please load kernel module 8021q on this host"
        exit 1
     fi
     echo "Using tap interface to simulate xe${INTNR}"
     $(create_tap_if xe$INTNR)
     ip link add link xe$INTNR name xe$INTNR.100 type vlan id 100
     ip link add link xe$INTNR name xe$INTNR.200 type vlan id 200
     # assign a static IPv6 address for local testing
     ip -6 addr add fc0${INTNR}::1/64 dev xe$INTNR.100
     ip -6 addr add fc1${INTNR}::1/64 dev xe$INTNR.200
     ifconfig xe$INTNR.100 up
     ifconfig xe$INTNR.200 up
     # blackhole all IPv6 traffic. Its just for local testing
     if [ 0 == $INTNR ]; then
        ip route add to blackhole :: dev lo
     fi
     # enabling IPv6 routing
     sysctl net.ipv6.conf.all.forwarding=1
  elif [ ! -d /sys/class/pci_bus/${PCI%:*}/ ]; then
     echo "Error: PCI $PCI doesn't exist on this server."
     exit 1
  fi

  NETDEVS="$NETDEVS -chardev socket,id=char$INTNR,path=./${INT}.socket,server \
        -netdev type=vhost-user,id=net$INTNR,chardev=char$INTNR \
        -device virtio-net-pci,netdev=net$INTNR,mac=$macaddr"

  INTNR=$(($INTNR + 1))
done # ===================================== loop thru interfaces done

QEMUVFPNUMA="numactl --membind=$NUMANODE"
if [ ! -z "$QEMUVFPCPUS" ]; then
  QEMUVFPNUMA="numactl --membind=$NUMANODE --physcpubind=$QEMUVFPCPUS"
fi
QEMUVCPNUMA="numactl --membind=$NUMANODE"
if [ ! -z "$QEMUVCPCPUS" ]; then
  QEMUVCPNUMA="numactl --membind=$NUMANODE --physcpubind=$QEMUVCPCPUS"
fi

echo "QEMUVFPNUMA=$QEMUVFPNUMA"

# calculate the cpu affinity mask excluding the ones for snabb
AVAIL_CORES=$(taskset -p $$|cut -d: -f2|cut -d' ' -f2)

echo "CPULIST=$CPULIST AVAIL_CORES=$AVAIL_CORES QEMUVFPCPUS=$QEMUVFPCPUS"

SNABB_AFFINITY=$(taskset -c $CPULIST /usr/bin/env bash -c 'taskset -p $$'|cut -d: -f2|cut -d' ' -f2)
let AFFINITY_MASK="0x$AVAIL_CORES ^ 0x$SNABB_AFFINITY"
AFFINITY_MASK=$(printf '%x\n' $AFFINITY_MASK)
# Note: doesn't work with numactl: it will refuse to use a cpu that is masked out
#echo "set cpu affinity mask $AFFINITY_MASK for everything but snabb"
#taskset -p $AFFINITY_MASK $$
echo "taskset -p $AFFINITY_MASK \$\$" >> /root/.bashrc

BINDINGS=$(grep binding_table_file /u/$CONFIG | awk '{print $2}'|cut -d';' -f1)
if [ -f /u/$BINDINGS ]; then
  cp /u/$BINDINGS /tmp/
  BINDINGS=$(basename $BINDINGS)
fi

# Check config for snabbvmx group entries. If there are any
# run its manager to create an intial set of configs for snabbvmx 
sx="\$(grep ' snabbvmx-' /u/$CONFIG)"
if [ ! -z "\$sx" ] && [ -f ./snabbvmx_manager.pl ]; then
    cd /tmp/
    numactl --membind=$NUMANODE /snabbvmx_manager.pl /u/$CONFIG
fi

# Launching snabb processes after we set excluded the cores
# from the scheduler
for INT in $INTLIST; do
  cd /tmp && numactl --membind=$NUMANODE /launch_snabb.sh $INT &
done

# launch vPFE/VFP

MEMBACKEND="\
    -object memory-backend-file,id=mem,size=${VFPMEM}M,mem-path=/hugetlbfs,share=on \
    -numa node,memdev=mem -mem-prealloc"

if [ ! -z "$VFPIMAGE" ]; then
  CMD="$QEMUVFPNUMA $qemu -M pc -smp $VFPCPU,sockets=1,cores=$VFPCPU,threads=1 \
    --enable-kvm -m $VFPMEM \
    -cpu Haswell,+abm,+pdpe1gb,+rdrand,+f16c,+osxsave,+dca,+pdcm,+xtpr,+tm2,+est,+smx,+vmx,+ds_cpl,+monitor,+dtes64,+pbe,+tm,+ht,+ss,+acpi,+ds,+vme,-rtm,-hle \
    $MEMBACKEND -realtime mlock=on \
    -no-user-config -nodefaults \
    -device piix3-usb-uhci,id=usb,bus=pci.0,addr=0x1.0x2 \
    -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 \
    -device AC97,id=sound0,bus=pci.0,addr=0x5 \
    -drive if=ide,file=$VFPIMAGE,format=raw \
    -netdev tap,id=tf0,ifname=$VFPMGMT,script=no,downscript=no \
    -device virtio-net-pci,netdev=tf0,mac=$MACP:A1 \
    -netdev tap,id=tf1,ifname=$VFPINT,script=no,downscript=no \
    -device virtio-net-pci,netdev=tf1,mac=$MACP:B1 \
    -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0xa -msg timestamp=on \
    -device isa-serial,chardev=charserial0,id=serial0 \
    -chardev socket,id=charserial0,host=0.0.0.0,port=8700,telnet,server,nowait \
    $NETDEVS -daemonize"
  echo $CMD
  if [ ! -z "$DEBUG" ]; then
    echo "DEBUG SHELL. Hit ^C to continue"
    bash
  fi
  $CMD
fi

if [ ! -z "$VMIMAGE" ]; then
  CMD="$QEMUVFPNUMA $qemu -M pc -smp $VFPCPU,sockets=1,cores=$VFPCPU,threads=1 --enable-kvm -cpu host -m $VFPMEM \
    $MEMBACKEND -realtime mlock=on \
    -netdev tap,id=tf0,ifname=em0,script=no,downscript=no \
    -device virtio-net-pci,netdev=tf0,mac=$macaddr \
    -drive if=virtio,file=$VMIMAGE,cache=none \
    -device isa-serial,chardev=charserial0,id=serial0 \
    -chardev socket,id=charserial0,host=0.0.0.0,port=8700,telnet,server,nowait \
    -drive file=/disk.config,if=virtio $NETDEVS -curses -vnc :1"
  echo $CMD
  if [ ! -z "$DEBUG" ]; then
    echo "DEBUG SHELL. Hit ^C to continue"
    bash
  fi
  $CMD
fi

if [ ! -z "$DEBUG" ]; then
  echo "DEBUG SHELL. Hit ^C to continue"
  bash
fi

if [ ! -z "$VCPIMAGE" ]; then

  cd /tmp && numactl --membind=$NUMANODE /launch_snabbvmx_manager.sh $MGMTIP $IDENTITY $BINDINGS &

  CMD="$QEMUVCPNUMA $qemu -M pc --enable-kvm -cpu host -smp $VCPCPU -m $VCPMEM \
    -drive if=ide,file=$VCPIMAGE -drive if=ide,file=$HDDIMAGE \
    -usb -usbdevice disk:format=raw:/metadata.img \
    -device cirrus-vga,id=video0,bus=pci.0,addr=0x2 \
    -netdev tap,id=tc0,ifname=$VCPMGMT,script=no,downscript=no \
    -device e1000,netdev=tc0,mac=$MACP:A0 \
    -netdev tap,id=tc1,ifname=$VCPINT,script=no,downscript=no \
    -device virtio-net-pci,netdev=tc1,mac=$MACP:B0 -nographic"
  echo $CMD
  $CMD
fi

exit  # this will call cleanup, thanks to trap set earlier (hopefully)
