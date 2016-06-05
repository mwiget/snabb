FROM ubuntu:14.04.4
MAINTAINER Marcel Wiget

# Install enough packages to compile snabb and qemu
RUN apt-get update && apt-get install -y --no-install-recommends net-tools \
  iproute2 dosfstools tcpdump tcpreplay bridge-utils numactl genisoimage python-pip

# fix usr/sbin/tcpdump by moving it into /sbin: error while loading shared libraries: libcrypto.so.1.0.0: cannot open shared object file: Permission denied
RUN mv /usr/sbin/tcpdump /sbin/

# Download and compile snabb and qemu, then cleanup
RUN apt-get install -y --no-install-recommends build-essential git ca-certificates \
  libqtcore4 libusbredirhost1 qtcore4-l10n spice-client-glib-usb-acl-helper \
  sshpass openssh-client rsync psmisc glib-2.0 libglib2.0-dev libaio-dev libcap-dev \
  libattr1-dev libpixman-1-dev libncurses5 libncurses5-dev libspice-server1 libtool \
  && git clone -b v2.4.0-snabb --depth 50 https://github.com/SnabbCo/qemu \
  && cd qemu && ./configure --target-list=x86_64-softmmu --disable-sdl && make -j \
  && make install \
  && apt-get purge -y build-essential git ca-certificates libncurses5-dev glib-2.0 \
  && apt-get autoremove -y \
  && rm -rf /var/lib/apt/lists/* /snabbswitch /qemu

COPY launch.sh README.md snabbvmx_manager.pl \
  launch_snabbvmx_manager.sh launch_snabb.sh show_affinity.sh topl.sh /

COPY snabb /usr/local/bin/

EXPOSE 8700 

ENTRYPOINT ["/launch.sh"]

CMD ["-h"]
