#!/usr/bin/perl

my $ip=shift;
my $identity=shift;

sub process_new_config {
  my ($file) = @_;
  open IN,"$file" or die $@;
  my $snabbvmx_config_file;
  my $snabbvmx_lwaftr_file;
  my $snabbvmx_binding_file;
  my $snabbvmx_address_file;
  my $closeme = 0;
  my $addresses;
  while(<IN>) {
    chomp;
    if ($_ =~ /(snabbvmx-lwaftr-\w+-\w+)/) {
      if ("" ne $snabbvmx_config_file) {
        # TODO close files correctly. We have more than one group to handle!!
      }
      $snabbvmx_config_file = "$1.cfg.new";
      $snabbvmx_lwaftr_file = "$1.conf.new";
      $snabbvmx_binding_file = "$1.binding.new";
      $snabbvmx_address_file = "$1.address.new";
      print("new snabbvmx config file $snabbvmx_config_file\n");
      open CFG,">$snabbvmx_config_file" or die $@;
      open LWA,">$snabbvmx_lwaftr_file" or die $@;
      open BDG,">$snabbvmx_binding_file" or die $@;
      print BDG "{\n";
      open ADR,">$snabbvmx_address_file" or die $@;
      print CFG "return {\n  lwaftr = \"$snabbvmx_lwaftr_file\",\n";
      print LWA "address_map = $snabbvmx_address_file,\n";
      print LWA "binding_table = $snabbvmx_binding_file,\n";
      print LWA "vlan_tagging = false,\n";
    } elsif ($_ =~ /apply-macro ipv6_interface/) {
      if ($closeme == 1) {
        print CFG "  },\n";
      }
      print CFG "  ipv6_interface = {\n";
      $closeme = 1;
    } elsif ($_ =~ /apply-macro ipv4_interface/) {
      if ($closeme == 1) {
        print CFG "  },\n";
      }
      print CFG "  ipv4_interface = {\n";
      $closeme = 1;
    } elsif ($_ =~ /ipv6_address ([\w:]+)/) {
      print CFG "    ipv6_address = \"$1\",\n";
      print CFG "    description = \"b4\",\n";
      print LWA "aftr_ipv6_ip = $1,\n";
      print LWA "aftr_mac_inet_side = 12:12:12:12:12:12,\n";
      print LWA "inet_mac = 66:66:66:66:66:66,\n";
    } elsif ($_ =~ /service_mac ([\w.:-]+)/) {
      print CFG "    service_mac = \"$1\",\n";
    } elsif ($_ =~ /ipv4_address ([\w.]+)/) {
      print CFG "    ipv4_address = \"$1\",\n";
      print CFG "    description = \"aftr\",\n";
      print LWA "aftr_ipv4_ip = $1,\n";
      print LWA "aftr_mac_b4_side = 22:22:22:22:22:22,\n";
      print LWA "b4_mac = 44:44:44:44:44:44,\n";
    } elsif ($_ =~ /next_hop_cache/) {
      print CFG "    next_hop_cache = true,\n";
    } elsif ($_ =~ /cache_refresh_interval (\d+)/) {
      print CFG "    cache_refresh_interval = $1,\n";
    } elsif ($_ =~ /vlan (\d+)/) {
      print CFG "    vlan = $1,\n";
    } elsif (/apply-macro binding_table/) {
      # 
    } elsif (/(policy\w+)\s+(\w+)/) {
      print LWA "$1 = " . uc($2) . ",\n";
    } elsif (/(icmp\w+)\s+(\w+)/) {
      print LWA "$1 = $2,\n";
    } elsif (/(ipv\d_mtu)\s+(\d+)/) {
      print LWA "$1 = $2,\n";
    } elsif (/hairpinning/) {
      print LWA "hairpinning = true,\n";
    } elsif (/([\w:]+)+\s+(\d+.\d+.\d+.\d+),(\d+),(\d+),(\d+)/) {
      # binding entry ipv6 ipv4,psid,psid_len,shift
      print BDG " {'$1', '$2', {psid=$3, psid_len=$4, shift=$5}},\n";
      $addresses{"$2"} = "{psid_len=$4, shift=$5}";
    }
  }

  if ($closeme == 1) {
    print CFG "  },\n";
  }
  print CFG "}\n";
  print BDG "}\n";

  close IN;
  close CFG;
  close LWA;
  close BDG;

  foreach my $key (sort keys %addresses) {
    print ADR "$key $addresses{$key}\n";
  }
  close ADR;

  # compare the generated files and kick snabbvmx accordingly!
  
}

sub check_config {
  `/usr/bin/ssh -o StrictHostKeyChecking=no -i $identity snabbvmx\@$ip show conf groups > /tmp/config.new`;
  my $delta = `/usr/bin/diff /tmp/config.new /tmp/config.old 2>&1`;
  if ($delta eq "") {
    print("nothing new here\n");
  } else {
    print("something changed!\n");
    unlink "/tmp/config.old";
    rename "/tmp/config.new","/tmp/config.old";
    &process_new_config("/tmp/config.old");
  }
}

#===============================================================
if ("" eq $identity && -f $ip) {
  &process_new_config($ip);
  exit(0);
}


open CMD,'-|',"echo '<rpc><get-syslog-events> <stream>messages</stream> <event>UI_COMMIT_COMPLETED</event></get-syslog-events></rpc>'|/usr/bin/ssh -T -s -p830 -o StrictHostKeyChecking=no -i $identity snabbvmx\@$ip netconf" or die $@;
my $line;
while (defined($line=<CMD>)) {
  chomp $line;
  if ($line =~ /<syslog-events>/ || $line =~ /UI_COMMIT_COMPLETED/) {
    print("check for config change...\n");
    &check_config();
    #   `pkill --signal $signal -f 'snabb snabbvmx'`;

  }
}
close CMD;

exit;
