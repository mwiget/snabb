#!/usr/bin/env perl

# will be replaced with a Junos JET based script once available

my $ip=shift;
my $identity=shift;

#my $snabbvmx_binding_file = "snabbvmx-lwaftr.binding";

sub file_changed {
  my ($file) = @_;
  my $new = "$file.new";
#  print("compare file $file with $new ...\n");
  my $delta = `/usr/bin/diff $file $new 2>&1`;
  if ($delta eq "") {
#    print("nothing new in $file\n");
    return 0;
  } else {
    print("file $file has changed\n");
    unlink $file;
    rename $new, $file;
    return 1;
  }
}

sub process_new_config {
  my ($file) = @_;
  open IN,"$file" or die $@;
  my $snabbvmx_config_file;
  my @files_config;
  my @files;

  while(<IN>) {
    chomp;
    if ($_ =~ /snabbvmx-l2tpv3-(xe\d+)/) {
       if ($snabbvmx_config_file) {
          print CFG "  }\n";
          print CFG "}\n";
          close CFG;
       }
      $snabbvmx_config_file = "snabbvmx-l2tpv3-$1.cfg";
      push @files, $snabbvmx_config_file;
      open CFG,">$snabbvmx_config_file.new" or die $@;
      print CFG "return {\n";
    } elsif (/single_stick/) {
       print CFG "   single_stick = true,\n";
    } elsif (/apply-macro tunnels_([\w:]+)/) {
       print CFG "   ipv6_address = \"$1\",\n";
       print CFG "   tunnels = {\n";
    } elsif (/([\w:]+)+\s+(\d+),(\w+),(\w+)/) {
      # tunnel entry ipv6 vlan,local-cookie, remote-cookie
      print CFG "      { ipv6=\"$1\", vlan=$2, lc=\"$3\", rc=\"$4\" },\n";
    }
  }

  print CFG "  }\n";
  print CFG "}\n";

  close IN;
  close CFG;

  # compare the generated files and kick snabbvmx accordingly!
  my $signal="";   # default is no change, no signal needed

  if (@files) {
    foreach my $file (@files) {
      if (&file_changed($file))  {
        $signal='TERM';
      }
    }
  } else {
    # removing existing config files
    unlink glob('snabbvmx-l2tpv3*');
    $signal='TERM';
  }

  if ($signal) {
    print("sending $signal to process snabb snabbvmx\n");
    `pkill -$signal -f 'snabb snabbvmx'`;
    `/usr/local/bin/snabb gc`;  # removing stale counters 
  }
}

sub check_config {
  `/usr/bin/ssh -o StrictHostKeyChecking=no -i $identity snabbvmx\@$ip show conf groups > /tmp/config.new1`;

  my $newfile = "/tmp/config.new";
  open NEW, ">$newfile" or die "can't write to file $newfile";
  open IP, "/tmp/config.new1" or die "can't open file /tmp/config.new1";
  my $file;
  while (<IP>) {
     print NEW $_;
  }
  close IP;
  close NEW;

  my $delta = `/usr/bin/diff /tmp/config.new /tmp/config.old 2>&1`;
  if ($delta eq "") {
    print("snabbvmx_manager: no config change related to snabbvmx found\n");
  } else {
    print("snabbvmx_manager: updated config for snabbvmx!\n");
    unlink "/tmp/config.old";
    rename "/tmp/config.new","/tmp/config.old";
    &process_new_config("/tmp/config.old");
  }
}

#===============================================================
# main()
#===============================================================
#
if ("" eq $identity && -f $ip) {
  my $newfile = "/tmp/newfile";
  open NEW, ">$newfile" or die "can't write to file $newfile";
  open IP, "$ip" or die "can't open file $ip";
  my $file;
  while (<IP>) {
     print NEW $_;
  }
  close IP;
  close NEW;
  &process_new_config($newfile);
  exit(0);
}


open CMD,'-|',"echo '<rpc><get-syslog-events> <stream>messages</stream> <event>UI_COMMIT_COMPLETED</event></get-syslog-events></rpc>'|/usr/bin/ssh -T -s -p830 -o StrictHostKeyChecking=no -i $identity snabbvmx\@$ip netconf" or die $@;
my $line;
while (defined($line=<CMD>)) {
  chomp $line;
  if ($line =~ /<syslog-events>/ or $line =~ /UI_COMMIT_COMPLETED/) {
    print("check for config change...\n");
    &check_config();

  }
}
close CMD;

exit;
