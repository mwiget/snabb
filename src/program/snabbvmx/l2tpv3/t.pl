#!/usr/bin/perl
print <<EOF;

return {
   tunnels = {
EOF
for (my $vlan = 1; $vlan < 4095; $vlan++) {
   print <<EOF;
      { ipv6="fc01::$vlan", vlan=$vlan, lc="00000000", rc="00000000" },
EOF
}
print <<EOF;
   }
}
EOF

