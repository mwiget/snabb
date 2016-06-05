#!/usr/bin/perl
print <<EOF;
      apply-macro tunnels {
EOF
for (my $vlan = 1; $vlan < 4095; $vlan++) {
#      { ipv6="fc01::$vlan", vlan=$vlan, lc="00000000", rc="00000000" },
   print <<EOF;
         fc00:1::$vlan $vlan,00000000,00000000;
EOF
}
print <<EOF;
      }
EOF

