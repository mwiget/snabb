#!/usr/bin/perl
#

$bindings=0;


open(ALL, ">result-all.csv") || die "cant write file";

print ALL "Seconds,Bindings, encap bpp, encap mpps, encap gbps, decap bpp, decap mpps, decap gbps\n";


while(<>) {

  if (/(\d+) bindings/) {
    $bindings = $1 ;
    $second=0;
    next;
  }
  next unless /^ip/;
  if (/(\d+) bpp (\d+.\d+) MPPS, (\d+.\d+) Gbps/) {
    ($bpp, $mpps, $gbps) = ($1, $2, $3);
  }

  if (/ipv4_to_ipv6/) {
    $second++;
    print ALL "$second,$bindings,$bpp,$mpps,$gbps";
    $rampup{$second}{$bindings} = $mpps;
  }
  if (/ipv6_to_ipv4/) {
    print ALL ",$bpp,$mpps,$gbps\n";
    $MPPS{$bindings}{$bpp} = $mpps;
    $GBPS{$bindings}{$bpp} = $gbps;
  }

}

open(RAMPUP, ">result-rampup.csv") || die "cant write file";

$firstrow = 1;
foreach $key (sort {$a <=> $b} keys %rampup) {
  if ($firstrow) {
    $firstrow=0;
    print RAMPUP "Seconds";
    foreach $binding (sort {$a <=> $b} keys %{$rampup{$key}}) {
      print RAMPUP ",$binding";
    }
    print RAMPUP "\n";
  }
  print RAMPUP "$key";
  foreach $binding (sort {$a <=> $b} keys %{$rampup{$key}}) {
    print RAMPUP ",$rampup{$key}{$binding}";
  }
    print RAMPUP "\n";
}

open(MPPS, ">result-mpps.csv") || die "cant write file";
$firstrow = 1;
foreach $key (sort {$a <=> $b} keys %MPPS) {
  if ($firstrow) {
    $firstrow=0;
    print MPPS "bps";
    foreach $bps (sort {$a <=> $b} keys %{$MPPS{$key}}) {
      print MPPS ",$bps";
    }
    print MPPS "\n";
  }
  print MPPS "$key";
  foreach $bps (sort {$a <=> $b} keys %{$MPPS{$key}}) {
    print MPPS ",$MPPS{$key}{$bps}";
  }
    print MPPS "\n";
}

open(GBPS, ">result-gbps.csv") || die "cant write file";
