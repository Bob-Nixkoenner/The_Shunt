#!/usr/bin/env bash
# Opsec scan: finds private data (mail addresses, real IPs, MACs, home paths,
# tokens, plus local private patterns) in the work tree and optionally the
# whole git history. Output is masked: only location and kind, never the value.
# Exit code 1 on findings, 0 if clean, 2 on usage error.
#
#   tools/opsec-scan.sh [--history] [--no-private] [--path DIR]
#
# OPSEC_PATTERNS  local file with private patterns (default
#                 ~/projects/shunt-lab-results/ersetzen.txt, never in the repo).
#                 Lines: LITERAL==>repl  or  regex:PCRE==>repl
# OPSEC_MAILMAP   optional local mailmap; its last <address> per line is scanned.
set -u
history=0; private=1; dir=.
while [ $# -gt 0 ]; do
  case "$1" in
    --history) history=1 ;;
    --no-private) private=0 ;;
    --path) dir=${2:?}; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac; shift
done
cd "$dir" || exit 2
root=$(git rev-parse --show-toplevel) || exit 2
cd "$root"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export OPSEC_ALLOW="${OPSEC_ALLOW:-$here/opsec-allow.txt}"
pat="${OPSEC_PATTERNS-$HOME/projects/shunt-lab-results/ersetzen.txt}"
mm="${OPSEC_MAILMAP-$(dirname "$pat")/mailmap.txt}"
export OPSEC_PRIV_FILE="" OPSEC_MM_FILE=""
if [ "$private" = 1 ]; then
  if [ -r "$pat" ]; then OPSEC_PRIV_FILE=$pat; else echo "note: no private pattern file ($pat), generic scan only" >&2; fi
  [ -r "$mm" ] && OPSEC_MM_FILE=$mm
fi
export OPSEC_HISTORY=$history

feed() {
  if [ "$history" = 1 ]; then
    git log --all -p --no-color --no-ext-diff --format='@@C %h%n@@M %an <%ae> / %cn <%ce>%n@@S %s%n%b%n@@E' 
    git for-each-ref refs/tags --format='@@C tag-%(refname:short)%n@@M %(taggername) %(taggeremail)%n@@S %(contents)%n@@E'
  else
    git grep -I -n --no-color -e '' | sed 's/^/@@T /'
  fi
}

feed | perl -e '
use strict; use warnings;
my (%cnt, %seen);
my @allow;
if (open my $a, "<", $ENV{OPSEC_ALLOW}) { while (<$a>) { chomp; next if /^\s*(#|$)/; push @allow, qr/^(?:$_)$/i } }
my @priv;
if ($ENV{OPSEC_PRIV_FILE} and open my $p, "<", $ENV{OPSEC_PRIV_FILE}) {
  while (<$p>) { chomp; next if /^\s*(#|$)/; s/==>.*$//;
    my $re = s/^regex://r; $re = quotemeta($_) if $re eq $_;
    my $q = eval { qr/$re/i }; push @priv, $q if $q; }
}
if ($ENV{OPSEC_MM_FILE} and open my $m, "<", $ENV{OPSEC_MM_FILE}) {
  while (<$m>) { if (/<([^<>@\s]+@[^<>\s]+)>\s*$/) { push @priv, qr/\Q$1\E/i } }
}
my @gen = (
 [email => qr/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/],
 [ipv4  => qr/(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w])(?!\.\d)/],
 [mac   => qr/(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])/],
 [home  => qr{/home/[A-Za-z_][\w.-]*}],
 [token => qr/ghp_[A-Za-z0-9]{30,}|github_pat_\w{20,}|gh[ousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
 [wgkey => qr{(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])}],
);
my ($commit, $meta, $file, $ln) = ("", 0, "", 0);
sub check {
  my ($loc, $text) = @_;
  for my $g (@gen) {
    my ($kind, $re) = @$g;
    while ($text =~ /($re)/g) {
      my $v = $1;
      next if grep { $v =~ $_ } @allow;
      $kind = "ipv4-private" if $kind eq "ipv4" and $v =~ /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
      next if $kind eq "wgkey" and $v !~ /[A-Z]/ || $v !~ /[a-z]/ || $v !~ /\d/;
      # Test fixtures (lab configs, unit tests) use private-range IPs, test keys and placeholder MACs on purpose.
      next if $kind =~ /^(?:ipv4-private|mac|wgkey|token)$/ and $loc =~ m{(?:^|:)(?:test/|tests-win/|[^:]*_test\.go:|[^:]*Test\.kt:|android/app/src/test/)};
      next if $seen{"$loc $kind"}++;
      print "$loc [$kind]\n"; $cnt{$kind}++;
    }
  }
  for my $p (@priv) { if ($text =~ $p) { next if $seen{"$loc private"}++; print "$loc [private]\n"; $cnt{private}++ } }
}
while (my $l = <STDIN>) {
  chomp $l;
  if ($l =~ /^\@\@T ([^:]+):(\d+):(.*)$/) { next if $1 =~ /(?:^|\/)(?:go\.sum|[^\/]*\.sum|package-lock\.json|yarn\.lock)$/; check("$1:$2", $3); next }
  if ($l =~ /^\@\@C (.+)/) { $commit = $1; $file = ""; $meta = 1; next }
  if ($l =~ /^\@\@E/) { $meta = 0; next }
  if ($meta) { $l =~ s/^\@\@[MS] //; check("$commit:meta", $l); next }
  if ($l =~ m{^\+\+\+ b/(.*)}) { $file = $1; next }
  next if $file =~ /(?:^|\/)(?:[^\/]*\.sum|package-lock\.json|yarn\.lock)$/;
  if ($l =~ /^\+(?!\+\+)(.*)/) { check("$commit:$file", $1) }
}
my $total = 0; $total += $_ for values %cnt;
print "---\n";
print "scan ", ($ENV{OPSEC_HISTORY} ? "history" : "tree"), ": $total finding(s)";
print "  [$_: $cnt{$_}]" for sort keys %cnt;
print "\n";
exit($total ? 1 : 0);
'
