#! /usr/bin/perl
# nagios: -epn

# Complete (?) check for valid SSL certificate
# Originally by Anders Nordby (anders@fupp.net), 2015-02-16
# Copied with permission on 2019-09-26 (https://github.com/nagios-plugins/nagios-plugins/issues/72)
# and modified to fit the needs of the nagios-plugins project.

# Copyright: GPLv2

# Checks all of the following:
# Fetch SSL certificate from URL (on optional given host)
# Does the certificate contain our hostname?
# Has the certificate expired?
# Download (and cache) CRL
# Has the certificate been revoked?

use Getopt::Std;
use File::Temp qw(tempfile);
use File::Basename;
use Crypt::X509;
use Date::Parse;
use Date::Format qw(ctime);
use POSIX qw(strftime);
use Digest::MD5 qw(md5_hex);
use LWP::Simple;
use Text::Glob qw(match_glob);

use Getopt::Long;
Getopt::Long::Configure('bundling');
GetOptions(
    "h"   => \$opt_h,   "help"                  => \$opt_h,
    "d"   => \$opt_d,   "debug"                 => \$opt_d,
    "o"   => \$opt_o,   "ocsp"                  => \$opt_o,
                        "ocsp-host=s"           => \$opt_ocsp_host,
    "C=s" => \$opt_C,   "crl-cache-frequency=s" => \$opt_C,
    "I=s" => \$opt_I,   "ip=s"                  => \$opt_I,
    "p=i" => \$opt_p,   "port=i"                => \$opt_p,
    "H=s" => \$opt_H,   "cert-hostname=s"       => \$opt_H,
    "w=i" => \$opt_w,   "warning=i"             => \$opt_w,
    "c=i" => \$opt_c,   "critical=i"            => \$opt_c,
    "t"   => \$opt_t,   "timeout"               => \$opt_t
);

my $chainfh, $chainfile, $escaped_tempfile, $ocsp_status;

sub usage {
    print "check_ssl_validity -H <cert hostname> [-I <IP/host>] [-p <port>]\n[-t <timeout>] [-w <expire warning (days)>] [-c <expire critical (dats)>]\n[-C (CRL update frequency in seconds)] [-d (debug)] [--ocsp] [--ocsp-host]\n";
    print "\nWill look for hostname provided with -H in the certificate, but will contact\n";
    print "server with host/IP provided by -I (optional)\n";
    exit(1);
}

sub updatecrl {
    my $url = shift;
    my $fn = shift;

    my $content = get($url);
    if (defined($content)) {
        if (open(CACHE, ">$cachefile")) {
            print CACHE $content;
        } else {
            doexit(2, "Could not open file $fn for writing CRL temp file for cert on $host:$port.");
        }
        close(CACHE);
    } else {
        doexit(2, "Could not download CRL Distribution Point URL $url for cert on $hosttxt.");
    }
}

sub ckserial {
    return if ($crserial eq "");
    if ($serial eq $crserial) {
        if ($crrev ne "") {
            $crrevtime = str2time($crrev);
            $revtime = $crrevtime-$uxtime;
            if ($revtime < 0) {
                doexit(2, "Found certificate for $vhost on CRL $crldp revoked already at date $crrev");
            } elsif (($revtime/86400) < $crit) {
                doexit(2, "Found certificate for $vhost on CRL $crldp revoked at date $crrev, within critical time frame $crit");
            } elsif (($revtime/86400) < $warn) {
                doexit(1, "Found certificate for $vhost on CRL $crldp revoked at date $crrev, within warning time frame $warn");
            }
        }
        doexit(1, "Found certificate for $vhost on CRL $crldp revoked $crrev. Time to check the revokation date");
    }
}

usage unless ($opt_H);

# Defaults
if ($opt_p) {
        $port = $opt_p;
} else {
        $port = 443;
}

if ($opt_t) {
        $tmout = $opt_t;
} else {
        $tmout = 10;
}

if ($opt_C) {
    $crlupdatefreq = $opt_C;
} else {
    $crlupdatefreq = 86400;
}

$vhost = $opt_H;
if ($opt_I) {
    $host = $opt_I;
} else {
    $host = $vhost;
}
$hosttxt = "$host:$port";

if ($opt_w && $opt_w =~ /^\d+$/) {
    $warn = $opt_w;
} else {
    $warn = 30;
}
if ($opt_c && $opt_c =~ /^\d+$/) {
    $crit = $opt_c;
} else {
    $crit = 30;
}

sub doexit {
    my $ret = shift;
    my $txt = shift;
    if ($ret == 0) {
        print "OK: ";
    }
    elsif ($ret == 1) {
        print "WARNING: ";
    }
    elsif ($ret == 2) {
        print "CRITICAL: ";
    }
    else {
        print "UNKNOWN: ";
    }
    print "$txt\n";
    exit($ret);
}

$alldata = "";
$cert = "";
$mode = 0;
open(CMD, "echo | openssl s_client -servername $vhost -connect $host:$port 2>&1 |");
while (<CMD>) {
    $alldata .= $_;
    if ($mode == 0) {
        if (/-----BEGIN CERTIFICATE-----/) {
            $cert .= $_;
            $mode = 1;
        }
    } elsif ($mode == 1) {
        $cert .= $_;
        if (/-----END CERTIFICATE-----/) {
            $mode = 2;
        }
    }
}
close(CMD);
$ret = $?;
if ($ret != 0) {
    $alldata =~ s@\n@ @g;
    $alldata =~ s@\s+$@@;
    doexit(2, "Error connecting to $hosttxt: $alldata");
} elsif ($cert eq "") {
    doexit(2, "No certificate found on $hosttxt");
} else {
    ($tmpfh,$tempfile) = tempfile(DIR=>'/tmp',UNLINK=>0);
    doexit(2, "Failed to open temp file: $!") unless (defined($tmpfh));
    $tmpfh->print($cert);
    $tmpfh->close;
}

$dercert = `openssl x509 -in $tempfile -outform DER 2>&1`;
$ret = $?;
if ($ret != 0) {
    $dercert =~ s@\n@ @g;
    $dercert =~ s@\s+$@@;
    doexit(2, "Could not convert certificate from PEM to DER format: $dercert");
}

$decoded = Crypt::X509->new( cert => $dercert );
if ($decoded->error) {
    doexit(2, "Could not parse X509 certificate on $hosttxt: " . $decoded->error);
}

$oktxt = "";
$cn = $decoded->subject_cn;
if ($opt_d) { print "Found CN: $cn\n"; }
if ($vhost eq $decoded->subject_cn) {
    $oktxt .= "Host $vhost matches CN $vhost on $hosttxt ";
} elsif ($decoded->subject_cn =~ /^.*\.(.*)$/) {
    $wcdomain = $1;
    $domain = $vhost;
    $domain =~ s@^[\w\-]+\.@@;
    if ($domain eq $wcdomain) {
        $oktxt .= "Host $vhost matches wildcard CN " . $decoded->subject_cn . " on $hosttxt ";
    }
}

if ($oktxt eq "") {
    # Cert not yet found
    if (defined($decoded->SubjectAltName)) {
        # Check altnames
        $altfound = 0;
        foreach $altnametxt (@{$decoded->SubjectAltName}) {
            if ($altnametxt =~ /^dNSName=(.*)/) {
                $altname = $1;
                if ($opt_d) { print "Found SAN: $altname\n"; }
                if (match_glob($altname, $vhost)) {
                    $altfound = 1;
                    $oktxt .= "Host $vhost found in SAN on $hosttxt ";
                    last;
                }
            }
        }
        if ($altfound == 0) {
            doexit(2, "Host $vhost not found in certificate on $hosttxt, not in CN or in alternative names");
        }
    } else {
        doexit(2, "Host $vhost not found in certificate on $hosttxt, not in CN and no alternative names found");
    }
}

# Check expire time
$uxtimegmt = strftime "%s", gmtime;
$uxtime = strftime "%s", localtime;
$certtime = $decoded->not_after;
$certdays = ($certtime-$uxtimegmt)/86400;
$certdaysfmt = sprintf("%.1f", $certdays);

if ($certdays < 0) {
    doexit(2, "${oktxt}but it is expired ($certdaysfmt days)");
} elsif ($certdays < $crit) {
    doexit(2, "${oktxt}but it is expiring in only $certdaysfmt days, critical limit is $crit.");
} elsif ($certdays < $warn) {
    doexit(1, "${oktxt}but it is expiring in only $certdaysfmt days, warning limit is $warn.");
}

$serial = $decoded->serial;
$serial = lc(sprintf("%x", $serial));
if ($opt_d) {
    print "Certificate serial: $serial\n";
}

if ($opt_o) {
    # Do OCSP instead of CRL checking

    $ocsp_uri = `openssl x509 -noout -ocsp_uri -in $tempfile`;
    $ocsp_uri =~ s/\s+$//;

    ($chainfh,$chainfile) = tempfile(DIR=>'/tmp',UNLINK=>0);
    # Get the certificate chain
    $chain_raw = `echo "Q" | openssl s_client -servername $vhost -connect $host:$port -showcerts 2>/dev/null`;
    $mode = 0;
    for(split /^/, $chain_raw) {
        if (/-----BEGIN CERTIFICATE-----/) {
            $mode += 1;
        }
        # Skip the first certificate returned
        if ($mode > 1) {
            $chain_processed .= $_;
        }
        if (/-----END CERTIFICATE-----/) {
            if ($mode > 1) {
                $mode -= 1;
            }
        }
    }

    $chainfh->print($chain_processed);
    $chainfh->close;

    $ocsp_cache = md5_hex($chain_processed);
    $ocsp_cache_file = dirname(__FILE__) . "/ssl_validity_data_" . $ocsp_cache;

    open(OCSP_CACHE, $ocsp_cache_file);
    while (my $line = <OCSP_CACHE>) {
        chomp $line;
        if ($line =~ /[0-9]+/) {
            $next_update_time = $line;
        }
    }
    close(OCSP_CACHE);

    $current_time = time();

    if ($current_time < $next_update_time) {
        # Use cached result
        $next_update_time_str = ctime($next_update_time);
        chomp $next_update_time_str;
        $ocsp_status = "good (cached until $next_update_time_str)";
    }
    else {
        # Time to update
        $cmd = "openssl ocsp -issuer $chainfile -verify_other $chainfile -cert $tempfile -url $ocsp_uri -text";
        if ($opt_ocsp_host) {
            $cmd .= " -header \"Host\" \"$opt_ocsp_host\"";
        }
        open(CMD, $cmd . " 2>/dev/null |");
        $escaped_tempfile = $tempfile;
        $escaped_tempfile =~ s/([\\\|\(\)\[\]\{\}\^\$\*\+\?\.])/\1/g;
        $ocsp_status = "unknown";
        while (<CMD>) {
            chomp;
            if ($_ =~ s/Next Update: (.*)/$1/) {
                $next_update_time = str2time($_);
            }

            if ($_ =~ s/$escaped_tempfile: (.*)/$1/) {
                $ocsp_status = $_;
            }
        }

        if ($ocsp_status =~ /good/) {
            open(OCSP_CACHE, ">", $ocsp_cache_file);
            print OCSP_CACHE $next_update_time;
            close(OCSP_CACHE);
        }
    }

    my $exit_code = 2;
    if ($ocsp_status =~ /good/) {
        $exit_code = 0;
    }
    doexit($exit_code, "$oktxt; OCSP responder ($ocsp_uri) says certificate is $ocsp_status");
}
else {
    # Do CRL-based checking

    @crldps = @{$decoded->CRLDistributionPoints};
    $crlskip = 0;
    foreach $crldp (@crldps) {
        if ($opt_d) {
            print "Checking CRL DP $crldp.\n";
        }
        $cachefile = "/tmp/" . md5_hex($crldp) . "_crl.tmp";
        if (-f $cachefile) {
            $cacheage = $uxtime-(stat($cachefile))[9];
            if ($cacheage > $crlupdatefreq) {
                if ($opt_d) { print "Download update, more than a day old.\n"; }
                updatecrl($crldp, $cachefile);
            } else {
                if ($opt_d) { print "Reusing cached copy.\n"; }
            }
        } else {
            if ($opt_d) { print "Download initial copy.\n"; }
            updatecrl($crldp, $cachefile);
        }

        $crl = "";
        my $format;
        open(my $cachefile_io, '<', $cachefile);
        $format = <$cachefile_io> =~ /-----BEGIN X509 CRL-----/ ? 'PEM' : 'DER';
        close $cachefile_io;
        open(CMD, "openssl crl -inform $format -text -in $cachefile -noout 2>&1 |");
        while (<CMD>) {
            $crl .= $_;
        }
        close(CMD);
        $ret = $?;
        if ($ret != 0) {
            $crl =~ s@\n@ @g;
            $crl =~ s@\s+$@@;
            doexit(2, "Could not parse $format from URL $crldp while checking $hosttxt: $crl");
        }

        # Crude CRL parsing goes here
        $mode = 0;
        foreach $cline (split(/\n/, $crl)) {
            if ($cline =~ /.*Next Update: (.+)/) {
                $nextup = $1;
                $nextuptime = str2time($nextup);
                $crlvalid = $nextuptime-$uxtime;
                if ($opt_d) { print "Next CRL update: $nextup\n"; }
                if ($crlvalid < 0) {
                    doexit(2, "Could not use CRL from $crldp, it expired past next update on $nextup");
                }
            } elsif ($cline =~ /.*Last Update: (.+)/) {
                $lastup = $1;
                if ($opt_d) { print "Last CRL update: $lastup\n"; }
            } elsif ($mode == 0) {
                if ($cline =~ /.*Serial Number: (\S+)/i) {
                    ckserial;
                    $crserial = lc($1);
                    $crrev = "";
                } elsif ($cline =~ /.*Revocation Date: (.+)/i) {
                    $crrev = $1;
                }
            } elsif ($cline =~ /Signature Algorithm/) {
                last;
            }
        }
        ckserial;
    }
}
if (-f $tempfile) {
    unlink ($tempfile);
}

$oktxt =~ s@\s+$@@;
print "$oktxt, still valid for $certdaysfmt days. ";
if ($crlskip == 0) {
    print "Serial $serial not found on any Certificate Revokation Lists.\n";
} else {
    print "CRL checks skipped, next check in " . ($crlupdatefreq - $cacheage) . " seconds.\n";
}

exit 0;