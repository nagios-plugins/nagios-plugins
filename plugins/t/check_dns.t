#! /usr/bin/perl -w -I ..
#
# Domain Name Server (DNS) Tests via check_dns
#
#

use strict;
use Test::More;
use NPTest;

plan skip_all => "check_dns not compiled" unless (-x "check_dns");

plan tests => 19;

my $successOutput = '/DNS OK: [\.0-9]+ seconds? response time/';

my $hostname_valid = getTestParameter( 
			"NP_HOSTNAME_VALID",
			"A valid (known to DNS) hostname",
			"nagios-plugins.org"
			);

my $hostname_valid_ip = getTestParameter(
			"NP_HOSTNAME_VALID_IP",
			"The IP address of the valid hostname $hostname_valid",
			"72.14.186.43",
			);

my $hostname_valid_reverse = getTestParameter(
			"NP_HOSTNAME_VALID_REVERSE",
			"The hostname of $hostname_valid_ip",
			"nagios-plugins.org.",
			);

my $hostname_invalid = getTestParameter( 
			"NP_HOSTNAME_INVALID", 
			"An invalid (not known to DNS) hostname",
			"nosuchhost.nagios-plugins.org",
			);

my $dns_server = getTestParameter(
			"NP_DNS_SERVER",
			"A non default (remote) DNS server",
			);

my $hostname_valid_aaaa = getTestParameter( 
			"NP_HOSTNAME_VALID_AAAA", 
			"A valid hostname for AAAA records"
			);

my $hostname_valid_mx = getTestParameter( 
			"NP_HOSTNAME_VALID_MX", 
			"A valid hostname for MX records",
			"nagios-plugins.org",
			);

my $hostname_valid_srv = getTestParameter( 
			"NP_HOSTNAME_VALID_SRV", 
			"A valid hostname for SRV records"
			); 

my $hostname_valid_txt = getTestParameter( 
			"NP_HOSTNAME_VALID_TXT", 
			"A valid hostname for TXT records"
			); 
my $res;

$res = NPTest->testCmd("./check_dns -H $hostname_valid -t 5");
cmp_ok( $res->return_code, '==', 0, "Found $hostname_valid");
like  ( $res->output, $successOutput, "Output OK" );

$res = NPTest->testCmd("./check_dns -H $hostname_valid -t 5 -w 0 -c 0");
cmp_ok( $res->return_code, '==', 2, "Critical threshold passed");

$res = NPTest->testCmd("./check_dns -H $hostname_valid -t 5 -w 0 -c 5");
cmp_ok( $res->return_code, '==', 1, "Warning threshold passed");
like( $res->output, '/\|time=[\d\.]+s;0.0*;5\.0*;0\.0*/', "Output performance data OK" );

$res = NPTest->testCmd("./check_dns -H $hostname_invalid -t 1");
cmp_ok( $res->return_code, '==', 2, "Invalid $hostname_invalid");

$res = NPTest->testCmd("./check_dns -H $hostname_valid -s $dns_server -t 5");
cmp_ok( $res->return_code, '==', 0, "Found $hostname_valid on $dns_server");
like  ( $res->output, $successOutput, "Output OK" );

$res = NPTest->testCmd("./check_dns -H $hostname_invalid -s $dns_server -t 1");
cmp_ok( $res->return_code, '==', 2, "Invalid $hostname_invalid on $dns_server");

$res = NPTest->testCmd("./check_dns -H $hostname_valid -a $hostname_valid_ip -t 5");
cmp_ok( $res->return_code, '==', 0, "Got expected address");

$res = NPTest->testCmd("./check_dns -H $hostname_valid -a 10.10.10.10 -t 5");
cmp_ok( $res->return_code, '==', 2, "Got wrong address");
like  ( $res->output, "/^DNS CRITICAL.*expected '10.10.10.10' but got '$hostname_valid_ip'".'$/', "Output OK");

$res = NPTest->testCmd("./check_dns -H $hostname_valid_ip -a $hostname_valid_reverse -t 5");
cmp_ok( $res->return_code, '==', 0, "Got expected fqdn");
like  ( $res->output, $successOutput, "Output OK");

SKIP: {
        skip "No server specified for checking TXT records", 2 unless $hostname_valid_txt;

	$res = NPTest->testCmd("./check_dns -H $hostname_valid_txt -s $dns_server -q TXT");
	cmp_ok( $res->return_code, '==', 0, "Found $hostname_valid_txt");
	like  ( $res->output, $successOutput, "TXT Output OK" );
}

SKIP: {
        skip "No server specified for checking SRV records", 2 unless $hostname_valid_srv;

	$res = NPTest->testCmd("./check_dns -H $hostname_valid_srv -s $dns_server -q SRV");
	cmp_ok( $res->return_code, '==', 0, "Found $hostname_valid_srv");
	like  ( $res->output, $successOutput, "SRV Output OK" );
}

SKIP: {
        skip "No server specified for checking AAAA records", 2 unless $hostname_valid_aaaa;

	$res = NPTest->testCmd("./check_dns -H $hostname_valid_aaaa -s $dns_server -q AAAA");
	cmp_ok( $res->return_code, '==', 0, "Found $hostname_valid_aaaa");
	like  ( $res->output, $successOutput, "TXT Output OK" );
}
