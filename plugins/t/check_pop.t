#! /usr/bin/perl -w -I ..
#
# Post Office Protocol (POP) Server Tests via check_pop
#
#

use strict;
use Test::More;
use NPTest;

plan tests => 11;

my $host_tcp_smtp = getTestParameter( 
			"NP_HOST_TCP_SMTP",
			"A host providing an STMP Service (a mail server)",
			"mailhost"
			);

my $host_tcp_pop = getTestParameter(
			"NP_HOST_TCP_POP",
			"A host providing a POP Service (a mail server)",
			$host_tcp_smtp
			);

my $host_tcp_pop_ssl = getTestParameter(
			"NP_HOST_TCP_POP_SSL",
			"Enable SSL for the host providing a POP Service (a mail server)",
			"disabled"
			);

my $host_nonresponsive = getTestParameter(
			"NP_HOST_NONRESPONSIVE", 
			"The hostname of system not responsive to network requests",
			"10.0.0.1",
			);

my $hostname_invalid   = getTestParameter( 
			"NP_HOSTNAME_INVALID",
			"An invalid (not known to DNS) hostname",
			"nosuchhost",
			);

my %exceptions = ( 2 => "No POP Server present?" );

my $t;
my $res;

SKIP: {
        skip "SSL Disabled", 6 unless ($host_tcp_pop_ssl ne "disabled");

	$res = NPTest->testCmd( "./check_pop -H $host_tcp_pop -S -p 995" );
	cmp_ok( $res->return_code, '==', 0, "SSL POP server ok");

	$res = NPTest->testCmd( "./check_pop -H $host_tcp_pop -p 995 -w 9 -c 9 -t 10 -S -e '+OK'");
	cmp_ok( $res->return_code, '==', 0, "SSL POP server returned +OK");

	$res = NPTest->testCmd( "./check_pop $host_tcp_pop -p 995 -wt 9 -ct 9 -to 10 -S -e '+OK'");
	cmp_ok( $res->return_code, '==', 0, "SSL Old syntax");
}

SKIP: {
        skip "SSL Enabled", 6 unless ($host_tcp_pop_ssl eq "disabled");
	
	$res = NPTest->testCmd( "./check_pop $host_tcp_pop" );
	cmp_ok( $res->return_code, '==', 0, "POP server ok");

	$res = NPTest->testCmd( "./check_pop -H $host_tcp_pop -p 110 -w 9 -c 9 -t 10 -e '+OK'");
	cmp_ok( $res->return_code, '==', 0, "POP server returned +OK");

	$res = NPTest->testCmd( "./check_pop $host_tcp_pop -p 110 -wt 9 -ct 9 -to 10 -e '+OK'");
	cmp_ok( $res->return_code, '==', 0, "Old syntax");
}

$res = NPTest->testCmd( "./check_pop $host_nonresponsive" );
cmp_ok( $res->return_code, '==', 2, "Non responsive host");

$res = NPTest->testCmd( "./check_pop $hostname_invalid" );
cmp_ok( $res->return_code, '==', 2, "Invalid host");
