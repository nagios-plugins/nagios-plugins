#!@PERL@ -w

# check_file_age.pl Copyright (C) 2003 Steven Grimm <koreth-nagios@midwinter.com>
#
# Checks a file's size and modification time to make sure it's not empty
# and that it's sufficiently recent.
#
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# you should have received a copy of the GNU General Public License
# along with this program (or with Nagios);  if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, 
# Boston, MA 02110-1301, USA

use strict;
use English;
use Getopt::Long;
use File::stat;
use File::Basename;
use vars qw($PROGNAME);
use FindBin;
use lib "$FindBin::Bin";
use lib '@libexecdir@';
use utils qw (%ERRORS &print_revision &support);

sub print_help ();
sub print_usage ();

my ($opt_c, $opt_f, $opt_w, $opt_C, $opt_W, $opt_h, $opt_V, $opt_i);
my ($result, $message, $age, $size, $st, $perfdata, $output, @filelist, $filename, $safe_filename, $counter, $summary, $high_water_mark, $this_level, $this_result);

$PROGNAME="check_file_age";

$ENV{'PATH'}='@TRUSTED_PATH@';
$ENV{'BASH_ENV'}=''; 
$ENV{'ENV'}='';

$opt_w = 240;
$opt_c = 600;
$opt_W = 0;
$opt_C = 0;
$opt_f = "";

Getopt::Long::Configure('bundling');
GetOptions(
	"V"   => \$opt_V, "version"	=> \$opt_V,
	"h"   => \$opt_h, "help"	=> \$opt_h,
	"i"   => \$opt_i, "ignore-missing"	=> \$opt_i,
	"f=s" => \$opt_f, "file"	=> \$opt_f,
	"w=f" => \$opt_w, "warning-age=f" => \$opt_w,
	"W=f" => \$opt_W, "warning-size=f" => \$opt_W,
	"c=f" => \$opt_c, "critical-age=f" => \$opt_c,
	"C=f" => \$opt_C, "critical-size=f" => \$opt_C);

if ($opt_V) {
	print_revision($PROGNAME, '@NP_VERSION@');
	exit $ERRORS{'OK'};
}

if ($opt_h) {
	print_help();
	exit $ERRORS{'OK'};
}

$opt_f = shift unless ($opt_f);

if (! $opt_f) {
	print "FILE_AGE UNKNOWN: No file specified\n";
	exit $ERRORS{'UNKNOWN'};
}

$opt_f = '"' . $opt_f . '"' if $opt_f =~ / /;

# Check that file(s) exists (can be directory or link)
$perfdata = "";
$output = "";
@filelist = glob($opt_f);
$counter = 0;
$high_water_mark = 0;

$result = "OK";
foreach $filename (@filelist) {
	unless (-e $filename) {
		if ($opt_i) {
			if ($output) {
				$output = $output . "\n";
			}
			$output = $output . "FILE_AGE OK: $filename doesn't exist, but ignore-missing was set\n";
			$this_result = "OK";
			$this_level = 0;

		} else {
			if ($output) {
				$output = $output . "\n";
			}
			$output = $output . "FILE_AGE CRITICAL: File not found - $filename\n";
			$this_result = "CRITICAL";
			$this_level = 2;
		}

		if ($high_water_mark < $this_level) {
			$high_water_mark = $this_level;
			$counter = 1;
			$result = $this_result;
		}
		elsif($high_water_mark = $this_level) {
			$counter = $counter + 1;
		}
		next;
	}

	$st = File::stat::stat($filename);
	$age = time - $st->mtime;
	$size = $st->size;
	if (scalar @filelist == 1) {
		$perfdata = $perfdata . "age=${age}s;${opt_w};${opt_c} size=${size}B;${opt_W};${opt_C};0 ";
	}
	else {
		$safe_filename = basename($filename);
		$safe_filename =~ s/[='"]/_/g;
		$perfdata = $perfdata . "${safe_filename}_age=${age}s;${opt_w};${opt_c} ${safe_filename}_size=${size}B;${opt_W};${opt_C};0 ";
	}

	$this_result = 'OK';
	$this_level = 0;

	if (($opt_c and $age > $opt_c) or ($opt_C and $size < $opt_C)) {
		$this_result = 'CRITICAL';
		$this_level = 2;
	}
	elsif (($opt_w and $age > $opt_w) or ($opt_W and $size < $opt_W)) {
		$this_result = 'WARNING';
		$this_level = 1;
	}

	if ($high_water_mark < $this_level) {
		$high_water_mark = $this_level;
		$counter = 1;
		$result = $this_result;
	}
	elsif ($high_water_mark == $this_level) {
		$counter = $counter + 1;
	}

	if ($output) {
		$output = $output . "\n";
	}
	$output = $output . "FILE_AGE $this_result: $filename is $age seconds old and $size bytes ";
}

$summary = "$result: $counter files are $result";

if (scalar @filelist == 1) {
	print "$output | $perfdata \n";
}
else {
	print "$summary \n$output | $perfdata \n";
}


exit $ERRORS{$result};

sub print_usage () {
	print "Usage:\n";
	print "  $PROGNAME [-w <secs>] [-c <secs>] [-W <size>] [-C <size>] [-i] -f <file>\n";
	print "  $PROGNAME [-h | --help]\n";
	print "  $PROGNAME [-V | --version]\n";
}

sub print_help () {
	print_revision($PROGNAME, '@NP_VERSION@');
	print "Copyright (c) 2003 Steven Grimm\n\n";
	print_usage();
	print "\n";
	print "  -i | --ignore-missing :  return OK if the file does not exist\n";
	print "  <secs>  File must be no more than this many seconds old (default: warn 240 secs, crit 600)\n";
	print "  <size>  File must be at least this many bytes long (default: crit 0 bytes)\n";
	print "\n";
	support();
}
