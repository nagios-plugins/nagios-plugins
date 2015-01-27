/*********************************************************************************
*
* Nagios check_uptime plugin
*
* License: GPL
* Copyright (c) 2013-2014 Nagios Plugin Development Team
*
* Description:
*
* This file contains the check_uptime plugin
*
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*********************************************************************************/

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include <time.h>

char *progname = "check_uptime";
char *version = "1.0";
char *email = "devel@nagios-plugins.org";
char *copyright = "2014";
char *developer = "Andy Brist";

static int process_arguments (int, char **);
void print_help (void);
void print_usage (void);
int verbose = 0;

char *warning, *critical, *timeunit;
thresholds *my_thresholds = NULL;

int main (int argc, char **argv) {

	// base values
	int status, intvalue;
	int upminutes, uphours, updays;
	double value, uptime;
	char* perf;
	char* output_message;

	/* Parse extra opts if any */
	argv = np_extra_opts (&argc, argv, progname);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	/* Set signal handling and alarm timeout */
	if (signal (SIGALRM, timeout_alarm_handler) == SIG_ERR) {
		die (STATE_UNKNOWN, _("Cannot catch SIGALRM"));
	}
	
	alarm (timeout_interval);
	
	value = getuptime();
	
	if (verbose >= 3) {
		printf("Uptime in seconds returned from timespec struct: %f\n", value);
	}
	intvalue = (int)value;
	
	updays = intvalue / 86400;
	uphours = (intvalue % 86400) / 3600;
	upminutes = ((intvalue % 86400) % 3600) / 60;

	if (!strncmp(timeunit, "minutes", strlen("minutes"))) {
		uptime = intvalue / 60;
	} else if (!strncmp(timeunit, "hours", strlen("hours"))) {
		uptime = intvalue / 3600;
	} else if (!strncmp(timeunit, "days", strlen("days"))) {
		uptime = intvalue / 86400;
	} else {
		uptime = intvalue;
	}	
	
	xasprintf(&output_message,_("%u day(s) %u hour(s) %u minute(s)"), updays, uphours, upminutes);
	
	xasprintf(&perf,_("%s"), 
	 fperfdata("uptime", uptime, "",
	 my_thresholds->warning?TRUE:FALSE, my_thresholds->warning?my_thresholds->warning->end:0,
	 my_thresholds->critical?TRUE:FALSE, my_thresholds->critical?my_thresholds->critical->end:0,
	 FALSE, 0,
	 FALSE, 0)
	);
	
	status = get_status(uptime, my_thresholds);
	
	if (status == STATE_OK) {
		printf("Uptime %s: %s | %s\n", _("OK"), output_message, perf);
	} else if (status == STATE_WARNING) {
		printf("Uptime %s: %s | %s\n", _("WARNING"), output_message, perf);
	} else if (status == STATE_CRITICAL) {
		printf("Uptime %s: %s | %s\n", _("CRITICAL"), output_message, perf);
	}

	return status;

} // end main

int getuptime () {

	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	if (t.tv_sec > 0) {
		return t.tv_sec;
	} else {
		printf("Uptime UNKNOWN: Timespec struct failed to retrieve uptime\n");
		exit (STATE_UNKNOWN); 
	}

} // end getuptime

static int process_arguments (int argc, char **argv) {

	int c;
        int escape = 0;
        char *temp;
	
        int option = 0;
        static struct option longopts[] = {
                {"critical", required_argument, 0, 'c'},
                {"warning", required_argument, 0, 'w'},
    		{"timeout", required_argument, 0, 't'},
                {"timeunit", required_argument, 0, 'u'},
                {"verbose", no_argument, 0, 'v'},
                {"version", no_argument, 0, 'V'},
                {"help", no_argument, 0, 'h'},
                {0, 0, 0, 0}
        };

	while ( 1 ) {

		c = getopt_long ( argc, argv, "+hvVu:c:w:t:", longopts, &option );

		if ( c == -1 || c == EOF || c == 1 ) break;
	
		switch ( c ) {
			case '?':
				usage5 ();
			case 'h':
				print_help ();
				exit ( STATE_OK );
			case 'v':
				verbose++;
				if (verbose >= 3) {
					printf("Verbose mode enabled\n");
				}
				break;
    			case 'V':
      				print_revision (progname, NP_VERSION);
      				exit (STATE_OK);
			case 'u':
				timeunit = optarg;
				break;
			case 'c':
				critical = optarg;
				break;
			case 'w':
				warning = optarg;
				break;
			case 't': /* timeout period */
				timeout_interval = parse_timeout_string (optarg);
				break;
			} // end case
		} // end while

	c = optind;
	set_thresholds(&my_thresholds, warning, critical);
	return validate_arguments ();

} // end process_arguments

int validate_arguments (void) {

	if (timeunit == NULL) {
		timeunit = "minutes";
		if (verbose >= 3) {
			printf("No unit of time measurement specified. Using default: \"minutes\"\n");
		}
	} else if (strncmp(timeunit, "seconds", strlen("seconds") + 1 ) && 
		strncmp(timeunit, "minutes", strlen("minutes") + 1) && 
		strncmp(timeunit, "hours", strlen("hours") + 1) && 
		strncmp(timeunit, "days", strlen("days") + 1)) {
		
		if (verbose >= 3) {
			printf("Invalid unit of time measurement specified: \"%s\"\n", timeunit);
		}
		usage4(_("Wrong -u argument, expected: seconds, minutes, hours, or days"));
	} else if (verbose >= 3) {
		printf("Specified unit of time measurement accepted: \"%s\"\n", timeunit);
	}
	return OK;

} //end validate

void print_usage (void) {
	
	printf( "%s\n", _("Usage:") );
	printf( "%s", _("check_uptime ") );
	printf( "%s\n", _("[-u uom] [-w threshold] [-c threshold] [-t] [-h] [-vvv] [-V]") );

} // end usage

void print_help (void) {

	print_revision ( progname, NP_VERSION );

	printf ( COPYRIGHT, copyright, developer, email );
	printf ( "%s\n", _("This plugin checks the system uptime and alerts if less than the threshold.") );
	printf ( "%s\n", _("Threshold unit of measurement specified with \"-u\".") );
	printf ( "%s\n", _("\"-u\" switch supports: seconds|minutes|hours|days.") );

	print_usage ();
	printf ( UT_HELP_VRSN );
	printf ( UT_EXTRA_OPTS );

        printf ( "%s\n", _("-t, Plugin timeout, default 10 seconds") );
        printf ( "%s\n", _("-c, Critcal threshold") );
	printf ( "%s\n", _("-w, Warning threshold") );
	printf ( "%s\n", _("-u, Time unit of measurement (seconds|minutes|hours|days) (default: minutes)") );
        printf ( "%s\n", _("-vvv, Enable verbose output") );
        //printf ( "%s\n", _("-h, Print help and usage") );

       printf ( UT_SUPPORT );

} // end print_help
