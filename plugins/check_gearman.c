/*********************************************************************************
*
* Nagios check_gearmand plugin
*
* License: GPL
* Copyright (c) 2013-2014 Nagios Plugin Development Team
*
* Description:
*
* This file contains the check_gearmand plugin
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
#include "utils_tcp.h"
#include "netutils.h"

// progam values
char *progname = "check_gearmand";
char *version = "0.1";
char *email = "devel@nagios-plugins.org";
char *copyright = "2013-2014";
char *developer = "Spenser Reinhardt";

// function initialization
static int process_arguments (int, char **);
void print_help (void);
void print_usage (void);

//base arg values
static char *server_addr = NULL;
static int socket_port = 4730;
static double socket_timeout = 30;
static int crit_worker = 0;
static int warn_worker = 0;
static char *func_str = NULL;
static struct function_string {
	char *name = NULL;
	int workers = 0;
	struct function_string *next = 0;
} func_struct;

// base socket values
static char *server_send = NULL;
static char *server_quit = NULL;
static char **server_expect;
static size_t server_expect_count = 0;

// base program values
static long microsec;
static char buffer[1024];


int main (int argc, char **argv) {

	// base values
	int result = STATE_UNKNOWN;
	char *status = NULL;
	struct timeval tv;
	struct timeval timeout;
	size_t len;
	int match = -1;
	fd_set rfds;

	FD_ZERO ( &rfds );

	setlocale ( LC_ALL, "" );

	//program and service name
	progname = strrchr ( argv[0], '/' );
	if ( progname != NULL ) progname++;
	else progname = argv[0];

	len = strlen ( progname );
	if ( len > 6 && !memcmp(progname, "check_", 6) ) {
		SERVICE = strdup ( progname + 6 );
		for ( i = 0; i < len -6; i++ )
			SERVICE[i] = toupper( SERVICE[i] );
	}

	server_expect  = calloc ( sizeof(char *), 2 );

	if ( process_arguments (&argc, argv, progname) == ERROR )
		usage4 ( _("Cound not parse arguments") );

	
	//timer
	signal ( SIGALRM, socket_timeout_alarm_handler );
	alarm( socket_timeout );
	gettimeofday ( &tv, NULL );

	// attempt connection and loop for recv
	result = process_tcp_request2( server_addr, server_port, &server_send, &server_expect, &server_expect_count )
	



} // end main

static int process_arguments (int argc, char **argv) {

	int c;
        int escape = 0;
        char *temp;

        int option = 0;
        static struct option longopts[] = {
                {"hostname", required_argument, 0, 'H'},
                {"critical", required_argument, 0, 'c'},
                {"warning", required_argument, 0, 'w'},
                {"timeout", required_argument, 0, 't'},
                {"port", required_argument, 0, 'p'},
		{"functions", required_argument, 0, 'f'},
                {"verbose", no_argument, 0, 'v'},
                {"help", no_argument, 0, 'h'},
                {0, 0, 0, 0}
        };

	if ( argc < 2 ) usage4 ( _("No arguments found.") );

	while ( 1 ) {

		c = getopt_long ( argc, argv, "+hvH:c:w:t:p:f:", longopts, &option );

		if ( c == -1 || c == EOF || c == 1 ) break;
	
		switch ( c ) {
			case '?':
				usage5 ();
			case 'h':
				print_help ();
				exit ( STATE_OK );
			case 'v':
				flags |= FLAG_VERBOSE;
				match_flags |= NP_MATCH_VERBOSE;
				break;
			case 'H':
				host_specified = TRUE;
				server_address = optarg;
				break;
			case 'p':
				if ( !is_intpos (optarg) )
					usage4 ( _("Port must be a positive integer.") );
				else
					server_port = atoi( optarg );
				break;
			case 't':
				if ( !is_intpos (optarg) )
					usage4 ( _("Timeout must be a positive integer.") );
				else
					socket_timeout = atoi ( optarg );
				break;
			case 'c':
				if ( !is_intpos (optarg) )
					usage4 ( _("Critical threshold must be a positive integer.") );
				else
					crit_worker = atoi ( optarg );
				break;
			case 'w':
				if ( !is_intpos (optarg) )
					usage ( _("Warning threshold must be a positive integer.") );
				else
					warn_worker = atoi ( optarg );
				break;
			case 'f':
				if ( optarg == NULL ) 
					usage ( _("Functions must be definied.") );
				else
					func_str = optarg;
				break;
			} // end case
		} // end while

	c = optind;

	// verify host has been specified (TRUE is set)
	if ( host_specified == FLASE && c < argc )
		server_address = strdup ( argv[c++] );

	// verify server addr is not null and is a nagios host
	if ( server_address == NULL )
		usage4 ( _("You must provide a server address.") );
	else if ( server_address[0] != '/' && is_host (server_address) == FALSE )
		die (STATE_CRITICAL, "%s %s - %s: %s\n", SERVICE state_text(STATE_CRITICAL), _("Invalid hostname, address, or socket"), server_address );
	
	// verify warning is less than crit value
	if ( warn_worker >= crit_worker )
		die (STATE_CRITICAL, "Warning values must be less than critical values.");
	
	return TRUE;

} // end process_arguments

void print_usage (void) {
	
	printf( "%s\n", _("Usage:") );
	printf( "%s", _("check_gearmand -H host -p port -f <func1[:threshold],...,funcN[:thresholdN]>") );
	printf( "%s\n", _("[-t <timeout>] [-c <critical workers>] [-w <warning workers>] [-v] [-h") );

} // end usage

void print_help (void) {

	print_revision ( progname, NP_VERSION );

	printf ( COPYRIGHT, copyright, developer, email );
	printf ( "%s\n", _("This plugin tests a gearman job server. It expects all functions in the function list argument to be registered for one or more workers") );

	print_usage ();
	printf ( UT_HELP_VRSN );
	printf ( UT_EXTRA_OPTS );
	printf ( UT_HOST_PORT, 'p', "4730" );
	printf ( UT_IPv46 ); 

        printf ( "%s\n", _("-f, Comma separated string of functions and optional threshold values, separated by colons(;).") );
        printf ( "%s\n", _("-t, Connection timeout, default 10 seconds.") );
        printf ( "%s\n", _("-c, Low threshold for critical number of workers per function.") );
	printf ( "%s\n", _("-w, Low threshold for warning number of workers per function.") );
        printf ( "%s\n", _("-v, Enable verbose output.") );
        printf ( "%s\n", _("-h, Print help and usage.") );

       printf ( UT_SUPPORT );

} // end print_help
