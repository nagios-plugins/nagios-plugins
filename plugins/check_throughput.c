/*****************************************************************************
*
* check_snmp_throughput - Nagios plugin for SNMP interface throughput
*
* License: GPL
* Copyright (c) 1999-2018 Nagios Plugins Development Team
*
* Description:
*
* Monitors interface bandwidth utilization via SNMP by polling ifInOctets /
* ifOutOctets (32-bit) or ifHCInOctets / ifHCOutOctets (64-bit) counters and
* calculating the rate of change between successive plugin invocations.
* State is persisted in a local SQLite database.
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
*
*****************************************************************************/

const char *progname = "check_snmp_throughput";
const char *copyright = "1999-2018";
const char *email = "devel@nagios-plugins.org";

#include "common.h"
#include "runcmd.h"
#include "utils.h"
#include "utils_cmd.h"
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>

#ifndef LOCALEDIR
#define LOCALEDIR "/usr/local/nagios/share/locale"
#endif

#define DEFAULT_COMMUNITY "public"
#define DEFAULT_PORT "161"
#define DEFAULT_PROTOCOL "1"
#define DEFAULT_RETRIES 5
#define DEFAULT_AUTH_PROTOCOL "MD5"
#define DEFAULT_PRIV_PROTOCOL "DES"
#define DEFAULT_UNITS "mbps"

/* Longopts-only arguments */
#define L_COUNTER_BITS CHAR_MAX+1
#define L_DB_PATH      CHAR_MAX+2
#define L_DB_KEY       CHAR_MAX+3

int process_arguments (int, char **);
int validate_arguments (void);
void print_usage (void);
void print_help (void);

char *server_address = NULL;
char *community = NULL;
char **contextargs = NULL;
char *context = NULL;
char **authpriv = NULL;
char *proto = NULL;
char *seclevel = NULL;
char *secname = NULL;
char *authproto = NULL;
char *privproto = NULL;
char *authpasswd = NULL;
char *privpasswd = NULL;
char *port = NULL;
int   numcontext = 0;
int   numauthpriv = 0;
int   retries = 0;
int   verbose = 0;
char *ip_version = "";

/* Throughput-specific globals */
char *oid_index  = NULL;  /* -i: interface index or name; appended to counter OIDs */
char *db_key     = NULL;  /* --db-key: SQLite state key; defaults to oid_index if omitted */
char *db_path = NULL;
char *custom_db_path = NULL;
int   explicit_counter_bits = 0;
char *units = NULL;
char *warning_thresholds = NULL;
char *critical_thresholds = NULL;
thresholds *thr_in = NULL;
thresholds *thr_out = NULL;

typedef struct {
	time_t             timestamp;
	unsigned long long in_octets;
	unsigned long long out_octets;
	int                counter_bits;
} OctetData;

const char *determine_db_path(void);
int   db_init(const char *db_path);
int   db_read_state(const char *db_path, const char *host, const char *iface, OctetData *data);
int   db_write_state(const char *db_path, const char *host, const char *iface, const OctetData *data);
unsigned long long calculate_wraparound(unsigned long long current, unsigned long long previous, int counter_bits);
double calc_bw(unsigned long long octet_diff, time_t time_diff, const char *unit);


int
main (int argc, char **argv)
{
	int i, return_code, external_error;
	char **command_line = NULL;
	char *snmpcmd = NULL;
	output chld_out, chld_err;
	time_t current_time;
	int command_interval;

	OctetData current = {0};
	OctetData previous = {0};
	int state = STATE_UNKNOWN;

	char oid_in[256], oid_out[256];

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	port = strdup (DEFAULT_PORT);
	retries = DEFAULT_RETRIES;

	np_init( (char *) progname, argc, argv );
	argv = np_extra_opts (&argc, argv, progname);
	np_set_args(argc, argv);

	time(&current_time);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	if (db_path == NULL)
		db_path = (char *)determine_db_path();

	command_interval = timeout_interval / retries + 1;
	if (command_interval < 1)
		usage4 (_("Command timeout must be 1 second or greater. Please increase timeout (-t) or decrease retries (-e)."));

	/* Display label: the interface index/name as provided. */
	const char *iface_label = oid_index;

	/* Counter width: explicit flag, defaulting to 64-bit */
	{
		int use_64 = (explicit_counter_bits == 32) ? 0 : 1;

		snprintf(oid_in,  sizeof(oid_in),  "%s.%s",
		         use_64 ? "1.3.6.1.2.1.31.1.1.1.6"  : "1.3.6.1.2.1.2.2.1.10", oid_index);
		snprintf(oid_out, sizeof(oid_out), "%s.%s",
		         use_64 ? "1.3.6.1.2.1.31.1.1.1.10" : "1.3.6.1.2.1.2.2.1.16", oid_index);
		current.counter_bits = use_64 ? 64 : 32;
	}

	snmpcmd = strdup(PATH_TO_SNMPGET);

	/* 10 base args + context + authpriv + host + 2 OIDs + NULL */
	command_line = calloc(10 + numcontext + numauthpriv + 1 + 2 + 1, sizeof(char *));
	command_line[0] = snmpcmd;
	command_line[1] = strdup("-Le");
	command_line[2] = strdup("-t");
	xasprintf(&command_line[3], "%d", command_interval);
	command_line[4] = strdup("-r");
	xasprintf(&command_line[5], "%d", retries);
	command_line[6] = strdup("-m");
	command_line[7] = strdup("");
	command_line[8] = strdup("-v");
	command_line[9] = strdup(proto);

	for (i = 0; i < numcontext; i++)
		command_line[10 + i] = contextargs[i];

	for (i = 0; i < numauthpriv; i++)
		command_line[10 + numcontext + i] = authpriv[i];

	int base = 10 + numcontext + numauthpriv;
	xasprintf(&command_line[base], "%s%s:%s", ip_version, server_address, port);
	command_line[base + 1] = oid_in;
	command_line[base + 2] = oid_out;
	command_line[base + 3] = NULL;

	if (signal(SIGALRM, runcmd_timeout_alarm_handler) == SIG_ERR)
		usage4(_("Cannot catch SIGALRM"));

	if (verbose)
		printf("snmpget %s:%s %s %s\n", server_address, port, oid_in, oid_out);

	alarm(timeout_interval + 1);
	return_code = cmd_run_array(command_line, &chld_out, &chld_err, 0);
	alarm(0);

	external_error = 0;
	if (return_code != 0)   external_error = 1;
	if (chld_out.lines == 0) external_error = 1;

	if (external_error) {
		if (chld_err.lines > 0 && strstr(chld_err.line[0], "Timeout")) {
			printf(_("%s - External command error: %s\n"), state_text(timeout_state), chld_err.line[0]);
			exit(timeout_state);
		} else if (chld_err.lines > 0) {
			printf(_("External command error: %s\n"), chld_err.line[0]);
			exit(STATE_UNKNOWN);
		} else {
			printf(_("External command error with no output (return code: %d)\n"), return_code);
			exit(STATE_UNKNOWN);
		}
	}

	if (verbose) {
		for (i = 0; i < chld_out.lines; i++)
			printf("%s\n", chld_out.line[i]);
	}

	/* Parse the two counter values from snmpget output */
	current.timestamp = current_time;

	{
		int val_idx = 0;
		for (i = 0; i < chld_out.lines && val_idx < 2; i++) {
			char *ptr = chld_out.line[i];
			char *eq = strstr(ptr, " = ");
			int   eq_len = 3;
			if (!eq) { eq = strstr(ptr, "="); eq_len = 1; }
			if (!eq) continue;
			char *val_ptr = eq + eq_len;

			static const struct { const char *tag; int len; } tags[] = {
				{"Counter64:", 10}, {"Counter32:", 10}, {"Gauge32:", 8}, {"INTEGER:", 8}, {NULL, 0}
			};
			for (int t = 0; tags[t].tag; t++) {
				char *p = strstr(val_ptr, tags[t].tag);
				if (p) { val_ptr = p + tags[t].len; break; }
			}

			while (*val_ptr == ' ' || *val_ptr == '\t') val_ptr++;

			unsigned long long val = strtoull(val_ptr, NULL, 10);
			if (val_idx == 0) current.in_octets  = val;
			else              current.out_octets = val;
			val_idx++;
		}

		if (val_idx < 2) {
			printf(_("UNKNOWN - Failed to parse counter values from SNMP output\n"));
			exit(STATE_UNKNOWN);
		}
	}

	/* First run: write baseline */
	if (db_read_state(db_path, server_address, db_key, &previous) != STATE_OK) {
		db_write_state(db_path, server_address, db_key, &current);
		printf("OK - Baseline established for %s interface %s (ifindex %s)\n",
			server_address, iface_label, oid_index);
		exit(STATE_OK);
	}

	const char *unit_str = (units && *units) ? units : DEFAULT_UNITS;
	time_t time_diff = current.timestamp - previous.timestamp;

	if (time_diff <= 0) {
		printf(_("UNKNOWN - Time delta between checks is zero or negative\n"));
		exit(STATE_UNKNOWN);
	}

	double val_in  = calc_bw(calculate_wraparound(current.in_octets,  previous.in_octets,  current.counter_bits), time_diff, unit_str);
	double val_out = calc_bw(calculate_wraparound(current.out_octets, previous.out_octets, current.counter_bits), time_diff, unit_str);

	state = max_state(
		thr_in  ? get_status(val_in,  thr_in)  : STATE_OK,
		thr_out ? get_status(val_out, thr_out) : STATE_OK);

	db_write_state(db_path, server_address, db_key, &current);

	printf("%s - In: %.2f %s, Out: %.2f %s | in=%.2f%s;%s;%s out=%.2f%s;%s;%s\n",
		state_text(state),
		val_in,  unit_str,
		val_out, unit_str,
		val_in,  unit_str,
		thr_in && thr_in->warning_string  ? thr_in->warning_string  : "",
		thr_in && thr_in->critical_string ? thr_in->critical_string : "",
		val_out, unit_str,
		thr_out && thr_out->warning_string  ? thr_out->warning_string  : "",
		thr_out && thr_out->critical_string ? thr_out->critical_string : "");

	exit(state);
}


int
process_arguments (int argc, char **argv)
{
	int c;
	int option = 0;

	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"community",     required_argument, 0, 'C'},
		{"units",         required_argument, 0, 'u'},
		{"port",          required_argument, 0, 'p'},
		{"retries",       required_argument, 0, 'e'},
		{"protocol",      required_argument, 0, 'P'},
		{"context",       required_argument, 0, 'N'},
		{"seclevel",      required_argument, 0, 'L'},
		{"secname",       required_argument, 0, 'U'},
		{"authproto",     required_argument, 0, 'a'},
		{"privproto",     required_argument, 0, 'x'},
		{"authpasswd",    required_argument, 0, 'A'},
		{"privpasswd",    required_argument, 0, 'X'},
		{"counter-bits",  required_argument, 0, L_COUNTER_BITS},
		{"db-path",       required_argument, 0, L_DB_PATH},
		{"db-key",        required_argument, 0, L_DB_KEY},
		{"ipv4",          no_argument,       0, '4'},
		{"ipv6",          no_argument,       0, '6'},
		{0, 0, 0, 0}
	};

	if (argc < 2)
		return ERROR;

	while (1) {
		c = getopt_long(argc, argv,
		    "hvVO46t:c:w:H:C:u:p:e:P:N:L:U:a:x:A:X:i:",
		    longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case '?':
			usage5();
		case 'h':
			print_help();
			exit(STATE_OK);
		case 'V':
			print_revision(progname, VERSION);
			exit(STATE_OK);
		case 'v':
			verbose++;
			break;
		case 'H':
			server_address = optarg;
			break;
		case 'C':
			community = optarg;
			break;
		case 'u':
			units = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 'e':
		case 'E':
			if (!is_integer(optarg))
				usage2(_("Retries must be a positive integer"), optarg);
			else
				retries = atoi(optarg);
			break;
		case 't':
			timeout_interval = parse_timeout_string(optarg);
			break;
		case 'w':
			warning_thresholds = optarg;
			break;
		case 'c':
			critical_thresholds = optarg;
			break;
		case 'P':
			proto = optarg;
			break;
		case 'N':
			context = optarg;
			break;
		case 'L':
			seclevel = optarg;
			break;
		case 'U':
			secname = optarg;
			break;
		case 'a':
			authproto = optarg;
			break;
		case 'x':
			privproto = optarg;
			break;
		case 'A':
			authpasswd = optarg;
			break;
		case 'X':
			privpasswd = optarg;
			break;
		case 'i':
			oid_index = optarg;
			break;
		case L_COUNTER_BITS:
			explicit_counter_bits = atoi(optarg);
			if (explicit_counter_bits != 32 && explicit_counter_bits != 64)
				usage2(_("--counter-bits must be 32 or 64"), optarg);
			break;
		case L_DB_PATH:
			custom_db_path = optarg;
			break;
		case L_DB_KEY:
			db_key = optarg;
			break;
		case '4':
			break;
		case '6':
			xasprintf(&ip_version, "udp6:");
			break;
		}
	}

	if (server_address == NULL)
		server_address = argv[optind];

	if (community == NULL)
		community = strdup(DEFAULT_COMMUNITY);

	return validate_arguments();
}


int
validate_arguments (void)
{
	if (server_address == NULL)
		die(STATE_UNKNOWN, _("No host specified\n"));

	if (oid_index == NULL)
		die(STATE_UNKNOWN, _("-i is required (interface index or name to append to the counter OIDs)\n"));

	/* DB key defaults to the numeric ifindex when not explicitly set */
	if (db_key == NULL)
		db_key = oid_index;

	if (units != NULL) {
		static const char *valid_units[] = {
			"bps", "kbps", "mbps", "gbps",
			"Bps", "KBps", "MBps", "GBps", NULL};
		int i, valid = 0;
		for (i = 0; valid_units[i]; i++) {
			if (strcmp(units, valid_units[i]) == 0) { valid = 1; break; }
		}
		if (!valid)
			die(STATE_UNKNOWN, _("Invalid units '%s'. Must be: bps, kbps, mbps, gbps, Bps, KBps, MBps, or GBps\n"), units);
	}

	/* Thresholds: -w WARN or -w WARN_IN,WARN_OUT for separate in/out limits */
	if (warning_thresholds || critical_thresholds) {
		char *w_in_s  = NULL, *w_out_s  = NULL;
		char *c_in_s  = NULL, *c_out_s  = NULL;
		char *comma;

		if (warning_thresholds) {
			w_in_s = strdup(warning_thresholds);
			if ((comma = strchr(w_in_s, ',')) != NULL) {
				*comma  = '\0';
				w_out_s = comma + 1;
			}
		}
		if (critical_thresholds) {
			c_in_s = strdup(critical_thresholds);
			if ((comma = strchr(c_in_s, ',')) != NULL) {
				*comma  = '\0';
				c_out_s = comma + 1;
			}
		}

		set_thresholds(&thr_in, w_in_s, c_in_s);

		if (w_out_s || c_out_s)
			set_thresholds(&thr_out, w_out_s, c_out_s);
		else
			thr_out = thr_in;
	}

	if (proto == NULL)
		xasprintf(&proto, DEFAULT_PROTOCOL);

	if ((strcmp(proto, "1") == 0) || (strcmp(proto, "2c") == 0)) {
		numauthpriv = 2;
		authpriv = calloc(numauthpriv, sizeof(char *));
		authpriv[0] = strdup("-c");
		authpriv[1] = strdup(community);
	} else if (strcmp(proto, "3") == 0) {
		if (context != NULL) {
			numcontext = 2;
			contextargs = calloc(numcontext, sizeof(char *));
			contextargs[0] = strdup("-n");
			contextargs[1] = strdup(context);
		}
		if (seclevel == NULL)
			xasprintf(&seclevel, "noAuthNoPriv");
		if (secname == NULL)
			die(STATE_UNKNOWN, _("Required parameter: %s\n"), "secname");

		if (strcmp(seclevel, "noAuthNoPriv") == 0) {
			numauthpriv = 4;
			authpriv = calloc(numauthpriv, sizeof(char *));
			authpriv[0] = strdup("-l"); authpriv[1] = strdup("noAuthNoPriv");
			authpriv[2] = strdup("-u"); authpriv[3] = strdup(secname);
		} else if (strcmp(seclevel, "authNoPriv") == 0 || strcmp(seclevel, "authPriv") == 0) {
			if (authproto == NULL) xasprintf(&authproto, DEFAULT_AUTH_PROTOCOL);
			if (authpasswd == NULL) die(STATE_UNKNOWN, _("Required parameter: %s\n"), "authpasswd");

			if (strcmp(seclevel, "authNoPriv") == 0) {
				numauthpriv = 8;
				authpriv = calloc(numauthpriv, sizeof(char *));
				authpriv[0] = strdup("-l"); authpriv[1] = strdup("authNoPriv");
				authpriv[2] = strdup("-a"); authpriv[3] = strdup(authproto);
				authpriv[4] = strdup("-u"); authpriv[5] = strdup(secname);
				authpriv[6] = strdup("-A"); authpriv[7] = strdup(authpasswd);
			} else {
				if (privproto == NULL) xasprintf(&privproto, DEFAULT_PRIV_PROTOCOL);
				if (privpasswd == NULL) die(STATE_UNKNOWN, _("Required parameter: %s\n"), "privpasswd");
				numauthpriv = 12;
				authpriv = calloc(numauthpriv, sizeof(char *));
				authpriv[0]  = strdup("-l");  authpriv[1]  = strdup("authPriv");
				authpriv[2]  = strdup("-a");  authpriv[3]  = strdup(authproto);
				authpriv[4]  = strdup("-u");  authpriv[5]  = strdup(secname);
				authpriv[6]  = strdup("-A");  authpriv[7]  = strdup(authpasswd);
				authpriv[8]  = strdup("-x");  authpriv[9]  = strdup(privproto);
				authpriv[10] = strdup("-X");  authpriv[11] = strdup(privpasswd);
			}
		} else {
			usage2(_("Invalid seclevel"), seclevel);
		}
	} else {
		usage2(_("Invalid SNMP version"), proto);
	}

	return OK;
}


void
print_help (void)
{
	print_revision(progname, VERSION);
	printf(COPYRIGHT, copyright, email);
	printf("%s\n", _("Monitor interface throughput via SNMP (ifInOctets/ifOutOctets or ifHCIn/ifHCOut)"));
	printf("\n\n");
	print_usage();
	printf(UT_HELP_VRSN);
	printf(UT_EXTRA_OPTS);
	printf(UT_IPv46);
	printf(UT_HOST_PORT, 'p', DEFAULT_PORT);

	printf (" %s\n", "-P, --protocol=[1|2c|3]");
	printf ("    %s\n", _("SNMP protocol version"));
	printf (" %s\n", "-C, --community=STRING");
	printf ("    %s (%s \"%s\")\n", _("Community string for SNMP communication"), _("default is"), DEFAULT_COMMUNITY);
	printf (" %s\n", "-N, --context=CONTEXT");
	printf ("    %s\n", _("SNMPv3 context"));
	printf (" %s\n", "-L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]");
	printf ("    %s\n", _("SNMPv3 security level"));
	printf (" %s\n", "-U, --secname=USERNAME");
	printf ("    %s\n", _("SNMPv3 username"));
	printf (" %s\n", "-a, --authproto=[MD5|SHA]");
	printf ("    %s\n", _("SNMPv3 auth protocol"));
	printf (" %s\n", "-x, --privproto=[DES|AES]");
	printf ("    %s\n", _("SNMPv3 priv protocol (default DES)"));
	printf (" %s\n", "-A, --authpasswd=PASSWORD");
	printf ("    %s\n", _("SNMPv3 authentication password"));
	printf (" %s\n", "-X, --privpasswd=PASSWORD");
	printf ("    %s\n", _("SNMPv3 privacy password"));

	printf ("\n");
	printf (" %s\n", "-i INDEX|NAME");
	printf ("    %s\n", _("Interface index (numeric) or name — appended to the counter OIDs (required)."));
	printf ("    %s\n", _("Also used as the default db-key when --db-key is not specified."));
	printf (" %s\n", "--db-key=STRING");
	printf ("    %s\n", _("SQLite state key for this interface (optional; defaults to -i value)."));
	printf ("    %s\n", _("Override to distinguish multiple services on the same physical interface."));
	printf (" %s\n", "-u, --units=STRING");
	printf ("    %s (%s \"%s\")\n",
		_("Units for throughput output"), _("default is"), DEFAULT_UNITS);
	printf ("    %s\n", _("Options: bps, kbps, mbps, gbps (bits/sec) or Bps, KBps, MBps, GBps (bytes/sec)"));
	printf (" %s\n", "-w, --warning=THRESHOLD[,THRESHOLD]");
	printf ("    %s\n", _("Warning threshold for inbound[,outbound] throughput"));
	printf (" %s\n", "-c, --critical=THRESHOLD[,THRESHOLD]");
	printf ("    %s\n", _("Critical threshold for inbound[,outbound] throughput"));
	printf (" %s\n", "--counter-bits=BITS");
	printf ("    %s\n", _("Counter size: 32 or 64 bits (default: 64)"));
	printf ("    %s\n", _("Use 32 for ifIn/OutOctets, 64 for ifHCIn/OutOctets"));
	printf (" %s\n", "--db-path=PATH");
	printf ("    %s\n", _("Custom path for SQLite database (directory or full file path)"));
	printf ("    %s\n", _("Default paths tried: /usr/local/nagios/var, /etc/nagios-mod-gearman, /var/tmp"));

	printf(UT_CONN_TIMEOUT, DEFAULT_SOCKET_TIMEOUT);
	printf (" %s\n", "-e, --retries=INTEGER");
	printf ("    %s\n", _("Number of SNMP retries (default 5)"));
	printf(UT_VERBOSE);

	printf("\n%s\n", _("Notes:"));
	printf(" %s\n", _("- On the first run a baseline is established and the plugin returns OK."));
	printf(" %s\n", _("- Subsequent runs calculate the rate of change between the two most"));
	printf("   %s\n", _("recent samples."));
	printf(" %s\n", _("- State is stored in a local SQLite database (one row per host+interface)."));
	printf(" %s\n", _("- Counter wrap-around is handled for both 32-bit and 64-bit counters."));
	printf(" %s\n", _("- Default counter size is 64-bit (ifHCIn/OutOctets)."));
	printf(" %s\n", _("- Use --counter-bits=32 to select ifIn/OutOctets (32-bit) counters."));

	printf(UT_SUPPORT);
}


void
print_usage (void)
{
	printf("%s\n", _("Usage:"));
	printf("%s -H <host> -i <index|name> [-w warn] [-c crit]\n", progname);
	printf("[-C community] [-u units] [-p port] [-P protocol] [-e retries]\n");
	printf("[-N context] [-L seclevel] [-U secname] [-a authproto] [-A authpasswd]\n");
	printf("[-x privproto] [-X privpasswd] [--counter-bits 32|64]\n");
	printf("[--db-key STRING] [--db-path PATH]\n");
}


/* SQLite state helpers */

const char *determine_db_path(void) {
	static char db_file[512];
	const char *paths[] = {"/usr/local/nagios/var", "/etc/nagios-mod-gearman", "/var/tmp"};
	const char *db_name = "nagios_snmp_throughput.db";
	int i;

	if (custom_db_path != NULL) {
		struct stat st;
		if (stat(custom_db_path, &st) == 0 && S_ISDIR(st.st_mode))
			snprintf(db_file, sizeof(db_file), "%s/%s", custom_db_path, db_name);
		else
			snprintf(db_file, sizeof(db_file), "%s", custom_db_path);
		if (verbose > 1) printf("DEBUG: Using custom database path: %s\n", db_file);
		return db_file;
	}

	for (i = 0; i < 3; i++) {
		if (access(paths[i], W_OK) == 0) {
			snprintf(db_file, sizeof(db_file), "%s/%s", paths[i], db_name);
			if (verbose > 1) printf("DEBUG: Using database path: %s\n", db_file);
			return db_file;
		}
	}
	return db_file;
}

int db_init(const char *path) {
	sqlite3 *db;
	char *err_msg = NULL;
	int rc;
	const char *sql =
		"CREATE TABLE IF NOT EXISTS states ("
		"host TEXT NOT NULL, "
		"interface TEXT NOT NULL, "
		"timestamp INTEGER NOT NULL, "
		"in_octets INTEGER NOT NULL, "
		"out_octets INTEGER NOT NULL, "
		"counter_bits INTEGER NOT NULL, "
		"PRIMARY KEY (host, interface));";;

	rc = sqlite3_open(path, &db);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "SQL error: %s\n", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	sqlite3_close(db);
	return STATE_OK;
}

int db_read_state(const char *path, const char *host, const char *iface, OctetData *data) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	rc = sqlite3_prepare_v2(db,
		"SELECT timestamp, in_octets, out_octets, counter_bits "
		"FROM states WHERE host = ? AND interface = ?",
		-1, &stmt, 0);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	sqlite3_bind_text(stmt, 1, host,  -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, iface, -1, SQLITE_STATIC);
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		data->timestamp    = sqlite3_column_int64(stmt, 0);
		data->in_octets    = sqlite3_column_int64(stmt, 1);
		data->out_octets   = sqlite3_column_int64(stmt, 2);
		data->counter_bits = sqlite3_column_int  (stmt, 3);
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return STATE_OK;
	}
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return STATE_UNKNOWN;
}

int db_write_state(const char *path, const char *host, const char *iface, const OctetData *data) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	db_init(path);

	rc = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	rc = sqlite3_prepare_v2(db,
		"INSERT OR REPLACE INTO states "
		"(host, interface, timestamp, in_octets, out_octets, counter_bits) "
		"VALUES (?, ?, ?, ?, ?, ?)",
		-1, &stmt, 0);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}
	sqlite3_bind_text (stmt, 1, host,   -1, SQLITE_STATIC);
	sqlite3_bind_text (stmt, 2, iface,  -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, data->timestamp);
	sqlite3_bind_int64(stmt, 4, data->in_octets);
	sqlite3_bind_int64(stmt, 5, data->out_octets);
	sqlite3_bind_int  (stmt, 6, data->counter_bits);

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return (rc == SQLITE_DONE) ? STATE_OK : STATE_UNKNOWN;
}

unsigned long long calculate_wraparound(unsigned long long current,
                                        unsigned long long previous,
                                        int counter_bits) {
	if (current >= previous) return current - previous;
	return (counter_bits == 64) ? 0ULL : ((0xFFFFFFFFUL - previous) + current + 1);
}

/* Returns throughput scaled to the requested unit */
double calc_bw(unsigned long long octet_diff, time_t time_diff, const char *unit) {
	if (time_diff <= 0) return 0.0;
	double bps = (double)octet_diff * (unit && strstr(unit, "Bp") ? 1.0 : 8.0) / (double)time_diff;
	if (unit) {
		if      (strcmp(unit, "kbps") == 0 || strcmp(unit, "KBps") == 0) return bps / 1e3;
		else if (strcmp(unit, "mbps") == 0 || strcmp(unit, "MBps") == 0) return bps / 1e6;
		else if (strcmp(unit, "gbps") == 0 || strcmp(unit, "GBps") == 0) return bps / 1e9;
	}
	return bps;
}
