/*****************************************************************************
* 
* Nagios check_dns plugin
* 
* License: GPL
* Copyright (c) 2000-2014 Nagios Plugins Development Team
* 
* Description:
* 
* This file contains the check_dns plugin
* 
* LIMITATION: nslookup on Solaris 7 can return output over 2 lines, which
* will not be picked up by this plugin
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
#define IF_RECORD(label, querytype, verb_str, comp_str) if (strstr (chld_out.line[i], label) && (strncmp(query_type, querytype, query_size) == 0 || strncmp(query_type, "-querytype=ANY", query_size) == 0)) { \
      if (verbose) printf(verb_str); \
      temp_buffer = rindex (chld_out.line[i], comp_str); \
      addresses[n_addresses++] = check_new_address(temp_buffer); \
      memset(query_found, '\0', sizeof(query_found)); \
      strncpy(query_found, querytype, sizeof(query_found)); 

const char *progname = "check_dns";
const char *copyright = "2000-2014";
const char *email = "devel@nagios-plugins.org";

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include "netutils.h"
#include "runcmd.h"

int process_arguments (int, char **);
int validate_arguments (void);
int error_scan (char *);
void print_help (void);
void print_usage (void);

#define ADDRESS_LENGTH 384 
char query_address[ADDRESS_LENGTH] = "";
char dns_server[ADDRESS_LENGTH] = "";
char tmp_dns_server[ADDRESS_LENGTH] = "";
char ptr_server[ADDRESS_LENGTH] = "";
char query_type[16] = "";
int query_set = FALSE;
int verbose = FALSE;
char **expected_address = NULL;
int expected_address_cnt = 0;

int expect_authority = FALSE;
int accept_cname = FALSE;
thresholds *time_thresholds = NULL;

static int
qstrcmp(const void *p1, const void *p2)
{
	/* The actual arguments to this function are "pointers to
	   pointers to char", but strcmp() arguments are "pointers
	   to char", hence the following cast plus dereference */
	return strcmp(* (char * const *) p1, * (char * const *) p2);
}

char *
check_new_address(char *temp_buffer)
{
      temp_buffer++;
      /* Strip leading spaces */
      for (; *temp_buffer != '\0' && *temp_buffer == ' '; temp_buffer++)
        /* NOOP */;

      strip(temp_buffer);
      if (temp_buffer==NULL || strlen(temp_buffer)==0)
        die (STATE_CRITICAL, "%s%s%s\n", _("DNS CRITICAL - '"), NSLOOKUP_COMMAND, _("' returned empty host name string"));

      return temp_buffer;
}

int
main (int argc, char **argv)
{
  char *command_line = NULL;
  char input_buffer[MAX_INPUT_BUFFER];
  char *address = NULL; /* comma seperated str with addrs/ptrs (sorted) */
  char **addresses = NULL;
  int n_addresses = 0;
  char *msg = NULL;
  char query_found[24] = "";
  int query_size = 24;
  char *temp_buffer = NULL;
  int non_authoritative = FALSE;
  int result = STATE_UNKNOWN;
  double elapsed_time;
  long microsec;
  struct timeval tv;
  int parse_address = FALSE; /* This flag scans for Address: but only after Name: */
  output chld_out, chld_err;
  size_t i;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* Set signal handling and alarm */
  if (signal (SIGALRM, runcmd_timeout_alarm_handler) == SIG_ERR)
    usage_va(_("Cannot catch SIGALRM"));

  /* Parse extra opts if any */
  argv=np_extra_opts (&argc, argv, progname);

  if (process_arguments (argc, argv) == ERROR)
    usage_va(_("Could not parse arguments"));

  /* get the command to run */
  xasprintf (&command_line, "%s %s %s %s", NSLOOKUP_COMMAND, query_type, query_address, dns_server);

  alarm (timeout_interval);
  gettimeofday (&tv, NULL);

  if (verbose)
    printf ("%s\n", command_line);

  /* run the command */
  if((np_runcmd(command_line, &chld_out, &chld_err, 0)) != 0) {
    msg = strdup(_("nslookup returned an error status"));
    result = STATE_WARNING;
  }

  /* scan stdout */
  for(i = 0; i < chld_out.lines; i++) {
    if (addresses == NULL)
      addresses = malloc(sizeof(*addresses)*10);
    else if (!(n_addresses % 10))
      addresses = realloc(addresses,sizeof(*addresses) * (n_addresses + 10));

    if (verbose)
      puts(chld_out.line[i]);

    /* bug ID: 2946553 - Older versions of bind will use all available dns
    + servers, we have to match the one specified */
    if (strlen(dns_server) > 0 && strstr(chld_out.line[i], "Server:")) {
        temp_buffer = strchr(chld_out.line[i], ':');
        temp_buffer++;

	if (temp_buffer > (char *)1) {
          /* Strip leading tabs */
          for (; *temp_buffer != '\0' && *temp_buffer == '\t'; temp_buffer++)
            /* NOOP */;

        strip(temp_buffer);
        if (temp_buffer==NULL || strlen(temp_buffer)==0)
          die (STATE_CRITICAL, "%s%s%s\n", _("DNS CRITICAL - '"), NSLOOKUP_COMMAND, _("' returned empty server string"));

        if (strcmp(temp_buffer, dns_server) != 0)
          die (STATE_CRITICAL, "%s %s\n", _("DNS CRITICAL - No response from DNS server:"), dns_server);
      }
    }
    /* Provide the server name\ip to error_scan when not using -s */
    else if (strlen(tmp_dns_server) == 0) {
	temp_buffer = strchr(chld_out.line[i], ':');
	temp_buffer++;
	if (temp_buffer > (char *)1) {
	  /* Strip leading tabs */
	  for (; *temp_buffer != '\0' && *temp_buffer == '\t'; temp_buffer++)
	      /* NOOP */;

	  strip(temp_buffer);
	  strncpy(tmp_dns_server, temp_buffer, ADDRESS_LENGTH);
	}
    }

    if (strstr (chld_out.line[i], "Authoritative answers can be found from:"))
      break;
    /* the server is responding, we just got the host name...*/
    if (strstr (chld_out.line[i], "Name:"))
      parse_address = TRUE;
    /* begin handling types of records */
    IF_RECORD("AAAA address", "-querytype=AAAA", "Found AAAA record\n", ' ') }
    else IF_RECORD("exchanger =", "-querytype=MX", "Found MX record\n", '=') }
    else IF_RECORD("service =", "-querytype=SRV", "Found SRV record\n", ' ') }
    else IF_RECORD("nameserver =", "-querytype=NS", "Found NS record\n", ' ') }
    else IF_RECORD("dname =", "-querytype=DNAME", "Found DNAME record\n", ' ') }
    else IF_RECORD("protocol =", "-querytype=WKS", "Found WKS record\n", ' ') }
    else if (strstr (chld_out.line[i], "text =") && (strncmp(query_type, "-querytype=TXT", query_size) == 0 || strncmp(query_type, "-querytype=ANY", query_size) == 0)) {
      if (verbose) printf("Found TXT record\n");
      temp_buffer = index(chld_out.line[i], '"');
      --temp_buffer;
      addresses[n_addresses++] = check_new_address(temp_buffer);
      memset(query_found, '\0', sizeof(query_found));
      strncpy(query_found, "-querytype=TXT", sizeof(query_found)); 
    }

    /* only matching for origin records, if requested other fields could be included at a later date */
    else IF_RECORD("origin =", "-querytype=SOA", "Found SOA record\n", ' ') }
    /* cnames cannot use macro as we must check for accepting them separately */
    else if (accept_cname && strstr (chld_out.line[i], "canonical name =") && (strncmp(query_type, "-querytype=CNAME", query_size) == 0 || strncmp(query_type, "-querytype=ANY", query_size) == 0)) {
      if (verbose) printf("Found CNAME record\n");
      temp_buffer = index (chld_out.line[i], '=');
      addresses[n_addresses++] = check_new_address(temp_buffer);
      strncpy(query_found, "-querytype=CNAME", sizeof(query_found));
    }
    /* does not need strncmp as we want A at all times unless another record match */
    else if (parse_address == TRUE && (strstr (chld_out.line[i], "Address:") || strstr (chld_out.line[i], "Addresses:"))) {
      if (verbose) printf("Found A record\n");
      temp_buffer = index (chld_out.line[i], ':');
      addresses[n_addresses++] = check_new_address(temp_buffer);
      strncpy(query_found, "-querytype=A", sizeof(query_found));
    }
    /* must be after other records with "name" as an identifier, as ptr does not spefify */
    else IF_RECORD("name =", "-querytype=PTR", "Found PTR record\n", ' ') }
    /* needed for non-query ptr\reverse lookup checks */
    else if (strstr(chld_out.line[i], ".in-addr.arpa") && !query_set) {
      if ((temp_buffer = strstr(chld_out.line[i], "name = ")))
        addresses[n_addresses++] = strdup(temp_buffer);
      else {
        xasprintf(&msg, "%s %s %s %s", _("Warning plugin error"));
        result = STATE_WARNING;
      }
    }

    if (strstr (chld_out.line[i], _("Non-authoritative answer:")))
      non_authoritative = TRUE;

    int tmp = error_scan(chld_out.line[i]);
    result = (result == STATE_UNKNOWN)
      ? tmp
      : (result < tmp)
        ? tmp : result;
    if (result != STATE_OK) {
      msg = strchr (chld_out.line[i], ':');
      if(msg)
			  msg++;
			else
			 msg = chld_out.line[i];
      break;
    }
  }

  /* scan stderr */
  for(i = 0; i < chld_err.lines; i++) { 
    if (verbose)
      puts(chld_err.line[i]);

    if (error_scan (chld_err.line[i]) != STATE_OK) {
      result = max_state (result, error_scan (chld_err.line[i]));
      msg = strchr(chld_err.line[i], ':');
      if(msg)
			  msg++;
			else
			  msg = chld_err.line[i];
    }
  }

  if (addresses) {
    int i,slen;
    char *adrp;
    qsort(addresses, n_addresses, sizeof(*addresses), qstrcmp);
    for(i=0, slen=1; i < n_addresses; i++)
      slen += strlen(addresses[i])+1;

    adrp = address = malloc(slen);
    for(i=0; i < n_addresses; i++) {
      if (i) *adrp++ = ',';
      strcpy(adrp, addresses[i]);
      adrp += strlen(addresses[i]);
    }
    *adrp = 0;
  } else
    die (STATE_CRITICAL, "%s%s%s\n", _("DNS CRITICAL - '"), NSLOOKUP_COMMAND, _("' msg parsing exited with no address"));

  /* compare to expected address */
  if (result == STATE_OK && expected_address_cnt > 0) {
    result = STATE_CRITICAL;
    temp_buffer = "";
    for (i=0; i<expected_address_cnt; i++) {
      /* check if we get a match and prepare an error string */
      if (strcmp(address, expected_address[i]) == 0) result = STATE_OK;
      xasprintf(&temp_buffer, "%s%s; ", temp_buffer, expected_address[i]);
    }
    if (result == STATE_CRITICAL) {
      /* Strip off last semicolon... */
      temp_buffer[strlen(temp_buffer)-2] = '\0';
      xasprintf(&msg, "%s%s%s%s%s", _("expected '"), temp_buffer, _("' but got '"), address, "'");
    }
  }

  /* check if authoritative */
  if (result == STATE_OK && expect_authority && non_authoritative) {
    result = STATE_CRITICAL;

    if (strncmp(dns_server, "", 1))
      xasprintf(&msg, "%s %s %s %s", _("server"), dns_server, _("is not authoritative for"), query_address);
    else
      xasprintf(&msg, "%s %s", _("there is no authoritative server for"), query_address);
  }

  /* compare query type to query found, if query type is ANY we can skip as any record is accepted*/
  if (result == STATE_OK && strncmp(query_type, "", 1) && (strncmp(query_type, "-querytype=ANY", 15) != 0)) {
    if (strncmp(query_type, query_found, 16) != 0) {
      if (verbose)
        printf( "%s %s %s %s %s\n", _("Failed query for"), query_type, _("only found"), query_found, _(", or nothing"));
      result = STATE_CRITICAL;
      xasprintf(&msg, "%s %s %s %s", _("query type of"), query_type, _("was not found for"), query_address);
    }
  }

  microsec = deltime (tv);
  elapsed_time = (double)microsec / 1.0e6;

  if (result == STATE_OK) {
    result = get_status(elapsed_time, time_thresholds);
    if (result == STATE_OK) {
      printf ("%s %s: ", _("DNS"), _("OK"));
    } else if (result == STATE_WARNING) {
      printf ("%s %s: ", _("DNS"), _("WARNING"));
    } else if (result == STATE_CRITICAL) {
      printf ("%s %s: ", _("DNS"), _("CRITICAL"));
    }
    printf (ngettext("%.3f second response time", "%.3f seconds response time", elapsed_time), elapsed_time);
    printf (". %s %s %s", query_address, _("returns"), address);
    if ((time_thresholds->warning != NULL) && (time_thresholds->critical != NULL)) {
      printf ("|%s\n", fperfdata ("time", elapsed_time, "s",
                                  TRUE, time_thresholds->warning->end,
                                  TRUE, time_thresholds->critical->end,
                                  TRUE, 0, FALSE, 0));
    } else if ((time_thresholds->warning == NULL) && (time_thresholds->critical != NULL)) {
      printf ("|%s\n", fperfdata ("time", elapsed_time, "s",
                                  FALSE, 0,
                                  TRUE, time_thresholds->critical->end,
                                  TRUE, 0, FALSE, 0));
    } else if ((time_thresholds->warning != NULL) && (time_thresholds->critical == NULL)) {
      printf ("|%s\n", fperfdata ("time", elapsed_time, "s",
                                  TRUE, time_thresholds->warning->end,
                                  FALSE, 0,
                                  TRUE, 0, FALSE, 0));
    } else
      printf ("|%s\n", fperfdata ("time", elapsed_time, "s", FALSE, 0, FALSE, 0, TRUE, 0, FALSE, 0));
  }
  else if (result == STATE_WARNING)
    printf ("%s %s\n", _("DNS WARNING -"), !strcmp (msg, "") ? _("Probably a non-existent host/domain") : msg);
  else if (result == STATE_CRITICAL)
    printf ("%s %s\n", _("DNS CRITICAL -"), !strcmp (msg, "") ? _("Probably a non-existent host/domain") : msg);
  else
    printf ("%s %s\n", _("DNS UNKNOWN -"), !strcmp (msg, "") ? _("Probably a non-existent host/domain") : msg);

  return result;
}



int
error_scan (char *input_buffer)
{

  /* the DNS lookup timed out */
  if (strstr (input_buffer, _("Note: nslookup is deprecated and may be removed from future releases.")) ||
      strstr (input_buffer, _("Consider using the `dig' or `host' programs instead.  Run nslookup with")) ||
      strstr (input_buffer, _("the `-sil[ent]' option to prevent this message from appearing.")))
    return STATE_OK;

  /* DNS server is not running... */
  else if (strstr (input_buffer, "No response from server"))
    die (STATE_CRITICAL, "%s %s\n", _("No response from DNS"), (strlen(dns_server)==0)?tmp_dns_server:dns_server);

  /* Host name is valid, but server doesn't have records... */
  else if (strstr (input_buffer, "No records") || strstr (input_buffer, "No answer"))
    die (STATE_CRITICAL, "%s %s %s\n", _("DNS"), (strlen(dns_server)==0)?tmp_dns_server:dns_server, _("has no records"));

  /* Connection was refused */
  else if (strstr (input_buffer, "Connection refused") ||
     strstr (input_buffer, "Couldn't find server") ||
           strstr (input_buffer, "Refused") ||
           (strstr (input_buffer, "** server can't find") &&
            strstr (input_buffer, ": REFUSED")))
    die (STATE_CRITICAL, "%s %s %s\n", _("Connection to DNS"), (strlen(dns_server)==0)?tmp_dns_server:dns_server, _("was refused"));

  /* Query refused (usually by an ACL in the namserver) */
  else if (strstr (input_buffer, "Query refused"))
    die (STATE_CRITICAL, "%s %s\n", _("Query was refused by DNS server at"), (strlen(dns_server)==0)?tmp_dns_server:dns_server);

  /* No information (e.g. nameserver IP has two PTR records) */
  else if (strstr (input_buffer, "No information"))
    die (STATE_CRITICAL, "%s %s\n", _("No information returned by DNS server at"), (strlen(dns_server)==0)?tmp_dns_server:dns_server);

  /* Host or domain name does not exist */
  else if (strstr (input_buffer, "Non-existent") ||
           strstr (input_buffer, "** server can't find") ||
     strstr (input_buffer,"NXDOMAIN"))
    die (STATE_CRITICAL, "%s %s %s\n", _("Domain"), query_address, _("was not found by the server"));

  /* Network is unreachable */
  else if (strstr (input_buffer, "Network is unreachable"))
    die (STATE_CRITICAL, "%s\n", _("Network is unreachable"));

  /* Internal server failure */
  else if (strstr (input_buffer, "Server failure"))
    die (STATE_CRITICAL, "%s %s\n", _("DNS failure for"), (strlen(dns_server)==0)?tmp_dns_server:dns_server);

  /* Request error or the DNS lookup timed out */
  else if (strstr (input_buffer, "Format error") ||
           strstr (input_buffer, "Timed out"))
    return STATE_WARNING;

  return STATE_OK;

}

/* process command-line arguments */
int
process_arguments (int argc, char **argv)
{
  int c;
  char *warning = NULL;
  char *critical = NULL;

  int opt_index = 0;
  static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'V'},
    {"verbose", no_argument, 0, 'v'},
    {"timeout", required_argument, 0, 't'},
    {"hostname", required_argument, 0, 'H'},
    {"server", required_argument, 0, 's'},
    {"reverse-server", required_argument, 0, 'r'},
    {"querytype", required_argument, 0, 'q'},
    {"expected-address", required_argument, 0, 'a'},
    {"expect-authority", no_argument, 0, 'A'},
    {"accept-cname", no_argument, 0, 'n'},
    {"warning", required_argument, 0, 'w'},
    {"critical", required_argument, 0, 'c'},
    {0, 0, 0, 0}
  };

  if (argc < 2)
    return ERROR;

  for (c = 1; c < argc; c++)
    if (strcmp ("-to", argv[c]) == 0)
      strcpy (argv[c], "-t");

  while (1) {
    c = getopt_long (argc, argv, "hVvAnt:H:s:r:a:q:w:c:", long_opts, &opt_index);

    if (c == -1 || c == EOF)
      break;

    switch (c) {
    case 'h': /* help */
      print_help ();
      exit (STATE_OK);
    case 'V': /* version */
      print_revision (progname, NP_VERSION);
      exit (STATE_OK);
    case 'v': /* version */
      verbose = TRUE;
      break;
    case 't': /* timeout period */
      timeout_interval = parse_timeout_string (optarg);
      break;
    case 'H': /* hostname */
      if (strlen (optarg) >= ADDRESS_LENGTH)
        die (STATE_UNKNOWN, "%s\n", _("Input buffer overflow"));
      strcpy (query_address, optarg);
      break;
    case 's': /* server name */
      /* TODO: this host_or_die check is probably unnecessary.
       * Better to confirm nslookup response matches */
      host_or_die(optarg);
      if (strlen (optarg) >= ADDRESS_LENGTH)
        die (STATE_UNKNOWN, "%s\n", _("Input buffer overflow"));
      strcpy (dns_server, optarg);
      break;
    case 'r': /* reverse server name */
      /* TODO: Is this host_or_die necessary? */
      host_or_die(optarg);
      if (strlen (optarg) >= ADDRESS_LENGTH)
        die (STATE_UNKNOWN, "%s\n", _("Input buffer overflow"));
      strcpy (ptr_server, optarg);
      break;
    case 'a': /* expected address */
      if (strlen (optarg) >= ADDRESS_LENGTH)
        die (STATE_UNKNOWN, "%s\n", _("Input buffer overflow"));
      expected_address = (char **)realloc(expected_address, (expected_address_cnt+1) * sizeof(char*));
      expected_address[expected_address_cnt] = strdup(optarg);
      expected_address_cnt++;
      break;
    case 'q': /* querytype -- A or AAAA or ANY or SRV or TXT, etc. */
      if (strlen (optarg) < 1 || strlen (optarg) > 5)
        die (STATE_UNKNOWN, "%s\n", _("Missing valid querytype parameter.  Try using 'A' or 'AAAA' or 'SRV'"));
      strntoupper(optarg, strlen(optarg));
      strcpy(query_type, "-querytype=");
      strcat(query_type, optarg);
      query_set = TRUE;
      /* logic is set such that we must accept cnames if they are querying for them */
      if (strcmp(query_type, "-querytype=CNAME") != 0)
        break;
    case 'n': /* accept cname responses as a result */
      accept_cname = TRUE;
      break;
    case 'A': /* expect authority */
      expect_authority = TRUE;
      break;
    case 'w':
      warning = optarg;
      break;
    case 'c':
      critical = optarg;
      break;
    default: /* args not parsable */
      usage5();
    }
  }

  set_thresholds(&time_thresholds, warning, critical);

  return validate_arguments ();
}


int
validate_arguments ()
{
  if (query_address[0] == 0)
    return ERROR;

  return OK;
}


void
print_help (void)
{
  print_revision (progname, NP_VERSION);

  printf ("%s\n", "Copyright (c) 1999 Ethan Galstad <nagios@nagios.org>");
  printf (COPYRIGHT, copyright, email);

  printf ("%s\n", _("This plugin uses the nslookup program to obtain the IP address for the given host/domain query."));
  printf ("%s\n", _("An optional DNS server to use may be specified."));
  printf ("%s\n", _("If no DNS server is specified, the default server(s) specified in /etc/resolv.conf will be used."));

  printf ("\n\n");

  print_usage ();

  printf (UT_HELP_VRSN);
  printf (UT_EXTRA_OPTS);

  printf ("%s\n", " -H, --hostname=HOST");
  printf ("    %s\n", _("The name or address you want to query"));
  printf ("%s\n", " -s, --server=HOST");
  printf ("    %s\n", _("Optional DNS server you want to use for the lookup"));
  printf ("%s\n", " -q, --querytype=TYPE");
  printf ("    %s\n", _("Optional DNS record query type where TYPE =(A, AAAA, SRV, TXT, MX, ANY)"));
  printf ("    %s\n", _("The default query type is 'A' (IPv4 host entry)"));
  printf ("%s\n", " -a, --expected-address=IP-ADDRESS|HOST");
  printf ("    %s\n", _("Optional IP-ADDRESS you expect the DNS server to return. HOST must end with"));
  printf ("    %s\n", _("a dot (.). This option can be repeated multiple times (Returns OK if any"));
  printf ("    %s\n", _("value match). If multiple addresses are returned at once, you have to match"));
  printf ("    %s\n", _("the whole string of addresses separated with commas (sorted alphabetically)."));
  printf ("    %s\n", _("If you would like to test for the presence of a cname, combine with -n param."));
  printf ("%s\n", " -A, --expect-authority");
  printf ("    %s\n", _("Optionally expect the DNS server to be authoritative for the lookup"));
  printf ("%s\n", " -n, --accept-cname");
  printf ("    %s\n", _("Optionally accept cname responses as a valid result to a query"));
  printf ("    %s\n", _("The default is to ignore cname responses as part of the result"));
  printf ("%s\n", " -w, --warning=seconds");
  printf ("    %s\n", _("Return warning if elapsed time exceeds value. Default off"));
  printf ("%s\n", " -c, --critical=seconds");
  printf ("    %s\n", _("Return critical if elapsed time exceeds value. Default off"));

  printf (UT_CONN_TIMEOUT, DEFAULT_SOCKET_TIMEOUT);

  printf (UT_SUPPORT);
}


void
print_usage (void)
{
  printf ("%s\n", _("Usage:"));
  printf ("%s %s\n", progname, "-H host [-s server] [-q type ] [-a expected-address] [-A] [-n] [-t timeout] [-w warn] [-c crit]");
}
