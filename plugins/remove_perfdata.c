/*****************************************************************************
* 
* Nagios remove perfdata plugin
* 
* License: GPL
* Copyright (c) 2002-2017 Nagios Plugins Development Team
* 
* Description:
* 
* This file contains the remove_perfdata plugin
* 
* Removes perfdata from a specified plugin's output. Optionally,
* you can choose to remove any long output as well
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

const char *progname = "remove_perfdata";
const char *copyright = "2002-2017";
const char *email = "devel@nagios-plugins.org";

/* timeout should be handled in the plugin being called */
#define DEFAULT_TIMEOUT 300

#include "common.h"
#include "utils.h"
#include "utils_cmd.h"

#include <ctype.h>

static const char **process_arguments(int, char **);
void validate_arguments(char **);
void print_help(void);
void print_usage(void);
int remove_perfdata = 1;
int remove_long_output = 0;


int
main(int argc, char **argv)
{
    int result = STATE_UNKNOWN;
    int c = 0;
    int i = 0;
    int j = 0;
    char *buf;
    char *sub;
    char **command_line;
    output chld_out;
    output chld_err;

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);

    command_line = (char **) process_arguments(argc, argv);

    /* Set signal handling and alarm */
    if (signal(SIGALRM, timeout_alarm_handler) == SIG_ERR) {
        die(STATE_UNKNOWN, _("Cannot catch SIGALRM"));
    }

    (void) alarm((unsigned) DEFAULT_TIMEOUT);

    /* catch when the command is quoted */
    if (command_line[1] == NULL) {
        result = cmd_run(command_line[0], &chld_out, &chld_err, 0);
    } else {
        result = cmd_run_array(command_line, &chld_out, &chld_err, 0);
    }

    if (chld_err.lines > 0) {
        printf("%s:\n", _("Error output from command"));
        for (i = 0; i < chld_err.lines; i++) {
            printf("%s\n", chld_err.line[i]);
        }
        exit(STATE_WARNING);
    }

    /* Return UNKNOWN or worse if no output is returned */
    if (chld_out.lines == 0) {
        die(max_state_alt(result, STATE_UNKNOWN), _("No data returned from command\n"));
    }

    for (i = 0; i < chld_out.lines; i++) {

        /* if we're on the first line, remove the perfdata */
        if (remove_perfdata && i == 0) {

            int in_quotes = 0;

            for (j = 0; j < (int) strlen(chld_out.line[i]); j++) {

                c = chld_out.line[i][j];

                if (c == '"') {
                    if (in_quotes) {
                        in_quotes = 0;
                    }
                    else {
                        in_quotes = 1;
                    }
                }

                /* when we reach an unquoted |, stop printing */
                if (!in_quotes && c == '|')
                    break;

                printf("%c", c);
            }

            /* and print a newline if we skipped past it */
            if (c != '\n') {
                printf("\n");
            }
        }

        /* if we don't want long output, don't print it */
        else if (remove_long_output && i > 0) {
            break;
        }

        /* for everything else, there's mastercard - or printing the full line to the screen */
        else {
            printf("%s\n", chld_out.line[i]);
        }
    }

    exit(result);
}


/* process command-line arguments */
static const char **
process_arguments(int argc, char **argv)
{
    int c = 0;
    int option = 0;
    static struct option longopts[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"remove-long-output", no_argument, 0, 'l'},
        {"dont-remove-perfdata", required_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    while (1) {
        c = getopt_long(argc, argv, "+hVld", longopts, &option);

        if (c == -1 || c == EOF)
            break;

        switch (c) {

        /* help */
        case '?':
            usage5();
            break;

        /* help */
        case 'h':
            print_help();
            exit(EXIT_SUCCESS);
            break;

        /* version */
        case 'V':
            print_revision(progname, NP_VERSION);
            exit(EXIT_SUCCESS);

        /* remove long output */
        case 'l':
            remove_long_output = 1;
            break;

        /* don't remove perfdata */
        case 'd':
            remove_perfdata = 0;
            break;
        }
    }

    validate_arguments(&argv[optind]);

    return (const char **) &argv[optind];
}


void
validate_arguments(char **command_line)
{
    if (command_line[0] == NULL)
        usage4(_("Could not parse arguments"));

    if (   strncmp(command_line[0], "/", 1) != 0 
        && strncmp(command_line[0], "./", 2) != 0)
        usage4(_("Require path to command"));
}


void
print_help(void)
{
    print_revision(progname, NP_VERSION);

    printf(COPYRIGHT, copyright, email);

    printf("%s\n", _("Removes perfdata from plugin output."));
    printf("%s\n", _("Additional switches can be used to remove long output as well."));

    printf("\n\n");
    print_usage();

    printf(UT_HELP_VRSN);

    printf(" -l, --remove-long-output\n");
    printf("    %s\n", _("Remove long output from specified plugin's output."));
    printf(" -d, --dont-remove-perfdata\n");
    printf("    %s\n", _("Don't remove perfdata from the specified plugin's output.\n"));

    printf("\n");

    printf("%s\n", _("Examples:"));
    printf("\n");
    printf("%s\n", "remove_perfdata /usr/local/nagios/libexec/check_ping -H host");
    printf("    %s\n", _("Run check_ping and remove performance data. (Must use full path to plugin.)"));
    printf("\n");
    printf("%s\n", _("Notes:"));
    printf("    %s\n", _("This plugin is a wrapper to take the output of another plugin and alter it."));
    printf("    %s\n", _("The full path of the plugin must be provided."));
    printf("\n");

    printf(UT_SUPPORT);
}



void
print_usage(void)
{
    printf("%s\n", _("Usage:"));
    printf("%s [-hV] [-l] [-d] <definition of wrapped plugin>\n", progname);
}
