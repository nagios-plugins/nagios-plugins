/*****************************************************************************
* 
* Library of useful functions for plugins
* 
* License: GPL
* Copyright (c) 2000 Karl DeBisschop (karl@debisschop.net)
* Copyright (c) 2002-2014 Nagios Plugin Development Team
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

#include "common.h"
#include "utils.h"
#include "utils_base.h"
#include <stdarg.h>
#include <limits.h>
#include <ctype.h>

#include <arpa/inet.h>

extern void print_usage (void);
extern const char *progname;

#define STRLEN 64
#define TXTBLK 128

unsigned int timeout_state = STATE_CRITICAL;
unsigned int timeout_interval = DEFAULT_SOCKET_TIMEOUT;

time_t start_time, end_time;

/* **************************************************************************
 * max_state(STATE_x, STATE_y)
 * compares STATE_x to  STATE_y and returns result based on the following
 * STATE_UNKNOWN < STATE_OK < STATE_WARNING < STATE_CRITICAL
 *
 * Note that numerically the above does not hold
 ****************************************************************************/

int
max_state (int a, int b)
{
	if (a == STATE_CRITICAL || b == STATE_CRITICAL)
		return STATE_CRITICAL;
	else if (a == STATE_WARNING || b == STATE_WARNING)
		return STATE_WARNING;
	else if (a == STATE_OK || b == STATE_OK)
		return STATE_OK;
	else if (a == STATE_UNKNOWN || b == STATE_UNKNOWN)
		return STATE_UNKNOWN;
	else if (a == STATE_DEPENDENT || b == STATE_DEPENDENT)
		return STATE_DEPENDENT;
	else
		return max (a, b);
}

/* **************************************************************************
 * min_state(STATE_x, STATE_y)
 * does the opposite of max_state(): returns the minimum of both states using
 * the ordder STATE_UNKNOWN < STATE_OK < STATE_WARNING < STATE_CRITICAL
 ****************************************************************************/
int min_state (int a, int b)
{
	if (a == STATE_UNKNOWN || b == STATE_UNKNOWN)
		return STATE_UNKNOWN;
	else if (a == STATE_OK || b == STATE_OK)
		return STATE_OK;
	else if (a == STATE_WARNING || b == STATE_WARNING)
		return STATE_WARNING;
	else if (a == STATE_CRITICAL || b == STATE_CRITICAL)
		return STATE_CRITICAL;
	else if (a == STATE_DEPENDENT || b == STATE_DEPENDENT)
		return STATE_DEPENDENT;
	else
		return min(a, b);
}

/* **************************************************************************
 * max_state_alt(STATE_x, STATE_y)
 * compares STATE_x to  STATE_y and returns result based on the following
 * STATE_OK < STATE_DEPENDENT < STATE_UNKNOWN < STATE_WARNING < STATE_CRITICAL
 *
 * The main difference between max_state_alt and max_state it that it doesn't
 * allow setting a default to UNKNOWN. It will instead prioritixe any valid
 * non-OK state.
 ****************************************************************************/

int
max_state_alt (int a, int b)
{
	if (a == STATE_CRITICAL || b == STATE_CRITICAL)
		return STATE_CRITICAL;
	else if (a == STATE_WARNING || b == STATE_WARNING)
		return STATE_WARNING;
	else if (a == STATE_UNKNOWN || b == STATE_UNKNOWN)
		return STATE_UNKNOWN;
	else if (a == STATE_DEPENDENT || b == STATE_DEPENDENT)
		return STATE_DEPENDENT;
	else if (a == STATE_OK || b == STATE_OK)
		return STATE_OK;
	else
		return max (a, b);
}

void usage (const char *msg)
{
	printf ("%s\n", msg);
	print_usage ();
	exit (STATE_UNKNOWN);
}

void usage_va (const char *fmt, ...)
{
	va_list ap;
	printf("%s: ", progname);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	exit (STATE_UNKNOWN);
}

void usage2(const char *msg, const char *arg)
{
	printf ("%s: %s - %s\n", progname, msg, arg?arg:"(null)" );
	print_usage ();
	exit (STATE_UNKNOWN);
}

void
usage3 (const char *msg, int arg)
{
	printf ("%s: %s - %c\n", progname, msg, arg);
	print_usage();
	exit (STATE_UNKNOWN);
}

void
usage4 (const char *msg)
{
	printf ("%s: %s\n", progname, msg);
	print_usage();
	exit (STATE_UNKNOWN);
}

void
usage5 (void)
{
	print_usage();
	exit (STATE_UNKNOWN);
}

void
print_revision (const char *command_name, const char *revision)
{
	printf ("%s v%s (%s %s)\n",
	         command_name, revision, PACKAGE, VERSION);
}

const char *
state_text (int result)
{
	switch (result) {
	case STATE_OK:
		return "OK";
	case STATE_WARNING:
		return "WARNING";
	case STATE_CRITICAL:
		return "CRITICAL";
	case STATE_DEPENDENT:
		return "DEPENDENT";
	default:
		return "UNKNOWN";
	}
}

void
timeout_alarm_handler (int signo)
{
	const char msg[] = " - Plugin timed out\n";
	if (signo == SIGALRM) {
/*		printf (_("%s - Plugin timed out after %d seconds\n"),
						state_text(timeout_state), timeout_interval); */
		switch(timeout_state) {
			case STATE_OK:
				write(STDOUT_FILENO, "OK", 2);
				break;
			case STATE_WARNING:
				write(STDOUT_FILENO, "WARNING", 7);
				break;
			case STATE_CRITICAL:
				write(STDOUT_FILENO, "CRITICAL", 8);
				break;
			case STATE_DEPENDENT:
				write(STDOUT_FILENO, "DEPENDENT", 9);
				break;
			default:
				write(STDOUT_FILENO, "UNKNOWN", 7);
				break;
		}
		write(STDOUT_FILENO, msg, sizeof(msg) - 1);
		exit (timeout_state);
	}
}

void
set_timeout_state (char *state) {
        if ((timeout_state = translate_state(state)) == ERROR)
                usage4 (_("Timeout result must be a valid state name (OK, WARNING, CRITICAL, UNKNOWN) or integer (0-3)."));
}

int
parse_timeout_string (char *timeout_str)
{
	char *seperated_str;
    char *timeout_val = "";
	char *timeout_sta = NULL;

	if (strstr(timeout_str, ":") == NULL) {
		timeout_val = timeout_str;
	} 
	else if (strncmp(timeout_str, ":", 1) == 0) {
		seperated_str = strtok(timeout_str, ":");

		if (seperated_str != NULL) {
			timeout_sta = seperated_str;
		}
	}
	else {
		seperated_str = strtok(timeout_str, ":");
		timeout_val = seperated_str;
		seperated_str = strtok(NULL, ":");

		if (seperated_str != NULL) {
			timeout_sta = seperated_str;
		}
	}

	if (timeout_sta != NULL) {
		set_timeout_state(timeout_sta);
	}

	if ((timeout_val == NULL) || (timeout_val[0] == '\0')) {
		return timeout_interval;
	} 
	else if (is_intpos(timeout_val)) {
		return atoi(timeout_val);
	}
	else {
		usage4 (_("Timeout value must be a positive integer"));
		exit (STATE_UNKNOWN);
	}
}

int
is_numeric (char *number)
{
	char tmp[1];
	float x;

	if (!number)
		return FALSE;
	else if (sscanf (number, "%f%c", &x, tmp) == 1)
		return TRUE;
	else
		return FALSE;
}

int
is_positive (char *number)
{
	if (is_numeric (number) && atof (number) > 0.0)
		return TRUE;
	else
		return FALSE;
}

int
is_negative (char *number)
{
	if (is_numeric (number) && atof (number) < 0.0)
		return TRUE;
	else
		return FALSE;
}

int
is_nonnegative (char *number)
{
	if (is_numeric (number) && atof (number) >= 0.0)
		return TRUE;
	else
		return FALSE;
}

int
is_percentage (char *number)
{
	int x;
	if (is_numeric (number) && (x = atof (number)) >= 0 && x <= 100)
		return TRUE;
	else
		return FALSE;
}

int
is_integer (char *number)
{
	long int n;

	if (!number || (strspn (number, "-0123456789 ") != strlen (number)))
		return FALSE;

	n = strtol (number, NULL, 10);

	if (errno != ERANGE && n >= INT_MIN && n <= INT_MAX)
		return TRUE;
	else
		return FALSE;
}

int
is_intpos (char *number)
{
	if (is_integer (number) && atoi (number) > 0)
		return TRUE;
	else
		return FALSE;
}

int
is_intneg (char *number)
{
	if (is_integer (number) && atoi (number) < 0)
		return TRUE;
	else
		return FALSE;
}

int
is_intnonneg (char *number)
{
	if (is_integer (number) && atoi (number) >= 0)
		return TRUE;
	else
		return FALSE;
}

int
is_intpercent (char *number)
{
	int i;
	if (is_integer (number) && (i = atoi (number)) >= 0 && i <= 100)
		return TRUE;
	else
		return FALSE;
}

int
is_option (char *str)
{
	if (!str)
		return FALSE;
	else if (strspn (str, "-") == 1 || strspn (str, "-") == 2)
		return TRUE;
	else
		return FALSE;
}

#ifdef NEED_GETTIMEOFDAY
int
gettimeofday (struct timeval *tv, struct timezone *tz)
{
	tv->tv_usec = 0;
	tv->tv_sec = (long) time ((time_t) 0);
}
#endif



double
delta_time (struct timeval tv)
{
	struct timeval now;

	gettimeofday (&now, NULL);
	return ((double)(now.tv_sec - tv.tv_sec) + (double)(now.tv_usec - tv.tv_usec) / (double)1000000);
}



long
deltime (struct timeval tv)
{
	struct timeval now;
	gettimeofday (&now, NULL);
	return (now.tv_sec - tv.tv_sec)*1000000 + now.tv_usec - tv.tv_usec;
}




void
strip (char *buffer)
{
	size_t x;
	int i;

	for (x = strlen (buffer); x >= 1; x--) {
		i = x - 1;
		if (buffer[i] == ' ' ||
				buffer[i] == '\r' || buffer[i] == '\n' || buffer[i] == '\t')
			buffer[i] = '\0';
		else
			break;
	}
	return;
}


/******************************************************************************
 *
 * Copies one string to another. Any previously existing data in
 * the destination string is lost.
 *
 * Example:
 *
 * char *str=NULL;
 * str = strscpy("This is a line of text with no trailing newline");
 *
 *****************************************************************************/

char *
strscpy (char *dest, const char *src)
{
	if (src == NULL)
		return NULL;

	xasprintf (&dest, "%s", src);

	return dest;
}



/******************************************************************************
 *
 * Returns a pointer to the next line of a multiline string buffer
 *
 * Given a pointer string, find the text following the next sequence
 * of \r and \n characters. This has the effect of skipping blank
 * lines as well
 *
 * Example:
 *
 * Given text as follows:
 *
 * ==============================
 * This
 * is
 * a
 * 
 * multiline string buffer
 * ==============================
 *
 * int i=0;
 * char *str=NULL;
 * char *ptr=NULL;
 * str = strscpy(str,"This\nis\r\na\n\nmultiline string buffer\n");
 * ptr = str;
 * while (ptr) {
 *   printf("%d %s",i++,firstword(ptr));
 *   ptr = strnl(ptr);
 * }
 * 
 * Produces the following:
 *
 * 1 This
 * 2 is
 * 3 a
 * 4 multiline
 *
 * NOTE: The 'firstword()' function is conceptual only and does not
 *       exist in this package.
 *
 * NOTE: Although the second 'ptr' variable is not strictly needed in
 *       this example, it is good practice with these utilities. Once
 *       the * pointer is advance in this manner, it may no longer be
 *       handled with * realloc(). So at the end of the code fragment
 *       above, * strscpy(str,"foo") work perfectly fine, but
 *       strscpy(ptr,"foo") will * cause the the program to crash with
 *       a segmentation fault.
 *
 *****************************************************************************/

char *
strnl (char *str)
{
	size_t len;
	if (str == NULL)
		return NULL;
	str = strpbrk (str, "\r\n");
	if (str == NULL)
		return NULL;
	len = strspn (str, "\r\n");
	if (str[len] == '\0')
		return NULL;
	str += len;
	if (strlen (str) == 0)
		return NULL;
	return str;
}


/******************************************************************************
 *
 * Like strscpy, except only the portion of the source string up to
 * the provided delimiter is copied.
 *
 * Example:
 *
 * str = strpcpy(str,"This is a line of text with no trailing newline","x");
 * printf("%s\n",str);
 *
 * Produces:
 *
 *This is a line of te
 *
 *****************************************************************************/

char *
strpcpy (char *dest, const char *src, const char *str)
{
	size_t len;

	if (src)
		len = strcspn (src, str);
	else
		return NULL;

	if (dest == NULL || strlen (dest) < len)
		dest = realloc (dest, len + 1);
	if (dest == NULL)
		die (STATE_UNKNOWN, _("failed realloc in strpcpy\n"));

	strncpy (dest, src, len);
	dest[len] = '\0';

	return dest;
}



/******************************************************************************
 *
 * Like strscat, except only the portion of the source string up to
 * the provided delimiter is copied.
 *
 * str = strpcpy(str,"This is a line of text with no trailing newline","x");
 * str = strpcat(str,"This is a line of text with no trailing newline","x");
 * printf("%s\n",str);
 * 
 *This is a line of texThis is a line of tex
 *
 *****************************************************************************/

char *
strpcat (char *dest, const char *src, const char *str)
{
	size_t len, l2;

	if (dest)
		len = strlen (dest);
	else
		len = 0;

	if (src) {
		l2 = strcspn (src, str);
	}
	else {
		return dest;
	}

	dest = realloc (dest, len + l2 + 1);
	if (dest == NULL)
		die (STATE_UNKNOWN, _("failed malloc in strscat\n"));

	strncpy (dest + len, src, l2);
	dest[len + l2] = '\0';

	return dest;
}


/******************************************************************************
 *
 * asprintf, but die on failure
 *
 ******************************************************************************/

int
xvasprintf (char **strp, const char *fmt, va_list ap)
{
	int result = vasprintf (strp, fmt, ap);
	if (result == -1 || *strp == NULL)
		die (STATE_UNKNOWN, _("failed malloc in xvasprintf\n"));
	return result;
}

int
xasprintf (char **strp, const char *fmt, ...)
{
	va_list ap;
	int result;
	va_start (ap, fmt);
	result = xvasprintf (strp, fmt, ap);
	va_end (ap);
	return result;
}

/******************************************************************************
 *
 * Print perfdata in a standard format
 *
 ******************************************************************************/

char *perfdata (const char *label,
 long int val,
 const char *uom,
 int warnp,
 long int warn,
 int critp,
 long int crit,
 int minp,
 long int minv,
 int maxp,
 long int maxv)
{
	char *data = NULL;

	if (strpbrk (label, "'= "))
		xasprintf (&data, "'%s'=%ld%s;", label, val, uom);
	else
		xasprintf (&data, "%s=%ld%s;", label, val, uom);

	if (warnp)
		xasprintf (&data, "%s%ld;", data, warn);
	else
		xasprintf (&data, "%s;", data);

	if (critp)
		xasprintf (&data, "%s%ld;", data, crit);
	else
		xasprintf (&data, "%s;", data);

	if (minp)
		xasprintf (&data, "%s%ld", data, minv);

	if (maxp)
		xasprintf (&data, "%s;%ld", data, maxv);

	return data;
}


char *fperfdata (const char *label,
 double val,
 const char *uom,
 int warnp,
 double warn,
 int critp,
 double crit,
 int minp,
 double minv,
 int maxp,
 double maxv)
{
	char *data = NULL;

	if (strpbrk (label, "'= "))
		xasprintf (&data, "'%s'=", label);
	else
		xasprintf (&data, "%s=", label);

	xasprintf (&data, "%s%f", data, val);
	xasprintf (&data, "%s%s;", data, uom);

	if (warnp)
		xasprintf (&data, "%s%f", data, warn);

	xasprintf (&data, "%s;", data);

	if (critp)
		xasprintf (&data, "%s%f", data, crit);

	xasprintf (&data, "%s;", data);

	if (minp)
		xasprintf (&data, "%s%f", data, minv);

	if (maxp) {
		xasprintf (&data, "%s;", data);
		xasprintf (&data, "%s%f", data, maxv);
	}

	return data;
}

char *sperfdata (const char *label,
 double val,
 const char *uom,
 char *warn,
 char *crit,
 int minp,
 double minv,
 int maxp,
 double maxv)
{
	char *data = NULL;
	if (strpbrk (label, "'= "))
		xasprintf (&data, "'%s'=", label);
	else
		xasprintf (&data, "%s=", label);

	xasprintf (&data, "%s%f", data, val);
	xasprintf (&data, "%s%s;", data, uom);

	if (warn!=NULL)
		xasprintf (&data, "%s%s", data, warn);

	xasprintf (&data, "%s;", data);

	if (crit!=NULL)
		xasprintf (&data, "%s%s", data, crit);

	xasprintf (&data, "%s;", data);

	if (minp)
		xasprintf (&data, "%s%f", data, minv);

	if (maxp) {
		xasprintf (&data, "%s;", data);
		xasprintf (&data, "%s%f", data, maxv);
	}

	return data;
}

char *sperfdata_int (const char *label,
 int val,
 const char *uom,
 char *warn,
 char *crit,
 int minp,
 int minv,
 int maxp,
 int maxv)
{
	char *data = NULL;
	if (strpbrk (label, "'= "))
		xasprintf (&data, "'%s'=", label);
	else
		xasprintf (&data, "%s=", label);

	xasprintf (&data, "%s%d", data, val);
	xasprintf (&data, "%s%s;", data, uom);

	if (warn!=NULL)
		xasprintf (&data, "%s%s", data, warn);

	xasprintf (&data, "%s;", data);

	if (crit!=NULL)
		xasprintf (&data, "%s%s", data, crit);

	xasprintf (&data, "%s;", data);

	if (minp)
		xasprintf (&data, "%s%d", data, minv);

	if (maxp) {
		xasprintf (&data, "%s;", data);
		xasprintf (&data, "%s%d", data, maxv);
	}

	return data;
}

/* set entire string to lower, no need to return as it works on string in place */
void strntolower (char * test_char, int size) {

        char * ptr = test_char;

        for (; ptr < test_char+size; ++ptr)
                *ptr = tolower(*ptr);

}

/* set entire string to lower, no need to return as it works on string in place */
void strntoupper (char * test_char, int size) {

        char * ptr = test_char;

        for (; ptr < test_char+size; ++ptr)
                *ptr = toupper(*ptr);

}
