#!/bin/sh

PROGNAME=$(basename "$0")
PROGPATH=$(echo "$0" | sed -e 's,[\\/][^\\/][^\\/]*$,,')
REVISION="@NP_VERSION@"
PATH="@TRUSTED_PATH@"

export PATH

. "$PROGPATH"/utils.sh

print_usage() {
	echo "Usage: $PROGNAME" [--ignore-fault]
}

print_help() {
	print_revision "$PROGNAME" "$REVISION"
	echo ""
	print_usage
	echo ""
	echo "This plugin checks hardware status using the lm_sensors package."
	echo ""
	support
	exit "$STATE_OK"
}

case "$1" in
	--help)
		print_help
		exit "$STATE_OK"
		;;
	-h)
		print_help
		exit "$STATE_OK"
		;;
	--version)
		print_revision "$PROGNAME" $REVISION
		exit "$STATE_OK"
		;;
	-V)
		print_revision "$PROGNAME" $REVISION
		exit "$STATE_OK"
		;;
	*)
		ignorefault=0
		if test "$1" = "-i" -o "$1" = "--ignore-fault"; then
			ignorefault=1
		fi

		sensordata=$(sensors 2>&1)
		status=$?

		# Set a default
		text="SENSOR UNKNOWN"
		exit=$STATE_UNKNOWN

		if [ $status -eq 127 ] ; then
			text="SENSORS UNKNOWN - command not found (did you install lmsensors?)"
			exit=$STATE_UNKNOWN
		elif [ "$status" != 0 ] ; then
			text="WARNING - sensors returned state $status"
			exit=$STATE_WARNING
		elif echo "${sensordata}" | egrep -q ALARM >/dev/null ; then
			text="SENSOR CRITICAL - Sensor alarm detected!"
			exit=$STATE_CRITICAL
		elif [ $ignorefault -eq 0 ] && echo "${sensordata}" | egrep -q FAULT  >/dev/null; then
			text="SENSOR UNKNOWN - Sensor reported fault"
			exit=$STATE_UNKNOWN
		else
			text="SENSORS OK"
			exit=$STATE_OK
		fi

		echo "$text"
		if test "$1" = "-v" -o "$1" = "--verbose"; then
			echo "${sensordata}"
		fi
		exit $exit
		;;
esac
