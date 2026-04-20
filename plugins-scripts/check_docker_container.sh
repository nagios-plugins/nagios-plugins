#!/bin/sh
# Check command to monitor if Docker Containers are running
#
# Requirements:
#  - Docker (duh...)
#  - Nagios-User needs to be a member of docker (adduser nagios docker)
# 
# 2021 by Kai Boenke - code@boenke.info

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
export PATH
PROGNAME=`basename $0`
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0"

# Grab defaults
. $PROGPATH/utils.sh

# Helper functions
print_usage() {
    echo "Usage: $PROGNAME containername [containername] [containername] [...]"
    echo "       $PROGNAME --help"
    echo "       $PROGNAME --version"
}

print_help() {
    print_revision $PROGNAME $REVISION
    echo ""
    print_usage
    echo ""
    echo "Check if a given docker-container is running."
}

check_container() {
    #Assemble Cointainername if it got separated
    for para in "$@"; do containername="$containername $para"; done
    
    #status: 1 (running), 2 (not defined), 3 (not runnning)
    containercheck=$(docker container inspect -f '{{.State.Status}}' $containername 2> /dev/null)
    if [ "$containercheck" = "running" ]; then
        echo "$containername is running"
        if [ -z "$status" ]; then status=1; fi
    elif [ -z "$containercheck" ]; then
        echo "$containername not found"
        if [ -z "$status" ] || [ $status -lt 2 ]; then status=2; fi
    else
        echo "$containername is $containercheck"
        status=3
    fi
    unset containername
}


# Check Arguments
if [ $# -lt 1 ]; then
    print_usage
    exit $STATE_UNKNOWN
fi
case "$1" in
    --help)
        print_help
        exit $STATE_OK
        ;;
    -h)
        print_help
        exit $STATE_OK
        ;;
    --version)
        print_revision $PROGNAME $REVISION
        exit $STATE_OK
        ;;
    -V)
        print_revision $PROGNAME $REVISION
        exit $STATE_OK
        ;;
esac

# Run checks
for arg in "$@"; do check_container $arg; done

if [ $status -eq 1 ]; then exit $STATE_OK
elif [ $status -eq 2 ]; then exit $STATE_WARNING
elif [ $status -eq 3 ]; then exit $STATE_CRITICAL
fi
exit $STATE_UNKNOWN
