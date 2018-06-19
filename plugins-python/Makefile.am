## Process this file with automake to produce Makefile.in

if RELEASE_PRESENT
NP_VERSION = @NP_RELEASE@
else
NP-VERSION-FILE: .FORCE-NP-VERSION-FILE
	@$(SHELL_PATH) $(top_srcdir)/NP-VERSION-GEN
.FORCE-NP-VERSION-FILE:
-include NP-VERSION-FILE
endif

SUFFIXES = .py .in

VPATH=$(top_srcdir) $(top_srcdir)/plugins-python

libexec_SCRIPTS = check_heartbleed.py  check_imap_login.py check_ncpa.py

EXTRA_DIST=check_heartbleed.in  check_imap_login.in  check_ncpa.in

EDIT = sed \
  -e 's|[@]NP_VERSION[@]|$(NP_VERSION)|g' \
  -e 's|[@]TRUSTED_PATH[@]|$(with_trusted_path)|g' \
  -e 's|[@]PYTHON[@]|$(PYTHON)|g' \
  -e 's|[@]libexecdir[@]|$(libexecdir)|g'

#TESTS_ENVIRONMENT=perl -I $(top_builddir) -I $(top_srcdir)

#TESTS = @SCRIPT_TEST@

#test:
#	perl -I $(top_builddir) -I $(top_srcdir) ../test.pl
#	perl -I $(top_builddir) -I $(top_srcdir) ../test.pl t/utils.t	# utils.t is excluded from above, so manually ask to test

#test-debug:
#	NPTEST_DEBUG=1 HARNESS_VERBOSE=1 perl -I $(top_builddir) -I $(top_srcdir) ../test.pl
#	NPTEST_DEBUG=1 HARNESS_VERBOSE=1 perl -I $(top_builddir) -I $(top_srcdir) ../test.pl t/utils.t	# utils.t is excluded from above, so manually ask to test

CLEANFILES=$(libexec_SCRIPTS)

.in.py:
	@if [ ! "$(PYTHON)" = "missing" ]; then \
	    $(EDIT) $< > $@; \
	    chmod +x $@; \
	fi

clean-local:
	rm -f NP-VERSION-FILE *.pyc
