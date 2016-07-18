AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS = dhcprobe
dhcprobe_SOURCES = dhcprobe.c dhcprobe_options.h
man_MANS = dhcprobe.8

dhcprobe.8: dhcprobe.pod
	$(PERL2MAN_RULE)
PERL2MAN_RULE = \
	pod2man --release="April 7, 2012" --date="April 7, 2012" --center="General Commands Manual" --section=8 $? > $@

