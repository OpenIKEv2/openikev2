# set the include path found by configure
INCLUDES = $(all_includes)

# the library search path.

sbin_PROGRAMS = openikev2
openikev2_SOURCES = configurerlibconfuse.cpp controlinterface.cpp \
	exitobserver.cpp ikesainfo.cpp openikev2.cpp
noinst_HEADERS = configurerlibconfuse.h controlinterface.h exitobserver.h \
	ikesainfo.h
bin_PROGRAMS = openikev2_monitor
openikev2_monitor_SOURCES = ikesainfo.cpp openikev2_monitor.cpp
