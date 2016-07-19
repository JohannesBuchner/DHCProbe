dnl
dnl dhcprobe configure.in. Scary... very scary.
dnl

#AC_INIT(dhcprobe.c)
AC_INIT([dhcprobe], [1.2])

AC_PROG_CC
AC_PROG_INSTALL

dnl
dnl some libs sunos/solaris needs
dnl
AC_CANONICAL_SYSTEM
case "$target_os" in
sunos*)
        AC_DEFINE(SUNOS)
	AC_CHECK_LIB(socket,main)
	AC_CHECK_LIB(nsl,main)
	AC_CHECK_LIB(resolv,main)
	OS_OPT=
	AC_SUBST(OS_OPT)
	;;
solaris*)
        AC_DEFINE(SUNOS)
	AC_CHECK_LIB(socket,main)
	AC_CHECK_LIB(nsl,main)
	AC_CHECK_LIB(resolv,main)
	OS_OPT=
	AC_SUBST(OS_OPT)
	;;
esac

#AM_INIT_AUTOMAKE(dhcprobe, 1.2)
AC_CONFIG_SRCDIR([dhcprobe.c])
AM_INIT_AUTOMAKE


AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

AC_CHECK_FUNCS([gethostbyname memset select socket])

AC_OUTPUT(Makefile)
