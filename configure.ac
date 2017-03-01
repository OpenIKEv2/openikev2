AC_INIT(configure.ac)

AM_CONFIG_HEADER(config.h)
AC_DEFINE(OPENIKE_VERSION, "0.7", [Version])
AM_INIT_AUTOMAKE(openikev2, 0.7)

AC_CONFIG_MACRO_DIR([m4])

AC_LANG_CPLUSPLUS
AC_PROG_CXX
AM_PROG_LIBTOOL


# Checks whether --enable-eap was given.
AC_ARG_ENABLE(eap, 
 [  --enable-eap[=client or server]      enables the client or server-side EAP methods implemetation],
 [ if   test "x$enableval" = "xclient" ; then
      eap=client; AC_DEFINE([EAP_CLIENT_ENABLED], [], [Client-side EAP methods implementation])
   elif test "x$enableval" = "xserver" ; then
      eap=server; AC_DEFINE([EAP_SERVER_ENABLED], [], [Server-side EAP methods implementation])
   else
	echo
	echo "Error!"
	echo "Use client or server in --enable-eap"
        exit -1
   fi
 ])
AM_CONDITIONAL(compile_EAP_client, [test "$enable_eap" = "client"])
AM_CONDITIONAL(compile_EAP_server, [test "$enable_eap" = "server"])



######################### CHECK FOR LIBRARIES ############################################
#####Check if libopenikev2 is installed
AC_CHECK_LIB(
    openikev2, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2 in order to compile openikev2.)
        exit
    ], 
    []
)

AC_CHECK_HEADERS(
    "libopenikev2/ikesacontroller.h", 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2 in order to compile openikev2.)
        exit
    ], 
    []
)

if test "$enable_eap" = "server"; then

#####Check if libradvd is installed
AC_CHECK_LIB(
    radvd, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2_impl with the library libradvd enabled in order to compile openikev2.)
        exit
    ], 
    []
)

AC_CHECK_HEADERS(
    libopenikev2_impl/radvd_wrapper.h, 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2_impl with the library libradvd enabled in order to compile openikev2.)
        exit
    ], 
    []
)

fi

#####Check if libopenikev2_impl is installed
#AC_CHECK_LIB(
#    openikev2_impl, 
#    main,
#    [], 
#    [
#        AC_MSG_RESULT(** ERROR ** You must install libopenikev2_impl in order to compile openikev2.)
#        exit
#    ], 
#    []
#)

AC_CHECK_HEADERS(
    libopenikev2_impl/eapserver.h, 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2_impl in order to compile openikev2.)
        exit
    ], 
    []
)

AC_CHECK_LIB(
    openikev2_impl,
    main,
    [],
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2_impl in order to compile openikev2.)
        exit
    ],
    []
)


#####Check if libconfuse is installed
AC_CHECK_LIB(
    confuse, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libconfuse in order to compile openikev2.)
        exit
    ], 
    []
)

AC_CHECK_HEADERS(
    confuse.h,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libconfuse in order to compile openikev2.)
        exit
    ], 
    []
)





AC_OUTPUT(Makefile src/Makefile samples/Makefile)
