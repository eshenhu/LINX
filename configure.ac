AC_INIT(linx, 2.5.1, linx@enea.com)
saved_CFLAGS=$CFLAGS	          
AC_PROG_CC
CFLAGS=$saved_CFLAGS	
AM_INIT_AUTOMAKE(linx,2.5.1)
AM_INIT_AUTOMAKE([tar-ustar])
AC_ARG_ENABLE([doc],
	[--enable-doc	Include documentation in the distribution],
	[case "${enableval}" in
	      yes) doc=true ;;
	      no)  doc=false ;;
	      *) AC_MSG_ERROR([bad value ${enableval} for --enable-doc]) ;;
	esac],[doc=true])
AM_CONDITIONAL([DOC], [test x$doc = xtrue])
AC_ARG_ENABLE([debug],
	[--enable-debug	Turn on debugging]],
	[case "${enableval}" in
	      yes) debug=true ;;
	      no)  debug=false ;;
	      *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
	esac],[debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])   		         
AM_PROG_CC_C_O
m4_undefine([AC_PROG_CXX])   
m4_defun([AC_PROG_CXX],[])
m4_undefine([AC_PROG_F77])
m4_defun([AC_PROG_F77],[])
AM_PROG_LIBTOOL
AC_OUTPUT([Makefile liblinx/Makefile linxstat/Makefile linxgw/linxgws/Makefile
	   bmark/linx_bmark/Makefile example/linx_basic/Makefile linxcfg/Makefile
	   linxdisc/Makefile linxgw/libgw/Makefile linxgw/linxgwcmd/Makefile ])


