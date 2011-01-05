dnl
dnl  configure.ac
dnl
dnl  Written by Jari Ruusu, June 3 2010
dnl
dnl  Copyright 2002-2010 by Jari Ruusu.
dnl  Redistribution of this file is permitted under the GNU Public License.
dnl

AC_INIT([aespipe], [2])
AC_CONFIG_SRCDIR([aespipe.c])
AC_GNU_SOURCE
AC_SYS_LARGEFILE
AC_PROG_CC
AC_PROG_GREP
AC_PROG_MAKE_SET
AC_CHECK_FUNCS([mlockall])
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([unistd.h fcntl.h sys/mman.h termios.h sys/ioctl.h strings.h pthread.h])
AC_C_BIGENDIAN
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_CHECK_TYPES([u_int32_t, u_int64_t])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_SIZEOF([unsigned long long])

dnl Make sure that u_int32_t is something sane
if test "${ac_cv_type_u_int32_t}" = "no"; then
	if test "${ac_cv_sizeof_unsigned_int}" = "4"; then
		AC_DEFINE([u_int32_t], [unsigned int])
	elif test "${ac_cv_sizeof_unsigned_long}" = "4"; then
		AC_DEFINE([u_int32_t], [unsigned long])
	else
		AC_MSG_ERROR([cannot determine u_int32_t])
	fi
fi

dnl Make sure that u_int64_t is something sane
if test "${ac_cv_type_u_int64_t}" = "no"; then
	if test "${ac_cv_sizeof_unsigned_long}" = "8"; then
		AC_DEFINE([u_int64_t], [unsigned long])
	elif test "${ac_cv_sizeof_unsigned_long_long}" = "8"; then
		AC_DEFINE([u_int64_t], [unsigned long long])
	else
		AC_MSG_ERROR([cannot determine u_int64_t])
	fi
fi

dnl Check if labels need underline prefix
AC_ARG_VAR([NM_PROG], [nm utility])
AC_CHECK_TOOL([NM_PROG],[nm])
AC_MSG_CHECKING([whether labels need underline prefix])
label="test1234test9876"
AC_LANG_CONFTEST([
void ${label}(void){}
])
if ${CC} ${CPPFLAGS} ${CFLAGS} -c conftest.c >/dev/null 2>&1 && ${NM_PROG} conftest.o | ${GREP} "_${label}" >/dev/null 2>&1; then
	AC_MSG_RESULT([yes])
	AC_DEFINE([USE_UNDERLINE], [1])
else
	AC_MSG_RESULT([no])
fi
rm -f conftest*

dnl Check if assembler understands .align 32
AC_MSG_CHECKING([whether assembler understands .align 32])
AC_COMPILE_IFELSE(
	[__asm__(" .align 32");],
	[x_asm_align_32_ok="yes"],
	[
		x_asm_align_32_ok="no"
		AC_DEFINE([ALIGN32BYTES], [4])
		AC_DEFINE([ALIGN64BYTES], [4])
	]
)
AC_MSG_RESULT([${x_asm_align_32_ok}])

dnl Check presence of strip tool
AC_ARG_VAR([STRIP_PROG], [strip utility])
AC_CHECK_TOOL([STRIP_PROG],[strip])
if test "${STRIP_PROG}" = "" ; then
	STRIP_PROG="true"
fi
AC_SUBST([STRIP_PROG])

dnl Check presence of md5sum or md5 program
AC_ARG_VAR([MD5SUM_PROG], [md5sum utility])
AC_CHECK_PROGS([MD5SUM_PROG],[md5sum])
AC_ARG_VAR([MD5_PROG], [md5 utility])
AC_CHECK_PROGS([MD5_PROG],[md5])
if test -n "${MD5SUM_PROG}"; then
	MD5WORKPART=3
elif test -n "${MD5_PROG}"; then
	MD5WORKPART=4
else
	MD5WORKPART=5
fi
AC_SUBST([MD5WORKPART])

dnl Check presence of gpg program
AC_ARG_VAR([GPG_PROG], [full path to gpg utility])
AC_PATH_PROGS([GPG_PROG],[gpg])
GPGWORKPART="true "
if test -n "${GPG_PROG}"; then
	GPGWORKPART=""
	AC_DEFINE_UNQUOTED([PATH_TO_GPG_PROGRAM], ["${GPG_PROG}"])
fi
AC_SUBST([GPGWORKPART])

dnl Check if noexec stack section can be used
AC_MSG_CHECKING([if assembler supports no exec stack section])
old_ac_ext="${ac_ext}"
ac_ext="S"
AC_COMPILE_IFELSE(
	[	.section .note.GNU-stack,"",@progbits ],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([SECTION_NOTE_GNU_STACK], [1])
	],
	[AC_MSG_RESULT([no])]
)
ac_ext="${old_ac_ext}"

dnl Detect target arch type
AC_ARG_VAR([SED_PROG], [sed utility])
AC_CHECK_PROGS([SED_PROG],[sed])
test -z "${SED_PROG}" && AC_MSG_ERROR([sed is required])
AC_MSG_CHECKING([output architecture])
x_x86_target=no
x_amd64_target=no
OUTPUT_ARCH="$(${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -Wl,--verbose 2>&1 | ${SED_PROG} -n 's/^OUTPUT_ARCH(\([[^)]]*\)).*/\1/p')"
if test -z "${OUTPUT_ARCH}"; then
	AC_MSG_RESULT([unknown])
else
	AC_MSG_RESULT([${OUTPUT_ARCH}])
	case "${OUTPUT_ARCH}" in
	i386)
		x_x86_target=yes
		;;
	*x86-64 | *x86_64 | *amd64)
		if test "$ac_cv_sizeof_unsigned_long" = 4; then
			x_x86_target=yes
		else
			x_amd64_target=yes
		fi
		;;
	esac
fi

dnl Handle --disable-asm, --enable-asm=x86, --enable-asm=amd64
AC_ARG_ENABLE([asm],
	[AS_HELP_STRING([--disable-asm],[disable optimized x86/amd64/padlock/intelaes assembler code])],
	[x_enable_asm=$enableval], [x_enable_asm=autodetect])

AC_MSG_CHECKING([whether to use optimized 32 bit x86 assembler code])
if test "$x_enable_asm" = x86 ; then
	x_enable_x86asm=yes
elif test "$x_enable_asm" = autodetect ; then
	x_enable_x86asm=$x_x86_target
else
	x_enable_x86asm=no
fi
AC_MSG_RESULT([${x_enable_x86asm}])

AC_MSG_CHECKING([whether to use optimized 64 bit amd64 assembler code])
if test "$x_enable_asm" = amd64 ; then
	x_enable_amd64asm=yes
elif test "$x_enable_asm" = autodetect ; then
	x_enable_amd64asm=$x_amd64_target
else
	x_enable_amd64asm=no
fi
AC_MSG_RESULT([${x_enable_amd64asm}])

dnl Select x86 asm / amd64 asm / C-language sources
if test "$x_enable_x86asm" = yes ; then
	OPTIMIZED_OBJS="aes-x86.o md5-x86.o"
	AC_DEFINE([X86_ASM], [1])
elif test "$x_enable_amd64asm" = yes ; then
	OPTIMIZED_OBJS="aes-amd64.o md5-amd64.o md5-2x-amd64.o"
	AC_DEFINE([AMD64_ASM], [1])
	AC_DEFINE([HAVE_MD5_2X_IMPLEMENTATION], [1])
else
	OPTIMIZED_OBJS="aes.o md5.o"
fi

dnl Handle --enable-padlock, --disable-padlock, --enable-intelaes, --disable-intelaes
AC_ARG_ENABLE([padlock],
	[AS_HELP_STRING([--enable-padlock],[include support for VIA padlock hardware AES])],
	[x_enable_padlock=$enableval],	[x_enable_padlock=autodetect])
AC_ARG_ENABLE([intelaes],
	[AS_HELP_STRING([--enable-intelaes],[include support for Intel hardware AES])],
	[x_enable_intelaes=$enableval],	[x_enable_intelaes=autodetect])
if test "$x_enable_x86asm" != yes -a "$x_enable_amd64asm" != yes ; then
	x_enable_padlock=no
	x_enable_intelaes=no
fi

AC_MSG_CHECKING([whether to include support for VIA padlock hardware AES])
if test "$x_enable_padlock" = autodetect ; then
	AC_RUN_IFELSE([#include <stdlib.h>
		int main(int argc, char **argv) {unsigned int eax, ebx, ecx, edx;
		__asm__ __volatile__("cpuid" : "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0), "b" (0), "c" (0), "d" (0));
		if((ebx != 0x746e6543) || (edx != 0x48727561) || (ecx != 0x736c7561)) exit(1);
		__asm__ __volatile__("cpuid" : "=a" (eax) : "a" (0xC0000000), "b" (0), "c" (0), "d" (0));
		if(eax < 0xC0000001) exit(1);
		__asm__ __volatile__("cpuid" : "=d" (edx) : "a" (0xC0000001), "b" (0), "c" (0), "d" (0));
		if((edx & 0xC0) != 0xC0) exit(1);
		__asm__ __volatile__("xor %%eax,%%eax" : "+a" (edx) : : "cc");
		exit(0);}
		],[x_enable_padlock=yes],[x_enable_padlock=no],[x_enable_padlock=no])
fi
if test "$x_enable_padlock" = yes ; then
	AC_DEFINE([SUPPORT_PADLOCK], [1])
fi
AC_MSG_RESULT([$x_enable_padlock])

AC_MSG_CHECKING([whether to include support for Intel hardware AES])
if test "$x_enable_intelaes" = autodetect ; then
	AC_RUN_IFELSE([#include <stdlib.h>
		int main(int argc, char **argv) {unsigned int ecx;
		__asm__ __volatile__("cpuid" : "=c" (ecx) : "a" (1), "b" (0), "c" (0), "d" (0));
		if((ecx & 0x02000000) != 0x02000000) exit(1);
		__asm__ __volatile__("pxor %%xmm0,%%xmm0; emms" : : : "cc");
		exit(0);}
		],[x_enable_intelaes=yes],[x_enable_intelaes=no],[x_enable_intelaes=no])
fi
if test "$x_enable_intelaes" = yes ; then
	AC_DEFINE([SUPPORT_INTELAES], [1])
	if test "$x_enable_x86asm" = yes ; then
		OPTIMIZED_OBJS="${OPTIMIZED_OBJS} aes-intel32.o"
	elif test "$x_enable_amd64asm" = yes ; then
		OPTIMIZED_OBJS="${OPTIMIZED_OBJS} aes-intel64.o"
	fi
fi
AC_MSG_RESULT([$x_enable_intelaes])

dnl Check presence of yasm tool
AC_ARG_VAR([YASM_PROG], [yasm])
AC_CHECK_PROG([YASM_PROG],[yasm],[yasm],[yasm not found])
AC_SUBST([YASM_PROG])

dnl Handle --enable-ctrmode, --disable-ctrmode
AC_MSG_CHECKING([whether to include support for multithreaded AES CTR mode])
AC_ARG_ENABLE([ctrmode],
	[AS_HELP_STRING([--enable-ctrmode],[include support for multithreaded AES CTR mode])],
	[x_enable_ctrmode=$enableval],	[x_enable_ctrmode=yes])
if test "$x_enable_intelaes" != yes -o "${YASM_PROG}" != "yasm" ; then
	x_enable_ctrmode=no
fi
if test "$x_enable_ctrmode" = yes ; then
	AC_DEFINE([SUPPORT_CTRMODE], [1])
	OPTIMIZED_OBJS="${OPTIMIZED_OBJS} ctrmode.o"
	LDFLAGS="${LDFLAGS} -lpthread"
	if test "$x_enable_x86asm" = yes ; then
		OPTIMIZED_OBJS="${OPTIMIZED_OBJS} aesni-x86.o iaes-x86.o do_rdtsc-x86.o"
	elif test "$x_enable_amd64asm" = yes ; then	
		OPTIMIZED_OBJS="${OPTIMIZED_OBJS} aesni-x64.o iaes-x64.o do_rdtsc-x64.o"
	fi
fi

AC_MSG_RESULT([$x_enable_ctrmode])


AC_SUBST([OPTIMIZED_OBJS])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

dnl Add space escaped srcdir to Makefile
echo "srcdir=$srcdir" | ${SED_PROG} -e 's/ /\\ /g' >ac-tmp-1.o
cat Makefile >>ac-tmp-1.o
mv ac-tmp-1.o Makefile
