srcdir=.
#
#  Makefile.in
#
#  Written by Jari Ruusu, June 3 2010
#
#  Copyright 2002-2010 by Jari Ruusu.
#  Redistribution of this file is permitted under the GNU Public License.
#

CC = gcc  -std=c99 -DPACKAGE_NAME=\"aespipe\" -DPACKAGE_TARNAME=\"aespipe\" -DPACKAGE_VERSION=\"2\" -DPACKAGE_STRING=\"aespipe\ 2\" -DPACKAGE_BUGREPORT=\"\" -D_GNU_SOURCE=1 -DHAVE_MLOCKALL=1 -DSTDC_HEADERS=1 -DHAVE_SYS_WAIT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_UNISTD_H=1 -DHAVE_FCNTL_H=1 -DHAVE_SYS_MMAN_H=1 -DHAVE_TERMIOS_H=1 -DHAVE_SYS_IOCTL_H=1 -DHAVE_STRINGS_H=1 -DHAVE_PTHREAD_H=1 -DHAVE_U_INT32_T=1 -DHAVE_U_INT64_T=1 -DSIZEOF_UNSIGNED_INT=4 -DSIZEOF_UNSIGNED_LONG=8 -DSIZEOF_UNSIGNED_LONG_LONG=8 -DUSE_UNDERLINE=1 -DSUPPORT_CTRMODE=1
LINK = gcc 
STRIP = strip
MD5SUM = 
MD5 = md5
YASM = yasm
prefix = /usr/local
exec_prefix = ${prefix}
builddir = .
datarootdir = ${prefix}/share

SKIP_STRIP = true

all x86 i586 amd64: aespipe

aespipe: aespipe.o aes.o md5.o ctrmode.o sha512.o rmd160.o
	$(LINK) -o aespipe aespipe.o aes.o md5.o ctrmode.o sha512.o rmd160.o 
aespipe.o: $(srcdir)/aespipe.c $(srcdir)/aes.h $(srcdir)/md5.h $(srcdir)/sha512.h $(srcdir)/rmd160.h
	$(CC) -o aespipe.o -c $(srcdir)/aespipe.c
aes.o: $(srcdir)/aes.c $(srcdir)/aes.h
	$(CC) -DCONFIGURE_DETECTS_BYTE_ORDER=1 -DDATA_ALWAYS_ALIGNED=1 -o aes.o -c $(srcdir)/aes.c
aes-x86.o: $(srcdir)/aes-x86.S $(srcdir)/aes.h
	$(CC) -o aes-x86.o -c $(srcdir)/aes-x86.S
aes-amd64.o: $(srcdir)/aes-amd64.S $(srcdir)/aes.h
	$(CC) -o aes-amd64.o -c $(srcdir)/aes-amd64.S
aes-intel32.o: $(srcdir)/aes-intel32.S $(srcdir)/aes.h
	$(CC) -o aes-intel32.o -c $(srcdir)/aes-intel32.S
aes-intel64.o: $(srcdir)/aes-intel64.S $(srcdir)/aes.h
	$(CC) -o aes-intel64.o -c $(srcdir)/aes-intel64.S
md5.o: $(srcdir)/md5.c $(srcdir)/md5.h
	$(CC) -o md5.o -c $(srcdir)/md5.c
md5-x86.o: $(srcdir)/md5-x86.S $(srcdir)/md5.h
	$(CC) -o md5-x86.o -c $(srcdir)/md5-x86.S
md5-amd64.o: $(srcdir)/md5-amd64.S $(srcdir)/md5.h
	$(CC) -o md5-amd64.o -c $(srcdir)/md5-amd64.S
md5-2x-amd64.o: $(srcdir)/md5-2x-amd64.S $(srcdir)/md5.h
	$(CC) -o md5-2x-amd64.o -c $(srcdir)/md5-2x-amd64.S
sha512.o: $(srcdir)/sha512.c $(srcdir)/sha512.h
	$(CC) -o sha512.o -c $(srcdir)/sha512.c
rmd160.o: $(srcdir)/rmd160.c $(srcdir)/rmd160.h
	$(CC) -o rmd160.o -c $(srcdir)/rmd160.c

#for ctr mode
ctrmode.o: $(srcdir)/ctrmode.c $(srcdir)/ctrmode.h
	$(CC) -o ctrmode.o -c $(srcdir)/ctrmode.c
aesni-x86.o: iaes-x86.o do_rdtsc-x86.o $(srcdir)/iaesni.h $(srcdir)/iaes_asm_interface.h
	$(CC) -o aesni-x86.o -c $(srcdir)/intel_aes.c
iaes-x86.o: $(srcdir)/iaes-x86.s
	$(YASM) -f elf32 -D__linux__ elf${sz} $(srcdir)/iaes-x86.s -o iaes-x86.o
do_rdtsc-x86.o: $(srcdir)/do_rdtsc-x86.s
	$(YASM) -f elf32 -D__linux__ elf${sz} $(srcdir)/do_rdtsc-x86.s -o do_rdtsc-x86.o
aesni-x64.o: iaes-x64.o do_rdtsc-x64.o $(srcdir)/iaesni.h $(srcdir)/iaes_asm_interface.h
	$(CC) -o aesni-x64.o -c $(srcdir)/intel_aes.c
iaes-x64.o: $(srcdir)/iaes-x64.s
	$(YASM) -f elf64 -D__linux__ elf${sz} $(srcdir)/iaes-x64.s -o iaes-x64.o
do_rdtsc-x64.o: $(srcdir)/do_rdtsc-x64.s
	$(YASM) -f elf64 -D__linux__ elf${sz} $(srcdir)/do_rdtsc-x64.s -o do_rdtsc-x64.o


clean:
	rm -f *.o aespipe test-file[12345] config.log config.status configure.lineno
	rm -f -r test-dir1 autom4te.cache
distclean: clean
	rm -f Makefile

install: aespipe
	mkdir -p "$(DESTDIR)${exec_prefix}/bin"
	rm -f "$(DESTDIR)${exec_prefix}/bin/aespipe"
	cp aespipe "$(DESTDIR)${exec_prefix}/bin/aespipe"
	$(SKIP_STRIP) "$(DESTDIR)${exec_prefix}/bin/aespipe"
	chmod 0755 "$(DESTDIR)${exec_prefix}/bin/aespipe"
	mkdir -p "$(DESTDIR)${datarootdir}/man/man1"
	rm -f "$(DESTDIR)${datarootdir}/man/man1/aespipe.1"
	cp $(srcdir)/aespipe.1 "$(DESTDIR)${datarootdir}/man/man1/aespipe.1"
	chmod 0644 "$(DESTDIR)${datarootdir}/man/man1/aespipe.1"

install-strip:
	$(MAKE) SKIP_STRIP=$(STRIP) install

tests: aespipe
	dd if=/dev/zero of=test-file1 bs=1024 count=33
	echo 09876543210987654321 >test-file4
	./aespipe -v -p 3 -e AES128 <test-file1 >test-file3 3<test-file4
	echo 12345678901234567890 >test-file4
	$(MAKE) test-part2 PAR="-e AES128" MD=7c1cfd4fdd0d7cc847dd0942a2d48e48 MD5WORK=test-part4
	$(MAKE) test-part2 PAR="-e AES192" MD=51c91bcc04ee2a4ca00310b519b3228c MD5WORK=test-part4
	$(MAKE) test-part2 PAR="-e AES256" MD=1bf92ee337b653cdb32838047dec00fc MD5WORK=test-part4
	$(MAKE) test-part2 PAR="-e AES256 -H rmd160" MD=c85eb59da18876ae71ebd838675c6ef4 MD5WORK=test-part4
	$(MAKE) test-part2 PAR="-e AES256 -C 10" MD=dadad48a6d3d9b9914199626ed7b710c MD5WORK=test-part4
	true rm -fr test-dir1
	true mkdir test-dir1
	true $(MAKE) test-part2 PAR="-e AES128 -K $(srcdir)/gpgkey1.asc -G test-dir1" MD=fa5c9a84bc8f6257830c3cbe60294c69 MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES192 -K $(srcdir)/gpgkey1.asc -G test-dir1" MD=ddec9544a36100156aef353ec2bf9740 MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES256 -K $(srcdir)/gpgkey1.asc -G test-dir1" MD=cb38b603f96f0deac1891d423983d69c MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES128 -K $(srcdir)/gpgkey2.asc -G test-dir1" MD=f9825b79873f5c439ae9371c1a929a6c MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES192 -K $(srcdir)/gpgkey2.asc -G test-dir1" MD=489991b779213f60219f09c575c08247 MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES256 -K $(srcdir)/gpgkey2.asc -G test-dir1" MD=2a1d0d3fce83fbe5f3edcca95fbab3b7 MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES128 -K $(srcdir)/gpgkey3.asc -G test-dir1" MD=fabe7422f534820838dfd4571ba14ade MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES192 -K $(srcdir)/gpgkey3.asc -G test-dir1" MD=3eadc976525f9df7e18d56676ec730c8 MD5WORK=test-part4
	true $(MAKE) test-part2 PAR="-e AES256 -K $(srcdir)/gpgkey3.asc -G test-dir1" MD=3be488a60dd77bcab9fbeba4a428c3d5 MD5WORK=test-part4
	echo 1234567890123456789012345678901 >test-file4
	$(MAKE) test-part2 PAR="-e AES -H unhashed1" MD=293b09053055af7ca5235dc6a5bc0b74 MD5WORK=test-part4
	echo 12345678901234567890123456789012 >test-file4
	$(MAKE) test-part2 PAR="-e AES -H unhashed1" MD=6b157917570250ef4370bf9acae49279 MD5WORK=test-part4
	echo 123456789012345678901234567890123456789012 >test-file4
	$(MAKE) test-part2 PAR="-e AES -H unhashed1" MD=6b157917570250ef4370bf9acae49279 MD5WORK=test-part4
	echo 1234567890123456789012345678901234567890123 >test-file4
	$(MAKE) test-part2 PAR="-e AES -H unhashed1" MD=e12fd55fbae9fc0e03517593e253e239 MD5WORK=test-part4
	rm -f -r test-file[12345] test-dir1
	@echo "*** Test results ok ***"
test-part2:
	./aespipe -v -p 3 $(PAR) <test-file3 >test-file1 3<test-file4
	$(MAKE) $(MD5WORK)
	cmp test-file2 test-file5
	./aespipe -v -d -P test-file4 $(PAR) <test-file1 >test-file2
	cmp test-file3 test-file2
test-part3:
	$(MD5SUM) test-file1 >test-file2
	echo "$(MD)  test-file1" >test-file5
test-part4:
	$(MD5) test-file1 >test-file2
	echo "MD5 (test-file1) = $(MD)" >test-file5
test-part5:
	echo "NO MD5 TEST" >test-file2
	echo "NO MD5 TEST" >test-file5

.PHONY: all x86 i586 amd64 clean distclean install install-strip tests test-part2 test-part3 test-part4 test-part5
