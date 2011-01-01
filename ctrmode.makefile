
#Copyright 2010 Rapleaf
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

CC = gcc
CFLAGS = -O3 -g -m64 -Iinclude
YASM = yasm
YFLAGS = -D__linux__ -g dwarf2 -f elf64

all: intel_aes

intel_aes: asm
	$(CC) $(CFLAGS) -c src/intel_aes.c -o src/intel_aes.o
	mkdir -p lib
	ar -r lib/intel_aes64.a src/*.o

asm:
	$(YASM) $(YFLAGS) src/iaesx64.s -o src/iaesx64.o
	$(YASM) $(YFLAGS) src/do_rdtsc.s -o src/do_rdtsc.o

clean:
	rm -rf src/*.o lib

