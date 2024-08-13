ifndef MSYSTEM
	CPREFIX = x86_64-w64-mingw32-
endif

WINDIVERTHEADERS = ../../../include
WINDIVERTLIBS = ../../binary
MINGWLIB = /usr/x86_64-w64-mingw32/lib/

TARGET = goodbyedpi.exe
LIBS = -L$(WINDIVERTLIBS) -lWinDivert -lws2_32 -l:libssp.a
CC = $(CPREFIX)gcc

CCWINDRES = $(CPREFIX)windres
ifeq (, $(shell which $(CPREFIX)windres))
	CCWINDRES = windres
endif

CFLAGS = -std=c99 -pipe -I$(WINDIVERTHEADERS) \
         -O2 -D_FORTIFY_SOURCE=2 -fstack-protector \
         -Wall -Wextra -Wpedantic -Wformat=2 -Wformat-overflow -Wformat-truncation \
         -Wformat-security -Wno-format-nonliteral -Wshadow -Wstrict-aliasing=1 \
         -Wnull-dereference -Warray-bounds -Wimplicit-fallthrough \
         -Wshift-overflow \
         -Wformat-signedness -Wstrict-overflow=2 \
         -Wcast-align \
         -Wfloat-equal -Wsign-conversion \
         -mcpu=skylake \
LDFLAGS = -fstack-protector -Wl,-O3,--dynamicbase,--nxcompat,--sort-common,--as-needed \
-Wl,--disable-auto-image-base

ifdef BIT64
	LDFLAGS += -Wl,--high-entropy-va -Wl,--pic-executable,-e,mainCRTStartup
else
	CFLAGS += -m32
	LDFLAGS += -Wl,--pic-executable,-e,_mainCRTStartup -m32
endif

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c utils/*.c)) goodbyedpi-rc.o
HEADERS = $(wildcard *.h utils/*.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

goodbyedpi-rc.o:
	$(CCWINDRES) goodbyedpi-rc.rc goodbyedpi-rc.o

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -s -o $@

clean:
	-rm -f *.o utils/*.o
	-rm -f $(TARGET)
