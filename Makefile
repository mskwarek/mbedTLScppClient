
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CC = g++
CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -g -pthread
LDFLAGS = -lpthread 
# -lgtest_main -lgtest 

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../mbedtls/include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../mbedtls/library/\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

ifndef SHARED
DEP=../mbedtls/library/libmbedcrypto.a ../mbedtls/library/libmbedx509.a ../mbedtls/library/libmbedtls.a
else
DEP=../mbedtls/library/libmbedcrypto.$(DLEXT) ../mbedtls/library/libmbedx509.$(DLEXT) ../mbedtls/library/libmbedtls.$(DLEXT)
endif

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# if we're running on Windows, build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

ifdef WINDOWS_BUILD
DLEXT=dll
EXEXT=.exe
LOCAL_LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
else
DLEXT=so
EXEXT=
SHARED_SUFFIX=
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

APPS =	mkoi_mbed_test$(EXEXT)

.SILENT:

.PHONY: all clean list

all: $(APPS)

$(DEP):
	$(MAKE) -C ../mbedtls/library
mkoi_mbed_test$(EXEXT): *.cpp  $(DEP)
	echo "  C++    mbed_tests.cpp"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) *.cpp *.c $(LOCAL_LDFLAGS) -o $@ $(LDFLAGS)

clean:
ifndef WINDOWS
	rm -f $(APPS)
else
	del /S /Q /F *.o *.exe
endif

list:
	echo $(APPS)
