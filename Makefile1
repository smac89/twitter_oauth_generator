BINDIR =    /usr/local/bin
MANDIR =    /usr/local/man/man1
LIBDIR =    /usr/local/lib
INCDIR =    /usr/local/include
CC =        cc
CFLAGS =    -O -ansi -pedantic -ggdb3 -U__STRICT_ANSI__ -Wall -Wextra -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wbad-function-cast -Wno-missing-field-initializers -Wno-long-long -Wswitch-default -Wshadow -Wunreachable-code -Wold-style-definition
LDFLAGS =   -L.
LIBS =      -loauthsign -lcrypto -lcurl

all:        oauth_sign liboauthsign.a

oauth_sign: logger.o liboauthsigntw.o oauth_sign.c liboauthsign.a
	$(CC) $(CFLAGS) oauth_sign.c $(LDFLAGS) -o oauth_sign logger.o liboauthsigntw.o $(LIBS)

logger.o: logger.c logger.h
	$(CC) -c $(CFLAGS) logger.c

liboauthsigntw.o: liboauthsigntw.c liboauthsigntw.h
	$(CC) -c $(CFLAGS) liboauthsigntw.c

liboauthsign.o: liboauthsign.c liboauthsign.h
	$(CC) -c $(CFLAGS) liboauthsign.c

liboauthsign.a: liboauthsign.o
	rm -f liboauthsign.a
	ar rc liboauthsign.a liboauthsign.o
	-ranlib liboauthsign.a

hmac.o:     hmac.c hmac.h
	$(CC) -c $(CFLAGS) hmac.c

install:    all
	rm -f $(BINDIR)/oauth_sign
	cp oauth_sign $(BINDIR)
	rm -f $(MANDIR)/oauth_sign.1
	cp oauth_sign.1 $(MANDIR)
	rm -f $(LIBDIR)/liboauthsign.a
	cp liboauthsign.a $(LIBDIR)
	rm -f $(INCDIR)/liboauthsign.h
	cp liboauthsign.h $(INCDIR)

clean:
	rm -f oauth_sign liboauthsign.a *.o core core.* *.core
