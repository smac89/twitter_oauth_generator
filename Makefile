BINDIR =	/usr/local/bin
MANDIR =	/usr/local/man/man1
LIBDIR =	/usr/local/lib
INCDIR =	/usr/local/include
CC =		cc
CFLAGS =	-O -ansi -pedantic -U__STRICT_ANSI__ -Wall -Wpointer-arith -Wshadow -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wno-long-long
LDFLAGS =	-L.
LIBS =		-loauthsign -lcrypto

all:		oauth_sign liboauthsign.a

oauth_sign:	oauth_sign.c liboauthsign.h liboauthsign.a
	$(CC) $(CFLAGS) oauth_sign.c $(LDFLAGS) $(LIBS) -o oauth_sign

liboauthsign.o:	liboauthsign.c liboauthsign.h
	$(CC) -c $(CFLAGS) liboauthsign.c

liboauthsign.a:	liboauthsign.o
	rm -f liboauthsign.a
	ar rc liboauthsign.a liboauthsign.o
	-ranlib liboauthsign.a

hmac.o:		hmac.c hmac.h
	$(CC) -c $(CFLAGS) hmac.c

install:	all
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
