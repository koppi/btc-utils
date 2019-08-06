LDLIBS=-lssl -lcrypto -lm -lsqlite3
CFLAGS=-Wall -O3 -Wno-implicit-function-declaration

all: brain-wallet brain-wallet-sqlite wallet-pkeys bwallet2sqlite

brain-wallet: brain-wallet.c util.c

brain-wallet-sqlite: brain-wallet-sqlite.c util.c

wallet-pkeys: wallet-pkeys.c util.c

bwallet2sqlite: bwallet2sqlite.c util.c

clean:
	rm -f brain-wallet brain-wallet-sqlite wallet-pkeys bwallet2sqlite
