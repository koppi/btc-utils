#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <math.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <sqlite3.h>

sqlite3 *db; char *zErrMsg = 0; char sql[512];

char pwbuf[128], ecprot1[128], ecprot2[128], pbuf[1024]; EC_KEY *pkey; int privtype, addrtype;

char *line;

unsigned long i;

int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key) {
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);

    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);

    ok = 1;

err:

    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);

    return(ok);
}

#define MINIMUM_CAPACITY 16

size_t read_line(char **buffer, size_t *capacity) {
    char *buf = *buffer;
    size_t cap = *capacity, pos = 0;

    if (cap < MINIMUM_CAPACITY) { cap = MINIMUM_CAPACITY; }

    for (;;) {
        buf = realloc(buf, cap);
        if (buf == NULL) { return pos; }
        *buffer = buf;
        *capacity = cap;

        if (fgets(buf + pos, cap - pos, stdin) == NULL) {
            break;
        }

        pos += strcspn(buf + pos, "\n");
        if (buf[pos] == '\n') {
            break;
        }

        cap *= 2;
    }

    return pos;
}

int main(int argc, char** argv) {
	char dbfile[1024];

    size_t size = 0;

	unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

	sprintf(dbfile, "%s/bwallet.sqlite3", getenv("HOME"));

    if( sqlite3_open(dbfile, &db) ){
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }

	sqlite3_exec(db, "PRAGMA synchronous = OFF", 0, 0, &zErrMsg);
	sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", 0, 0, &zErrMsg);

	OpenSSL_add_all_algorithms();
	
	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	addrtype = 0; privtype = 128;
		
	size_t end;

    for (end = read_line(&line, &size);
		 line[end] == '\n'; end = read_line(&line, &size)) {

        line[end] = '\0';

		SHA256_Init(&sha256);
		SHA256_Update(&sha256, line, strlen(line));
		SHA256_Final(hash, &sha256);
		
		BIGNUM *bn = BN_bin2bn(&hash[0], SHA256_DIGEST_LENGTH, BN_new());

		// assert(bn);
		EC_KEY_regenerate_key(pkey, bn);
		BN_free(bn);
		
		vg_encode_address(EC_KEY_get0_public_key(pkey),
						  EC_KEY_get0_group(pkey),
						  addrtype, ecprot1);
		
		sprintf(sql, "INSERT OR REPLACE INTO address VALUES('%s','%s');", line, ecprot1);
		
		if (i++ % 10000 == 0) {
			fprintf(stderr, "%s %s\n", ecprot1, line);
		}
		
		if (sqlite3_exec(db, sql, 0, 0, &zErrMsg) != SQLITE_OK ){
			fprintf(stderr, "SQL error: %s\n", zErrMsg);
			sqlite3_free(zErrMsg);
			exit(0);
		}

		// vg_encode_privkey(pkey, privtype, ecprot2);
		// printf("%s %s\n", ecprot1, ecprot2);
	}

	fprintf(stderr, " done.\n");
		
	EC_KEY_free(pkey);

	free(line);

    sqlite3_close(db);

	return 0;		
}

	
