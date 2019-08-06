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

int main(int argc, char** argv) {
	char ecprot1[128], ecprot2[128];
	EC_KEY *pkey; int privtype, addrtype;

	BIO *out = NULL;

	out = BIO_new(BIO_s_file());

	BIO_set_fp(out, stdout, BIO_NOCLOSE);

	OpenSSL_add_all_algorithms();
	
	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	addrtype = 0; privtype = 128;

	if (argc != 2) {
		printf("usage: wallet-pkeys [int between 1 and 115792089237316195423570985008687907852837564279074904382605163141518161494336]\n");
		exit(1);
	}

	BIGNUM* bn = BN_new();
	BN_dec2bn(&bn, argv[1]);
	
	// BN_print(out, bn); printf("\n");
	
	EC_KEY_regenerate_key(pkey, bn);
		
	vg_encode_address(EC_KEY_get0_public_key(pkey),
					  EC_KEY_get0_group(pkey),
					  addrtype, ecprot1);
		
	vg_encode_privkey(pkey, privtype, ecprot2);
	printf("%s %s\n", ecprot1, ecprot2);

	BN_free(bn);

	BIO_free(out);

	return 0;		
}

	
