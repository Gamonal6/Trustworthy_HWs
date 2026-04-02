/*
 * signer1.c — Level 1 Signer (ID_1) for Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implement HIBS.Extract for hierarchy level k = 1.
 *   This program derives the private key for ID_1 from the PKG master secret.
 *
 * INPUT FILES:
 *   - ID1.txt            : contains identity string ID_1
 *   - signer1_b1.txt     : contains random scalar b1 (hex)
 *   - msk.txt            : contains master secret x (hex)
 *
 * OUTPUT FILES:
 *   - sk_ID1.txt         : private key for ID_1 (hex scalar)
 *   - Q_ID1.txt          : public delegation point (hex EC point)
 *
 * REQUIRED CRYPTOGRAPHIC RELATION:
 *   sk_ID1 = x * c_ID1 + b1 mod q
 *   where c_ID1 = H1(ID_1 || Q_ID1)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_1[1024];

int main(int argc, char **argv) {
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *x = NULL;        /* sk_ID0 (master secret scalar) */
    BIGNUM *b1 = NULL;       /* random delegation scalar */
    EC_POINT *Q_ID1 = NULL;  /* public delegation point */
    BIGNUM *c_ID1 = NULL;    /* hash-derived scalar */
    BIGNUM *sk_ID1 = NULL;   /* derived private key */

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *buf = NULL;
    BIGNUM *tmp = NULL;

    size_t id_len = 0;
    const char *id_path = NULL;
    const char *b1_path = NULL;
    const char *msk_path = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <ID1.txt> <signer1_b1.txt> <msk.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    id_path  = argv[1];
    b1_path  = argv[2];
    msk_path = argv[3];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize EC group and domain parameters             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Call init_group(&group, &q)
     *   - Retrieve generator P using EC_GROUP_get0_generator()
     */
    /* ------------------------------------------------------------ */

    // initialize the elliptic curve group and extract group order q
    if (!init_group(&group, &q))
    {
        fprintf(stderr, "signer1 - group init failed\n");
        return EXIT_FAILURE;
    }

    // retrieve the generator point P from the curve group
    P = EC_GROUP_get0_generator(group);
    if (!P)
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 1: Read master secret x (sk_ID0) from msk.txt            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Use read_bn_hex(msk_path, &x)
     *   - x is a scalar in Z_q
     */
    /* ------------------------------------------------------------ */

    // read the PKG master secret scalar x from the msk file
    if (!read_bn_hex(msk_path, &x))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 2: Read identity string ID_1 from ID1.txt                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Open ID1.txt
     *   - Read the identity string into ID_1
     *   - Strip newline characters
     *   - Compute id_len
     */
    /* ------------------------------------------------------------ */

    // read the identity string ID_1 from ID1.txt and strip newlines
    {
        FILE *f = fopen(id_path, "r");
        if (!f)
            return EXIT_FAILURE;
        if (!fgets(ID_1, sizeof(ID_1), f))
        {
            fclose(f);
            return EXIT_FAILURE;
        }
        fclose(f);
        // strip trailing newline/carriage return characters
        id_len = strlen(ID_1);
        while (id_len > 0 && (ID_1[id_len - 1] == '\n' || ID_1[id_len - 1] == '\r'))
            ID_1[--id_len] = '\0';
    }

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context and allocate scalars            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     *   - Allocate b1 and sk_ID1 using BN_new()
     */
    /* ------------------------------------------------------------ */

    // allocate BN context and scalars for delegation computation
    ctx = BN_CTX_new();
    if (!ctx)
        return EXIT_FAILURE;
    sk_ID1 = BN_new();
    if (!sk_ID1)
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 4: Read delegation randomness b1                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read scalar b1 from signer1_b1.txt using read_bn_hex()
     *   - b1 must lie in Z_q
     */
    /* ------------------------------------------------------------ */

    // read the random delegation scalar b1 from signer1_b1.txt
    if (!read_bn_hex(b1_path, &b1))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 5: Compute Q_ID1 = b1 * P                                 */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate Q_ID1 using EC_POINT_new(group)
     *   - Compute Q_ID1 = b1 * P
     *   - Use EC_POINT_mul(group, Q_ID1, NULL, P, b1, ctx)
     */
    /* ------------------------------------------------------------ */

    // compute the public identity point Q_ID1 = b1 * P
    Q_ID1 = EC_POINT_new(group);
    if (!Q_ID1)
        return EXIT_FAILURE;
    if (!EC_POINT_mul(group, Q_ID1, NULL, P, b1, ctx))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 6: Compute c_ID1 = H1(ID_1 || Q_ID1)                      */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 using point_to_bytes()
     *   - Concatenate ID_1 || serialized Q_ID1 into a buffer
     *   - Hash buffer using H1_to_scalar()
     *   - Output must be a scalar mod q stored in c_ID1
     */
    /* ------------------------------------------------------------ */

    // serialize Q_ID1 to bytes for hashing
    {
        size_t qid1_len = 0;
        if (!point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len))
            return EXIT_FAILURE;

        // concatenate ID_1 || Q_ID1 into a single buffer
        size_t buf_len = id_len + qid1_len;
        buf = (unsigned char *)malloc(buf_len);
        if (!buf)
            return EXIT_FAILURE;
        memcpy(buf, ID_1, id_len);
        memcpy(buf + id_len, qid1_bytes, qid1_len);

        // hash the concatenated buffer to produce the scalar c_ID1
        if (!H1_to_scalar(buf, buf_len, q, &c_ID1))
            return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 7: Compute sk_ID1 = x * c_ID1 + b1 mod q                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp
     *   - Compute tmp = x * c_ID1 mod q using BN_mod_mul()
     *   - Compute sk_ID1 = tmp + b1 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    // compute the level-1 private key: sk_ID1 = x * c_ID1 + b1 mod q
    tmp = BN_new();
    if (!tmp)
        return EXIT_FAILURE;
    // tmp = x * c_ID1 mod q
    if (!BN_mod_mul(tmp, x, c_ID1, q, ctx))
        return EXIT_FAILURE;
    // sk_ID1 = tmp + b1 mod q
    if (!BN_mod_add(sk_ID1, tmp, b1, q, ctx))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 8: Write output keys                                     */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Write sk_ID1 to sk_ID1.txt using write_bn_hex()
     *   - Write Q_ID1 to Q_ID1.txt using write_point_hex()
     */
    /* ------------------------------------------------------------ */

    // write the level-1 private key to sk_ID1.txt
    if (!write_bn_hex("sk_ID1.txt", sk_ID1))
    {
        fprintf(stderr, "signer1 - write sk_ID1.txt failed\n");
        return EXIT_FAILURE;
    }

    // write the public delegation point to Q_ID1.txt
    if (!write_point_hex("Q_ID1.txt", group, Q_ID1))
    {
        fprintf(stderr, "signer1 - write Q_ID1.txt failed\n");
        return EXIT_FAILURE;
    }

    printf("[signer1] Delegation complete.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Follow the same order as allocation
     */
    /* ------------------------------------------------------------ */

    // free all allocated objects to avoid memory leaks
    if (tmp) BN_free(tmp);
    if (c_ID1) BN_free(c_ID1);
    if (buf) free(buf);
    if (qid1_bytes) free(qid1_bytes);
    if (sk_ID1) BN_free(sk_ID1);
    if (Q_ID1) EC_POINT_free(Q_ID1);
    if (b1) BN_free(b1);
    if (x) BN_free(x);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (q) BN_free(q);

    return EXIT_SUCCESS;
}
