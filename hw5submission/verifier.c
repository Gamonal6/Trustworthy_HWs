/*
 * verifier.c — Public Verifier for 2-Level Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements HIBS.Verify for k = 2.
 *   Verifies a Schnorr-HIBS signature using only public information.
 *
 * INPUT FILES:
 *   - ID1.txt        : identity string for level 1
 *   - ID2.txt        : identity string for level 2
 *   - message.txt    : signed message
 *   - mpk.txt        : master public key
 *   - Q_ID1.txt      : level-1 public delegation point
 *   - Q_ID2.txt      : level-2 public delegation point
 *   - sig_s.txt      : signature scalar s
 *   - sig_h.txt      : signature hash h
 *
 * OUTPUT:
 *   - verification.txt : recomputed hash value (for debugging)
 *   - Console message indicating VALID or INVALID signature
 *
 * VERIFICATION EQUATION:
 *
 *   PK_eff =
 *     (c_ID1 * c_ID2) * mpk
 *     + (c_ID2 * Q_ID1)
 *     + Q_ID2
 *
 *   R' = s * P − h * PK_eff
 *
 *   Accept iff:
 *     h == H2(message || R')
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

static char ID_1[1024];
static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    EC_POINT *mpk = NULL;
    EC_POINT *Q_ID1 = NULL;
    EC_POINT *Q_ID2 = NULL;

    BIGNUM *s = NULL;
    BIGNUM *h = NULL;

    BIGNUM *c_ID1 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *c1c2 = NULL;

    EC_POINT *PK_eff = NULL;
    EC_POINT *term1 = NULL;
    EC_POINT *term2 = NULL;

    EC_POINT *Rprime = NULL;
    EC_POINT *hpke = NULL;

    BIGNUM *h_check = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf1 = NULL;
    unsigned char *buf2 = NULL;
    unsigned char *Rprime_bytes = NULL;
    unsigned char *hbuf = NULL;

    size_t id1_len = 0;
    size_t id2_len = 0;
    size_t m_len = 0;

    const char *id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;
    const char *mpk_path = NULL;
    const char *qid1_path = NULL;
    const char *qid2_path = NULL;
    const char *sig_s_path = NULL;
    const char *sig_h_path = NULL;

    if (argc != 9)
    {
        return EXIT_FAILURE;
    }

    id1_path   = argv[1];
    id2_path   = argv[2];
    msg_path   = argv[3];
    mpk_path   = argv[4];
    qid1_path  = argv[5];
    qid2_path  = argv[6];
    sig_s_path = argv[7];
    sig_h_path = argv[8];

    /* ------------------------------------------------------------ */
    /* Step 0: Initialize elliptic curve parameters                  */
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
        fprintf(stderr, "verify: init error\n");
        return EXIT_FAILURE;
    }

    // retrieve the generator point P from the curve group
    P = EC_GROUP_get0_generator(group);
    if (!P)
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 1: Read public parameters and signature                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read mpk from mpk.txt using read_point_hex()
     *   - Read Q_ID1 and Q_ID2 using read_point_hex()
     *   - Read signature scalars s and h using read_bn_hex()
     */
    /* ------------------------------------------------------------ */

    // read the master public key from mpk.txt
    if (!read_point_hex(mpk_path, group, &mpk))
        return EXIT_FAILURE;

    // read the level-1 and level-2 public delegation points
    if (!read_point_hex(qid1_path, group, &Q_ID1))
        return EXIT_FAILURE;
    if (!read_point_hex(qid2_path, group, &Q_ID2))
        return EXIT_FAILURE;

    // read the signature scalars s and h
    if (!read_bn_hex(sig_s_path, &s))
        return EXIT_FAILURE;
    if (!read_bn_hex(sig_h_path, &h))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 2: Read identities and message                            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read ID_1 from ID1.txt and compute id1_len
     *   - Read ID_2 from ID2.txt and compute id2_len
     *   - Read MESSAGE from message.txt and compute m_len
     */
    /* ------------------------------------------------------------ */

    //read the identity ID_ m file and strip newlines
    {
        FILE *f = fopen(id1_path, "r");
        if (!f)
            return EXIT_FAILURE;
        if (!fgets(ID_1, sizeof(ID_1), f))
        {
            fclose(f);
            return EXIT_FAILURE;
        }
        fclose(f);
        id1_len = strlen(ID_1);
        while (id1_len > 0 && (ID_1[id1_len - 1] == '\n' || ID_1[id1_len - 1] == '\r'))
            ID_1[--id1_len] = '\0';
    }

    // read identity ID_2 from file and strip newlines
    {
        FILE *f = fopen(id2_path, "r");
        if (!f)
            return EXIT_FAILURE;
        if (!fgets(ID_2, sizeof(ID_2), f))
        {
            fclose(f);
            return EXIT_FAILURE;
        }
        fclose(f);
        id2_len = strlen(ID_2);
        while (id2_len > 0 && (ID_2[id2_len - 1] == '\n' || ID_2[id2_len - 1] == '\r'))
            ID_2[--id2_len] = '\0';
    }

    //read the message from file and strip newlines
    {
        FILE *f = fopen(msg_path, "r");
        if (!f)
            return EXIT_FAILURE;
        if (!fgets(MESSAGE, sizeof(MESSAGE), f))
        {
            fclose(f);
            return EXIT_FAILURE;
        }
        fclose(f);
        m_len = strlen(MESSAGE);
        while (m_len > 0 && (MESSAGE[m_len - 1] == '\n' || MESSAGE[m_len - 1] == '\r'))
            MESSAGE[--m_len] = '\0';
    }

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context                                  */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     */
    /* ------------------------------------------------------------ */

    // allocate the BN context for big number operations
    ctx = BN_CTX_new();
    if (!ctx)
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 4: Compute c_ID1 = H1(ID_1 || Q_ID1)                      */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 using point_to_bytes()
     *   - Concatenate ID_1 || Q_ID1
     *   - Hash using H1_to_scalar() to obtain c_ID1
     */
    /* ------------------------------------------------------------ */


    {
        size_t qid1_len = 0;
        if (!point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len))
            return EXIT_FAILURE;

        // concatenate ID_1 || Q_ID1 into buffer
        size_t buf_len = id1_len + qid1_len;
        buf1 = (unsigned char *)malloc(buf_len);
        if (!buf1)
            return EXIT_FAILURE;
        memcpy(buf1, ID_1, id1_len);
        memcpy(buf1 + id1_len, qid1_bytes, qid1_len);

        // hash to scalar c_ID1
        if (!H1_to_scalar(buf1, buf_len, q, &c_ID1))
            return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2
     *   - Hash using H1_to_scalar() to obtain c_ID2
     */
    /* ------------------------------------------------------------ */

    // serialize Q_ID2 and hash ID_2 || Q_ID1 || Q_ID2 to produce c_ID2
    {
        size_t qid1_len = 0, qid2_len = 0;

        // reuse qid1_bytes from step 4 — need to get its length again
        if (!point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len))
            return EXIT_FAILURE;
        if (!point_to_bytes(group, Q_ID2, &qid2_bytes, &qid2_len))
            return EXIT_FAILURE;

        // concatenate ID_2 || Q_ID1 || Q_ID2 into buffer
        size_t buf_len = id2_len + qid1_len + qid2_len;
        buf2 = (unsigned char *)malloc(buf_len);
        if (!buf2)
            return EXIT_FAILURE;
        memcpy(buf2, ID_2, id2_len);
        memcpy(buf2 + id2_len, qid1_bytes, qid1_len);
        memcpy(buf2 + id2_len + qid1_len, qid2_bytes, qid2_len);

        // hash to scalar c_ID2
        if (!H1_to_scalar(buf2, buf_len, q, &c_ID2))
            return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 6: Reconstruct effective public key PK_eff                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute c1c2 = c_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute term1 = (c1c2) * mpk using EC_POINT_mul()
     *   - Compute term2 = c_ID2 * Q_ID1 using EC_POINT_mul()
     *   - Compute PK_eff = term1 + term2 + Q_ID2 using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */

    // compute the product c1c2 = c_ID1 * c_ID2 mod q
    c1c2 = BN_new();
    if (!c1c2)
        return EXIT_FAILURE;
    if (!BN_mod_mul(c1c2, c_ID1, c_ID2, q, ctx))
        return EXIT_FAILURE;

    // compute term1 = c1c2 * mpk
    term1 = EC_POINT_new(group);
    if (!term1)
        return EXIT_FAILURE;
    if (!EC_POINT_mul(group, term1, NULL, mpk, c1c2, ctx))
        return EXIT_FAILURE;

    // compute term2 = c_ID2 * Q_ID1
    term2 = EC_POINT_new(group);
    if (!term2)
        return EXIT_FAILURE;
    if (!EC_POINT_mul(group, term2, NULL, Q_ID1, c_ID2, ctx))
        return EXIT_FAILURE;

    // compute PK_eff = term1 + term2 + Q_ID2
    PK_eff = EC_POINT_new(group);
    if (!PK_eff)
        return EXIT_FAILURE;
    if (!EC_POINT_add(group, PK_eff, term1, term2, ctx))
        return EXIT_FAILURE;
    if (!EC_POINT_add(group, PK_eff, PK_eff, Q_ID2, ctx))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 7: Compute R' = s * P − h * PK_eff                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Compute hpke = h * PK_eff using EC_POINT_mul()
     *   - Invert hpke using EC_POINT_invert()
     *   - Compute s * P using EC_POINT_mul()
     *   - Add points to obtain R' using EC_POINT_add()
     */
    /* ------------------------------------------------------------ */

    // compute hpke = h * PK_eff, then invert to get -h * PK_eff
    hpke = EC_POINT_new(group);
    if (!hpke)
        return EXIT_FAILURE;
    if (!EC_POINT_mul(group, hpke, NULL, PK_eff, h, ctx))
        return EXIT_FAILURE;
    if (!EC_POINT_invert(group, hpke, ctx))
        return EXIT_FAILURE;

    // ompute R' = s * P + (-h * PK_eff)
    Rprime = EC_POINT_new(group);
    if (!Rprime)
        return EXIT_FAILURE;

    //first compute s * P into Rprime
    if (!EC_POINT_mul(group, Rprime, NULL, P, s, ctx))
        return EXIT_FAILURE;

    //then add the inverted hpke to get R' = s*P - h*PK_eff
    if (!EC_POINT_add(group, Rprime, Rprime, hpke, ctx))
        return EXIT_FAILURE;

    /* ------------------------------------------------------------ */
    /* Step 8: Verify hash consistency                                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R' using point_to_bytes()
     *   - Concatenate MESSAGE || R'
     *   - Hash using H2_to_scalar() to obtain h_check
     *   - Compare h_check and h using BN_cmp()
     *   - Write h_check to verification.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */

    {
        size_t Rprime_len = 0;
        if (!point_to_bytes(group, Rprime, &Rprime_bytes, &Rprime_len))
            return EXIT_FAILURE;

        // concatenate MESSAGE || R' into buffer for hashing
        size_t hbuf_len = m_len + Rprime_len;
        hbuf = (unsigned char *)malloc(hbuf_len);
        if (!hbuf)
            return EXIT_FAILURE;
        memcpy(hbuf, MESSAGE, m_len);
        memcpy(hbuf + m_len, Rprime_bytes, Rprime_len);

        // hash to get the recomputed challenge scalar h_check
        if (!H2_to_scalar(hbuf, hbuf_len, q, &h_check))
            return EXIT_FAILURE;

        // write h_check to verification.txt for debugging
        if (!write_bn_hex("verification.txt", h_check))
        {
            fprintf(stderr, "verify: cannot write verification.txt\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------ */
    /* Step 9: Output verification result                             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Print VALID if h == h_check
     *   - Print INVALID otherwise
     */
    /* ------------------------------------------------------------ */

    // compare the recomputed hash with the original signature hash
    if (BN_cmp(h_check, h) == 0)
    {
        printf("[verifier] Signature is VALID.\n");
    }
    else
    {
        printf("[verifier] Signature is INVALID.\n");
    }

    printf("[verifier] Verification completed.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Ensure no memory leaks
     */
    /* ------------------------------------------------------------ */

    // free all allocated objects to avoid memory leaks
    if (h_check) BN_free(h_check);
    if (hbuf) free(hbuf);
    if (Rprime_bytes) free(Rprime_bytes);
    if (Rprime) EC_POINT_free(Rprime);
    if (hpke) EC_POINT_free(hpke);
    if (PK_eff) EC_POINT_free(PK_eff);
    if (term2) EC_POINT_free(term2);
    if (term1) EC_POINT_free(term1);
    if (c1c2) BN_free(c1c2);
    if (c_ID2) BN_free(c_ID2);
    if (c_ID1) BN_free(c_ID1);
    if (buf2) free(buf2);
    if (buf1) free(buf1);
    if (qid2_bytes) free(qid2_bytes);
    if (qid1_bytes) free(qid1_bytes);
    if (h) BN_free(h);
    if (s) BN_free(s);
    if (Q_ID2) EC_POINT_free(Q_ID2);
    if (Q_ID1) EC_POINT_free(Q_ID1);
    if (mpk) EC_POINT_free(mpk);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (q) BN_free(q);

    return EXIT_SUCCESS;
}
