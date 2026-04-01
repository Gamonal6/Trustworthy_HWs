/*
 * signer2.c — Level 2 Signer (ID_2) for Schnorr-HIBS
 *
 * ASSIGNMENT TEMPLATE
 *
 * ROLE:
 *   Implements:
 *     (1) HIBS.Extract for hierarchy level k = 2
 *     (2) Schnorr signature generation
 *
 * INPUT FILES:
 *   - sk_ID1.txt          : level-1 private key (hex scalar)
 *   - signer2_b2.txt     : random delegation scalar b2 (hex)
 *   - signer2_r.txt      : signing randomness r (hex)
 *   - Q_ID1.txt          : level-1 public delegation point (hex EC point)
 *   - ID2.txt             : identity string for ID_2
 *   - message.txt         : message to be signed
 *
 * OUTPUT FILES:
 *   - Q_ID2.txt            : level-2 public delegation point
 *   - sig_s.txt            : Schnorr signature scalar s
 *   - sig_h.txt            : Schnorr signature hash h
 *
 * REQUIRED RELATIONS:
 *   Delegation:
 *     c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)
 *     sk_ID2 = sk_ID1 * c_ID2 + b2 mod q
 *
 *   Signing:
 *     R = r * P
 *     h = H2(message || R)
 *     s = r + h * sk_ID2 mod q
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

static char ID_2[1024];
static char MESSAGE[4096];

int main(int argc, char **argv)
{
    EC_GROUP *group = NULL;
    BIGNUM *q = NULL;
    const EC_POINT *P = NULL;

    BIGNUM *sk_ID1 = NULL;
    EC_POINT *Q_ID1 = NULL;

    BIGNUM *b2 = NULL;
    EC_POINT *Q_ID2 = NULL;
    BIGNUM *c_ID2 = NULL;
    BIGNUM *sk_ID2 = NULL;

    BIGNUM *r = NULL;
    EC_POINT *R = NULL;
    BIGNUM *h = NULL;
    BIGNUM *s = NULL;

    BN_CTX *ctx = NULL;

    unsigned char *qid1_bytes = NULL;
    unsigned char *qid2_bytes = NULL;
    unsigned char *buf = NULL;
    unsigned char *R_bytes = NULL;
    unsigned char *hbuf = NULL;

    BIGNUM *tmp = NULL;
    BIGNUM *tmp2 = NULL;

    size_t id_len = 0;
    size_t m_len = 0;

    const char *sk_id1_path = NULL;
    const char *b2_path = NULL;
    const char *r_path = NULL;
    const char *q_id1_path = NULL;
    const char *id2_path = NULL;
    const char *msg_path = NULL;

    if (argc != 7)
    {
        fprintf(stderr,
            "Usage: %s <sk_ID1.txt> <signer2_b2.txt> <signer2_r.txt> "
            "<Q_ID1.txt> <ID2.txt> <message.txt>\n", argv[0]);
        return EXIT_FAILURE;
    }

    sk_id1_path = argv[1];
    b2_path     = argv[2];
    r_path      = argv[3];
    q_id1_path  = argv[4];
    id2_path    = argv[5];
    msg_path    = argv[6];

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
        fprintf(stderr, "Error: failed to initialize EC group.\n");
        return EXIT_FAILURE;
    }

    // retrieve the generator point P from the curve group
    P = EC_GROUP_get0_generator(group);
    if (!P)
    {
        fprintf(stderr, "Error: failed to get generator P.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 1: Read level-1 secret key and public delegation point   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read sk_ID1 from sk_ID1.txt using read_bn_hex()
     *   - Read Q_ID1 from Q_ID1.txt using read_point_hex()
     */
    /* ------------------------------------------------------------ */

    // read the level-1 private key scalar from sk_ID1.txt
    if (!read_bn_hex(sk_id1_path, &sk_ID1))
    {
        fprintf(stderr, "Error: failed to read sk_ID1 from %s.\n", sk_id1_path);
        return EXIT_FAILURE;
    }

    // read the level-1 public delegation point from Q_ID1.txt
    if (!read_point_hex(q_id1_path, group, &Q_ID1))
    {
        fprintf(stderr, "Error: failed to read Q_ID1 from %s.\n", q_id1_path);
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 2: Read identity ID_2 and message                        */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Open ID2.txt and read identity string into ID_2
     *   - Strip newline characters and compute id_len
     *
     *   - Open message.txt and read message into MESSAGE
     *   - Strip newline characters and compute m_len
     */
    /* ------------------------------------------------------------ */

    // read the identity string ID_2 from ID2.txt and strip newlines
    {
        FILE *f = fopen(id2_path, "r");
        if (!f)
        {
            fprintf(stderr, "Error: cannot open %s.\n", id2_path);
            return EXIT_FAILURE;
        }
        if (!fgets(ID_2, sizeof(ID_2), f))
        {
            fclose(f);
            fprintf(stderr, "Error: failed to read identity from %s.\n", id2_path);
            return EXIT_FAILURE;
        }
        fclose(f);
        id_len = strlen(ID_2);
        while (id_len > 0 && (ID_2[id_len - 1] == '\n' || ID_2[id_len - 1] == '\r'))
            ID_2[--id_len] = '\0';
    }

    // read the message from message.txt and strip newlines
    {
        FILE *f = fopen(msg_path, "r");
        if (!f)
        {
            fprintf(stderr, "Error: cannot open %s.\n", msg_path);
            return EXIT_FAILURE;
        }
        if (!fgets(MESSAGE, sizeof(MESSAGE), f))
        {
            fclose(f);
            fprintf(stderr, "Error: failed to read message from %s.\n", msg_path);
            return EXIT_FAILURE;
        }
        fclose(f);
        m_len = strlen(MESSAGE);
        while (m_len > 0 && (MESSAGE[m_len - 1] == '\n' || MESSAGE[m_len - 1] == '\r'))
            MESSAGE[--m_len] = '\0';
    }

    /* ------------------------------------------------------------ */
    /* Step 3: Initialize BN context and allocate scalars            */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Create BN_CTX using BN_CTX_new()
     *   - Allocate b2, sk_ID2, r, and s using BN_new()
     */
    /* ------------------------------------------------------------ */

    // allocate BN context and scalars for delegation and signing
    ctx = BN_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Error: BN_CTX_new failed.\n");
        return EXIT_FAILURE;
    }
    sk_ID2 = BN_new();
    s = BN_new();
    if (!sk_ID2 || !s)
    {
        fprintf(stderr, "Error: BN_new failed.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 4: Delegation — read b2 and compute Q_ID2                */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read b2 from signer2_b2.txt using read_bn_hex()
     *   - Allocate Q_ID2 using EC_POINT_new(group)
     *   - Compute Q_ID2 = b2 * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */

    // read the random delegation scalar b2 from signer2_b2.txt
    if (!read_bn_hex(b2_path, &b2))
    {
        fprintf(stderr, "Error: failed to read b2 from %s.\n", b2_path);
        return EXIT_FAILURE;
    }

    // compute the level-2 public delegation point Q_ID2 = b2 * P
    Q_ID2 = EC_POINT_new(group);
    if (!Q_ID2)
    {
        fprintf(stderr, "Error: EC_POINT_new failed.\n");
        return EXIT_FAILURE;
    }
    if (!EC_POINT_mul(group, Q_ID2, NULL, P, b2, ctx))
    {
        fprintf(stderr, "Error: EC_POINT_mul failed for Q_ID2.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 5: Compute c_ID2 = H1(ID_2 || Q_ID1 || Q_ID2)             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize Q_ID1 and Q_ID2 using point_to_bytes()
     *   - Concatenate ID_2 || Q_ID1 || Q_ID2 into buffer
     *   - Hash buffer to scalar c_ID2 using H1_to_scalar()
     */
    /* ------------------------------------------------------------ */

    // serialize Q_ID1 and Q_ID2 to bytes, then hash ID_2 || Q_ID1 || Q_ID2
    {
        size_t qid1_len = 0, qid2_len = 0;
        if (!point_to_bytes(group, Q_ID1, &qid1_bytes, &qid1_len))
        {
            fprintf(stderr, "Error: point_to_bytes failed for Q_ID1.\n");
            return EXIT_FAILURE;
        }
        if (!point_to_bytes(group, Q_ID2, &qid2_bytes, &qid2_len))
        {
            fprintf(stderr, "Error: point_to_bytes failed for Q_ID2.\n");
            return EXIT_FAILURE;
        }

        // concatenate ID_2 || Q_ID1 || Q_ID2 into a single buffer
        size_t buf_len = id_len + qid1_len + qid2_len;
        buf = (unsigned char *)malloc(buf_len);
        if (!buf)
        {
            fprintf(stderr, "Error: malloc failed.\n");
            return EXIT_FAILURE;
        }
        memcpy(buf, ID_2, id_len);
        memcpy(buf + id_len, qid1_bytes, qid1_len);
        memcpy(buf + id_len + qid1_len, qid2_bytes, qid2_len);

        // hash the concatenated buffer to produce the scalar c_ID2
        if (!H1_to_scalar(buf, buf_len, q, &c_ID2))
        {
            fprintf(stderr, "Error: H1_to_scalar failed.\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------ */
    /* Step 6: Compute sk_ID2 = sk_ID1 * c_ID2 + b2 mod q             */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp
     *   - Compute tmp = sk_ID1 * c_ID2 mod q using BN_mod_mul()
     *   - Compute sk_ID2 = tmp + b2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    // compute the level-2 private key: sk_ID2 = sk_ID1 * c_ID2 + b2 mod q
    tmp = BN_new();
    if (!tmp)
    {
        fprintf(stderr, "Error: BN_new failed for tmp.\n");
        return EXIT_FAILURE;
    }
    if (!BN_mod_mul(tmp, sk_ID1, c_ID2, q, ctx))
    {
        fprintf(stderr, "Error: BN_mod_mul failed.\n");
        return EXIT_FAILURE;
    }
    if (!BN_mod_add(sk_ID2, tmp, b2, q, ctx))
    {
        fprintf(stderr, "Error: BN_mod_add failed.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 7: Signing — read r and compute R                         */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Read r from signer2_r.txt using read_bn_hex()
     *   - Allocate EC_POINT R
     *   - Compute R = r * P using EC_POINT_mul()
     */
    /* ------------------------------------------------------------ */

    // read the signing nonce r from signer2_r.txt
    if (!read_bn_hex(r_path, &r))
    {
        fprintf(stderr, "Error: failed to read r from %s.\n", r_path);
        return EXIT_FAILURE;
    }

    // compute the commitment point R = r * P
    R = EC_POINT_new(group);
    if (!R)
    {
        fprintf(stderr, "Error: EC_POINT_new failed for R.\n");
        return EXIT_FAILURE;
    }
    if (!EC_POINT_mul(group, R, NULL, P, r, ctx))
    {
        fprintf(stderr, "Error: EC_POINT_mul failed for R.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 8: Compute h = H2(message || R)                           */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Serialize R using point_to_bytes()
     *   - Concatenate MESSAGE || R into buffer
     *   - Hash buffer to scalar h using H2_to_scalar()
     */
    /* ------------------------------------------------------------ */

    // serialize R and hash MESSAGE || R to produce the challenge scalar h
    {
        size_t R_len = 0;
        if (!point_to_bytes(group, R, &R_bytes, &R_len))
        {
            fprintf(stderr, "Error: point_to_bytes failed for R.\n");
            return EXIT_FAILURE;
        }

        // concatenate MESSAGE || R into a buffer for hashing
        size_t hbuf_len = m_len + R_len;
        hbuf = (unsigned char *)malloc(hbuf_len);
        if (!hbuf)
        {
            fprintf(stderr, "Error: malloc failed.\n");
            return EXIT_FAILURE;
        }
        memcpy(hbuf, MESSAGE, m_len);
        memcpy(hbuf + m_len, R_bytes, R_len);

        // hash to get the Schnorr challenge scalar h
        if (!H2_to_scalar(hbuf, hbuf_len, q, &h))
        {
            fprintf(stderr, "Error: H2_to_scalar failed.\n");
            return EXIT_FAILURE;
        }
    }

    /* ------------------------------------------------------------ */
    /* Step 9: Compute s = r + h * sk_ID2 mod q                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Allocate temporary BIGNUM tmp2
     *   - Compute tmp2 = h * sk_ID2 mod q using BN_mod_mul()
     *   - Compute s = r + tmp2 mod q using BN_mod_add()
     */
    /* ------------------------------------------------------------ */

    // compute the Schnorr signature scalar: s = r + h * sk_ID2 mod q
    tmp2 = BN_new();
    if (!tmp2)
    {
        fprintf(stderr, "Error: BN_new failed for tmp2.\n");
        return EXIT_FAILURE;
    }
    if (!BN_mod_mul(tmp2, h, sk_ID2, q, ctx))
    {
        fprintf(stderr, "Error: BN_mod_mul failed.\n");
        return EXIT_FAILURE;
    }
    if (!BN_mod_add(s, r, tmp2, q, ctx))
    {
        fprintf(stderr, "Error: BN_mod_add failed.\n");
        return EXIT_FAILURE;
    }

    /* ------------------------------------------------------------ */
    /* Step 10: Write output files                                   */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Write Q_ID2 to Q_ID2.txt using write_point_hex()
     *   - Write s to sig_s.txt using write_bn_hex()
     *   - Write h to sig_h.txt using write_bn_hex()
     */
    /* ------------------------------------------------------------ */

    // write the level-2 public delegation point to Q_ID2.txt
    if (!write_point_hex("Q_ID2.txt", group, Q_ID2))
    {
        fprintf(stderr, "Error: failed to write Q_ID2.txt.\n");
        return EXIT_FAILURE;
    }

    // write the Schnorr signature scalar s to sig_s.txt
    if (!write_bn_hex("sig_s.txt", s))
    {
        fprintf(stderr, "Error: failed to write sig_s.txt.\n");
        return EXIT_FAILURE;
    }

    // write the Schnorr signature hash h to sig_h.txt
    if (!write_bn_hex("sig_h.txt", h))
    {
        fprintf(stderr, "Error: failed to write sig_h.txt.\n");
        return EXIT_FAILURE;
    }

    printf("[signer2] Delegation and signing complete.\n");

    /* ------------------------------------------------------------ */
    /* Cleanup                                                       */
    /* ------------------------------------------------------------ */
    /*
     * TODO:
     *   - Free all allocated BIGNUMs, EC_POINTs, buffers, and contexts
     *   - Follow correct order and avoid memory leaks
     */
    /* ------------------------------------------------------------ */

    // free all allocated objects to avoid memory leaks
    if (tmp) BN_free(tmp);
    if (tmp2) BN_free(tmp2);
    if (c_ID2) BN_free(c_ID2);
    if (h) BN_free(h);
    if (s) BN_free(s);
    if (sk_ID2) BN_free(sk_ID2);
    if (r) BN_free(r);
    if (b2) BN_free(b2);
    if (sk_ID1) BN_free(sk_ID1);
    if (hbuf) free(hbuf);
    if (R_bytes) free(R_bytes);
    if (buf) free(buf);
    if (qid2_bytes) free(qid2_bytes);
    if (qid1_bytes) free(qid1_bytes);
    if (R) EC_POINT_free(R);
    if (Q_ID2) EC_POINT_free(Q_ID2);
    if (Q_ID1) EC_POINT_free(Q_ID1);
    if (ctx) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (q) BN_free(q);

    return EXIT_SUCCESS;
}
