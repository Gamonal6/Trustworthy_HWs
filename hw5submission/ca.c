/*
 * ca.c — Certificate Authority for Arazi–Qi Key Exchange (ECDLP)
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement the offline Certificate Authority (CA) phase of the
 *   Arazi–Qi identity-based key agreement protocol.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Identity strings
 *     - Overall control flow
 *
 *   You MUST replace the TODO sections with working code
 *   using the specified helper functions and OpenSSL APIs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Public identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Cryptographic objects === */
	EC_GROUP *group = NULL;      /* Elliptic curve group */
	BIGNUM *q = NULL;            /* Group order */
	const EC_POINT *P = NULL;    /* Generator */
	BN_CTX *ctx = NULL;

	BIGNUM *d = NULL;            /* CA master secret */
	EC_POINT *D = NULL;          /* CA master public key */

	BIGNUM *b_a = NULL;
	BIGNUM *b_b = NULL;
	EC_POINT *U_a = NULL;
	EC_POINT *U_b = NULL;

	BIGNUM *h_a = NULL;
	BIGNUM *h_b = NULL;
	BIGNUM *x_a = NULL;
	BIGNUM *x_b = NULL;
	BIGNUM *tmp = NULL;

	unsigned char *U_bytes = NULL;
	size_t U_len = 0;
	unsigned char *buf = NULL;
	size_t buf_len = 0;

	/* =====================================================
	 * 1. Command-line argument validation
	 * =====================================================
	 *
	 * REQUIRED invocation:
	 *
	 *   ./ca <d_file> <b_a_file> <b_b_file>
	 *
	 *   <d_file>   : hex-encoded master secret d
	 *   <b_a_file> : hex-encoded scalar b_a
	 *   <b_b_file> : hex-encoded scalar b_b
	 *
	 * ACTION:
	 *   - If argc != 4, print usage and EXIT_FAILURE.
	 */
	if (argc != 4)
	{
		fprintf(stderr, "%s <d_file> <b_a_file> <b_b_file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	/* =====================================================
	 * 2. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize an EC_GROUP using a named curve
	 *   - Obtain the group order q
	 *
	 * FUNCTION TO USE:
	 *   init_group(&group, &q)
	 *
	 * EXIT if this function returns false.
	 */

	// initialize the EC group and retrieve the group order q
	if (!init_group(&group, &q)) {
		fprintf(stderr, "[CA] setup failed\n");
		goto cleanup;
	}

	/* =====================================================
	 * 3. Obtain generator P
	 * =====================================================
	 *
	 * TASK:
	 *   - Retrieve generator P from the EC group
	 *
	 * FUNCTION TO USE:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// retrieve generator point P from the curve group
	P = EC_GROUP_get0_generator(group);
	if (!P)
		goto cleanup;

	/* =====================================================
	 * 4. Allocate context and master key objects
	 * =====================================================
	 *
	 * TASK:
	 *   - Allocate BN_CTX using BN_CTX_new()
	 *   - Allocate BIGNUM d using BN_new()
	 *   - Allocate EC_POINT D using EC_POINT_new(group)
	 *
	 * EXIT if any allocation fails.
	 */

	// allocate BN context and master public key point D
	ctx = BN_CTX_new();
	D = EC_POINT_new(group);
	if (!ctx || !D)
		goto cleanup;

	/* =====================================================
	 * 5. Load CA master secret d
	 * =====================================================
	 *
	 * INPUT FILE:
	 *   argv[1] — hex-encoded scalar
	 *
	 * FUNCTION TO USE:
	 *   read_bn_hex(argv[1], &d)
	 *
	 * EXIT if:
	 *   - File does not exist
	 *   - Parsing fails
	 */

	// read the CA master secret d from the hex-encoded input file
	if (!read_bn_hex(argv[1], &d))
		goto cleanup;

	/* =====================================================
	 * 6. Compute CA master public key D
	 * =====================================================
	 *
	 * FORMULA:
	 *   D = d * P
	 *
	 * FUNCTION TO USE:
	 *   EC_POINT_mul(group, D, NULL, P, d, ctx)
	 *
	 * EXIT on failure.
	 */

	// compute master public key D = d * P
	if (!EC_POINT_mul(group, D, NULL, P, d, ctx))
		goto cleanup;

	/* =====================================================
	 * 7. Write CA master keys to disk
	 * =====================================================
	 *
	 * OUTPUT FILES (HEX):
	 *   - ca_master_secret_d.txt  (scalar)
	 *   - ca_master_public_D.txt  (EC point)
	 *
	 * FUNCTIONS TO USE:
	 *   write_bn_hex(...)
	 *   write_point_hex(...)
	 *
	 * EXIT if any write fails.
	 */

	// write the master secret scalar d to file
	if (!write_bn_hex("ca_master_secret_d.txt", d))
		goto cleanup;
	// write the master public key point D to file
	if (!write_point_hex("ca_master_public_D.txt", group, D)) {
		fprintf(stderr, "[CA] write D failed\n");
		goto cleanup;
	}

	/* =====================================================
	 * 8. Allocate per-user objects
	 * =====================================================
	 *
	 * TASK:
	 *   Allocate the following using BN_new() / EC_POINT_new():
	 *     b_a, b_b, U_a, U_b, x_a, x_b, tmp
	 *
	 * EXIT if allocation fails.
	 */

	// allocate per-user EC points and BIGNUMs for key computation
	U_a = EC_POINT_new(group);
	U_b = EC_POINT_new(group);
	x_a = BN_new();
	x_b = BN_new();
	tmp = BN_new();
	if (!U_a || !U_b || !x_a || !x_b || !tmp)
		goto cleanup;

	/* =====================================================
	 * 9. Load per-user random scalars
	 * =====================================================
	 *
	 * INPUT FILES:
	 *   argv[2] → b_a
	 *   argv[3] → b_b
	 *
	 * FUNCTION TO USE:
	 *   read_bn_hex(file, &bn)
	 *
	 * EXIT if files do not exist or parsing fails.
	 */

	// read Alice's random scalar b_a from the hex-encoded file
	if (!read_bn_hex(argv[2], &b_a))
		goto cleanup;
	// read Bob's random scalar b_b from the hex-encoded file
	if (!read_bn_hex(argv[3], &b_b))
		goto cleanup;

	/* =====================================================
	 * 10. Alice offline key generation
	 * =====================================================
	 *
	 * STEPS:
	 *
	 * 1. Compute U_a = b_a * P
	 *    Function: EC_POINT_mul
	 *
	 * 2. Serialize U_a to bytes
	 *    Function: point_to_bytes
	 *
	 * 3. Compute h_a = H(ID_A || U_a) mod q
	 *    Function: sha256_to_scalar
	 *
	 * 4. Compute x_a = (h_a * b_a + d) mod q
	 *    Functions:
	 *      BN_mod_mul
	 *      BN_mod_add
	 *
	 * 5. Write outputs:
	 *    - alice_private_xa.txt (scalar)
	 *    - alice_public_Ua.txt  (EC point)
	 *
	 * EXIT immediately on any failure.
	 */

	// compute Alice's public identity component U_a = b_a * P
	if (!EC_POINT_mul(group, U_a, NULL, P, b_a, ctx))
		goto cleanup;

	// serialize U_a into bytes for hash concatenation
	if (!point_to_bytes(group, U_a, &U_bytes, &U_len))
		goto cleanup;

	// build the hash input buffer: ID_A || U_a_bytes
	{
		size_t id_len = strlen(ID_A);
		buf_len = id_len + U_len;
		buf = malloc(buf_len);
		if (!buf)
			goto cleanup;
		memcpy(buf, ID_A, id_len);
		memcpy(buf + id_len, U_bytes, U_len);
	}

	// compute h_a = H(ID_A || U_a) mod q using SHA-256
	if (!sha256_to_scalar(buf, buf_len, q, &h_a))
		goto cleanup;

	// compute x_a = (h_a * b_a + d) mod q
	if (!BN_mod_mul(tmp, h_a, b_a, q, ctx))
		goto cleanup;
	if (!BN_mod_add(x_a, tmp, d, q, ctx))
		goto cleanup;

	// write Alice's private key x_a to file
	if (!write_bn_hex("alice_private_xa.txt", x_a))
		goto cleanup;
	// write Alice's public identity component U_a to file
	if (!write_point_hex("alice_public_Ua.txt", group, U_a))
		goto cleanup;

	/* =====================================================
	 * 11. Bob offline key generation
	 * =====================================================
	 *
	 * IDENTICAL to Alice, except:
	 *   ID_A → ID_B
	 *   b_a  → b_b
	 *   U_a  → U_b
	 *   h_a  → h_b
	 *   x_a  → x_b
	 *
	 * OUTPUT FILES:
	 *   - bob_private_xb.txt
	 *   - bob_public_Ub.txt
	 */

	// free Alice's buffers before reusing for Bob
	free(U_bytes); U_bytes = NULL;
	free(buf); buf = NULL;

	// compute Bob's public identity component U_b = b_b * P
	if (!EC_POINT_mul(group, U_b, NULL, P, b_b, ctx))
		goto cleanup;

	// serialize U_b into bytes for hash concatenation
	if (!point_to_bytes(group, U_b, &U_bytes, &U_len))
		goto cleanup;

	// build the hash input buffer: ID_B || U_b_bytes
	{
		size_t id_len = strlen(ID_B);
		buf_len = id_len + U_len;
		buf = malloc(buf_len);
		if (!buf)
			goto cleanup;
		memcpy(buf, ID_B, id_len);
		memcpy(buf + id_len, U_bytes, U_len);
	}

	// compute h_b = H(ID_B || U_b) mod q using SHA-256
	if (!sha256_to_scalar(buf, buf_len, q, &h_b))
		goto cleanup;

	// compute x_b = (h_b * b_b + d) mod q
	if (!BN_mod_mul(tmp, h_b, b_b, q, ctx))
		goto cleanup;
	if (!BN_mod_add(x_b, tmp, d, q, ctx))
		goto cleanup;

	// write Bob's private key x_b to file
	if (!write_bn_hex("bob_private_xb.txt", x_b))
		goto cleanup;
	// write Bob's public identity component U_b to file
	if (!write_point_hex("bob_public_Ub.txt", group, U_b))
		goto cleanup;

	printf("[CA] Offline keys generated for Alice and Bob.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 12. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated memory using:
	 *     BN_free
	 *     EC_POINT_free
	 *     EC_GROUP_free
	 *     BN_CTX_free
	 *
	 * No memory leaks are allowed.
	 */

cleanup:
	// free all allocated resources to prevent memory leaks
	if (U_bytes) free(U_bytes);
	if (buf) free(buf);
	BN_free(d);
	BN_free(b_a);
	BN_free(b_b);
	BN_free(h_a);
	BN_free(h_b);
	BN_free(x_a);
	BN_free(x_b);
	BN_free(tmp);
	EC_POINT_free(D);
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);
	BN_free(q);
	if (ctx) BN_CTX_free(ctx);
	if (group) EC_GROUP_free(group);

	return ret;
}
