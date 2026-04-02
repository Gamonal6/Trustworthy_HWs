/*
 * alice.c — Node Alice for Arazi–Qi Key Exchange (ECDLP)
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement Alice's online (ephemeral) phase and shared key computation
 *   for the Arazi–Qi identity-based authenticated Diffie–Hellman protocol.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Identity strings
 *     - Function signatures
 *
 *   You MUST replace all TODO sections with working code
 *   using the specified helper functions and OpenSSL APIs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "RequiredFunctions.h"

/* Fixed identity strings */
static const char *ID_A = "alice@example.com";
static const char *ID_B = "bob@example.com";

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Cryptographic context === */
	EC_GROUP *group = NULL;
	BIGNUM *q = NULL;
	const EC_POINT *P = NULL;
	BN_CTX *ctx = NULL;

	/* === Long-term and ephemeral objects === */
	BIGNUM *x_a = NULL;	  /* Alice private key */
	BIGNUM *p_a = NULL;	  /* Alice ephemeral scalar */
	EC_POINT *U_a = NULL; /* Alice public identity point */
	EC_POINT *U_b = NULL; /* Bob public identity point */
	EC_POINT *D = NULL;	  /* CA master public key */
	EC_POINT *E_a = NULL; /* Alice ephemeral public */
	EC_POINT *E_b = NULL; /* Bob ephemeral public */

	EC_POINT *temp1 = NULL;
	EC_POINT *temp2 = NULL;
	EC_POINT *K_ab = NULL;

	BIGNUM *h_B = NULL;
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
	 *   ./alice <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>
	 *
	 * ARGUMENTS:
	 *   argv[1] : alice_private_xa.txt
	 *   argv[2] : alice_public_Ua.txt
	 *   argv[3] : alice_ephemeral_pa.txt
	 *   argv[4] : bob_public_Ub.txt
	 *   argv[5] : ca_master_public_D.txt
	 *
	 * ACTION:
	 *   - If argc != 6, print usage and EXIT_FAILURE.
	 */

	if (argc != 6)
	{
		fprintf(stderr,
				"Usage: %s <x_a_file> <U_a_file> <p_a_file> <U_b_file> <D_file>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	/* =====================================================
	 * 2. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize EC_GROUP using a named curve
	 *   - Retrieve group order q
	 *
	 * FUNCTION:
	 *   init_group(&group, &q)
	 *
	 * EXIT on failure.
	 */

	// initialize the EC group and retrieve the group order q
	if (!init_group(&group, &q)) {
		fprintf(stderr, "alice: init error\n");
		goto cleanup;
	}

	/* =====================================================
	 * 3. Obtain generator P
	 * =====================================================
	 *
	 * FUNCTION:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// retrieve generator point P from the curve group
	P = EC_GROUP_get0_generator(group);
	if (!P)
		goto cleanup;

	/* =====================================================
	 * 4. Allocate BN_CTX
	 * =====================================================
	 *
	 * FUNCTION:
	 *   BN_CTX_new()
	 *
	 * EXIT if allocation fails.
	 */

	// allocate the big-number context for EC operations
	ctx = BN_CTX_new();
	if (!ctx)
		goto cleanup;

	/* =====================================================
	 * 5. Load Alice and system public parameters
	 * =====================================================
	 *
	 * FILE INPUTS:
	 *   argv[1] : x_a (scalar)
	 *   argv[2] : U_a (EC point)
	 *   argv[4] : U_b (EC point)
	 *   argv[5] : D   (EC point)
	 *
	 * FUNCTIONS:
	 *   read_bn_hex
	 *   EC_POINT_new
	 *   read_point_hex
	 *
	 * EXIT if any file does not exist or parsing fails.
	 */

	// read Alice's long-term private scalar x_a from file
	if (!read_bn_hex(argv[1], &x_a))
		goto cleanup;
	// read Alice's public identity point U_a from file
	if (!read_point_hex(argv[2], group, &U_a))
		goto cleanup;
	// read Bob's public identity point U_b from file
	if (!read_point_hex(argv[4], group, &U_b))
		goto cleanup;
	// read the CA master public key D from file
	if (!read_point_hex(argv[5], group, &D))
		goto cleanup;

	/* =====================================================
	 * 6. Load Alice ephemeral scalar p_a
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   argv[3] : alice_ephemeral_pa.txt
	 *
	 * FUNCTION:
	 *   read_bn_hex
	 *
	 * EXIT if missing or invalid.
	 */

	// read Alice's ephemeral scalar p_a from file
	if (!read_bn_hex(argv[3], &p_a))
		goto cleanup;

	/* =====================================================
	 * 7. Compute Alice ephemeral public E_a
	 * =====================================================
	 *
	 * FORMULA:
	 *   E_a = p_a * P
	 *
	 * FUNCTION:
	 *   EC_POINT_mul
	 *
	 * OUTPUT FILE:
	 *   alice_ephemeral_Ea.txt
	 */

	// allocate E_a and compute E_a = p_a * P
	E_a = EC_POINT_new(group);
	if (!E_a)
		goto cleanup;
	if (!EC_POINT_mul(group, E_a, NULL, P, p_a, ctx))
		goto cleanup;
	// write Alice's ephemeral public point E_a to file
	if (!write_point_hex("alice_ephemeral_Ea.txt", group, E_a))
		goto cleanup;

	/* =====================================================
	 * 8. Read Bob ephemeral public E_b (if available)
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   bob_ephemeral_Eb.txt
	 *
	 * FUNCTION:
	 *   read_point_hex
	 *
	 * BEHAVIOR:
	 *   - If file does NOT exist:
	 *       * Print informational message
	 *       * Exit successfully after writing E_a
	 */

	// attempt to read Bob's ephemeral public point E_b
	if (!read_point_hex("bob_ephemeral_Eb.txt", group, &E_b)) {
		printf("[Alice] Bob's ephemeral key not yet available. Wrote E_a.\n");
		ret = EXIT_SUCCESS;
		goto cleanup;
	}

	/* =====================================================
	 * 9. Compute h_B = H(ID_B || U_b)
	 * =====================================================
	 *
	 * STEPS:
	 *   1. Serialize U_b to bytes
	 *      Function: point_to_bytes
	 *   2. Concatenate ID_B || U_b_bytes
	 *   3. Hash and reduce mod q
	 *      Function: sha256_to_scalar
	 */

	// serialize Bob's public identity point U_b into bytes
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

	// compute h_B = H(ID_B || U_b) mod q using SHA-256
	if (!sha256_to_scalar(buf, buf_len, q, &h_B))
		goto cleanup;

	/* =====================================================
	 * 10. Compute shared key K_ab
	 * =====================================================
	 *
	 * FORMULA:
	 *
	 *   K_ab =
	 *     x_a * ( H(ID_B||U_b) * U_b + D )
	 *     + p_a * E_b
	 *
	 * FUNCTIONS:
	 *   EC_POINT_mul
	 *   EC_POINT_add
	 *
	 * STEPS:
	 *   temp1 = H * U_b
	 *   temp1 = temp1 + D
	 *   temp2 = x_a * temp1
	 *   temp1 = p_a * E_b
	 *   K_ab  = temp2 + temp1
	 */

	// allocate temporary EC points and the shared key point
	temp1 = EC_POINT_new(group);
	temp2 = EC_POINT_new(group);
	K_ab = EC_POINT_new(group);
	if (!temp1 || !temp2 || !K_ab)
		goto cleanup;

	// compute temp1 = h_B * U_b
	if (!EC_POINT_mul(group, temp1, NULL, U_b, h_B, ctx))
		goto cleanup;
	// compute temp1 = temp1 + D  (i.e., h_B * U_b + D)
	if (!EC_POINT_add(group, temp1, temp1, D, ctx))
		goto cleanup;
	// compute temp2 = x_a * temp1  (i.e., x_a * (h_B * U_b + D))
	if (!EC_POINT_mul(group, temp2, NULL, temp1, x_a, ctx))
		goto cleanup;
	// compute temp1 = p_a * E_b  (ephemeral DH component)
	if (!EC_POINT_mul(group, temp1, NULL, E_b, p_a, ctx))
		goto cleanup;
	// compute K_ab = temp2 + temp1  (final shared key point)
	if (!EC_POINT_add(group, K_ab, temp2, temp1, ctx))
		goto cleanup;

	/* =====================================================
	 * 11. Write shared key to disk
	 * =====================================================
	 *
	 * OUTPUT FILE:
	 *   alice_shared_key_Kab.txt
	 *
	 * FUNCTION:
	 *   write_point_hex
	 */

	// write the shared session key K_ab to file
	if (!write_point_hex("alice_shared_key_Kab.txt", group, K_ab)) {
		fprintf(stderr, "alice: write K_ab failed\n");
		goto cleanup;
	}

	printf("[Alice] Shared key K_ab computed and written.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 12. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated objects using:
	 *     BN_free
	 *     EC_POINT_free
	 *     EC_GROUP_free
	 *     BN_CTX_free
	 */

cleanup:
	// free all allocated resources to prevent memory leaks
	if (U_bytes) free(U_bytes);
	if (buf) free(buf);
	BN_free(x_a);
	BN_free(p_a);
	BN_free(h_B);
	BN_free(tmp);
	EC_POINT_free(U_a);
	EC_POINT_free(U_b);
	EC_POINT_free(D);
	EC_POINT_free(E_a);
	EC_POINT_free(E_b);
	EC_POINT_free(temp1);
	EC_POINT_free(temp2);
	EC_POINT_free(K_ab);
	BN_free(q);
	if (ctx) BN_CTX_free(ctx);
	if (group) EC_GROUP_free(group);

	return ret;
}
