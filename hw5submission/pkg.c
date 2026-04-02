/*
 * pkg.c — PKG (Level 0) for Schnorr-HIBS over ECDLP
 *
 * ============================
 * ASSIGNMENT TEMPLATE VERSION
 * ============================
 *
 * STUDENT TASK:
 *   Implement the system setup algorithm (HIBS.Setup) for a
 *   Hierarchical Identity-Based Schnorr Signature scheme.
 *
 *   This file represents the trusted Private Key Generator (PKG)
 *   at hierarchy level 0.
 *
 *   You MUST NOT change:
 *     - File names
 *     - Variable names
 *     - Function signatures
 *     - Output file names
 *
 *   You MUST replace all TODO sections with correct code using:
 *     - OpenSSL EC / BN APIs
 *     - Helper functions from RequiredFunctions.h
 *
 * OVERVIEW:
 *   The PKG initializes global system parameters and computes:
 *
 *     - Master secret key: x ∈ Z_q
 *     - Master public key: mpk = x * P
 *
 *   The master secret x must remain private and is only used later
 *   for hierarchical key derivation.
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/bn.h>

#include "RequiredFunctions.h"

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	/* === Global cryptographic parameters === */
	EC_GROUP *group = NULL;      /* Elliptic curve group */
	BIGNUM *q = NULL;            /* Group order */
	const EC_POINT *P = NULL;    /* Generator point */

	/* === PKG keys === */
	BIGNUM *msk = NULL;          /* Master secret key x */
	EC_POINT *mpk = NULL;        /* Master public key x * P */

	BN_CTX *ctx = NULL;          /* BN context */

	/* =====================================================
	 * 1. Initialize elliptic curve group
	 * =====================================================
	 *
	 * TASK:
	 *   - Initialize a named elliptic curve group
	 *   - Extract the group order q
	 *
	 * FUNCTION:
	 *   init_group(&group, &q)
	 *
	 * EXIT if initialization fails.
	 */

	// initialize the elliptic curve group and extract group order q
	if (!init_group(&group, &q))
	{
		fprintf(stderr, "[pkg] EC group init failed\n");
		goto cleanup;
	}

	/* =====================================================
	 * 2. Obtain generator P
	 * =====================================================
	 *
	 * TASK:
	 *   - Retrieve the generator point P of the group
	 *
	 * FUNCTION:
	 *   EC_GROUP_get0_generator(group)
	 *
	 * EXIT if P == NULL.
	 */

	// retrieve the generator point P from the curve group
	P = EC_GROUP_get0_generator(group);
	if (!P)
		goto cleanup;

	/* =====================================================
	 * 3. Command-line argument validation
	 * =====================================================
	 *
	 * REQUIRED invocation:
	 *
	 *   ./pkg <pkg_x.txt>
	 *
	 * ARGUMENTS:
	 *   argv[1] : pkg_x.txt
	 *            Hex-encoded master secret scalar x ∈ Z_q
	 *
	 * ACTION:
	 *   - If argc != 2, print usage and EXIT_FAILURE.
	 */

	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <pkg_x.txt>\n", argv[0]);
		goto cleanup;
	}

	/* =====================================================
	 * 4. Allocate BN context
	 * =====================================================
	 *
	 * TASK:
	 *   - Allocate a BN_CTX for big number operations
	 *
	 * FUNCTION:
	 *   BN_CTX_new()
	 *
	 * EXIT if allocation fails.
	 */

	// allocate a BN context for big number operations
	ctx = BN_CTX_new();
	if (!ctx)
		goto cleanup;

	/* =====================================================
	 * 5. Load master secret key x
	 * =====================================================
	 *
	 * FILE INPUT:
	 *   argv[1] : pkg_x.txt
	 *
	 * FORMAT:
	 *   - Hex-encoded scalar
	 *   - Must satisfy 1 ≤ x < q
	 *
	 * FUNCTION:
	 *   read_bn_hex
	 *
	 * EXIT if file does not exist or parsing fails.
	 */

	// read the master secret key x from the input file
	if (!read_bn_hex(argv[1], &msk))
		goto cleanup;

	/* =====================================================
	 * 6. Compute master public key mpk
	 * =====================================================
	 *
	 * FORMULA:
	 *   mpk = x * P
	 *
	 * FUNCTIONS:
	 *   EC_POINT_new
	 *   EC_POINT_mul
	 *
	 * NOTES:
	 *   - Scalar multiplication only
	 *   - Do NOT treat EC points as integers
	 */

	// allocate the master public key point and compute mpk = msk * P
	mpk = EC_POINT_new(group);
	if (!mpk)
		goto cleanup;
	if (!EC_POINT_mul(group, mpk, NULL, P, msk, ctx))
		goto cleanup;

	/* =====================================================
	 * 7. Write master public key to disk
	 * =====================================================
	 *
	 * OUTPUT FILE:
	 *   mpk.txt
	 *
	 * FORMAT:
	 *   - Hex-encoded EC point
	 *   - Use uncompressed representation
	 *
	 * FUNCTION:
	 *   write_point_hex
	 *
	 * EXIT if file cannot be written.
	 */

	// write the master public key to mpk.txt as hex-encoded EC point
	if (!write_point_hex("mpk.txt", group, mpk))
	{
		fprintf(stderr, "[pkg] could not write mpk.txt\n");
		goto cleanup;
	}

	printf("[PKG] Setup complete. Wrote mpk.txt.\n");
	ret = EXIT_SUCCESS;

	/* =====================================================
	 * 8. Cleanup
	 * =====================================================
	 *
	 * TASK:
	 *   Free ALL allocated objects using:
	 *     - EC_POINT_free
	 *     - BN_free
	 *     - BN_CTX_free
	 *     - EC_GROUP_free
	 */

cleanup:
	// free all allocated objects to avoid memory leaks
	if (mpk) EC_POINT_free(mpk);
	if (msk) BN_free(msk);
	if (ctx) BN_CTX_free(ctx);
	if (group) EC_GROUP_free(group);
	if (q) BN_free(q);

	return ret;
}
