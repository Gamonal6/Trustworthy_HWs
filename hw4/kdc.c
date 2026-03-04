#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos KDC / Authentication Server — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or alter their formats.
 *  - The grading scripts depend strictly on these filenames.
 *
 * This program implements the Authentication Service (AS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and temporary keys are assumed to have
 * been generated BEFORE this program runs.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (AS PHASE):
 *
 * 1) Verify the client’s signature on its temporary public key
 * 2) Derive a shared secret using ECDH
 * 3) Derive Key_Client_AS from the shared secret
 * 4) Issue a Ticket Granting Ticket (TGT)
 * 5) Build and encrypt AS_REP.txt
 *
 * Cryptographic concepts involved:
 *  - ECDSA signature verification
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption (ECB for simplicity in this demo)
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Read and understand them before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[])
{

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : Client_Signature.txt
	 * argv[2] : Client_temp_PK.txt
	 * argv[3] : AS_temp_SK.txt
	 * argv[4] : AS_temp_PK.txt
	 *
	 * These files MUST already exist.
	 * The KDC must NOT generate any keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 5)
	{
		fprintf(stderr,
				"Usage: %s <Client_Signature> <Client_temp_PK> <AS_temp_SK> <AS_temp_PK>\n",
				argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_sig_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_sk_path = argv[3];
	const char *as_temp_pk_path = argv[4];

	/* Buffers for cryptographic material */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required input files exist
	 *
	 * The AS must ensure:
	 *  - Client signature file exists
	 *  - AS temporary key pair exists
	 *
	 * Abort immediately on missing files.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_sig_path
	 *        as_temp_sk_path
	 *        as_temp_pk_path
	 *  - Print descriptive errors and exit on failure
	 */
	if (!file_exists(client_sig_path))
	{
		fprintf(stderr, "Missing client signature: %s\n", client_sig_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path))
	{
		fprintf(stderr, "Missing client temp public key: %s\n", client_temp_pk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_sk_path))
	{
		fprintf(stderr, "Missing AS temp private key: %s\n", as_temp_sk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(as_temp_pk_path))
	{
		fprintf(stderr, "Missing AS temp public key: %s\n", as_temp_pk_path);
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 1: Verify client identity
	 *
	 * The client authenticates by signing its temporary
	 * public key using its long-term private key.
	 *
	 * Verification inputs:
	 *  - Client_PK.txt        (long-term client public key)
	 *  - Client_temp_PK.txt  (signed data)
	 *  - Client_Signature.txt
	 *
	 * Abort if verification fails.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Verify ECDSA signature
	 *  - Use Client_PK.txt as the verification key
	 *  - Treat failure as an authentication failure
	 */

	if (!ecdsa_verify_file_from_hex("Client_PK.txt", client_temp_pk_path, client_sig_path))
	{
		fprintf(stderr, "Client signature verification failed\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 2: Derive shared secret (ECDH)
	 *
	 * Compute:
	 *
	 *   shared_secret = ECDH(AS_temp_SK, Client_temp_PK)
	 *
	 * The raw shared secret MUST be written to:
	 *      "shared_secret.txt"   (hex format)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the AS temporary private key
	 *  - Use the client's temporary public key
	 *  - Write the shared secret to shared_secret.txt (hex)
	 */
	unsigned char *shared_secret = NULL;
	size_t shared_secret_len = 0;
	if (!ecdh_shared_secret_files(as_temp_sk_path, client_temp_pk_path, &shared_secret, &shared_secret_len))
	{
		fprintf(stderr, "ECDH failed\n");
		return EXIT_FAILURE;
	}
	if (!write_hex_file("shared_secret.txt", shared_secret, shared_secret_len))
	{
		free(shared_secret);
		fprintf(stderr, "Failed to write shared_secret.txt\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * Compute:
	 *
	 *   Key_Client_AS = SHA256(shared_secret)
	 *
	 * Write the derived key to:
	 *      "Key_Client_AS.txt"   (hex format, 32 bytes)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Hash the shared secret using SHA-256
	 *  - Write exactly 32 bytes to Key_Client_AS.txt
	 */
	if (!sha256_bytes(shared_secret, shared_secret_len, key_client_as))
	{
		free(shared_secret);
		fprintf(stderr, "SHA-256 failed\n");
		return EXIT_FAILURE;
	}
	free(shared_secret);
	if (!write_hex_file("Key_Client_AS.txt", key_client_as, sizeof(key_client_as)))
	{
		fprintf(stderr, "Failed to write Key_Client_AS.txt\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated session key (Client ↔ TGS)
	 *
	 * For this demo, the KDC does NOT generate a new
	 * Key_Client_TGS. Instead, it reads an existing one:
	 *
	 *      "Key_Client_TGS.txt"
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_TGS.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes in key_client_tgs
	 */
	unsigned char *key_client_tgs_buf = NULL;
	size_t key_client_tgs_len = 0;
	if (!read_hex_file_bytes("Key_Client_TGS.txt", &key_client_tgs_buf, &key_client_tgs_len))
	{
		fprintf(stderr, "Failed to read Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_client_tgs_len != sizeof(key_client_tgs))
	{
		free(key_client_tgs_buf);
		fprintf(stderr, "Invalid Key_Client_TGS length\n");
		return EXIT_FAILURE;
	}
	memcpy(key_client_tgs, key_client_tgs_buf, sizeof(key_client_tgs));
	free(key_client_tgs_buf);

	/* ------------------------------------------------------------
	 * STEP 5: Build the Ticket Granting Ticket (TGT)
	 *
	 * TGT plaintext format:
	 *
	 *      "Client" || Key_Client_TGS_hex
	 *
	 * The TGT is encrypted using the long-term key shared
	 * between the AS and TGS:
	 *
	 *      Key_AS_TGS.txt
	 *
	 * Encryption:
	 *  - AES-256-ECB (for simplicity in this assignment)
	 *
	 * Output:
	 *  - TGT hex string (stored in memory for next step)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_AS_TGS.txt (hex, 32 bytes)
	 *  - Concatenate client ID and Key_Client_TGS hex
	 *  - AES-encrypt under Key_AS_TGS
	 *  - Hex-encode the ciphertext
	 */
	unsigned char *key_as_tgs = NULL;
	size_t key_as_tgs_len = 0;
	if (!read_hex_file_bytes("Key_AS_TGS.txt", &key_as_tgs, &key_as_tgs_len))
	{
		fprintf(stderr, "Failed to read Key_AS_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_as_tgs_len != 32)
	{
		free(key_as_tgs);
		fprintf(stderr, "Invalid Key_AS_TGS length\n");
		return EXIT_FAILURE;
	}
	char *key_client_tgs_hex = bytes_to_hex(key_client_tgs, sizeof(key_client_tgs));
	if (!key_client_tgs_hex)
	{
		free(key_as_tgs);
		return EXIT_FAILURE;
	}
	size_t tgt_plain_len = strlen("Client") + strlen(key_client_tgs_hex);
	unsigned char *tgt_plain = malloc(tgt_plain_len);
	if (!tgt_plain)
	{
		free(key_as_tgs);
		free(key_client_tgs_hex);
		return EXIT_FAILURE;
	}
	memcpy(tgt_plain, "Client", strlen("Client"));
	memcpy(tgt_plain + strlen("Client"), key_client_tgs_hex, strlen(key_client_tgs_hex));
	char *tgt_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_as_tgs, tgt_plain, tgt_plain_len, &tgt_hex))
	{
		free(key_as_tgs);
		free(key_client_tgs_hex);
		free(tgt_plain);
		fprintf(stderr, "Failed to encrypt TGT\n");
		return EXIT_FAILURE;
	}
	free(key_as_tgs);
	free(key_client_tgs_hex);
	free(tgt_plain);

	/* ------------------------------------------------------------
	 * STEP 6: Build AS_REP
	 *
	 * AS_REP plaintext format:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Encrypt AS_REP using:
	 *
	 *      Key_Client_AS
	 *
	 * Output file:
	 *      "AS_REP.txt"   (hex ciphertext)
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Concatenate raw Key_Client_TGS and TGT hex string
	 *  - AES-256 encrypt using Key_Client_AS
	 *  - Hex-encode ciphertext
	 *  - Write to AS_REP.txt (single line)
	 */
	
	size_t as_rep_plain_len = sizeof(key_client_tgs) + strlen(tgt_hex);
	unsigned char *as_rep_plain = malloc(as_rep_plain_len);
	if (!as_rep_plain)
	{
		free(tgt_hex);
		return EXIT_FAILURE;
	}
	memcpy(as_rep_plain, key_client_tgs, sizeof(key_client_tgs));
	memcpy(as_rep_plain + sizeof(key_client_tgs), tgt_hex, strlen(tgt_hex));
	char *as_rep_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_client_as, as_rep_plain, as_rep_plain_len, &as_rep_hex))
	{
		free(tgt_hex);
		free(as_rep_plain);
		fprintf(stderr, "Failed to encrypt AS_REP\n");
		return EXIT_FAILURE;
	}
	free(as_rep_plain);
	if (!write_text_lines("AS_REP.txt", as_rep_hex, NULL, NULL))
	{
		free(tgt_hex);
		free(as_rep_hex);
		fprintf(stderr, "Failed to write AS_REP.txt\n");
		return EXIT_FAILURE;
	}
	free(tgt_hex);
	free(as_rep_hex);

	return EXIT_SUCCESS;
}
