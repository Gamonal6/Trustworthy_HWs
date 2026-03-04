#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Client (File-Based Demo) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files or change their formats.
 *  - The grading scripts rely strictly on these filenames.
 *
 * This program implements the CLIENT SIDE of a simplified
 * Kerberos protocol using files for message passing.
 *
 * The client program is executed multiple times by an
 * external script and must correctly handle different
 * protocol phases depending on which files already exist.
 *
 * ------------------------------------------------------------
 * PROTOCOL PHASES IMPLEMENTED BY THIS CLIENT:
 *
 * 1) AS phase   (Authentication Server)
 * 2) TGS_REQ    (Ticket Granting Service Request)
 * 3) APP_REQ    (Application Server Request)
 *
 * Cryptographic primitives used conceptually:
 *  - ECDSA signatures
 *  - ECDH key agreement
 *  - SHA-256 key derivation
 *  - AES-256 encryption/decryption
 *
 * You are provided helper functions in:
 *      RequiredFunctions.c
 * Study them carefully before implementing this file.
 *
 * ============================================================
 */

#include "RequiredFunctions.c"

int main(int argc, char *argv[]) {

	/* ------------------------------------------------------------
	 * Command-line arguments:
	 *
	 * argv[1] : path to Client temporary private key file
	 * argv[2] : path to Client temporary public key file
	 * argv[3] : path to AS temporary public key file
	 *
	 * These files MUST already exist. Do NOT generate keys here.
	 * ------------------------------------------------------------
	 */
	if (argc != 4) {
		fprintf(stderr,
		        "Usage: %s <Client_temp_SK> <Client_temp_PK> <AS_temp_PK>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *client_temp_sk_path = argv[1];
	const char *client_temp_pk_path = argv[2];
	const char *as_temp_pk_path     = argv[3];

	/* Buffers for symmetric keys derived during Kerberos */
	unsigned char key_client_as[32];
	unsigned char key_client_tgs[32];
	unsigned char key_client_app[32];

	/* ------------------------------------------------------------
	 * STEP 0: Verify required client temporary key files exist
	 *
	 * The client must already possess a temporary EC key pair.
	 * If either file is missing, abort immediately.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of:
	 *        client_temp_sk_path
	 *        client_temp_pk_path
	 *  - Print an error and exit on failure
	 */
	if (!file_exists(client_temp_sk_path))
	{
		fprintf(stderr, "Missing client temp private key: %s\n", client_temp_sk_path);
		return EXIT_FAILURE;
	}
	if (!file_exists(client_temp_pk_path))
	{
		fprintf(stderr, "Missing client temp public key: %s\n", client_temp_pk_path);
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 1: Sign Client temporary public key
	 *
	 * The client authenticates itself to the AS by signing its
	 * temporary public key using its long-term private key.
	 *
	 * INPUT:
	 *  - Client_SK.txt          (long-term client private key)
	 *  - client_temp_pk_path    (temporary public key)
	 *
	 * OUTPUT (must always be regenerated):
	 *  - Client_Signature.txt   (hex-encoded ECDSA signature)
	 *
	 * NOTE:
	 *  - Even if the file already exists, regenerate it.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Use an ECDSA signing helper
	 *  - Sign the CONTENTS of client_temp_pk_path
	 *  - Write the signature in hex format to:
	 *        "Client_Signature.txt"
	 */
	if (!ecdsa_sign_file_to_hex("Client_SK.txt", client_temp_pk_path, "Client_Signature.txt"))
	{
		fprintf(stderr, "Failed to generate client signature\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 2: Wait for AS response
	 *
	 * The Authentication Server writes AS_REP.txt when ready.
	 * If it does not yet exist, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check if "AS_REP.txt" exists
	 *  - If not, print a status message and exit SUCCESSFULLY
	 */
	if (!file_exists("AS_REP.txt"))
	{
		printf("AS has not responded yet\n");
		return EXIT_SUCCESS;
	}

	/* ------------------------------------------------------------
	 * STEP 3: Derive Key_Client_AS
	 *
	 * The client derives a shared secret with the AS using ECDH:
	 *
	 *      shared = ECDH(Client_temp_SK, AS_temp_PK)
	 *
	 * Then derives a symmetric key:
	 *
	 *      Key_Client_AS = SHA256(shared)
	 *
	 * This key MUST match the reference key stored in:
	 *      "Key_Client_AS.txt"
	 *
	 * Abort if the derived key does not match.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Perform ECDH using the two key files
	 *  - Hash the shared secret using SHA-256
	 *  - Read "Key_Client_AS.txt" (hex)
	 *  - Compare values byte-for-byte
	 */
	
	unsigned char *shared_secret = NULL;
	size_t shared_secret_len = 0;
	if (!ecdh_shared_secret_files(client_temp_sk_path, as_temp_pk_path, &shared_secret, &shared_secret_len))
	{
		fprintf(stderr, "ECDH failed\n");
		return EXIT_FAILURE;
	}
	if (!sha256_bytes(shared_secret, shared_secret_len, key_client_as))
	{
		free(shared_secret);
		fprintf(stderr, "SHA-256 failed\n");
		return EXIT_FAILURE;
	}
	free(shared_secret);

	unsigned char *key_client_as_ref = NULL;
	size_t key_client_as_ref_len = 0;
	if (!read_hex_file_bytes("Key_Client_AS.txt", &key_client_as_ref, &key_client_as_ref_len))
	{
		fprintf(stderr, "Failed to read Key_Client_AS.txt\n");
		return EXIT_FAILURE;
	}
	//compare derived key with reference
	if (key_client_as_ref_len != sizeof(key_client_as) ||
	    memcmp(key_client_as, key_client_as_ref, sizeof(key_client_as)) != 0)
	{
		free(key_client_as_ref);
		fprintf(stderr, "Key_Client_AS mismatch\n");
		return EXIT_FAILURE;
	}
	free(key_client_as_ref);

	/* ------------------------------------------------------------
	 * STEP 4: Decrypt AS_REP
	 *
	 * AS_REP.txt is AES-256 encrypted using Key_Client_AS.
	 *
	 * After decryption, the plaintext contains:
	 *
	 *   [ 32 bytes Key_Client_TGS ] ||
	 *   [ ASCII hex string of TGT ]
	 *
	 * Extract BOTH values.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-decrypt AS_REP.txt using Key_Client_AS
	 *  - Copy first 32 bytes → key_client_tgs
	 *  - Remaining bytes → TGT (hex string)
	 */
	
	unsigned char *as_rep_plain = NULL;
	size_t as_rep_plain_len = 0;
	if (!aes256_decrypt_hex_file_to_bytes(key_client_as, "AS_REP.txt", &as_rep_plain, &as_rep_plain_len))
	{
		fprintf(stderr, "Failed to decrypt AS_REP.txt\n");
		return EXIT_FAILURE;
	}
	if (as_rep_plain_len < 32)
	{
		free(as_rep_plain);
		fprintf(stderr, "AS_REP.txt plaintext too short\n");
		return EXIT_FAILURE;
	}
	memcpy(key_client_tgs, as_rep_plain, 32);
	size_t tgt_hex_len = as_rep_plain_len - 32;
	char *tgt_hex = malloc(tgt_hex_len + 1);
	if (!tgt_hex)
	{
		free(as_rep_plain);
		return EXIT_FAILURE;
	}
	memcpy(tgt_hex, as_rep_plain + 32, tgt_hex_len);
	tgt_hex[tgt_hex_len] = '\0';
	free(as_rep_plain);

	/* ------------------------------------------------------------
	 * STEP 5: Create TGS_REQ (only once)
	 *
	 * If TGS_REQ.txt does NOT already exist:
	 *
	 *   Auth_Client_TGS = AES(Key_Client_TGS, "Client")
	 *
	 * Write TGS_REQ.txt with EXACTLY THREE lines:
	 *
	 *   line 1: TGT hex
	 *   line 2: Auth_Client_TGS hex
	 *   line 3: Service ID string (plain text): "Service"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REQ.txt"
	 *  - If missing:
	 *      - Encrypt string "Client" using Key_Client_TGS
	 *      - Write all three required lines in order
	 */
	if (!file_exists("TGS_REQ.txt"))
	{
		//create authenticator for TGS
		char *auth_client_tgs_hex = NULL;
		if (!aes256_encrypt_bytes_to_hex_string(key_client_tgs,
		                                        (const unsigned char *)"Client",
		                                        strlen("Client"),
		                                        &auth_client_tgs_hex))
		{
			free(tgt_hex);
			fprintf(stderr, "Failed to encrypt Auth_Client_TGS\n");
			return EXIT_FAILURE;
		}
		if (!write_text_lines("TGS_REQ.txt", tgt_hex, auth_client_tgs_hex, "Service"))
		{
			free(tgt_hex);
			free(auth_client_tgs_hex);
			fprintf(stderr, "Failed to write TGS_REQ.txt\n");
			return EXIT_FAILURE;
		}
		free(auth_client_tgs_hex);
	}

	/* ------------------------------------------------------------
	 * STEP 6: Wait for TGS response
	 *
	 * TGS writes "TGS_REP.txt" when ready.
	 * If missing, exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of "TGS_REP.txt"
	 *  - If not present, print status and exit SUCCESSFULLY
	 */
	if (!file_exists("TGS_REP.txt"))
	{
		free(tgt_hex);
		printf("TGS has not responded yet\n");
		return EXIT_SUCCESS;
	}

	/* ------------------------------------------------------------
	 * STEP 7: Recover Key_Client_App
	 *
	 * TGS_REP.txt format:
	 *
	 *   line 1: Ticket_App (hex)
	 *   line 2: enc_key_client_app (hex, AES under Key_Client_TGS)
	 *
	 * Decrypt line 2 using Key_Client_TGS to recover:
	 *      Key_Client_App (hex → 32 bytes)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read second line of TGS_REP.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Convert hex string to raw bytes
	 *  - Store exactly 32 bytes in key_client_app
	 */

	char *enc_key_client_app_hex = read_line("TGS_REP.txt", 2);
	if (!enc_key_client_app_hex)
	{
		free(tgt_hex);
		fprintf(stderr, "Failed to read TGS_REP.txt line 2\n");
		return EXIT_FAILURE;
	}
	unsigned char *key_client_app_hex_bytes = NULL;
	size_t key_client_app_hex_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_tgs,
	                                        enc_key_client_app_hex,
	                                        &key_client_app_hex_bytes,
	                                        &key_client_app_hex_len))
	{
		free(tgt_hex);
		free(enc_key_client_app_hex);
		fprintf(stderr, "Failed to decrypt Key_Client_App\n");
		return EXIT_FAILURE;
	}
	free(enc_key_client_app_hex);
	if (key_client_app_hex_len != 64)
	{
		free(tgt_hex);
		free(key_client_app_hex_bytes);
		fprintf(stderr, "Invalid Key_Client_App length\n");
		return EXIT_FAILURE;
	}
	char *key_client_app_hex = malloc(key_client_app_hex_len + 1);
	if (!key_client_app_hex)
	{
		free(tgt_hex);
		free(key_client_app_hex_bytes);
		return EXIT_FAILURE;
	}
	memcpy(key_client_app_hex, key_client_app_hex_bytes, key_client_app_hex_len);
	key_client_app_hex[key_client_app_hex_len] = '\0';
	free(key_client_app_hex_bytes);
	unsigned char *key_client_app_buf = NULL;
	size_t key_client_app_len = 0;
	if (!hex_to_bytes(key_client_app_hex, &key_client_app_buf, &key_client_app_len) ||
	    key_client_app_len != 32)
	{
		free(tgt_hex);
		free(key_client_app_hex);
		fprintf(stderr, "Failed to parse Key_Client_App\n");
		return EXIT_FAILURE;
	}
	memcpy(key_client_app, key_client_app_buf, 32);
	free(key_client_app_buf);
	free(key_client_app_hex);

	/* ------------------------------------------------------------
	 * STEP 8: Create APP_REQ
	 *
	 *   Auth_Client_App = AES(Key_Client_App, "Client")
	 *
	 * Write APP_REQ.txt with EXACTLY TWO lines:
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: Auth_Client_App hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Encrypt string "Client" using Key_Client_App
	 *  - Read Ticket_App from TGS_REP.txt (line 1)
	 *  - Write both values to "APP_REQ.txt"
	 */

	char *ticket_app_hex = read_line("TGS_REP.txt", 1);
	if (!ticket_app_hex)
	{
		free(tgt_hex);
		fprintf(stderr, "Failed to read TGS_REP.txt line 1\n");
		return EXIT_FAILURE;
	}
	char *auth_client_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_client_app,
	                                        (const unsigned char *)"Client",
	                                        strlen("Client"),
	                                        &auth_client_app_hex))
	{
		free(tgt_hex);
		free(ticket_app_hex);
		fprintf(stderr, "Failed to encrypt Auth_Client_App\n");
		return EXIT_FAILURE;
	}
	if (!write_text_lines("APP_REQ.txt", ticket_app_hex, auth_client_app_hex, NULL))
	{
		free(tgt_hex);
		free(ticket_app_hex);
		free(auth_client_app_hex);
		fprintf(stderr, "Failed to write APP_REQ.txt\n");
		return EXIT_FAILURE;
	}
	free(ticket_app_hex);
	free(auth_client_app_hex);
	free(tgt_hex);

	return EXIT_SUCCESS;
}