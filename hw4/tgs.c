#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

/*
 * ============================================================
 * Kerberos Ticket Granting Server (TGS) — ASSIGNMENT TEMPLATE
 * ============================================================
 *
 * IMPORTANT:
 *  - You MUST read from and write to files using the EXACT
 *    filenames specified in this template.
 *  - Do NOT rename files, reorder lines, or alter formats.
 *  - Automated grading scripts depend on strict filenames
 *    and exact file structure.
 *
 * This program implements the Ticket Granting Server (TGS)
 * portion of a simplified, file-based Kerberos protocol.
 *
 * All long-term keys and all session keys are assumed to
 * already exist on disk. The TGS must NOT generate keys.
 *
 * ------------------------------------------------------------
 * OVERALL FLOW (TGS PHASE):
 *
 * 1) Receive and parse TGS_REQ
 * 2) Decrypt and validate the Ticket Granting Ticket (TGT)
 * 3) Verify the client authenticator
 * 4) Issue a service ticket (Ticket_App)
 * 5) Encrypt and return Key_Client_App
 *
 * Cryptographic primitives used conceptually:
 *  - AES-256 encryption/decryption (ECB mode in this demo)
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
	 * Command-line arguments (file paths):
	 *
	 * argv[1] : TGS_REQ.txt
	 * argv[2] : Key_AS_TGS.txt
	 * argv[3] : Key_Client_TGS.txt
	 * argv[4] : Key_Client_App.txt
	 * argv[5] : Key_TGS_App.txt
	 *
	 * All files MUST already exist.
	 * The TGS must NOT generate any keys.
	 * ------------------------------------------------------------
	 */
	if (argc != 6) {
		fprintf(stderr,
		        "Usage: %s <TGS_REQ> <Key_AS_TGS> <Key_Client_TGS> <Key_Client_App> <Key_TGS_App>\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	const char *tgs_req_path        = argv[1];
	const char *key_as_tgs_path     = argv[2];
	const char *key_client_tgs_path = argv[3];
	const char *key_client_app_path = argv[4];
	const char *key_tgs_app_path    = argv[5];

	/* ------------------------------------------------------------
	 * STEP 0: Wait for TGS request
	 *
	 * If the TGS request file does not yet exist, print:
	 *
	 *      "TGS_REQ not created"
	 *
	 * and exit gracefully.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Check existence of tgs_req_path
	 *  - If missing, print required message and exit
	 */
	if (!file_exists(tgs_req_path))
	{
		printf("TGS_REQ not created\n");
		return EXIT_SUCCESS;
	}

	printf("TGS_REQ received\n");

	/* ------------------------------------------------------------
	 * STEP 1: Read and decrypt the Ticket Granting Ticket (TGT)
	 *
	 * TGS_REQ.txt format:
	 *
	 *   line 1: TGT (hex)
	 *   line 2: Auth_Client_TGS (hex)
	 *   line 3: Service ID (plain text, ignored here)
	 *
	 * The TGT is encrypted under the AS–TGS shared key:
	 *      Key_AS_TGS.txt
	 *
	 * Decrypted TGT plaintext format:
	 *
	 *      clientID || Key_Client_TGS_hex
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 1 from TGS_REQ.txt
	 *  - Read Key_AS_TGS.txt (32 bytes)
	 *  - AES-decrypt the TGT
	 *  - Treat the result as ASCII data
	 */

	char *tgt_hex = read_line(tgs_req_path, 1);
	if (!tgt_hex)
	{
		fprintf(stderr, "Failed to read TGS_REQ line 1\n");
		return EXIT_FAILURE;
	}
	unsigned char *key_as_tgs = NULL;
	size_t key_as_tgs_len = 0;
	if (!read_hex_file_bytes(key_as_tgs_path, &key_as_tgs, &key_as_tgs_len))
	{
		free(tgt_hex);
		fprintf(stderr, "Failed to read Key_AS_TGS\n");
		return EXIT_FAILURE;
	}
	if (key_as_tgs_len != 32)
	{
		free(tgt_hex);
		free(key_as_tgs);
		fprintf(stderr, "Invalid Key_AS_TGS length\n");
		return EXIT_FAILURE;
	}
	unsigned char *tgt_plain_bytes = NULL;
	size_t tgt_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_as_tgs, tgt_hex, &tgt_plain_bytes, &tgt_plain_len))
	{
		free(tgt_hex);
		free(key_as_tgs);
		fprintf(stderr, "Failed to decrypt TGT\n");
		return EXIT_FAILURE;
	}
	free(tgt_hex);
	free(key_as_tgs);
	char *tgt_plain = malloc(tgt_plain_len + 1);
	if (!tgt_plain)
	{
		free(tgt_plain_bytes);
		return EXIT_FAILURE;
	}
	memcpy(tgt_plain, tgt_plain_bytes, tgt_plain_len);
	tgt_plain[tgt_plain_len] = '\0';
	free(tgt_plain_bytes);

	/* ------------------------------------------------------------
	 * STEP 2: Parse client identity and Key_Client_TGS
	 *
	 * From decrypted TGT plaintext:
	 *  - The LAST 64 characters represent Key_Client_TGS in hex
	 *  - Everything before that is the client ID
	 *
	 * Validate:
	 *  - Key_Client_TGS is exactly 256 bits
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Split decrypted TGT plaintext
	 *  - Convert Key_Client_TGS hex → raw bytes
	 *  - Abort if parsing or conversion fails
	 */

	if (tgt_plain_len < 64)
	{
		free(tgt_plain);
		fprintf(stderr, "TGT plaintext too short\n");
		return EXIT_FAILURE;
	}
	size_t client_id_len = tgt_plain_len - 64;
	char *client_id = malloc(client_id_len + 1);
	if (!client_id)
	{
		free(tgt_plain);
		return EXIT_FAILURE;
	}
	memcpy(client_id, tgt_plain, client_id_len);
	client_id[client_id_len] = '\0';
	char *key_client_tgs_hex = tgt_plain + client_id_len;
	unsigned char *key_client_tgs = NULL;
	size_t key_client_tgs_len = 0;
	if (!hex_to_bytes(key_client_tgs_hex, &key_client_tgs, &key_client_tgs_len) ||
	    key_client_tgs_len != 32)
	{
		free(tgt_plain);
		free(client_id);
		fprintf(stderr, "Invalid Key_Client_TGS in TGT\n");
		return EXIT_FAILURE;
	}
	unsigned char *key_client_tgs_ref = NULL;
	size_t key_client_tgs_ref_len = 0;
	if (!read_hex_file_bytes(key_client_tgs_path, &key_client_tgs_ref, &key_client_tgs_ref_len))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to read Key_Client_TGS.txt\n");
		return EXIT_FAILURE;
	}
	if (key_client_tgs_ref_len != 32 ||
	    memcmp(key_client_tgs, key_client_tgs_ref, 32) != 0)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_tgs_ref);
		fprintf(stderr, "Key_Client_TGS mismatch\n");
		return EXIT_FAILURE;
	}
	free(key_client_tgs_ref);

	/* ------------------------------------------------------------
	 * STEP 3: Verify client authenticator
	 *
	 * Auth_Client_TGS is found on line 2 of TGS_REQ.txt.
	 *
	 * It is encrypted using Key_Client_TGS and should
	 * decrypt to a value identifying the client.
	 *
	 * NOTE:
	 *  - For this demo, successful decryption is sufficient.
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read line 2 from TGS_REQ.txt
	 *  - AES-decrypt using Key_Client_TGS
	 *  - Treat failure as authentication failure
	 */
	
	char *auth_client_tgs_hex = read_line(tgs_req_path, 2);
	if (!auth_client_tgs_hex)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to read TGS_REQ line 2\n");
		return EXIT_FAILURE;
	}
	unsigned char *auth_plain = NULL;
	size_t auth_plain_len = 0;
	if (!aes256_decrypt_hex_string_to_bytes(key_client_tgs,
	                                        auth_client_tgs_hex,
	                                        &auth_plain,
	                                        &auth_plain_len))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(auth_client_tgs_hex);
		fprintf(stderr, "Failed to decrypt Auth_Client_TGS\n");
		return EXIT_FAILURE;
	}
	free(auth_client_tgs_hex);
	free(auth_plain);

	/* ------------------------------------------------------------
	 * STEP 4: Load pre-generated Key_Client_App
	 *
	 * The TGS does NOT generate a new application session key.
	 * Instead, it reads an existing one from:
	 *
	 *      Key_Client_App.txt
	 *
	 * This file must contain exactly 256 bits (32 bytes).
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_Client_App.txt (hex)
	 *  - Validate length
	 *  - Store raw bytes locally
	 */

	char *key_client_app_hex = read_line(key_client_app_path, 1);
	if (!key_client_app_hex)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		fprintf(stderr, "Failed to read Key_Client_App.txt\n");
		return EXIT_FAILURE;
	}
	unsigned char *key_client_app = NULL;
	size_t key_client_app_len = 0;
	if (!hex_to_bytes(key_client_app_hex, &key_client_app, &key_client_app_len) ||
	    key_client_app_len != 32)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		fprintf(stderr, "Invalid Key_Client_App\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 5: Build and encrypt Ticket_App
	 *
	 * Ticket_App plaintext format:
	 *
	 *      clientID || Key_Client_App_hex
	 *
	 * Ticket_App is encrypted under the TGS–App shared key:
	 *
	 *      Key_TGS_App.txt
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Read Key_TGS_App.txt (32 bytes)
	 *  - Concatenate client ID and Key_Client_App hex
	 *  - AES-encrypt using Key_TGS_App
	 *  - Hex-encode ciphertext → Ticket_App
	 */

	unsigned char *key_tgs_app = NULL;
	size_t key_tgs_app_len = 0;
	if (!read_hex_file_bytes(key_tgs_app_path, &key_tgs_app, &key_tgs_app_len))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		fprintf(stderr, "Failed to read Key_TGS_App.txt\n");
		return EXIT_FAILURE;
	}
	if (key_tgs_app_len != 32)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		free(key_tgs_app);
		fprintf(stderr, "Invalid Key_TGS_App length\n");
		return EXIT_FAILURE;
	}
	size_t ticket_plain_len = strlen(client_id) + strlen(key_client_app_hex);
	unsigned char *ticket_plain = malloc(ticket_plain_len);
	if (!ticket_plain)
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		free(key_tgs_app);
		return EXIT_FAILURE;
	}
	memcpy(ticket_plain, client_id, strlen(client_id));
	memcpy(ticket_plain + strlen(client_id), key_client_app_hex, strlen(key_client_app_hex));
	char *ticket_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_tgs_app, ticket_plain, ticket_plain_len, &ticket_app_hex))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		free(key_tgs_app);
		free(ticket_plain);
		fprintf(stderr, "Failed to encrypt Ticket_App\n");
		return EXIT_FAILURE;
	}
	free(key_tgs_app);
	free(ticket_plain);

	/* ------------------------------------------------------------
	 * STEP 6: Encrypt Key_Client_App for the client
	 *
	 * Encrypt:
	 *
	 *      Key_Client_App_hex
	 *
	 * using:
	 *
	 *      Key_Client_TGS
	 *
	 * Result:
	 *  - enc_key_client_app (hex)
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - AES-encrypt Key_Client_App hex using Key_Client_TGS
	 *  - Hex-encode the ciphertext
	 */

	char *enc_key_client_app_hex = NULL;
	if (!aes256_encrypt_bytes_to_hex_string(key_client_tgs,(const unsigned char *)key_client_app_hex, strlen(key_client_app_hex), &enc_key_client_app_hex))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		free(ticket_app_hex);
		fprintf(stderr, "Failed to encrypt Key_Client_App\n");
		return EXIT_FAILURE;
	}

	/* ------------------------------------------------------------
	 * STEP 7: Write TGS_REP.txt
	 *
	 * Output file format (EXACT):
	 *
	 *   line 1: Ticket_App hex
	 *   line 2: enc_key_client_app hex
	 *
	 * Filename MUST be:
	 *      "TGS_REP.txt"
	 *
	 * ------------------------------------------------------------
	 */
	/* TODO:
	 *  - Write exactly two lines to TGS_REP.txt
	 *  - Preserve order and formatting
	 */
	
	if (!write_text_lines("TGS_REP.txt", ticket_app_hex, enc_key_client_app_hex, NULL))
	{
		free(tgt_plain);
		free(client_id);
		free(key_client_tgs);
		free(key_client_app_hex);
		free(key_client_app);
		free(ticket_app_hex);
		free(enc_key_client_app_hex);
		fprintf(stderr, "Failed to write TGS_REP.txt\n");
		return EXIT_FAILURE;
	}
	free(tgt_plain);
	free(client_id);
	free(key_client_tgs);
	free(key_client_app_hex);
	free(key_client_app);
	free(ticket_app_hex);
	free(enc_key_client_app_hex);

	return EXIT_SUCCESS;
}
