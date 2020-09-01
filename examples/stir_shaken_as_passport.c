#include <stir_shaken.h>


/**
 * This example demonstrates how to create simplest authentication service (STI-SP/AS).
 *
 * 1. Get SSL keys or generate them with stir_shaken_generate_keys
 * 2. Create PASSporT stir_shaken_passport_params_t params = { .x5u = "https://sp.com/sp.pem", (...) }
 * 3. OPTIONALLY Get plain form of PASSporT (decoded, i.e. without signature) with stir_shaken_passport_dump_str
 * 4. Get signed PASSporT with stir_shaken_passport_sign
 *  
 **/

int main(void)
{
	stir_shaken_context_t ss = { 0 };
	const char *error_description = NULL;
	stir_shaken_error_t error_code = STIR_SHAKEN_ERROR_GENERAL;
	stir_shaken_passport_t passport = {0};
	stir_shaken_status_t	status = STIR_SHAKEN_STATUS_FALSE;

	char *s = NULL;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *private_key = NULL;
	EVP_PKEY *public_key = NULL;

	unsigned char	priv_raw[STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN] = { 0 };
	uint32_t		priv_raw_len = STIR_SHAKEN_PRIV_KEY_RAW_BUF_LEN;	

	stir_shaken_passport_params_t params = { .x5u = "https://sp.com/sp.pem", .attest = "A", .desttn_key = "tn", .desttn_val = "01256500600", .iat = time(NULL), .origtn_key = "tn", .origtn_val = "01256789999", .origid = "ref" };


	status = stir_shaken_do_init(NULL, NULL, NULL, STIR_SHAKEN_LOGLEVEL_HIGH);
	if (STIR_SHAKEN_STATUS_OK != status) {

		printf("Cannot init lib\n");
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			printf("Error description is: '%s'\n", error_description);
			printf("Error code is: '%d'\n", error_code);
		}

		return -1;
	}

	// If you do not have SSL keys yet, generate them
	status = stir_shaken_generate_keys(&ss, &ec_key, &private_key, &public_key, "sp.priv", "sp.pub", priv_raw, &priv_raw_len);
	if (STIR_SHAKEN_STATUS_OK != status) {

		printf("Cannot generate SSL keys\n");
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			printf("Error description is: '%s'\n", error_description);
			printf("Error code is: '%d'\n", error_code);
		}

		return -2;
	}

	// Assign parameters to PASSporT
	status = stir_shaken_passport_init(&ss, &passport, &params, priv_raw, priv_raw_len);
	if (STIR_SHAKEN_STATUS_OK != status) {

		printf("Cannot generate PASSporT\n");
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			printf("Error description is: '%s'\n", error_description);
			printf("Error code is: '%d'\n", error_code);
		}

		return -3;
	}

	// Get plain version of PASSporT (decoded, not signed, with no signature)
	s = stir_shaken_passport_dump_str(&passport, 1);
	printf("PASSporT is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	// Encode (sign) using default key (key given to stir_shaken_passport_init)
	status = stir_shaken_passport_sign(&ss, &passport, NULL, 0, &s);
	if (STIR_SHAKEN_STATUS_OK != status) {

		printf("Cannot sign PASSporT\n");
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			printf("Error description is: '%s'\n", error_description);
			printf("Error code is: '%d'\n", error_code);
		}

		return -4;
	}
	printf("PASSporT encoded (signed) is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	// Encode (sign) using specific key
	status = stir_shaken_passport_sign(&ss, &passport, priv_raw, priv_raw_len, &s);
	if (STIR_SHAKEN_STATUS_OK != status) {

		printf("Cannot sign PASSporT\n");
		if (stir_shaken_is_error_set(&ss)) {
			error_description = stir_shaken_get_error(&ss, &error_code);
			printf("Error description is: '%s'\n", error_description);
			printf("Error code is: '%d'\n", error_code);
		}

		return -5;
	}
	printf("PASSporT encoded (signed) is:\n%s\n", s);
	stir_shaken_free_jwt_str(s);
	s = NULL;

	stir_shaken_destroy_keys_ex(&ec_key, &private_key, &public_key);
	stir_shaken_passport_destroy(&passport);
	stir_shaken_do_deinit();

	return 0;
}
