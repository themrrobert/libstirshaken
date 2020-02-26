#include <stir_shaken_tool.h>


int stirshaken_command_configure(stir_shaken_context_t *ss, const char *command_name, struct ca *ca, struct sp *sp, struct options *options)
{
	if (!command_name || !ca || !sp || !options) {
		return COMMAND_UNKNOWN;
	}

	if (!strcmp(command_name, COMMAND_NAME_KEYS)) {

		return COMMAND_KEYS;

	} else if (!strcmp(command_name, COMMAND_NAME_CSR)) {

		sp->code = options->spc;
		strncpy(sp->csr_name, options->file, STIR_SHAKEN_BUFLEN);
		strncpy(sp->public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
		strncpy(sp->subject_c, options->subject_c, STIR_SHAKEN_BUFLEN);
		strncpy(sp->subject_cn, options->subject_cn, STIR_SHAKEN_BUFLEN);
		return COMMAND_CSR;

	} else if (!strcmp(command_name, COMMAND_NAME_CERT)) {

		if (COMMAND_CERT_CA == options->command_cert_type) {

			strncpy(ca->cert_name, options->file, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_c, options->issuer_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_cn, options->issuer_cn, STIR_SHAKEN_BUFLEN);
			strncpy(ca->public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_CA;

		} else if (COMMAND_CERT_SP == options->command_cert_type) {

			strncpy(ca->public_key_name, options->public_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->private_key_name, options->private_key_name, STIR_SHAKEN_BUFLEN);
			strncpy(sp->csr_name, options->csr_name, STIR_SHAKEN_BUFLEN);
			strncpy(ca->cert_name, options->ca_cert, STIR_SHAKEN_BUFLEN);
			strncpy(sp->cert_name, options->file, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_c, options->issuer_c, STIR_SHAKEN_BUFLEN);
			strncpy(ca->issuer_cn, options->issuer_cn, STIR_SHAKEN_BUFLEN);
			strncpy(ca->tn_auth_list_uri, options->tn_auth_list_uri, STIR_SHAKEN_BUFLEN);
			return COMMAND_CERT_SP;

		} else {
			stir_shaken_set_error(ss, "Bad --type", STIR_SHAKEN_ERROR_GENERAL);
			return COMMAND_UNKNOWN;
		}

	} else if (!strcmp(command_name, COMMAND_NAME_INSTALL_CERT)) {

		fprintf(stderr, "\n\nConfiguring install CA certificate command...\n\n");
		return COMMAND_INSTALL_CERT;

	} else {

		stir_shaken_set_error(ss, "Unknown command", STIR_SHAKEN_ERROR_GENERAL);
		return COMMAND_UNKNOWN;
	}
}

stir_shaken_status_t stirshaken_command_validate(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options)
{
	switch (command) {

		case COMMAND_KEYS:

			if (stir_shaken_zstr(options->private_key_name) && stir_shaken_zstr(options->public_key_name)) {
				goto fail;
			}
			break;

		case COMMAND_CSR:

			if (stir_shaken_zstr(sp->private_key_name) || stir_shaken_zstr(sp->public_key_name)
					|| stir_shaken_zstr(sp->subject_c) || stir_shaken_zstr(sp->subject_cn)
						|| stir_shaken_zstr(sp->csr_name)) {
				goto fail;
			}
			break;

		case COMMAND_CERT_CA:

			if (stir_shaken_zstr(ca->cert_name) || stir_shaken_zstr(ca->private_key_name) || stir_shaken_zstr(ca->public_key_name)
					|| stir_shaken_zstr(ca->issuer_c) || stir_shaken_zstr(ca->issuer_cn)) {
				goto fail;
			}
			break;
		
		case COMMAND_CERT_SP:

			if (stir_shaken_zstr(sp->cert_name) || stir_shaken_zstr(ca->private_key_name) || stir_shaken_zstr(ca->public_key_name)
					|| stir_shaken_zstr(sp->csr_name) || stir_shaken_zstr(ca->cert_name)
					|| stir_shaken_zstr(ca->issuer_c) || stir_shaken_zstr(ca->issuer_cn) || stir_shaken_zstr(ca->tn_auth_list_uri)) {
				goto fail;
			}
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_CERT:
		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}

stir_shaken_status_t stirshaken_command_execute(stir_shaken_context_t *ss, int command, struct ca *ca, struct sp *sp, struct options *options)
{
	stir_shaken_status_t status = STIR_SHAKEN_STATUS_OK;
	unsigned long	hash = 0;
	char			hashstr[100] = { 0 }, cert_hashed_as_text[1000] = { 0 };
	int				hashstrlen = 100;


	if (STIR_SHAKEN_STATUS_OK != stir_shaken_do_init(ss, options->ca_dir, options->crl_dir)) {
		goto fail;
	}

	switch (command) {

		case COMMAND_KEYS:

			status = stir_shaken_generate_keys(ss, &options->keys.ec_key, &options->keys.private_key, &options->keys.public_key, options->private_key_name, options->public_key_name, NULL, NULL);
			if (STIR_SHAKEN_STATUS_OK != status) {
				goto fail;
			}
			break;

		case COMMAND_CSR:

			fprintf(stderr, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &sp->keys.private_key, &sp->keys.public_key, sp->private_key_name, sp->public_key_name, NULL, NULL)) {
				goto fail;
			}
			
			fprintf(stderr, "Generating CSR...\n");
			status = stir_shaken_generate_csr(ss, sp->code, &sp->csr.req, sp->keys.private_key, sp->keys.public_key, sp->subject_c, sp->subject_cn);
			if (STIR_SHAKEN_STATUS_OK != status) {
				goto fail;
			}
			fprintf(stderr, "Saving CSR...\n");
			status = stir_shaken_csr_to_disk(ss, sp->csr.req, sp->csr_name);
			if (STIR_SHAKEN_STATUS_OK != status) {
				goto fail;
			}
			break;

		case COMMAND_CERT_CA:

			fprintf(stderr, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &ca->keys.private_key, &ca->keys.public_key, ca->private_key_name, ca->public_key_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Generating cert...\n");
			ca->cert.x = stir_shaken_generate_x509_self_signed_ca_cert(ss, ca->keys.private_key, ca->keys.public_key, ca->issuer_c, ca->issuer_cn, ca->serial, ca->expiry_days);
			if (!ca->cert.x) {
				goto fail;
			}
			
			fprintf(stderr, "Configuring certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(ss, &ca->cert, ca->cert_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Saving certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->cert.x, ca->cert.name)) {
				goto fail;
			}

			stir_shaken_hash_cert_name(ss, &ca->cert);
			printf("CA name hash is %lu\n", ca->cert.hash);
			printf("CA hashed file name is %s\n", ca->cert.cert_name_hashed);

			fprintf(stderr, "Saving certificate under hashed name...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, ca->cert.x, ca->cert.cert_name_hashed)) {
				goto fail;
			}

			break;

		case COMMAND_CERT_SP:

			fprintf(stderr, "Loading keys...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_load_keys(ss, &ca->keys.private_key, &ca->keys.public_key, ca->private_key_name, ca->public_key_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Loading CSR...\n");
			sp->csr.req = stir_shaken_load_x509_req_from_file(ss, sp->csr_name);
			if (!sp->csr.req) {
				goto fail;
			}

			fprintf(stderr, "Loading CA certificate...\n");
			ca->cert.x = stir_shaken_load_x509_from_file(ss, ca->cert_name);
			if (!ca->cert.x) {
				goto fail;
			}

			fprintf(stderr, "Generating cert...\n");
			sp->cert.x = stir_shaken_generate_x509_end_entity_cert_from_csr(ss, ca->cert.x, ca->keys.private_key, ca->issuer_c, ca->issuer_cn, sp->csr.req, ca->serial_sp, ca->expiry_days_sp, ca->tn_auth_list_uri);
			if (!sp->cert.x) {
				goto fail;
			}

			fprintf(stderr, "Configuring certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_cert_configure(ss, &sp->cert, sp->cert_name, NULL, NULL)) {
				goto fail;
			}

			fprintf(stderr, "Saving certificate...\n");
			if (STIR_SHAKEN_STATUS_OK != stir_shaken_x509_to_disk(ss, sp->cert.x, sp->cert.name)) {
				goto fail;
			}
			break;

		case COMMAND_INSTALL_CERT:
			break;

		case COMMAND_UNKNOWN:
		default:
			goto fail;
	}

	return STIR_SHAKEN_STATUS_OK;

fail:
	return STIR_SHAKEN_STATUS_FALSE;
}
