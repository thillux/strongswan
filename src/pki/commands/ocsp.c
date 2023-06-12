/*
 * Copyright (C) 2023 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "pki.h"

#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_responder.h>

/**
 * Read input data as chunk
 */
static chunk_t read_from_stream(FILE *stream)
{
	char buf[8096];
	size_t len, total = 0;

	while (TRUE)
	{
		len = fread(buf + total, 1, sizeof(buf) - total, stream);
		if (len < (sizeof(buf) - total))
		{
			if (ferror(stream))
			{
				return chunk_empty;
			}
			if (feof(stream))
			{
				return chunk_clone(chunk_create(buf, total + len));
			}
		}
		total += len;
		if (total == sizeof(buf))
		{
			fprintf(stderr, "buffer too small to read input!\n");
			return chunk_empty;
		}
	}
}

/**
 * Write output data from chunk to stream
 */
static bool write_to_stream(FILE *stream, chunk_t data)
{
	size_t len, total = 0;

	set_file_mode(stream, CERT_ASN1_DER);
	while (total < data.len)
	{
		len = fwrite(data.ptr + total, 1, data.len - total, stream);
		if (len <= 0)
		{
			return FALSE;
		}
		total += len;
	}
	return TRUE;
}


/**
 * Respond to OCSP request
 */
static int respond(chunk_t chunk, certificate_t *cert, private_key_t *key,
				   hash_algorithm_t digest, signature_params_t *scheme)
{
	write_to_stream(stdout, chunk);

	return 0;
}

/**
 * Show|Respond to OCSP requests
 */
static int ocsp()
{
	char *arg, *file = NULL, *error = NULL;
	private_key_t *key = NULL;
	certificate_t *cert = NULL, *ocsp_req = NULL;
	certificate_t *issuer_cacert = NULL, *cacert = NULL;
	ocsp_request_t *ocsp_request;
	ocsp_responder_t *ocsp_responder = NULL;
	chunk_t data = chunk_empty;
	chunk_t caNameHash = chunk_empty, caKeyHash = chunk_empty;
	chunk_t issuerNameHash, issuerKeyHash, serialNumber;
	hash_algorithm_t digest = HASH_UNKNOWN;
	signature_params_t *scheme = NULL;
	time_t revocation_time;
	crl_reason_t reason;
	mem_cred_t *creds;
	int res = 0;
	FILE *in;
	enumerator_t *enumerator;
	bool trusted = TRUE;


	enum {
		OP_SHOW,
		OP_RESPOND,
	} op = OP_SHOW;

	bool pss = lib->settings->get_bool(lib->settings, "%s.rsa_pss", FALSE,
									   lib->ns);

	creds = mem_cred_create();

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				goto usage;
			case 'i':
				file = arg;
				continue;
			case 'r':
				op = OP_RESPOND;
				continue;
			case 'k':
				key = lib->creds->create(lib->creds,
										 CRED_PRIVATE_KEY, KEY_ANY,
										 BUILD_FROM_FILE, arg, BUILD_END);
				if (!key)
				{
					error = "parsing private key failed";
					goto usage;
				}
				creds->add_key(creds, key);
				continue;
			case 'c':
				cert = lib->creds->create(lib->creds,
										  CRED_CERTIFICATE, CERT_X509,
										  BUILD_FROM_FILE, arg, BUILD_END);
				if (!cert)
				{
					error = "parsing certificate failed";
					goto usage;
				}
				creds->add_cert(creds, TRUE, cert);
				continue;
			case 'I':
				issuer_cacert = lib->creds->create(lib->creds,
											CRED_CERTIFICATE, CERT_X509,
											BUILD_FROM_FILE, arg, BUILD_END);
				if (!issuer_cacert)
				{
					error = "parsing Issuer CA certificate failed";
					goto usage;
				}
				creds->add_cert(creds, TRUE, issuer_cacert);
				continue;
			case 'C':
				cacert = lib->creds->create(lib->creds,
											CRED_CERTIFICATE, CERT_X509,
											BUILD_FROM_FILE, arg, BUILD_END);
				if (!cacert)
				{
					error = "parsing CA certificate failed";
					goto usage;
				}
				creds->add_cert(creds, TRUE, cacert);
				continue;
			case 'g':
				if (!enum_from_name(hash_algorithm_short_names, arg, &digest))
				{
					error = "invalid --digest type";
					goto usage;
				}
				continue;
			case 'R':
				if (!parse_rsa_padding(arg, &pss))
				{
					error = "invalid RSA padding";
					goto usage;
				}
				continue;
			case EOF:
				break;
			default:
				error = "invalid --ocsp option";
				goto usage;
		}
		break;
	}

	/* In the case of a one-tier CA certificate hierarchy */
	if (!issuer_cacert)
	{
		issuer_cacert = cacert;
	}

	lib->credmgr->add_local_set(lib->credmgr, &creds->set, FALSE);

	if (file)
	{
		in = fopen(file, "r");
		if (in)
		{
			data = read_from_stream(in);
			fclose(in);
		}
	}
	else
	{
		data = read_from_stream(stdin);
	}

	if (!data.len)
	{
		error = "reading input failed";
		goto end;
	}

	if (op == OP_RESPOND && !cacert)
	{
		error = "respond mode requires a ca certificate";
		goto end;
	}
	/*
	if (op == OP_RESPOND && !key)
	{
		error = "respond mode requires a private key";
		goto end;
	}
	*/
	/* parse OCSP request */
	ocsp_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
						CERT_X509_OCSP_REQUEST,
						BUILD_BLOB_ASN1_DER, data, BUILD_END);
	if (!ocsp_req)
	{
		goto end;
	}
	ocsp_request = (ocsp_request_t*)ocsp_req;

	/* compute SHA1 name and key hashes of issuer cacert */
	if (issuer_cacert)
	{
		identification_t *requestor, *issuer;
		certificate_t *signer_cert, *cert_found;
		identification_t *signer;
		public_key_t *public;
		hasher_t *hasher;
		enumerator_t *certs;

		requestor = ocsp_req->get_subject(ocsp_req);
		if (requestor)
		{
			DBG1(DBG_LIB, "requestor:     \"%Y\"", requestor);

			signer_cert = ocsp_request->get_signer_cert(ocsp_request);
			if (signer_cert)
			{
				signer = signer_cert->get_subject(signer_cert);

				/* establish trust relative to root CA */
				creds->add_cert(creds, FALSE, signer_cert->get_ref(signer_cert));
				certs = lib->credmgr->create_trusted_enumerator(lib->credmgr,
											KEY_ANY, signer, FALSE);
				trusted = certs->enumerate(certs, &cert_found, NULL) &&
										  (cert_found == signer_cert);
				certs->destroy(certs);
				trusted &= ocsp_req->issued_by(ocsp_req, signer_cert, NULL);
				DBG1(DBG_LIB, "  %strusted", trusted ? "" : "not ");
			}
		}

		issuer = issuer_cacert->get_subject(issuer_cacert);
		DBG1(DBG_LIB, "issuer:        \"%Y\"", issuer);

		public = issuer_cacert->get_public_key(issuer_cacert);
		if (!public->get_fingerprint(public, KEYID_PUBKEY_SHA1, &caKeyHash))
		{
			public->destroy(public);
			error = "failed to compute SHA1 caKeyHash";
			goto end;
		}
		public->destroy(public);

		hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (!hasher)
		{
			error = "failed to create SHA1 hasher";
			goto end;
		}

		if (!hasher->allocate_hash(hasher, issuer->get_encoding(issuer), &caNameHash))
		{
			hasher->destroy(hasher);
			error = "failed to compute SHA1 caNameHash";
			goto end;
		}
		hasher->destroy(hasher);
	}

	if (op == OP_RESPOND && trusted)
	{
		ocsp_responder = lib->get(lib, "ocsp-responder");
		if (!ocsp_responder)
		{
			error = "no OCSP responder available";
			goto end;
		}
		/*
		scheme = get_signature_scheme(key, digest, pss);
		if (!scheme)
		{
			error = "no signature scheme found";
			goto end;
		}
		if (digest == HASH_UNKNOWN)
		{
			digest = hasher_from_signature_scheme(scheme->scheme,
												  scheme->params);
		}
		*/
	}

	enumerator = ocsp_request->create_request_enumerator(ocsp_request);
	while (enumerator->enumerate(enumerator, NULL, &issuerNameHash,
											 &issuerKeyHash, &serialNumber))
	{
		cert_validation_t status;
		bool issuerNameHash_ok = FALSE, issuerKeyHash_ok = FALSE;

		if (cacert)
		{
			issuerNameHash_ok = chunk_equals(issuerNameHash, caNameHash);
			issuerKeyHash_ok  = chunk_equals(issuerKeyHash,  caKeyHash);
		}

		if (op == OP_SHOW || !issuerNameHash_ok || !issuerKeyHash_ok)
		{
			DBG1(DBG_LIB, "issuerNameHash: %#B (%s)", &issuerNameHash,
						   issuerNameHash_ok ? "ok" : "no match");
			DBG1(DBG_LIB, "issuerKeyHash:  %#B (%s)", &issuerKeyHash,
						   issuerKeyHash_ok ? "ok" : "no match");
			DBG1(DBG_LIB, "serialNumber:   %#B", &serialNumber);
			continue;
		}

		DBG1(DBG_LIB, "serialNumber:   %#B", &serialNumber);
		status = ocsp_responder->get_status(ocsp_responder, issuer_cacert,
									serialNumber, &revocation_time, &reason);

		DBG1(DBG_LIB, "certValidation: %N", cert_validation_names, status);
		if (status == VALIDATION_REVOKED || status == VALIDATION_ON_HOLD)
		{
			DBG1(DBG_LIB, "revocationTime: %T", &revocation_time, TRUE);
			DBG1(DBG_LIB, "crlReason:      %N", crl_reason_names, reason);
		}
		if (status != VALIDATION_FAILED)
		{
			res = respond(data, cert, key, digest, scheme);
		}
	}
	enumerator->destroy(enumerator);

end:
	lib->credmgr->remove_local_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	DESTROY_IF(ocsp_req);
	signature_params_destroy(scheme);
	free(data.ptr);
	free(caNameHash.ptr);
	if (error)
	{
		fprintf(stderr, "%s\n", error);
		return 1;
	}
	return res;

usage:
	creds->destroy(creds);
	return command_usage(error);
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		ocsp, 'o', "ocsp", "OCSP responder",
		{"[--in file] [--respond] [--cert file] [--key file]",
		 "[--issuer-cacert file] [--cacert file]+",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
		 "[--rsa-padding pkcs1|pss]"},
		{
			{"help",          'h', 0, "show usage information"},
			{"respond",       'r', 0, "respond to OCSP request with OCSP response"},
			{"in",            'i', 1, "input file, default: stdin"},
			{"key",           'k', 1, "path to OCSP signing private key"},
			{"cert",          'c', 1, "path to OCSP signing certificate"},
			{"issuer-cacert", 'I', 1, "Issuer CA certificate"},
			{"cacert",        'C', 1, "CA certificate"},
			{"digest",        'g', 1, "digest for signature creation, default: key-specific"},
			{"rsa-padding",   'R', 1, "padding for RSA signatures, default: pkcs1"},
		}
	});
}
