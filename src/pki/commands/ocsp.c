/*
 * Copyright (C) 2023 Andreas Steffen, strongSec GmbH
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

#include <errno.h>
#include <time.h>

#include "pki.h"

#include <credentials/sets/mem_cred.h>
#include <credentials/certificates/ocsp_request.h>
#include <credentials/certificates/ocsp_response.h>
#include <credentials/certificates/ocsp_single_response.h>
#include <credentials/certificates/ocsp_responder.h>

/**
 * Show|Respond to OCSP requests
 */
static int ocsp()
{
	char *arg, *file = NULL, *error = NULL;
	cred_encoding_type_t form = CERT_ASN1_DER;
	private_key_t *key = NULL;
	certificate_t *cert = NULL, *ocsp_req = NULL, *ocsp_resp = NULL;
	certificate_t *issuer_cacert = NULL, *cacert = NULL;
	ocsp_request_t *ocsp_request;
	ocsp_status_t ocsp_status = OCSP_SUCCESSFUL;
	ocsp_responder_t *ocsp_responder = NULL;
	linked_list_t *responses = NULL;
	chunk_t encoding = chunk_empty;
	chunk_t caNameHash = chunk_empty, caKeyHash = chunk_empty;
	chunk_t issuerNameHash, issuerKeyHash, serialNumber;
	hash_algorithm_t hashAlgorithm = HASH_SHA1, digest = HASH_UNKNOWN;
	signature_params_t *scheme = NULL;
	time_t lifetime = 0;
	mem_cred_t *creds;
	enumerator_t *enumerator;
	bool trusted = TRUE;
	int res = 1;

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
			case 'l':
				lifetime = atoi(arg) * 60;
				if (!lifetime)
				{
					error = "invalid --lifetime value";
					goto usage;
				}
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

	responses = linked_list_create();

	if (op == OP_RESPOND && !cacert)
	{
		error = "respond mode requires a ca certificate";
		goto end;
	}

	if (op == OP_RESPOND && !key)
	{
		error = "respond mode requires a private signer key";
		goto end;
	}

	if (file)
	{
		ocsp_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
								CERT_X509_OCSP_REQUEST,
								BUILD_FROM_FILE, file, BUILD_END);
	}
	else
	{
		chunk_t chunk;

		set_file_mode(stdin, CERT_ASN1_DER);
		if (!chunk_from_fd(0, &chunk))
		{
			fprintf(stderr, "%s: ", strerror(errno));
			error = "reading certificate request failed";
			goto end;
		}
		ocsp_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
								CERT_X509_OCSP_REQUEST,
								BUILD_BLOB_ASN1_DER, chunk, BUILD_END);
		free(chunk.ptr);
	}
	if (!ocsp_req)
	{
		if (op == OP_SHOW)
		{
			error = "malformed OCSP request";
			goto end;
		}
		else
		{
			ocsp_status = OCSP_MALFORMEDREQUEST;
			goto gen;
		}
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
			DBG1(DBG_LIB, "requestor:         \"%Y\"", requestor);

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
		DBG1(DBG_LIB, "issuer:            \"%Y\"", issuer);

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
			ocsp_status = OCSP_INTERNALERROR;
			goto gen;
		}

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
	}

	enumerator = ocsp_request->create_request_enumerator(ocsp_request);
	while (enumerator->enumerate(enumerator, &hashAlgorithm, &issuerNameHash,
											 &issuerKeyHash, &serialNumber))
	{
		cert_validation_t status = VALIDATION_FAILED;
		ocsp_single_response_t *response = NULL;
		time_t revocationTime;
		crl_reason_t revocationReason;
		bool issuerNameHash_ok = FALSE, issuerKeyHash_ok = FALSE;

		if (cacert)
		{
			issuerNameHash_ok = hashAlgorithm == HASH_SHA1 &&
								chunk_equals(issuerNameHash, caNameHash);
			issuerKeyHash_ok  = hashAlgorithm == HASH_SHA1 &&
								chunk_equals(issuerKeyHash,  caKeyHash);
		}

		if (op == OP_SHOW || !issuerNameHash_ok || !issuerKeyHash_ok)
		{
			DBG1(DBG_LIB, "  issuerNameHash:   %#B (%s)", &issuerNameHash,
							 issuerNameHash_ok ? "ok" : "no match");
			DBG1(DBG_LIB, "  issuerKeyHash:    %#B (%s)", &issuerKeyHash,
							 issuerKeyHash_ok ? "ok" : "no match");
		}
		DBG1(DBG_LIB, "  serialNumber:     %#B", &serialNumber);

		if (op == OP_SHOW)
		{
			continue;
		}

		/**
		 *  fill in the OCSP single response
		 */
		response = ocsp_single_response_create();
		response->hashAlgorithm  = hashAlgorithm;
		response->issuerNameHash = chunk_clone(issuerNameHash);
		response->issuerKeyHash = chunk_clone(issuerKeyHash);
		response->serialNumber   = chunk_clone(serialNumber);
		response->thisUpdate     = time(NULL);
		DBG1(DBG_LIB, "  thisUpdate:       %#T", &response->thisUpdate, TRUE);

		if (lifetime)
		{
			response->nextUpdate = response->thisUpdate + lifetime;
			DBG1(DBG_LIB, "  nextUpdate:       %#T", &response->nextUpdate, TRUE);
		}

		status = ocsp_responder->get_status(ocsp_responder,
							 				issuer_cacert,	serialNumber,
							 				&revocationTime, &revocationReason);
		DBG1(DBG_LIB, "  certValidation:   %N", cert_validation_names, status);
		response->status = status;

		if (status == VALIDATION_REVOKED || status == VALIDATION_ON_HOLD)
		{
			DBG1(DBG_LIB, "  revocationTime:   %T", &revocationTime, TRUE);
			DBG1(DBG_LIB, "  revocationReason: %N", crl_reason_names,
												  revocationReason);
			response->revocationTime   = revocationTime;
			response->revocationReason = revocationReason;
		}
		responses->insert_last(responses, response);
	}
	enumerator->destroy(enumerator);

gen:
	if (op == OP_RESPOND)
	{
		DBG1(DBG_LIB, "ocspResponseStatus: %N", ocsp_status_names, ocsp_status);

		enumerator = responses->create_enumerator(responses);
		ocsp_resp = lib->creds->create(lib->creds, CRED_CERTIFICATE,
						CERT_X509_OCSP_RESPONSE,
						BUILD_OCSP_STATUS, ocsp_status,
						BUILD_OCSP_RESPONSES, enumerator,
						BUILD_SIGNING_KEY, key,
						BUILD_SIGNING_CERT, cert,
						BUILD_SIGNATURE_SCHEME, scheme,
						BUILD_END);
		enumerator->destroy(enumerator);

		if (!ocsp_resp)
		{
			error = "generating OCSP response failed";
			goto end;
		}
		if (!ocsp_resp->get_encoding(ocsp_resp, form, &encoding))
		{
			error = "encoding OCSP response failed";
			goto end;
		}
		set_file_mode(stdout, form);
		if (fwrite(encoding.ptr, encoding.len, 1, stdout) != 1)
		{
			error = "writing OCSP response failed";
			goto end;
		}
	}
	res = 0;

end:
	lib->credmgr->remove_local_set(lib->credmgr, &creds->set);
	creds->destroy(creds);
	responses->destroy_offset(responses, offsetof(ocsp_single_response_t, destroy));
	DESTROY_IF(ocsp_req);
	DESTROY_IF(ocsp_resp);
	signature_params_destroy(scheme);
	free(encoding.ptr);
	free(caNameHash.ptr);
	if (error)
	{
		fprintf(stderr, "%s\n", error);
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
		 "[--issuer-cacert file] [--cacert file]+ [--lifetime minutes]",
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
			{"lifetime",      'l', 1, "validity in minutes of the OCSP response (if missing, nextUpdate is omitted)"},
			{"digest",        'g', 1, "digest for signature creation, default: key-specific"},
			{"rsa-padding",   'R', 1, "padding for RSA signatures, default: pkcs1"},
		}
	});
}
