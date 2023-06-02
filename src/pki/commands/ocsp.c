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
 * Show info about OCSP request
 */
static int show(chunk_t chunk, certificate_t *cacert)
{
	certificate_t *ocsp_req;
	ocsp_request_t *ocsp_request;
	enumerator_t *enumerator;
	chunk_t issuerNameHash, issuerKeyHash, serialNumber;
	int res = 1;

	ocsp_req = lib->creds->create(lib->creds, CRED_CERTIFICATE,
						CERT_X509_OCSP_REQUEST,
						BUILD_BLOB_ASN1_DER, chunk,	BUILD_END);
	if (!ocsp_req)
	{
		return 1;
	}
	ocsp_request = (ocsp_request_t*)ocsp_req;

	if (cacert)
	{
		identification_t *issuer;
		public_key_t *public;
		hasher_t *hasher;
		chunk_t caNameHash, caKeyHash;

		public = cacert->get_public_key(cacert);
		if (!public->get_fingerprint(public, KEYID_PUBKEY_SHA1, &caKeyHash))
		{
			DBG1(DBG_LIB, "failed to compute SHA1 caKeyHash");
			public->destroy(public);
			goto error;
		}
		public->destroy(public);

		hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
		if (!hasher)
		{
			DBG1(DBG_LIB, "failed to create SHA1 hasher");
			goto error;
		}

		issuer = cacert->get_subject(cacert);
		printf("issuer:        \"%Y\"\n", issuer);

		if (!hasher->allocate_hash(hasher, issuer->get_encoding(issuer), &caNameHash))
		{
			DBG1(DBG_LIB, "failed to compute SHA1 caNameHash");
			hasher->destroy(hasher);
			goto error;
		}
		hasher->destroy(hasher);

		enumerator = ocsp_request->create_request_enumerator(ocsp_request);
		while (enumerator->enumerate(enumerator, NULL, &issuerNameHash,
												 &issuerKeyHash, &serialNumber))
		{
			printf("issuerNameHash: %#B (%s)\n", &issuerNameHash,
				   chunk_equals(issuerNameHash, caNameHash) ? "ok" : "no match");
			printf("issuerKeyHash:  %#B (%s)\n", &issuerKeyHash,
				   chunk_equals(issuerKeyHash,  caKeyHash)  ? "ok" : "no match");
			printf("serialNumber:   %#B\n", &serialNumber);
		}
		enumerator->destroy(enumerator);
		chunk_free(&caNameHash);
	}
	else
	{
		enumerator = ocsp_request->create_request_enumerator(ocsp_request);
		while (enumerator->enumerate(enumerator, NULL, &issuerNameHash,
												 &issuerKeyHash, &serialNumber))
		{
			printf("issuerNameHash: %#B\n", &issuerNameHash);
			printf("issuerKeyHash:  %#B\n", &issuerKeyHash);
			printf("serialNumber:   %#B\n", &serialNumber);
		}
		enumerator->destroy(enumerator);
	}
	res = 0;

error:
	ocsp_req->destroy(ocsp_req);

	return res;
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
	certificate_t *cert = NULL, *cacert = NULL;
	chunk_t data = chunk_empty;
	hash_algorithm_t digest = HASH_UNKNOWN;
	signature_params_t *scheme = NULL;
	mem_cred_t *creds;
	int res = 0;
	FILE *in;
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
	if (op != OP_SHOW && !cert)
	{
		error = "requiring a certificate";
		goto end;
	}

	lib->credmgr->add_local_set(lib->credmgr, &creds->set, FALSE);

	switch (op)
	{
		case OP_RESPOND:
			if (!key)
			{
				error = "OCSP signing requires a private key";
				break;
			}
			scheme = get_signature_scheme(key, digest, pss);
			if (!scheme)
			{
				error = "no signature scheme found";
				break;
			}
			if (digest == HASH_UNKNOWN)
			{
				digest = hasher_from_signature_scheme(scheme->scheme,
													  scheme->params);
			}
			res = respond(data, cert, key, digest, scheme);
			break;
		case OP_SHOW:
			res = show(data, cacert);
			break;
		default:
			res = 1;
			break;
	}
	lib->credmgr->remove_local_set(lib->credmgr, &creds->set);

end:
	signature_params_destroy(scheme);
	creds->destroy(creds);
	free(data.ptr);
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
		{"[--in file] [--respond] [--cert file] [--key file] [--cacert file]",
		 "[--digest md5|sha1|sha224|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512]",
		 "[--rsa-padding pkcs1|pss]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"respond",		'r', 0, "respond to OCSP request with OCSP response"},
			{"in",			'i', 1, "input file, default: stdin"},
			{"key",			'k', 1, "path to OCSP signing private key"},
			{"cert",		'c', 1, "path to OCSP signing certificate"},
			{"cacert",      'C', 1, "CA certificate"},
			{"digest",		'g', 1, "digest for signature creation, default: key-specific"},
			{"rsa-padding",	'R', 1, "padding for RSA signatures, default: pkcs1"},
		}
	});
}
