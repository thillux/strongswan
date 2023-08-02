/*
 * Copyright (C) 2023 Markus Theil
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <utils/debug.h>

#include "esdm_rng.h"
#include "esdm_plugin.h"
#include <esdm/esdm_rpc_client.h>

typedef struct private_esdm_rng_t private_esdm_rng_t;

/**
 * Private data of an esdm_rng_t object.
 */
struct private_esdm_rng_t {

	/**
	 * Public esdm_rng_t interface.
	 */
	esdm_rng_t public;

	/**
	 * random quality target
	 */
	rng_quality_t quality;
};

METHOD(rng_t, get_bytes, bool,
	private_esdm_rng_t *this, size_t bytes, uint8_t *buffer)
{
	ssize_t ret = 0;

	switch(this->quality) {
		case RNG_WEAK:
			esdm_invoke(esdm_rpcc_get_random_bytes_min(buffer, bytes));
			break;
		case RNG_STRONG:
			esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, bytes));
			break;
		case RNG_TRUE:
			esdm_invoke(esdm_rpcc_get_random_bytes_pr(buffer, bytes));
			break;
	}

	if(ret != (ssize_t) bytes) {
		DBG1(DBG_LIB, "reading from esdm failed");
		return FALSE;
	}

	return TRUE;
}

METHOD(rng_t, allocate_bytes, bool,
	private_esdm_rng_t *this, size_t bytes, chunk_t *chunk)
{
	*chunk = chunk_alloc(bytes);
	return get_bytes(this, chunk->len, chunk->ptr);
}

METHOD(rng_t, destroy, void,
	private_esdm_rng_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
esdm_rng_t *esdm_rng_create(rng_quality_t quality)
{
	private_esdm_rng_t *this;

	INIT(this,
		.public = {
			.rng = {
				.get_bytes = _get_bytes,
				.allocate_bytes = _allocate_bytes,
				.destroy = _destroy,
			},
		},
	);

	switch (quality)
	{
		case RNG_TRUE:
		case RNG_STRONG:
		case RNG_WEAK:
			this->quality = quality;
		default:
			this->quality = RNG_STRONG;
			break;
	}

	return &this->public;
}

