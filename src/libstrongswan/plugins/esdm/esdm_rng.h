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

/**
 * @defgroup esdm_rng esdm_rng
 * @{ @ingroup esdm_p
 */

#ifndef ESDM_RNG_H_
#define ESDM_RNG_H_

typedef struct esdm_rng_t esdm_rng_t;

#include <library.h>

/**
 * rng_t implementation on top of ESDM
 */
struct esdm_rng_t {

	/**
	 * Implements rng_t.
	 */
	rng_t rng;
};

/**
 * Creates an esdm_rng_t instance.
 *
 * @param quality	required quality of randomness
 * @return			created esdm_rng_t
 */
esdm_rng_t *esdm_rng_create(rng_quality_t quality);

#endif /** ESDM_RNG_H_ @} */
