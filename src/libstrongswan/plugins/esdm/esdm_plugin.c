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

#include "esdm_plugin.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <library.h>
#include <utils/debug.h>
#include "esdm_rng.h"
#include <esdm/esdm_rpc_client.h>

typedef struct private_esdm_plugin_t private_esdm_plugin_t;

/**
 * private data of esdm_plugin
 */
struct private_esdm_plugin_t {

	/**
	 * public functions
	 */
	esdm_plugin_t public;
};

METHOD(plugin_t, get_name, char*,
	private_esdm_plugin_t *this)
{
	return "esdm";
}

METHOD(plugin_t, get_features, int,
	private_esdm_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_REGISTER(RNG, esdm_rng_create),
			PLUGIN_PROVIDE(RNG, RNG_WEAK),
			PLUGIN_PROVIDE(RNG, RNG_STRONG),
			PLUGIN_PROVIDE(RNG, RNG_TRUE),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_esdm_plugin_t *this)
{
	esdm_rpcc_fini_unpriv_service();
	free(this);
}

/*
 * see header file
 */
plugin_t *esdm_plugin_create()
{
	private_esdm_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	if (esdm_rpcc_init_unpriv_service(NULL) != 0)
	{
		destroy(this);
		return NULL;
	}

	return &this->public.plugin;
}

