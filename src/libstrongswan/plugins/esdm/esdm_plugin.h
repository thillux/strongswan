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
 * @defgroup esdm_p esdm
 * @ingroup plugins
 *
 * @defgroup esdm_plugin esdm_plugin
 * @{ @ingroup esdm_p
 */

#ifndef ESDM_PLUGIN_H_
#define ESDM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct esdm_plugin_t esdm_plugin_t;

/**
 * Plugin implementing a RNG reading from ESDM
 */
struct esdm_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

/**
 * Constructor to create ESDM random source plugin
 *
 * @return			esdm plugin public plugin_t
 */
plugin_t *esdm_plugin_create();

#endif /** ESDM_PLUGIN_H_ @}*/
