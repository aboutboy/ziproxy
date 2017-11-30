/* session.h
 * Session base code.
 *
 * Ziproxy - the HTTP acceleration proxy
 * This code is under the following conditions:
 *
 * ---------------------------------------------------------------------
 * Copyright (c)2005-2010 Daniel Mealha Cabrita
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111 USA
 * ---------------------------------------------------------------------
 */

#ifndef SRC_SESSION_H
#define SRC_SESSION_H

#include <stdio.h>
#include "user_settings.h"

extern FILE *sess_rclient;
extern FILE *sess_wclient;
extern int domain_isin_squidcached;
extern int access_for_apache;

#ifdef USER_SETTINGS
extern clc_setting_t user_settings;
extern int got_user_settings;
///
extern server_host_ip server_hosts[MAX_SERVER_HOST_SIZE];
#endif

#endif

