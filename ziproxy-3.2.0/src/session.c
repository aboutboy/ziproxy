/* session.c
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

#include <stdio.h>
#include "session.h"
#include "user_settings.h"

FILE *sess_rclient;
FILE *sess_wclient;

int domain_isin_squidcached;
int access_for_apache;//判断访问是来值apache 或者测试 规则是根据没有修改 http
#ifdef USER_SETTINGS
clc_setting_t user_settings;
int got_user_settings;
///
server_host_ip server_hosts[MAX_SERVER_HOST_SIZE];
//squid cached for domain
#endif

