// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/* 
 *  config.h - VaultGuard configuration definitions
 *  Copyright (C) 2012 ANSSI
 *  Author: Mickaël Salaün <clipos@ssi.gouv.fr>
 *
 *  Distributed under the terms of the GNU Lesser General Public License v2.1
 */

#include <glib.h>

#if ! DEBUG
#define g_debug(...) {}
#endif

#define VAULT_CONF_KEY_CMD "cmd"
#define VAULT_CONF_KEY_BANK "bank"
#define VAULT_CONF_KEY_ENV "env"
#define VAULT_CONF_KEYBEG_FILE "file "
#define VAULT_CONF_SUFFIX ".conf"

typedef struct {
	int fd_out;
	int fd_tmp;
	char *name;
	char *note;
	char **filter;
} file_t;

typedef struct {
	char *name;
	struct {
		char *exe;
		char *note;
		char *cwd;
		char *in;
		char *out;
		char *err;
		char **argv;
		char **envp;
		gboolean respawn;
	} cmd;
	struct {
		char *path;
	} bank;
	GPtrArray *files;
	int profile_fd;
	int tmp_fd;
	int lock_fd;
} profile_t;

GPtrArray *load_config(const char *conf_dir);
