// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/* 
 *  config.c - VaultGuard configuration
 *  Copyright (C) 2012 ANSSI
 *  Author: Mickaël Salaün <clipos@ssi.gouv.fr>
 *
 *  Distributed under the terms of the GNU Lesser General Public License v2.1
 */

#include <glib.h>
#include <string.h>

#include "config.h"

void free_file(file_t *file) {
	g_debug("freeing file %s", file->name);
	g_free(file->name);
	g_free(file->note);
	/*
	g_strfreev(file->filter);
	*/
	g_free(file);
}

void free_profile(profile_t *profile) {
	g_debug("freeing profile %s", profile->name);
	g_free(profile->name);
	g_free(profile->cmd.exe);
	g_free(profile->cmd.note);
	g_free(profile->cmd.cwd);
	g_free(profile->cmd.in);
	g_free(profile->cmd.out);
	g_free(profile->cmd.err);
	g_free(profile->bank.path);
	g_strfreev(profile->cmd.argv);
	g_strfreev(profile->cmd.envp);
	g_ptr_array_free(profile->files, TRUE);
	g_free(profile);
}

#define PROFILE_LOAD_ERROR \
	if (error != NULL) { \
		g_error("%s (%d)", error->message, error->code); \
		g_free(conf); \
		return NULL; \
	}

profile_t *profiles_load(char *conf_name, char *conf_file) {
	profile_t *conf;
	GKeyFile *keyfile;
	GError *error = NULL;
	gsize file_len, argv_len, env_len;
	file_t *file;
	char **flist;
	char **env_var, *env_data;
	int i;

	/* Load file */
	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, conf_file, G_KEY_FILE_NONE, &error)) {
		g_error("%s", error->message);
		return NULL;
	}
	
	/* Parse configuration */
	conf = g_new(profile_t, 1);

	/* Common */
	conf->name = g_strdup(conf_name);
	conf->profile_fd = -1;
	conf->tmp_fd = -1;
	conf->lock_fd = -1;

	/* cmd */
	conf->cmd.exe = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "exe", &error);
	PROFILE_LOAD_ERROR;
	conf->cmd.note = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "note", &error);
	PROFILE_LOAD_ERROR;
	conf->cmd.cwd = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "cwd", &error);
	PROFILE_LOAD_ERROR;
	conf->cmd.in = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "stdin", &error);
	PROFILE_LOAD_ERROR;
	if (strlen(conf->cmd.in) == 0) {
		g_free(conf->cmd.in);
		conf->cmd.in = NULL;
	}
	conf->cmd.out = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "stdout", &error);
	PROFILE_LOAD_ERROR;
	if (strlen(conf->cmd.out) == 0) {
		g_free(conf->cmd.out);
		conf->cmd.out = NULL;
	}
	conf->cmd.err = g_key_file_get_string(keyfile, VAULT_CONF_KEY_CMD, "stderr", &error);
	PROFILE_LOAD_ERROR;
	if (strlen(conf->cmd.err) == 0) {
		g_free(conf->cmd.err);
		conf->cmd.err = NULL;
	}
	conf->cmd.argv = g_key_file_get_string_list(keyfile, VAULT_CONF_KEY_CMD, "argv", &argv_len, &error);
	PROFILE_LOAD_ERROR;
	conf->cmd.respawn = g_key_file_get_boolean(keyfile, VAULT_CONF_KEY_CMD, "respawn", &error);
	PROFILE_LOAD_ERROR;

	/* bank */
	conf->bank.path = g_key_file_get_string(keyfile, VAULT_CONF_KEY_BANK, "path", &error);
	PROFILE_LOAD_ERROR;

	/*g_debug("%s: %s (%s)", conf->name, conf->cmd.exe, conf->cmd.note);*/

	/* Get files list */
	flist = g_key_file_get_groups(keyfile, &file_len);
	conf->files = g_ptr_array_new_with_free_func((GDestroyNotify)free_file);
	for(i = 0; i < file_len; i++) {
		if (g_str_has_prefix(flist[i], VAULT_CONF_KEYBEG_FILE)) {
			file = g_new(file_t, 1);
			file->name = g_strdup(g_strstrip(flist[i] + strlen(VAULT_CONF_KEYBEG_FILE)));
			file->fd_out = g_key_file_get_integer(keyfile, flist[i], "fd", &error);
			if (file->fd_out < 0) {
				error = g_error_new(1, G_KEY_FILE_ERROR_INVALID_VALUE, "Key file contains key '%s' in group '%s' which has invalid file descriptor value %d", "fd", flist[i], file->fd_out);
			}
			PROFILE_LOAD_ERROR;
			file->fd_tmp = -1;
			file->note = g_key_file_get_string(keyfile, flist[i], "note", &error);
			PROFILE_LOAD_ERROR;
			/* TODO: filter plugins */
			/*
			file->filter = g_key_file_get_string_list(keyfile, flist[i], "filter", &filter_len, &error);
			PROFILE_LOAD_ERROR;
			*/
			g_ptr_array_add(conf->files, file);
		}
	}

	/* Get environment */
	env_var = g_key_file_get_keys(keyfile, VAULT_CONF_KEY_ENV, &env_len, &error);
	PROFILE_LOAD_ERROR;
	conf->cmd.envp = g_new(char *, env_len + 1);
	for(i = 0; i < env_len; i++) {
		env_data = g_key_file_get_string(keyfile, VAULT_CONF_KEY_ENV, env_var[i], &error);
		PROFILE_LOAD_ERROR;
		conf->cmd.envp[i] = g_strconcat(env_var[i], "=", env_data, NULL);
		g_free(env_data);
	}
	conf->cmd.envp[i] = NULL;

	g_strfreev(env_var);
	g_strfreev(flist);
	return conf;
}

/* load_config - load configuration from @conf_dir into newly allocated GPtrArray
 */
GPtrArray *load_config(const char *conf_dir) {
	GPtrArray *profiles;
	GDir *confd;
	const char *confn;
	char *conf_file, *conf_ext, *conf_name;
	GError *error = NULL;

	/* List confs */
	profiles = g_ptr_array_new_with_free_func((GDestroyNotify)free_profile);
	confd = g_dir_open(conf_dir, 0, &error);
	if (error != NULL) {
		g_error("%s", error->message);
		return NULL;
	}
	while ((confn = g_dir_read_name(confd)) != NULL) {
		/*g_debug("dir: %s", confn);*/
		if (g_str_has_suffix(confn, VAULT_CONF_SUFFIX)) {
			conf_file = g_strconcat(conf_dir, G_DIR_SEPARATOR_S, confn, NULL);
			conf_name = g_strdup(confn);
			conf_ext = g_strrstr(conf_name, VAULT_CONF_SUFFIX);
			conf_name[conf_ext - conf_name] = '\0';
			g_ptr_array_add(profiles, profiles_load(conf_name, conf_file));
			g_free(conf_file);
			g_free(conf_name);
		}
	}
	g_dir_close(confd);
	return profiles;
}
