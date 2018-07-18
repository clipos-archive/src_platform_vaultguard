// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/* 
 *  vault-exec.h - VaultGuard definitions
 *  Copyright (C) 2012 ANSSI
 *  Author: Mickaël Salaün <clipos@ssi.gouv.fr>
 *
 *  Distributed under the terms of the GNU Lesser General Public License v2.1
 */

/* XXX: unistd.h mess up */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

/* Error handlers */
#define ERROR_PRINT() _print_error(__func__, __LINE__, NULL)
#define ERROR_PRINT_MSG(...) do { char *msg; if (asprintf(&msg, __VA_ARGS__) != -1) { _print_error(__func__, __LINE__, msg); free(msg); } } while (0);
#define ERROR_RET1_IF(cond) { if (cond) {_print_error(__func__, __LINE__, NULL); return 1; } }
#define ERROR_RET1_CHECK(cond) { if (cond) {_print_msg(__func__, __LINE__); return 1; } }
#define ERROR_GOTO_IF(cond, addr) { if (cond) {_print_error(__func__, __LINE__, NULL); error = 1; goto addr; } }
#define print_error(...) { fprintf(stderr, __VA_ARGS__); }

/* Files flags & modes */
#define VAULT_HOME_FLAGS O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_SYNC | O_RDONLY
#define VAULT_ROOT_FLAGS VAULT_HOME_FLAGS
#define VAULT_SUBDIR_FLAGS VAULT_ROOT_FLAGS
#define VAULT_SECDIR_FLAGS VAULT_SUBDIR_FLAGS
#define VAULT_SECFILE_WRITE_FLAGS O_CLOEXEC | O_NOFOLLOW | O_SYNC | O_RDWR | O_CREAT | O_TRUNC
#define VAULT_SECFILE_READ_FLAGS O_CLOEXEC | O_NOFOLLOW | O_SYNC | O_RDONLY
#define VAULT_TESTFILE_FLAGS O_CLOEXEC | O_NOFOLLOW | O_SYNC | O_RDONLY
#define VAULT_HOME_MODE S_IRWXU
#define VAULT_ROOT_MODE S_IRWXU | S_IXGRP | S_IRGRP
#define VAULT_SUBDIR_MODE S_IRWXU | S_IRWXG | S_ISVTX
#define VAULT_SECDIR_MODE S_IRWXU
#define VAULT_SECFILE_MODE S_IRUSR | S_IWUSR
#define VAULT_UMASK S_IRWXO

/* Files names */
#define VAULT_SUBDIR_PROFILES "profiles"
#define VAULT_SUBDIR_TMP "tmp"

/* Vault user & groups */
#ifndef VAULT_UID
#error "You need to define VAULT_UID"
#endif

#ifndef VAULT_GID_GUARD
#error "You need to define VAULT_GID_GUARD"
#endif

#ifndef VAULT_GID_IMPORT
#error "You need to define VAULT_GID_IMPORT"
#endif

/* Globals variables */
#define VAULT_RESPAWN_SLEEP 1
#define VAULT_CMD_NAME "vault"

/* User names policy */
#define ASCII_ALPHA "abcdefghijklmnopqrstuvwxyz"
#define ASCII_DIGIT "0123456789"
#define ASCII_SIGN "-"
/* No '.' nor '/' ! */
#define VAULT_VALID_STRING ASCII_ALPHA ASCII_DIGIT ASCII_SIGN

typedef struct {
	char *name;
	file_t *match;
} search_file_t;

typedef struct {
	char *profile;
	char *key;
	gboolean full;
	gboolean lock;
	gboolean error;
	profile_t *conf;
	int lock_fd;
} profile_browse_t;
