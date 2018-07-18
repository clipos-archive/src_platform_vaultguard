// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.
/* 
 * vault-exec.c - VaultGuard exec
 * Copyright (C) 2012 ANSSI
 * Author: Mickaël Salaün <clipos@ssi.gouv.fr>
 *
 * Distributed under the terms of the GNU Lesser General Public License v2.1
 *
 * Need some rights: SUID to "_vault" and SGID to "vault_guard" (+CAP_DAC_OVERRIDE)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/capability.h>
#include <clip.h>

#include "config.h"
#include "vault-exec.h"

void _print_error(const char *func, const int line, const char *arg) {
	char *msg;
	char tmpl[] = "Vault error (%d) in %s at %d [%s]";
	if (!arg) {
		tmpl[strlen(tmpl) - 5] = 0;
	}
	/* TODO: check and use stderr */
	if (asprintf(&msg, tmpl, errno, func, line, arg) != -1) {
		perror(msg);
		free(msg);
	}
}

void _print_msg(const char *func, const int line) {
	printf("Vault error in %s at %d\n", func, line);
}

#define WRAP_MODE_BEGIN \
	int error;\
	mode_t mask;\
	mask = umask(VAULT_UMASK);

#define WRAP_MODE_END \
	umask(mask);\
	return error;

int _open(const char *pathname, int flags) {
	WRAP_MODE_BEGIN;
	error = open(pathname, flags);
	WRAP_MODE_END;
}

int _open_create(const char *pathname, int flags, mode_t mode) {
	WRAP_MODE_BEGIN;
	error = open(pathname, flags, mode);
	WRAP_MODE_END;
}

int _openat(int dirfd, const char *pathname, int flags) {
	WRAP_MODE_BEGIN;
	error = openat(dirfd, pathname, flags);
	WRAP_MODE_END;
}

int _openat_create(int dirfd, const char *pathname, int flags, mode_t mode) {
	WRAP_MODE_BEGIN;
	error = openat(dirfd, pathname, flags, mode);
	WRAP_MODE_END;
}

int _mkdirat(int dirfd, const char *pathname, mode_t mode) {
	WRAP_MODE_BEGIN;
	error = mkdirat(dirfd, pathname, mode);
	WRAP_MODE_END;
}

int check_bank_parent(int fd) {
	struct stat st;
	int ret;
	ERROR_RET1_CHECK(fd == -1);
	ret = fstat(fd, &st);
	ERROR_RET1_CHECK(ret);
	ERROR_RET1_CHECK(st.st_uid != getuid());
	ERROR_RET1_CHECK((st.st_mode && (mode_t)(VAULT_HOME_MODE | S_IFDIR)) == (mode_t)(VAULT_HOME_MODE | S_IFDIR));
	if (st.st_mode != (mode_t)(VAULT_HOME_MODE | S_IFDIR)) {
		print_error("Warning: the home directory is not exclusively writable by yourself.\n");
	}
	return 0;
}

int _check_bank(int fd, int nlink) {
	struct stat st;
	int ret;
	ERROR_RET1_CHECK(fd == -1);
	ret = fstat(fd, &st);
	ERROR_RET1_CHECK(ret);
	ERROR_RET1_CHECK(st.st_mode != (mode_t)(VAULT_ROOT_MODE | S_IFDIR));
	ERROR_RET1_CHECK(st.st_nlink != nlink);
	ERROR_RET1_CHECK(st.st_uid != VAULT_UID);
	ERROR_RET1_CHECK(st.st_gid != VAULT_GID_GUARD);
	return 0;
}

inline int check_bank_dir(int fd) {
	return _check_bank(fd, 2);
}

inline int check_bank_tree(int fd) {
	return _check_bank(fd, 4);
}

/* profile_lock - per user locking system */
int profile_lock(profile_t *conf) {
	int error = 0;
	int euid;
	int ret;

	if (!conf) {
		return 0;
	}

	/* Switch to real UID */
	/* TODO: Deactivate caps */
	euid = geteuid();
	g_debug("euid: %d", geteuid());
	if (seteuid(getuid()) == -1) {
		ERROR_PRINT_MSG("euid-1");
		return 1;
	}
	/* Does not need to open RW */
	conf->lock_fd = _openat_create(conf->profile_fd, conf->name, VAULT_SECDIR_FLAGS, VAULT_SECDIR_MODE);
	/* If no profile exist => lock-like */
	if (conf->lock_fd == -1) {
		error = 1;
		ERROR_PRINT_MSG("open lock");
	} else {
		ret = flock(conf->lock_fd, LOCK_EX | LOCK_NB);
		if (ret) {
			error = 1;
			ERROR_PRINT_MSG("flock");
		}
	}
	if (seteuid(euid) == -1) {
		ERROR_PRINT_MSG("euid-2");
	}
	return error;
}

int profile_close(profile_t *conf) {
	int error = 0;
	if (!conf) {
		return 0;
	}
	if (conf->profile_fd != -1 && close(conf->profile_fd)) {
		print_error("closing profile_fd failed\n");
		error = 1;
	}
	if (conf->tmp_fd != -1 && close(conf->tmp_fd)) {
		print_error("closing tmp_fd failed\n");
		error = 1;
	}
	if (conf->lock_fd != -1 && close(conf->lock_fd)) {
		print_error("closing lock_fd failed\n");
		error = 1;
	}
	return error;
}

/*
 * profile_init - make a vault hierarchy
 * Try to avoid TOCTOU as much as possible.
 *
 * e.g.
 * real user: 1000
 * _vault user: 5000
 * vault_guard group: 2000
 *
 * [drwxr-x--- 5000     2000    ]  .vault
 * ├── [drwxrwx--T 5000     2000    ]  profiles
 * │   └── [drwx------ 1000     2000    ]  tls
 * │       └── [-rw------- 1000     2000    ]  user-key
 * └─── [drwxrwx--T 5000     2000    ]  tmp
 */
int profile_init(profile_t *conf, profile_browse_t *plist) {
	int profile_fd = -1, tmp_fd = -1, root_fd = -1, home_fd = -1;
	int ret;
	char error = 0;
	char *dirpath = NULL, *bankname = NULL;
	gboolean justcreated = FALSE;
	gboolean match = FALSE;

	if (plist->error) {
		error = 1;
		goto drop_cap;
	}
	dirpath = dirname(strdupa(conf->bank.path));
	home_fd = _open_create(dirpath, VAULT_HOME_FLAGS, VAULT_HOME_MODE);
	/* Extra check needed if CAP_DAC_OVERRIDE is used */
	if (check_bank_parent(home_fd)) {
		print_error("The directory \"%s\" is not yours.\n", dirpath);
		error = 1;
		goto close_home;
	}
	/* Check for existing dir with good rights */
	bankname = basename(conf->bank.path);
	root_fd = _openat_create(home_fd, bankname, VAULT_ROOT_FLAGS, VAULT_ROOT_MODE);
	/* No root hierarchy? */
	if (root_fd == -1) {
		if (errno == ENOENT) {
			ret = _mkdirat(home_fd, bankname, VAULT_ROOT_MODE);
			ERROR_GOTO_IF(ret, drop_cap);
			/* XXX: Race condition, but only at initialization... */
			root_fd = _openat(home_fd, bankname, VAULT_ROOT_FLAGS);
			ERROR_GOTO_IF(root_fd == -1, drop_cap);
			/* mkdir profiles */
			ret = _mkdirat(root_fd, VAULT_SUBDIR_PROFILES, VAULT_SUBDIR_MODE);
			ERROR_GOTO_IF(ret, close_root);
			/* mkdir tmp */
			ret = _mkdirat(root_fd, VAULT_SUBDIR_TMP, VAULT_SUBDIR_MODE);
			ERROR_GOTO_IF(ret, close_root);
			justcreated = TRUE;
		} else {
			ERROR_PRINT_MSG("bad bank: %s", conf->bank.path);
			error = 1;
			goto drop_cap;
		}
	}
	if (check_bank_tree(root_fd)) {
		/* Bad FD or bad rights */
		print_error("Sanity check failed\n");
		error = 1;
		goto close_root;
	}
	/* TODO: Check conf->{profile,lock,tmp}_fd */
	profile_fd = _openat(root_fd, VAULT_SUBDIR_PROFILES, VAULT_SUBDIR_FLAGS);
	ERROR_GOTO_IF(profile_fd == -1, close_root);
	if (justcreated) {
		/* chmod profiles */
		ret = fchmod(profile_fd, VAULT_SUBDIR_MODE);
		ERROR_GOTO_IF(ret, close_root);
	}
	tmp_fd = _openat(root_fd, VAULT_SUBDIR_TMP, VAULT_SUBDIR_FLAGS);
	ERROR_GOTO_IF(tmp_fd == -1, close_root);
	if (justcreated) {
		/* chmod tmp */
		ret = fchmod(tmp_fd, VAULT_SUBDIR_MODE);
		ERROR_GOTO_IF(ret, close_root);
	}
	if (g_strcmp0(plist->profile, conf->name) == 0) {
		match = TRUE;
	}
close_root:
	if (close(root_fd)) {
		ERROR_PRINT();
		error = 1;
	}
close_home:
	if (close(home_fd)) {
		ERROR_PRINT();
		error = 1;
	}
drop_cap:
	if (error) {
		/* TODO: Use profile_close instead */
		print_error("failed with sub_fd\n");
		if (profile_fd != -1) {
			close(profile_fd);
		}
		if (tmp_fd != -1) {
			close(tmp_fd);
		}
	}
	/* Remove EUID (but keep EGID) and drop all capabilities (CAP_DAC_OVERRIDE) */
	/* TODO: Re-re-check privs/caps everywhere ! */
	error |= clip_revokeprivs(getuid(), -1, NULL, 0, 0);
	if (error) {
		plist->error = TRUE;
		return 1;
	}
	if (match) {
		/* cd ~/.vault/tmp */
		ERROR_RET1_IF(fchdir(tmp_fd));
		if (plist->conf) {
			print_error("profile clones!\n");
			return 1;
		}
		plist->conf = conf;
	}
	if (plist->full || match) {
		conf->profile_fd = profile_fd;
		conf->tmp_fd = tmp_fd;
	} else {
		/* TODO: Use profile_close instead */
		close(profile_fd);
		close(tmp_fd);
	}
	/* No lock for CmdImport => asynchronous importation */
	if (match && plist->lock) {
		if (profile_lock(conf)) {
			print_error("Profile already in use\n");
			error = 1;
			goto drop_cap;
		}
	}
	return 0;
}

void print_help(name) {
	fprintf(stderr, "%s usage:\n"
			"  List keys: -l\n"
			"  Import a key from stdin: -i -p <profile> -k <key>\n"
			"  Execute a profile: -e -p <profile>\n", VAULT_CMD_NAME);
}

char *sanitize_filename(char *file) {
	return g_strcanon(file, VAULT_VALID_STRING, '-');
}

typedef enum {
	CmdInvalid,
	CmdImport,
	CmdExecute,
	CmdList
} cmd_t;

cmd_t parse_options(const int argc, const char *argv[], char **profile, char **key) {
	cmd_t cmd = CmdInvalid;
	int choice;
	gboolean checked = FALSE;
	int nb_cmd = 0, nb_prof = 0, nb_key = 0;
	extern char *optarg;
	while ((choice = getopt(argc, argv, "p:k:iel")) != -1) {
		switch(choice) {
			case 'i':
				cmd = CmdImport;
				nb_cmd++;
				break;
			case 'e':
				cmd = CmdExecute;
				nb_cmd++;
				break;
			case 'l':
				cmd = CmdList;
				nb_cmd++;
				break;
			case 'p':
				if (!nb_prof) {
					*profile = sanitize_filename(g_strdup(optarg));
				}
				nb_prof++;
				break;
			case 'k':
				if (!nb_key) {
					*key = sanitize_filename(g_strdup(optarg));
				}
				nb_key++;
				break;
		}
	}
	if (cmd == CmdImport && nb_prof && nb_key) {
		checked = TRUE;
	}
	else if (cmd == CmdExecute && nb_prof && !nb_key) {
		checked = TRUE;
	}
	else if (cmd == CmdList && !nb_prof && !nb_key) {
		checked = TRUE;
	}
	if (!checked || nb_cmd > 1 || nb_prof > 1 || nb_key > 1) {
		if (nb_prof) {
			g_free(*profile);
			*profile = NULL;
		}
		if (nb_key) {
			g_free(*key);
			*key = NULL;
		}
		cmd = CmdInvalid;
	}
	return cmd;
}

/* set_unpriv - unset all capabilities and reset *[UG]ID */
int set_unpriv(void) {
	return clip_revokeprivs(getuid(), getgid(), NULL, 0, 0);
}

/* _vault_open_key - return the key file descriptor or -1 otherwise
 *
 * If the target fd is already open, then it will be close!
 */
int _vault_open_key(profile_t *conf, char *key, int flags) {
	int key_fd;
	char *key_path;
	key_path = g_strconcat(conf->name, G_DIR_SEPARATOR_S, key, NULL);
	key_fd = _openat_create(conf->profile_fd, key_path, flags, VAULT_SECFILE_MODE);
	/* if (key_fd == -1) {
		printf("path: %s fd: %d\n", key_path, key_fd);
		perror("key_fd");
	} */
	free(key_path);
	return key_fd;
}

int vault_open_key(profile_t *conf, char *key, int flags) {
	int error;

	/* Create directory if none */
	error = _mkdirat(conf->profile_fd, conf->name, VAULT_SECDIR_MODE);
	if (error && errno != EEXIST) {
		perror("mkdir profile failed\n");
		return -1;
	}
	return _vault_open_key(conf, key, flags);
}

int profile_secret_exist(profile_browse_t *plist) {
	int exist;
	int fdkey;
	fdkey = _vault_open_key(plist->conf, plist->key, VAULT_TESTFILE_FLAGS);
	close(fdkey);
	exist = (fdkey != -1);
	plist->full &= exist;
	return exist;
}

int profile_file_exist(file_t *file, profile_browse_t *plist) {
	plist->key = file->name;
	return profile_secret_exist(plist);
}

/* profile_exist - check if all secrets exist */
int profile_exist(profile_t *conf) {
	profile_browse_t plist = {
		.conf = conf,
		.full = TRUE
	};
	g_ptr_array_foreach(conf->files, (GFunc)profile_file_exist, &plist);
	if (!plist.full) {
		print_error("not all secret present\n");
	}
	return plist.full;
}

void profile_file_print(file_t *file, profile_browse_t *plist) {
	plist->key = file->name;
	printf("  [%c] %s (%d): %s\n", profile_secret_exist(plist) ? '+' : '-', file->name, file->fd_out, file->note);
}

void profile_print(profile_t *conf, profile_browse_t *plist) {
	plist->conf = conf;
	printf("%s: %s\n", conf->name, conf->cmd.note);
	g_ptr_array_foreach(conf->files, (GFunc)profile_file_print, plist);
}

void action_list(GPtrArray *profiles) {
	profile_browse_t plist = {
		.profile = NULL,
		.key = NULL
	};
	g_ptr_array_foreach(profiles, (GFunc)profile_print, &plist);
}

/* TODO: Check egid (sgid filepicker) */
int action_import(int fout) {
	int len = -1;
	char buf[1024];
	if (fout == STDIN_FILENO) {
		return 1;
	}
	while ((len = read(STDIN_FILENO, buf, sizeof(buf), 1)) > 0) {
		write(fout, buf, len);
	}
	if (len < 0) {
		return 1;
	}
	return 0;
}

void profile_find_file(file_t *key, search_file_t *search) {
	if (!search->match && g_strcmp0(key->name, search->name) == 0) {
		search->match = key;
	}
}

file_t *vault_get_key(profile_t *conf, char *key) {
	if (!conf) {
		return NULL;
	}
	search_file_t search = {
		.name = key,
		.match = NULL,
	};
	g_ptr_array_foreach(conf->files, (GFunc)profile_find_file, &search);
	return search.match;
}

void profile_files_cleanup(file_t *file, void *data) {
	if (file->fd_tmp != -1) {
		close(file->fd_tmp);
	}
}

void vault_files2tmp(file_t *file, profile_browse_t *plist) {
	char *tmp_path;
	int tmp_len;
	int fin, fdt;
	int error;
	int len;
	char buf[1024];
	struct stat st;
	int *swap_fd = NULL;

	if (plist->error) {
		return;
	}
	/* Create temporary file */
	tmp_len = asprintf(&tmp_path, "%d_%s_%s_XXXXXX", getuid(), plist->conf->name, file->name);
	if (tmp_len == -1) {
		ERROR_PRINT_MSG("tmp_len");
		return;
	}

	fdt = mkstemp(tmp_path);
	if (fdt == -1) {
		plist->error = TRUE;
		ERROR_PRINT();
		goto out_ok;
	}
	error = unlink(tmp_path);
	if (error) {
		plist->error = TRUE;
		close(fdt);
		ERROR_PRINT();
		goto close_fdt;
	}
	/* Copy file content */
	fin = vault_open_key(plist->conf, file->name, VAULT_SECFILE_READ_FLAGS);
	if (fin < 0) {
		print_error("vault_open_key failed: %d\n", fin);
		plist->error = TRUE;
		goto close_fdt;
	}
	while ((len = read(fin, buf, sizeof(buf), 1)) > 0) {
		write(fdt, buf, len);
	}
	close(fin);
	if (len < 0) {
		ERROR_PRINT();
		plist->error = TRUE;
		goto close_fdt;
	}
	/* TODO: Don't print msg if std fds are not open! */
	file->fd_tmp = fdt;
	if (file->fd_tmp != file->fd_out) {
		/* Hack to move opened fd */
		if (file->fd_out == plist->conf->profile_fd) {
			swap_fd = &plist->conf->profile_fd;
		} else if (file->fd_out == plist->conf->lock_fd) {
			swap_fd = &plist->conf->lock_fd;
		} else if (file->fd_out == plist->conf->tmp_fd) {
			swap_fd = &plist->conf->tmp_fd;
		}
		if (swap_fd) {
			*swap_fd = dup(*swap_fd);
			if (*swap_fd == -1) {
				ERROR_PRINT_MSG("dup profile");
				plist->error = TRUE;
				goto close_fdt;
			}
			if (close(file->fd_out)) {
				ERROR_PRINT_MSG("close");
				plist->error = TRUE;
				goto close_fdt;
			}
		}
		if (!fstat(file->fd_out, &st)) {
			ERROR_PRINT_MSG("fd already existing: %d", file->fd_out);
			plist->error = TRUE;
			goto close_fdt;
		}
		if (dup2(file->fd_tmp, file->fd_out) != file->fd_out) {
			ERROR_PRINT_MSG("dup2");
			plist->error = TRUE;
			goto close_fdt;
		}
		if (close(file->fd_tmp)) {
			ERROR_PRINT_MSG("close");
		}
	}
out_ok:
	free(tmp_path);
	return;
close_fdt:
	if (close(fdt)) {
		ERROR_PRINT_MSG("close");
	}
	goto out_ok;
}

int vault_std_assign(int src_fd, int dst_fd) {
	int error = 0;
	if (src_fd == -1 || dst_fd == -1) {
		/* ERROR_PRINT_MSG("bad fd"); */
		error = 1;
		goto close_src;
	}
	if (src_fd == dst_fd) {
		/* print_error("src and dst fd should be differents\n"); */
		error = 1;
		goto close_src;
	}
	if (dup2(src_fd, dst_fd) != dst_fd) {
		/* ERROR_PRINT_MSG("dup fd %d", dst_fd); */
		error = 1;
		goto close_src;
	}
close_src:
	close(src_fd);
	return error;
}

/* TODO: dup stderr! */
int vault_cleanup(profile_t *conf) {
	int error = 0;
	int cwd_fd;
	int stdfd;
	cwd_fd = _open(conf->cmd.cwd, VAULT_HOME_FLAGS);
	if (cwd_fd == -1) {
		error = 1;
		goto close_cwd;
	}
	if (fchdir(cwd_fd)) {
		error = 1;
		goto close_cwd;
	}

	if (conf->cmd.in) {
		stdfd = _open(conf->cmd.in, O_RDONLY);
		if ((error = vault_std_assign(stdfd, STDIN_FILENO))) {
			goto close_cwd;
		}
	}
	if (conf->cmd.out) {
		stdfd = _open(conf->cmd.out, O_APPEND);
		if ((error = vault_std_assign(stdfd, STDOUT_FILENO))) {
			goto close_cwd;
		}
	}
	if (conf->cmd.err) {
		stdfd = _open(conf->cmd.err, O_APPEND);
		if ((error = vault_std_assign(stdfd, STDERR_FILENO))) {
			goto close_cwd;
		}
	}
close_cwd:
	close(cwd_fd);

	return error;
}

int vault_exec(profile_t *conf) {
	int child, dead_new = -1, dead_old = -1;
	int error = 1;
	int status;
	profile_browse_t plist = {
		.conf = conf,
		.error = FALSE
	};

	child = fork();
	switch(child) {
		case -1:
			ERROR_PRINT_MSG("fork");
			break;
			;;
		case 0:
			g_ptr_array_foreach(conf->files, (GFunc)vault_files2tmp, &plist);
			profile_close(conf);
			if (plist.error) {
				/* Cleanup the mess */
				g_ptr_array_foreach(conf->files, (GFunc)profile_files_cleanup, NULL);
				return 1;
			}

			if (vault_cleanup(conf)) {
				/* print_error("Error on cleanup\n"); */
				return 1;
			}
			execve(conf->cmd.exe, conf->cmd.argv, conf->cmd.envp);
			ERROR_PRINT_MSG("%s", conf->cmd.exe);
			break;
			;;
		default:
			/* XXX: How to wait for ALL childs (with new session) ?! */
			do {
				dead_old = dead_new;
				error = WEXITSTATUS(status);
				dead_new = wait(&status);
			} while (errno != ECHILD);
			/* TODO: log */
			g_debug("Last child %d returned %d", dead_old, error);
			break;
			;;
	}
	return error;
}

int vault_init(GPtrArray *profiles, gboolean open_all, gboolean lock_profile, char *profile_match, profile_t **conf_ret) {
	profile_browse_t plist = {
		.profile = profile_match,
		.conf = NULL,
		.full = open_all,
		.lock = lock_profile,
		.error = FALSE
	};
	/* Bonus check */
	if (geteuid() != VAULT_UID && getegid() != VAULT_GID_GUARD) {
		print_error("Bad creds: need more powa!\n");
		return 1;
	}
	if (!profiles) {
		print_error("No profiles found\n");
		return 1;
	}
	g_ptr_array_foreach(profiles, (GFunc)profile_init, &plist);
	if (plist.error) {
		return 1;
	}
	if (profile_match && !plist.conf) {
		print_error("Not a valid profile\n");
		return 1;
	}
	if (conf_ret) {
		g_debug("setting conf_ret");
		*conf_ret = plist.conf;
	}
	return 0;
}

int main(const int argc, const char *argv[], const char *envp[]) {
	int error = 0;
	cmd_t cmd;
	char *profile = NULL, *key = NULL;
	profile_t *conf = NULL;
	file_t *key_file;
	GPtrArray *profiles = NULL;
	int fout = -1;
	int dolock = 1;

	if (clip_closeall(0)) {
		ERROR_PRINT();
		return 1;
	}
	cmd = parse_options(argc, argv, &profile, &key);

	switch(cmd) {
		case CmdImport:
			dolock = 0;
		case CmdExecute:
			profiles = load_config(VAULT_ETC);
			if (vault_init(profiles, FALSE, dolock, profile, &conf)) {
				error = 1;
				goto out_error;
			}
			break;
		case CmdList:
			profiles = load_config(VAULT_ETC);
			if (vault_init(profiles, TRUE, FALSE, NULL, &conf)) {
				error = 1;
				goto out_error;
			}
			break;
		default:
			if (set_unpriv()) {
				print_error("set_unpriv failed\n");
				return 1;
			}
			break;
	}

	switch(cmd) {
		case CmdInvalid:
			print_help();
			error = 1;
			break;
		case CmdExecute:
			g_debug("initial execution of %s", profile);
			if (profile_exist(conf)) {
do_execute:
				error = vault_exec(conf);
				if (!error && conf->cmd.respawn) {
					sleep(VAULT_RESPAWN_SLEEP);
					goto do_execute;
				}
			}
			break;
		case CmdImport:
			printf("import: %s/%s\n", profile, key);
			key_file = vault_get_key(conf, key);
			if (key_file == NULL) {
				error = 1;
				print_error("not a valid key\n");
				goto out_error;
			}
			fout = vault_open_key(conf, key, VAULT_SECFILE_WRITE_FLAGS);
			if (fout < 0) {
				print_error("vault_open_key failed\n");
				goto out_error;
			}
			error = action_import(fout);
			close(fout);
			if (error) {
				print_error("action_import failed\n");
				goto out_error;
			}
			break;
		case CmdList:
			action_list(profiles);
			break;
	}
out_error:
	profile_close(conf);
	if (set_unpriv()) {
		print_error("set_unpriv failed\n");
	}
	if (profiles) {
		g_ptr_array_free(profiles, TRUE);
	}
	g_free(profile);
	g_free(key);
	return error;
}
