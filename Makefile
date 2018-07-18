# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2012-2018 ANSSI. All Rights Reserved.
INC=/usr/include/glib-2.0 /usr/lib/glib-2.0/include /usr/include/clip
LIB=glib-2.0 clip

CC=gcc
LDLIBS := $(foreach l, $(LIB), -l$l)
CFLAGS += $(foreach d, $(INC), -I$d)

PREFIX ?= /usr
PREFIX_ETC ?= 
VAULT_BIN = $(DESTDIR)$(PREFIX)/bin/vault
VAULT_ETC = $(DESTDIR)$(PREFIX_ETC)/etc/vault.d

DEBUG ?= 0

VAULT_DEFINES = -DVAULT_UID=$(VAULT_UID) -DVAULT_GID_GUARD=$(VAULT_GID_GUARD) -DVAULT_GID_IMPORT=$(VAULT_GID_IMPORT) -DVAULT_ETC=\"$(VAULT_ETC)\" -DDEBUG=${DEBUG}

all: vault-exec

vault-exec: vault-exec.o config.o
	$(CC) -o $@ $(LDLIBS) $(LDFLAGS) $(CFLAGS) $^

%.o: %.c %.h
ifndef VAULT_UID
	@echo VAULT_UID must be defined >&2
	exit 1
endif
ifndef VAULT_GID_GUARD
	@echo VAULT_GID_GUARD must be defined >&2
	exit 1
endif
ifndef VAULT_GID_IMPORT
	@echo VAULT_GID_IMPORT must be defined >&2
	exit 1
endif
	$(CC) -c -o $@ $(LDLIBS) $(LDFLAGS) $(CFLAGS) $(VAULT_DEFINES) $<

clean:
	rm -- *.o

mrproper: clean
	rm -f -- vault-exec

install: vault-exec
	install -D vault-exec "$(VAULT_BIN)"
	chown "$(VAULT_UID):$(VAULT_GID_GUARD)" "$(VAULT_BIN)"
	chmod 6711 "$(VAULT_BIN)"
	mkdir -p "$(VAULT_ETC)"
