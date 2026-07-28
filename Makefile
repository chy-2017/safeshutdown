CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lpthread
PREFIX  = /usr/local
SBINDIR = $(PREFIX)/sbin
CONFDIR = /etc
SYSDDIR = /etc/systemd/system

.PHONY: all clean install uninstall

all: safeshutdown

safeshutdown: safeshutdown.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	strip $@
	@echo "=== 编译完成 ==="
	@ls -lh safeshutdown

clean:
	rm -f safeshutdown

install: safeshutdown safeshutdown.conf safeshutdown.service
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 safeshutdown $(DESTDIR)$(SBINDIR)/safeshutdown
	install -m 644 safeshutdown.conf $(DESTDIR)$(CONFDIR)/safeshutdown.conf
	install -m 644 safeshutdown.service $(DESTDIR)$(SYSDDIR)/safeshutdown.service
	@echo "=== 安装完成 ==="
	@echo "运行: sudo systemctl enable --now safeshutdown"

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/safeshutdown
	rm -f $(DESTDIR)$(CONFDIR)/safeshutdown.conf
	rm -f $(DESTDIR)$(SYSDDIR)/safeshutdown.service
	@echo "=== 已卸载 ==="
