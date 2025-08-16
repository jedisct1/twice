CFLAGS_FILE?=.cflags
COMPILE_TEST_FILE?=.test.c
PREFIX?=/usr/local

all: twice

twice: $(CFLAGS_FILE) Makefile src/twice.c src/os.c src/HiAE_amalgamated.c include/twice.h include/os.h
	$(CC) $$(cat "$(CFLAGS_FILE)") $(OPTFLAGS) -Iinclude -o $@ src/twice.c src/os.c src/HiAE_amalgamated.c
	strip $@

install: twice
	install -d $(PREFIX)/sbin
	install -m 0755 twice $(PREFIX)/sbin

uninstall:
	rm -f $(PREFIX)/sbin/twice

clean:
	rm -f twice *~ $(CFLAGS_FILE) $(COMPILE_TEST_FILE)

$(CFLAGS_FILE):
	@CFLAGS="$(CFLAGS)"
	@if [ -z "$$CFLAGS" ]; then \
		if [ ! -r "$(CFLAGS_FILE)" ]; then \
			echo "int main(void) { return 0; }" > "$(COMPILE_TEST_FILE)"; \
			for flag in -march=native -mtune=native -O3 -Wno-unused-command-line-argument; do \
				$(CC) $${CFLAGS} $${flag} "$(COMPILE_TEST_FILE)" >/dev/null 2>&1 && CFLAGS="$$CFLAGS $$flag"; \
			done; \
			rm -f a.out; \
			CFLAGS="$${CFLAGS} -Wall -W -Wshadow -Wmissing-prototypes"; \
		fi \
	fi; \
	echo "$$CFLAGS" > "$(CFLAGS_FILE)"

.PHONY: all install uninstall clean