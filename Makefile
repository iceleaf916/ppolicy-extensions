CC = gcc
CFLAGS = -Wall -Wextra -fPIC -I./include
LDFLAGS = -shared
# 如果有 libldap 则链接
HAS_LDAP := $(shell ldconfig -p 2>/dev/null | grep -q libldap && echo yes)
ifeq ($(HAS_LDAP),yes)
LDFLAGS += -lldap -llber
endif

# 架构支持
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
ARCH_NAME = amd64
else ifeq ($(ARCH),aarch64)
ARCH_NAME = arm64
else
ARCH_NAME = $(ARCH)
endif

# 源文件
SRC = src/utils.c \
      src/check_maxlength.c \
      src/check_charset.c \
      src/check_user.c \
      src/check_forbidden.c \
      src/check.c \
      src/module.c \
      src/check_password.c

# 对象文件
OBJ = $(SRC:.c=.o)
OBJ := $(addprefix build/$(ARCH_NAME)/,$(notdir $(OBJ)))

# 库文件
MODULE = lib/ppolicy_ext_$(ARCH_NAME).so

.PHONY: all clean test install build-all build-amd64 build-arm64

all: lib $(MODULE)

build-all: build-amd64 build-arm64

build-amd64:
	$(MAKE) ARCH=x86_64 CC=gcc

build-arm64:
	$(MAKE) ARCH=aarch64 CC=aarch64-linux-gnu-gcc

lib:
	mkdir -p lib

build/$(ARCH_NAME):
	mkdir -p build/$(ARCH_NAME)

build/$(ARCH_NAME)/%.o: src/%.c | build/$(ARCH_NAME)
	$(CC) $(CFLAGS) -c $< -o $@

$(MODULE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Module built: $@ ($(ARCH_NAME))"

test: $(MODULE)
	@echo "Running unit tests..."
	gcc $(CFLAGS) -o test_utils tests/unit/test_utils.c src/utils.c && ./test_utils && rm -f test_utils
	gcc $(CFLAGS) -o test_maxlength tests/unit/test_check_maxlength.c src/check_maxlength.c && ./test_maxlength && rm -f test_maxlength
	gcc $(CFLAGS) -o test_charset tests/unit/test_check_charset.c src/check_charset.c src/utils.c && ./test_charset && rm -f test_charset
	gcc $(CFLAGS) -o test_user tests/unit/test_check_user.c src/check_user.c src/utils.c && ./test_user && rm -f test_user
	gcc $(CFLAGS) -o test_forbidden tests/unit/test_check_forbidden.c src/check_forbidden.c src/utils.c && ./test_forbidden && rm -f test_forbidden
	@echo "===================="
	@echo "All tests passed!"

clean:
	rm -rf build lib *.o test_*

install: $(MODULE)
	install -d $(DESTDIR)/opt/ppolicy-extensions/lib
	install -m 755 $(MODULE) $(DESTDIR)/opt/ppolicy-extensions/lib/
	install -d $(DESTDIR)/etc/openldap/schema
	install -m 644 schema/ppolicy-extension.schema $(DESTDIR)/etc/openldap/schema/
	@echo "Installed to /opt/ppolicy-extensions"
