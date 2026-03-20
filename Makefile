CC = gcc
CFLAGS = -Wall -Wextra -fPIC -I./include
LDFLAGS = -shared
# 如果有 libldap 则链接
ifneq ($(wildcard /usr/lib/libldap*),)
LDFLAGS += -lldap
endif

# 源文件
SRC = src/utils.c \
      src/check_maxlength.c \
      src/check_charset.c \
      src/check_user.c \
      src/check_forbidden.c \
      src/check.c \
      src/policy.c \
      src/module.c

# 对象文件
OBJ = $(SRC:.c=.o)
OBJ := $(addprefix build/,$(notdir $(OBJ)))

# 库文件
MODULE = lib/ppolicy_ext.so

.PHONY: all clean test install

all: lib $(MODULE)

lib:
	mkdir -p lib

build:
	mkdir -p build

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

$(MODULE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "Module built: $@"

test: $(MODULE)
	@echo "Running unit tests..."
	gcc $(CFLAGS) -o test_utils tests/unit/test_utils.c src/utils.c && ./test_utils && rm -f test_utils
	gcc $(CFLAGS) -o test_maxlength tests/unit/test_check_maxlength.c src/check_maxlength.c && ./test_maxlength && rm -f test_maxlength
	gcc $(CFLAGS) -o test_charset tests/unit/test_check_charset.c src/check_charset.c src/utils.c && ./test_charset && rm -f test_charset
	gcc $(CFLAGS) -o test_user tests/unit/test_check_user.c src/check_user.c src/utils.c && ./test_user && rm -f test_user
	gcc $(CFLAGS) -o test_forbidden tests/unit/test_check_forbidden.c src/check_forbidden.c src/utils.c && ./test_forbidden && rm -f test_forbidden
	gcc $(CFLAGS) -o test_policy tests/unit/test_policy.c src/policy.c && ./test_policy && rm -f test_policy
	@echo "===================="
	@echo "All tests passed!"

clean:
	rm -rf build lib *.o test_* $(MODULE)

install: $(MODULE)
	install -d $(DESTDIR)/opt/ppolicy-extensions/lib
	install -m 755 $(MODULE) $(DESTDIR)/opt/ppolicy-extensions/lib/
	install -d $(DESTDIR)/etc/openldap/schema
	install -m 644 schema/ppolicy-extension.schema $(DESTDIR)/etc/openldap/schema/
	@echo "Installed to /opt/ppolicy-extensions"
