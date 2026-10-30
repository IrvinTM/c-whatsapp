# c-whatsapp — Makefile (primary build)
# Requires: gcc, make, OpenSSL + zlib + libsodium + qrencode dev headers.
#   Arch:   sudo pacman -S --needed base-devel openssl zlib libsodium qrencode
#   Debian: sudo apt-get install -y libssl-dev zlib1g-dev libsodium-dev libqrencode-dev
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -g
CPPFLAGS += -Iinclude
LDLIBS  += -lssl -lcrypto -lz -lsodium -lqrencode

# Size-first build: "make tiny" -> build/tiny/c-whatsapp (stripped, LTO, -Os).
TINY_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Os -DNDEBUG \
               -ffunction-sections -fdata-sections -flto \
               -fno-unwind-tables -fno-asynchronous-unwind-tables
TINY_LDFLAGS := -flto -Wl,--gc-sections -Wl,-O1 -s

BUILD   := build
LIB_SRC := src/binary.c src/auth.c src/crypto.c src/noise.c src/pb.c src/ws.c src/pairing.c src/socket.c src/send.c src/qr.c src/remind.c src/signal.c
LIB_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRC))

all: $(BUILD)/c-whatsapp

# Build the deployment binary in its own object dir so debug/tiny objects
# never mix. The output is stripped and should be a small fraction of -g.
tiny:
	$(MAKE) BUILD=$(BUILD)/tiny CFLAGS="$(TINY_CFLAGS)" \
		LDFLAGS="$(TINY_LDFLAGS)" $(BUILD)/tiny/c-whatsapp
	@ls -lh $(BUILD)/tiny/c-whatsapp

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD)/c-whatsapp: src/main.c $(LIB_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_binary: tests/test_binary.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_auth: tests/test_auth.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_noise: tests/test_noise.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_pb: tests/test_pb.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_signal: tests/test_signal.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_remind: tests/test_remind.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

test: all $(BUILD)/test_binary $(BUILD)/test_auth $(BUILD)/test_noise $(BUILD)/test_pb $(BUILD)/test_signal $(BUILD)/test_remind
	./$(BUILD)/test_binary
	./$(BUILD)/test_auth
	./$(BUILD)/test_noise
	./$(BUILD)/test_pb
	./$(BUILD)/test_signal
	./$(BUILD)/test_remind

clean:
	rm -rf $(BUILD)

.PHONY: all tiny test clean
