# c-whatsapp — Makefile (primary build)
# Requires: gcc, make, OpenSSL + zlib dev headers.
#   sudo apt-get install -y libssl-dev zlib1g-dev
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -g
CPPFLAGS += -Iinclude
LDLIBS  += -lssl -lcrypto -lz -lsodium

BUILD   := build
LIB_SRC := src/binary.c src/auth.c src/crypto.c src/noise.c src/pb.c src/ws.c src/pairing.c src/socket.c src/send.c
LIB_OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(LIB_SRC))

all: $(BUILD)/c-whatsapp

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

test: all $(BUILD)/test_binary $(BUILD)/test_auth $(BUILD)/test_noise $(BUILD)/test_pb
	./$(BUILD)/test_binary
	./$(BUILD)/test_auth
	./$(BUILD)/test_noise
	./$(BUILD)/test_pb

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
