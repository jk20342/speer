# speer - Minimal P2P Networking Substrate
# High-performance C library for peer-to-peer networking

CC ?= gcc
CFLAGS = -std=c99 -Wall -Wextra -Werror -O3 -fPIC \
         -fno-exceptions -fno-unwind-tables \
         -ffunction-sections -fdata-sections \
         -fvisibility=hidden \
         -DNDEBUG

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS = -shared -Wl,--gc-sections
    TARGET = libspeer.so
    LIBS = -lm
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS = -shared -Wl,-dead_strip
    TARGET = libspeer.dylib
    LIBS =
endif
ifeq ($(OS),Windows_NT)
    LDFLAGS = -shared
    TARGET = speer.dll
    LIBS = -lws2_32 -liphlpapi -ladvapi32
    CFLAGS += -D_WIN32_WINNT=0x0600
    EXEEXT = .exe
else
    EXEEXT =
endif

# Unit test binaries (link against static lib)
UNIT_TESTS = \
	varint_length_prefix_check \
	multiaddr_peer_id_check \
	protobuf_sha256_check \
	buf_cursor_check \
	asn1_check \
	buffer_pool_check \
	yamux_hdr_check \
	yamux_session_check \
	multistream_check \
	quic_frame_check \
	tls_msg_check \
	tls13_full_handshake_check \
	tls13_negotiation_check \
	tls13_negative_vectors_check \
	tls13_hrr_check \
	tls13_key_update_check \
	tls13_psk_ticket_check \
	tls13_record_handshake_check \
	tls13_openssl_smoke_check \
	tls13_auth_check \
	packet_check \
	aead_check \
	ed25519_check \
	noise_check \
	x25519_check \
	quic_initial_check \
	quic_pkt_robustness_check \
	webpki_check \
	dht_check \
	dht_check_negative \
	dht_iterative_check \
	dht_maintenance_check \
	dht_libp2p_check \
	dht_libp2p_stream_check \
	mdns_check \
	dcutr_check \
	dcutr_relay_integration_check \
	relay_client_check \
	cpu_features_check \
	poly1305_kat_check \
	rng_failure_check \
	parser_robustness_check \
	chacha_counter_check \
	ecdsa_p256_check \
	identify_check \
	libp2p_tcp_primitives_check

TEST_PROGS = $(patsubst %,tests/%$(EXEEXT),$(UNIT_TESTS))

# Source files
SRCDIR = src
INCDIR = include
OBJDIR = obj

# All source files across module subdirectories
SUBDIRS = util crypto wire infra libp2p transport tls quic relay discovery
SOURCES = $(wildcard $(SRCDIR)/*.c) $(foreach d,$(SUBDIRS),$(wildcard $(SRCDIR)/$(d)/*.c))
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

# Add a -I for every module so unqualified includes work both from inside the same
# module and across modules.
SRC_INCLUDES = $(foreach d,$(SUBDIRS),-I$(SRCDIR)/$(d)) -I$(SRCDIR)
CFLAGS += $(SRC_INCLUDES)

# Static library
STATIC = libspeer.a

# Default target
all: $(STATIC) $(TARGET)

# Create object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Compile source files (out-of-tree, mirroring src/ subdirs into obj/)
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Static library
$(STATIC): $(OBJECTS)
	ar rcs $@ $^
	ranlib $@

# Shared library
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Examples
.PHONY: examples
clean:
	rm -rf $(OBJDIR) $(STATIC) $(TARGET)
	rm -f examples/echo_server examples/chat $(TEST_PROGS)

.PHONY: install
install: all
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include
	install -m 644 $(STATIC) $(DESTDIR)/usr/local/lib/
	install -m 644 $(INCDIR)/speer.h $(DESTDIR)/usr/local/include/
	install -m 644 $(INCDIR)/speer_libp2p_tcp.h $(DESTDIR)/usr/local/include/

# Development/debug build
debug: CFLAGS = -std=c99 -Wall -Wextra -g -O0 -DDEBUG -fsanitize=address,undefined
debug: LDFLAGS = -fsanitize=address,undefined
debug: all

# Release build with LTO
release: CFLAGS += -flto -march=native
release: LDFLAGS += -flto
release: all

# Amalgamated single-file build
amalgamate:
	@echo "/* speer - Minimal P2P Networking Substrate */" > speer.c
	@echo "/* Single-file amalgamation - $(shell date) */" >> speer.c
	@cat $(INCDIR)/speer.h >> speer.c
	@cat $(SOURCES) >> speer.c

tests/%$(EXEEXT): tests/%.c $(STATIC)
	$(CC) $(CFLAGS) -I$(INCDIR) $< $(STATIC) $(LIBS) -o $@

.PHONY: check
check: $(STATIC) $(TEST_PROGS)
	@echo "Running unit tests..."
	@failed=0; \
	for test in $(UNIT_TESTS); do \
		echo "==> $$test"; \
		./tests/$$test$(EXEEXT) || failed=$$((failed + 1)); \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo ""; \
		echo "$$failed test(s) FAILED"; \
		exit 1; \
	else \
		echo ""; \
		echo "All unit tests passed"; \
	fi

# Benchmark targets
.PHONY: bench
bench: $(STATIC)
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_crypto.c $(STATIC) $(LIBS) -o tests/benchmark/bench_crypto
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_wire.c $(STATIC) $(LIBS) -o tests/benchmark/bench_wire
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_protocol.c $(STATIC) $(LIBS) -o tests/benchmark/bench_protocol
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_throughput.c $(STATIC) $(LIBS) -o tests/benchmark/bench_throughput
	@echo "=== Crypto Benchmarks ==="
	@tests/benchmark/bench_crypto
	@echo "=== Wire Format Benchmarks ==="
	@tests/benchmark/bench_wire
	@echo "=== Protocol Benchmarks ==="
	@tests/benchmark/bench_protocol
	@echo "=== Throughput Benchmarks ==="
	@tests/benchmark/bench_throughput

.PHONY: bench-crypto
bench-crypto: $(STATIC)
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_crypto.c $(STATIC) $(LIBS) -o tests/benchmark/bench_crypto
	@tests/benchmark/bench_crypto

.PHONY: bench-wire
bench-wire: $(STATIC)
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_wire.c $(STATIC) $(LIBS) -o tests/benchmark/bench_wire
	@tests/benchmark/bench_wire

.PHONY: bench-protocol
bench-protocol: $(STATIC)
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_protocol.c $(STATIC) $(LIBS) -o tests/benchmark/bench_protocol
	@tests/benchmark/bench_protocol

.PHONY: bench-throughput
bench-throughput: $(STATIC)
	$(CC) $(CFLAGS) -O3 -I$(INCDIR) tests/benchmark/bench_throughput.c $(STATIC) $(LIBS) -o tests/benchmark/bench_throughput
	@tests/benchmark/bench_throughput

.PHONY: all clean install debug release amalgamate examples check bench bench-crypto bench-wire bench-protocol bench-throughput
