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
	packet_check \
	aead_check \
	ed25519_check \
	noise_check \
	x25519_check \
	quic_initial_check \
	webpki_check \
	dht_check \
	dht_iterative_check \
	dht_maintenance_check \
	dht_libp2p_check \
	dht_libp2p_stream_check \
	mdns_check \
	dcutr_check \
	dcutr_relay_integration_check \
	relay_client_check \
	cpu_features_check

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
	tests/varint_length_prefix_check$(EXEEXT)
	tests/multiaddr_peer_id_check$(EXEEXT)
	tests/protobuf_sha256_check$(EXEEXT)
	tests/buf_cursor_check$(EXEEXT)
	tests/asn1_check$(EXEEXT)
	tests/buffer_pool_check$(EXEEXT)
	tests/yamux_hdr_check$(EXEEXT)
	tests/yamux_session_check$(EXEEXT)
	tests/multistream_check$(EXEEXT)
	tests/quic_frame_check$(EXEEXT)
	tests/tls_msg_check$(EXEEXT)
	tests/tls13_full_handshake_check$(EXEEXT)
	tests/tls13_negotiation_check$(EXEEXT)
	tests/tls13_negative_vectors_check$(EXEEXT)
	tests/tls13_hrr_check$(EXEEXT)
	tests/tls13_key_update_check$(EXEEXT)
	tests/tls13_psk_ticket_check$(EXEEXT)
	tests/tls13_record_handshake_check$(EXEEXT)
	tests/tls13_openssl_smoke_check$(EXEEXT)
	tests/packet_check$(EXEEXT)
	tests/aead_check$(EXEEXT)
	tests/ed25519_check$(EXEEXT)
	tests/noise_check$(EXEEXT)
	tests/x25519_check$(EXEEXT)
	tests/quic_initial_check$(EXEEXT)
	tests/webpki_check$(EXEEXT)
	tests/dht_check$(EXEEXT)
	tests/dht_iterative_check$(EXEEXT)
	tests/dht_maintenance_check$(EXEEXT)
	tests/dht_libp2p_check$(EXEEXT)
	tests/dht_libp2p_stream_check$(EXEEXT)
	tests/mdns_check$(EXEEXT)
	tests/dcutr_check$(EXEEXT)
	tests/dcutr_relay_integration_check$(EXEEXT)
	tests/relay_client_check$(EXEEXT)
	tests/cpu_features_check$(EXEEXT)

.PHONY: all clean install debug release amalgamate examples check
