#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

uint8_t client_nonce[NONCE_SIZE];
uint8_t server_nonce[NONCE_SIZE];

static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    uint64_t value = 0;

    // read the bytes left to right and build the number
    for (size_t i = 0; i < nbytes; i++) {
        value = (value << 8) | bytes[i];
    }

    return value;
}


static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    if (life == NULL || start_ts == NULL || end_ts == NULL) {
        return false;
    }

    // lifetime should be 16 bytes: 8 for start, 8 for end
    if (life->length != 16 || life->val == NULL) {
        return false;
    }

    const uint8_t* bytes = life->val;

    *start_ts = read_be_uint(bytes, 8);
    *end_ts = read_be_uint(bytes + 8, 8);

    // start time can't be after end time
    if (*start_ts > *end_ts) {
        return false;
    }

    return true;
}

static void enforce_lifetime_valid(const tlv* life) {
    uint64_t start_ts;
    uint64_t end_ts;

    // if parsing fails it's malformed input
    if (!parse_lifetime_window(life, &start_ts, &end_ts)) {
        exit(6);
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        exit(6);
    }

    // cert must be valid at the current time
    if ((uint64_t) now < start_ts || (uint64_t) now > end_ts) {
        exit(1);
    }
}
static void enforce_hostname_valid(const tlv* cert) {
    tlv* dns = get_tlv((tlv*) cert, DNS_NAME);

    if (dns == NULL || dns->val == NULL || hostname == NULL) {
        exit(2);
    }

    size_t host_len = strlen(hostname);

    if (dns->length != host_len) {
        exit(2);
    }

    // check the cert dns name matches the expected hostname
    if (memcmp(dns->val, hostname, host_len) != 0) {
        exit(2);
    }
}

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();
    
    priv_key = NULL;
    client_hello = NULL;
    server_hello = NULL;

    // client setup
    if (state_sec == CLIENT_CLIENT_HELLO_SEND || state_sec == CLIENT_SERVER_HELLO_AWAIT) {
        load_ca_public_key("ca_public_key.bin");

        // create ephemeral keypair for this handshake
        generate_private_key();
        derive_public_key();

        priv_key = get_private_key();
    }

    // Server side: load certificate and prepare ephemeral keypair.
else if (state_sec == SERVER_CLIENT_HELLO_AWAIT || state_sec == SERVER_SERVER_HELLO_SEND) {
        load_certificate("server_cert.bin");

        generate_private_key();
        derive_public_key();

        priv_key = get_private_key();
    }
    else {
        exit(6);
    }
}

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    switch ( state_sec ) {

    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        // generate client nonce and keep it for later
        generate_nonce(client_nonce, NONCE_SIZE);

        client_hello = create_tlv(CLIENT_HELLO);

        // protocol version
        tlv* version_tlv = create_tlv(VERSION_TAG);
        uint8_t version = PROTOCOL_VERSION;
        add_val(version_tlv, &version, 1);
        add_tlv(client_hello, version_tlv);

        // client nonce
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, client_nonce, NONCE_SIZE);
        add_tlv(client_hello, nonce_tlv);

        // client ephemeral public key
        tlv* pubkey_tlv = create_tlv(PUBLIC_KEY);
        add_val(pubkey_tlv, public_key, pub_key_size);
        add_tlv(client_hello, pubkey_tlv);

        uint16_t msg_len = serialize_tlv(out_buf, client_hello);

        if (msg_len > out_cap) {
            exit(6);
        }

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t) msg_len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");
        UNUSED(out_buf);
        UNUSED(out_cap);
        // TODO: build SERVER_HELLO with NONCE, CERTIFICATE, PUBLIC_KEY, HANDSHAKE_SIGNATURE.
        // Sign the expected handshake transcript, derive session keys, then enter DATA_STATE.
        return (ssize_t) 0;
    }
    case DATA_STATE: {
        UNUSED(out_buf);
        UNUSED(out_cap);
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        return (ssize_t) 0;
    }
    default:
        // TODO: handle unexpected states.
        return (ssize_t) 0;
    }
}

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {

    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse CLIENT_HELLO, validate required fields and protocol version.
        // Load peer ephemeral key, store client nonce, and transition to SERVER_SERVER_HELLO_SEND.
        break;
    }

    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");

        server_hello = deserialize_tlv(in_buf, in_len);
        if (server_hello == NULL || server_hello->type != SERVER_HELLO) {
            exit(6);
        }

        tlv* nonce_tlv = NULL;
        tlv* cert_tlv = NULL;
        tlv* pubkey_tlv = NULL;
        tlv* hs_sig_tlv = NULL;

        // grab the pieces from server hello
        for (int i = 0; i < MAX_CHILDREN; i++) {
            tlv* child = server_hello->children[i];
            if (child == NULL) continue;

            if (child->type == NONCE) nonce_tlv = child;
            else if (child->type == CERTIFICATE) cert_tlv = child;
            else if (child->type == PUBLIC_KEY) pubkey_tlv = child;
            else if (child->type == HANDSHAKE_SIGNATURE) hs_sig_tlv = child;
        }

        if (nonce_tlv == NULL || cert_tlv == NULL || pubkey_tlv == NULL || hs_sig_tlv == NULL) {
            exit(6);
        }

        if (nonce_tlv->val == NULL || nonce_tlv->length != NONCE_SIZE) {
            exit(6);
        }

        memcpy(server_nonce, nonce_tlv->val, NONCE_SIZE);

        tlv* cert_dns = get_tlv(cert_tlv, DNS_NAME);
        tlv* cert_key = get_tlv(cert_tlv, PUBLIC_KEY);
        tlv* cert_sig = get_tlv(cert_tlv, SIGNATURE);
        tlv* cert_life = get_tlv(cert_tlv, LIFETIME);

        if (cert_dns == NULL || cert_key == NULL || cert_sig == NULL || cert_life == NULL) {
            exit(6);
        }

        enforce_lifetime_valid(cert_life);
        enforce_hostname_valid(cert_tlv);

        uint8_t cert_data_buf[2048];
        size_t cert_data_len = 0;

        cert_data_len += serialize_tlv(cert_data_buf + cert_data_len, cert_dns);
        cert_data_len += serialize_tlv(cert_data_buf + cert_data_len, cert_life);
        cert_data_len += serialize_tlv(cert_data_buf + cert_data_len, cert_key);

        if (verify(cert_sig->val, cert_sig->length,
                   cert_data_buf, cert_data_len, ec_ca_public_key) != 1) {
            exit(1);
        }

        // verify handshake signature
        load_peer_public_key(cert_key->val, cert_key->length);
        EVP_PKEY* server_identity_key = ec_peer_public_key;

        uint8_t hs_data_buf[4096];
        size_t hs_data_len = 0;

        hs_data_len += serialize_tlv(hs_data_buf + hs_data_len, client_hello);
        hs_data_len += serialize_tlv(hs_data_buf + hs_data_len, nonce_tlv);
        hs_data_len += serialize_tlv(hs_data_buf + hs_data_len, pubkey_tlv);

        if (verify(hs_sig_tlv->val, hs_sig_tlv->length,
                   hs_data_buf, hs_data_len, server_identity_key) != 1) {
            exit(3);
        }

        // switch to server ephemeral key for secret derivation
        load_peer_public_key(pubkey_tlv->val, pubkey_tlv->length);

        set_private_key(priv_key);
        derive_secret();

        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);

        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
