#include "speer_internal.h"
#include "x509_webpki.h"
#include "asn1.h"
#include "sig_dispatch.h"
#include "tls_msg.h"

static int parse_time(const speer_asn1_t* node, int64_t* out) {
    int yr, mo, d, h, m, s;
    const char* v = (const char*)node->value;
    size_t l = node->value_len;
    int yr_offset;
    if (node->tag == ASN1_UTCTIME) {
        if (l < 11) return -1;
        int yy = (v[0]-'0')*10 + (v[1]-'0');
        yr = yy < 50 ? 2000 + yy : 1900 + yy;
        yr_offset = 2;
    } else if (node->tag == ASN1_GENERALIZEDTIME) {
        if (l < 13) return -1;
        yr = (v[0]-'0')*1000 + (v[1]-'0')*100 + (v[2]-'0')*10 + (v[3]-'0');
        yr_offset = 4;
    } else return -1;
    mo = (v[yr_offset]-'0')*10 + (v[yr_offset+1]-'0');
    d  = (v[yr_offset+2]-'0')*10 + (v[yr_offset+3]-'0');
    h  = (v[yr_offset+4]-'0')*10 + (v[yr_offset+5]-'0');
    m  = (v[yr_offset+6]-'0')*10 + (v[yr_offset+7]-'0');
    s  = (v[yr_offset+8]-'0')*10 + (v[yr_offset+9]-'0');

    static const int days_before_month[] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int64_t t = (yr - 1970) * 365LL + ((yr - 1969) / 4) - ((yr - 1901) / 100) + ((yr - 1601) / 400);
    t += days_before_month[mo - 1] + (d - 1);
    if (mo > 2) {
        int leap = (yr % 4 == 0 && yr % 100 != 0) || (yr % 400 == 0);
        if (leap) t++;
    }
    t = t * 86400 + h * 3600 + m * 60 + s;
    *out = t;
    return 0;
}

static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55,0x1d,0x13};
static const uint8_t OID_KEY_USAGE[]         = {0x55,0x1d,0x0f};
static const uint8_t OID_EXT_KEY_USAGE[]     = {0x55,0x1d,0x25};
static const uint8_t OID_SAN[]               = {0x55,0x1d,0x11};
static const uint8_t OID_EKU_SERVER_AUTH[]   = {0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x01};
static const uint8_t OID_EKU_CLIENT_AUTH[]   = {0x2b,0x06,0x01,0x05,0x05,0x07,0x03,0x02};

static int oid_eq(const speer_asn1_t* n, const uint8_t* o, size_t ol) {
    return n->tag == ASN1_OID && n->value_len == ol && memcmp(n->value, o, ol) == 0;
}

static int parse_extensions(speer_x509_t* x, const speer_asn1_t* exts) {
    speer_asn1_t exts_seq;
    if (speer_asn1_parse(exts->value, exts->value_len, &exts_seq) != 0) return -1;
    if (exts_seq.tag != ASN1_SEQUENCE) return -1;
    const uint8_t* c; const uint8_t* e;
    if (speer_asn1_seq_iter_init(&exts_seq, &c, &e) != 0) return -1;

    while (c < e) {
        speer_asn1_t ext;
        if (speer_asn1_seq_next(&c, e, &ext) != 0) return -1;
        const uint8_t* xc; const uint8_t* xe;
        if (speer_asn1_seq_iter_init(&ext, &xc, &xe) != 0) continue;
        speer_asn1_t oid;
        if (speer_asn1_seq_next(&xc, xe, &oid) != 0) continue;
        speer_asn1_t maybe;
        if (speer_asn1_seq_next(&xc, xe, &maybe) != 0) continue;
        speer_asn1_t value;
        if (maybe.tag == ASN1_BOOLEAN) {
            if (speer_asn1_seq_next(&xc, xe, &value) != 0) continue;
        } else value = maybe;
        if (value.tag != ASN1_OCTET_STRING) continue;

        if (oid_eq(&oid, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS))) {
            speer_asn1_t bc;
            if (speer_asn1_parse(value.value, value.value_len, &bc) != 0) continue;
            if (bc.tag != ASN1_SEQUENCE) continue;
            const uint8_t* bc_c; const uint8_t* bc_e;
            speer_asn1_seq_iter_init(&bc, &bc_c, &bc_e);
            while (bc_c < bc_e) {
                speer_asn1_t inner;
                if (speer_asn1_seq_next(&bc_c, bc_e, &inner) != 0) break;
                if (inner.tag == ASN1_BOOLEAN) {
                    x->is_ca = inner.value_len > 0 && inner.value[0] != 0;
                } else if (inner.tag == ASN1_INTEGER) {
                    uint32_t pl = 0;
                    speer_asn1_get_int_u32(&inner, &pl);
                    x->path_len_constraint = (int)pl;
                }
            }
        } else if (oid_eq(&oid, OID_KEY_USAGE, sizeof(OID_KEY_USAGE))) {
            speer_asn1_t bs;
            if (speer_asn1_parse(value.value, value.value_len, &bs) != 0) continue;
            if (bs.tag == ASN1_BIT_STRING && bs.value_len >= 2) {
                x->key_usage = bs.value[1];
            }
        } else if (oid_eq(&oid, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE))) {
            speer_asn1_t s;
            if (speer_asn1_parse(value.value, value.value_len, &s) != 0) continue;
            const uint8_t* ec; const uint8_t* ee;
            if (speer_asn1_seq_iter_init(&s, &ec, &ee) != 0) continue;
            while (ec < ee) {
                speer_asn1_t o;
                if (speer_asn1_seq_next(&ec, ee, &o) != 0) break;
                if (oid_eq(&o, OID_EKU_SERVER_AUTH, sizeof(OID_EKU_SERVER_AUTH)))
                    x->ext_key_usage |= X509_EKU_SERVER_AUTH;
                if (oid_eq(&o, OID_EKU_CLIENT_AUTH, sizeof(OID_EKU_CLIENT_AUTH)))
                    x->ext_key_usage |= X509_EKU_CLIENT_AUTH;
            }
        } else if (oid_eq(&oid, OID_SAN, sizeof(OID_SAN))) {
            speer_asn1_t s;
            if (speer_asn1_parse(value.value, value.value_len, &s) != 0) continue;
            const uint8_t* sc; const uint8_t* se;
            if (speer_asn1_seq_iter_init(&s, &sc, &se) != 0) continue;
            while (sc < se && x->num_san_dns < SPEER_X509_MAX_DNS) {
                speer_asn1_t name;
                if (speer_asn1_seq_next(&sc, se, &name) != 0) break;
                if (name.tag == 0x82) {
                    size_t l = name.value_len < SPEER_X509_NAME_MAX - 1 ? name.value_len : SPEER_X509_NAME_MAX - 1;
                    COPY(x->san_dns[x->num_san_dns], name.value, l);
                    x->san_dns[x->num_san_dns][l] = 0;
                    x->num_san_dns++;
                }
            }
        }
    }
    return 0;
}

int speer_x509_parse(speer_x509_t* x, const uint8_t* der, size_t der_len) {
    ZERO(x, sizeof(*x));
    speer_asn1_t cert;
    if (speer_asn1_parse(der, der_len, &cert) != 0) return -1;
    if (cert.tag != ASN1_SEQUENCE) return -1;
    const uint8_t* cc; const uint8_t* ce;
    if (speer_asn1_seq_iter_init(&cert, &cc, &ce) != 0) return -1;

    speer_asn1_t tbs;
    if (speer_asn1_seq_next(&cc, ce, &tbs) != 0) return -1;
    if (tbs.tag != ASN1_SEQUENCE) return -1;
    x->tbs = tbs.tlv_start;
    x->tbs_len = tbs.tlv_total_len;

    speer_asn1_t sig_alg;
    if (speer_asn1_seq_next(&cc, ce, &sig_alg) != 0) return -1;
    if (sig_alg.tag == ASN1_SEQUENCE) {
        const uint8_t* sa_c; const uint8_t* sa_e;
        speer_asn1_seq_iter_init(&sig_alg, &sa_c, &sa_e);
        speer_asn1_t inner_oid;
        if (speer_asn1_seq_next(&sa_c, sa_e, &inner_oid) == 0) {
            x->sig_alg_oid = inner_oid.value;
            x->sig_alg_oid_len = inner_oid.value_len;
        }
    }

    speer_asn1_t sig_bs;
    if (speer_asn1_seq_next(&cc, ce, &sig_bs) != 0) return -1;
    if (sig_bs.tag != ASN1_BIT_STRING || sig_bs.value_len < 1) return -1;
    x->sig = sig_bs.value + 1;
    x->sig_len = sig_bs.value_len - 1;

    const uint8_t* tc; const uint8_t* te;
    if (speer_asn1_seq_iter_init(&tbs, &tc, &te) != 0) return -1;

    speer_asn1_t node;
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    if (node.tag == 0xa0) {
        if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;
    }
    if (speer_asn1_seq_next(&tc, te, &node) != 0) return -1;

    speer_asn1_t issuer;
    if (speer_asn1_seq_next(&tc, te, &issuer) != 0) return -1;
    x->issuer_dn = issuer.tlv_start;
    x->issuer_dn_len = issuer.tlv_total_len;

    speer_asn1_t validity;
    if (speer_asn1_seq_next(&tc, te, &validity) != 0) return -1;
    {
        const uint8_t* vc; const uint8_t* ve;
        speer_asn1_seq_iter_init(&validity, &vc, &ve);
        speer_asn1_t nb, na;
        if (speer_asn1_seq_next(&vc, ve, &nb) != 0) return -1;
        if (speer_asn1_seq_next(&vc, ve, &na) != 0) return -1;
        if (parse_time(&nb, &x->not_before_utc) != 0) return -1;
        if (parse_time(&na, &x->not_after_utc) != 0) return -1;
    }

    speer_asn1_t subject;
    if (speer_asn1_seq_next(&tc, te, &subject) != 0) return -1;
    x->subject_dn = subject.tlv_start;
    x->subject_dn_len = subject.tlv_total_len;

    speer_asn1_t spki;
    if (speer_asn1_seq_next(&tc, te, &spki) != 0) return -1;
    x->spki = spki.tlv_start;
    x->spki_len = spki.tlv_total_len;
    {
        const uint8_t* sc; const uint8_t* se;
        speer_asn1_seq_iter_init(&spki, &sc, &se);
        speer_asn1_t alg;
        if (speer_asn1_seq_next(&sc, se, &alg) == 0 && alg.tag == ASN1_SEQUENCE) {
            const uint8_t* ac; const uint8_t* ae;
            speer_asn1_seq_iter_init(&alg, &ac, &ae);
            speer_asn1_t alg_oid;
            if (speer_asn1_seq_next(&ac, ae, &alg_oid) == 0) {
                x->spki_alg_oid = alg_oid.value;
                x->spki_alg_oid_len = alg_oid.value_len;
            }
        }
        speer_asn1_t pk_bs;
        if (speer_asn1_seq_next(&sc, se, &pk_bs) == 0 && pk_bs.tag == ASN1_BIT_STRING && pk_bs.value_len >= 1) {
            x->spki_pubkey = pk_bs.value + 1;
            x->spki_pubkey_len = pk_bs.value_len - 1;
        }
    }

    while (tc < te) {
        speer_asn1_t opt;
        if (speer_asn1_seq_next(&tc, te, &opt) != 0) break;
        if (opt.tag == 0xa3) {
            parse_extensions(x, &opt);
        }
    }
    return 0;
}

static int hostname_match(const char* pattern, const char* host) {
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char* dot = host;
        while (*dot && *dot != '.') dot++;
        if (*dot != '.') return 0;
        dot++;
        size_t lp = 0; while (pattern[2 + lp]) lp++;
        size_t lh = 0; while (dot[lh]) lh++;
        if (lp != lh) return 0;
        for (size_t i = 0; i < lp; i++) {
            char a = pattern[2 + i]; char b = dot[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) return 0;
        }
        return 1;
    }
    size_t lp = 0; while (pattern[lp]) lp++;
    size_t lh = 0; while (host[lh]) lh++;
    if (lp != lh) return 0;
    for (size_t i = 0; i < lp; i++) {
        char a = pattern[i]; char b = host[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

int speer_x509_match_hostname(const speer_x509_t* cert, const char* hostname) {
    for (size_t i = 0; i < cert->num_san_dns; i++) {
        if (hostname_match(cert->san_dns[i], hostname)) return 0;
    }
    return -1;
}

static const uint8_t OID_RSA_SHA256[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b};
static const uint8_t OID_RSA_SHA384[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0c};
static const uint8_t OID_RSA_SHA512[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0d};
static const uint8_t OID_RSA_PSS[]    = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0a};
static const uint8_t OID_ECDSA_SHA256[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};
static const uint8_t OID_ECDSA_SHA384[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03};
static const uint8_t OID_ED25519[]    = {0x2b,0x65,0x70};

static int sig_alg_to_tls_id(const uint8_t* oid, size_t l, uint16_t* out) {
    if (l == sizeof(OID_RSA_SHA256) && memcmp(oid, OID_RSA_SHA256, l) == 0) { *out = TLS_SIGSCHEME_RSA_PKCS1_SHA256; return 0; }
    if (l == sizeof(OID_RSA_SHA384) && memcmp(oid, OID_RSA_SHA384, l) == 0) { *out = TLS_SIGSCHEME_RSA_PKCS1_SHA384; return 0; }
    if (l == sizeof(OID_RSA_SHA512) && memcmp(oid, OID_RSA_SHA512, l) == 0) { *out = TLS_SIGSCHEME_RSA_PKCS1_SHA512; return 0; }
    if (l == sizeof(OID_RSA_PSS) && memcmp(oid, OID_RSA_PSS, l) == 0) { *out = TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256; return 0; }
    if (l == sizeof(OID_ECDSA_SHA256) && memcmp(oid, OID_ECDSA_SHA256, l) == 0) { *out = TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256; return 0; }
    if (l == sizeof(OID_ECDSA_SHA384) && memcmp(oid, OID_ECDSA_SHA384, l) == 0) { *out = TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384; return 0; }
    if (l == sizeof(OID_ED25519) && memcmp(oid, OID_ED25519, l) == 0) { *out = TLS_SIGSCHEME_ED25519; return 0; }
    return -1;
}

static int dn_eq(const uint8_t* a, size_t al, const uint8_t* b, size_t bl) {
    return al == bl && memcmp(a, b, al) == 0;
}

static int verify_signed_by(const speer_x509_t* child, const uint8_t* parent_spki_pubkey, size_t parent_spki_pubkey_len) {
    uint16_t sig_id;
    if (sig_alg_to_tls_id(child->sig_alg_oid, child->sig_alg_oid_len, &sig_id) != 0) return -1;
    return speer_sig_verify(sig_id,
                              parent_spki_pubkey, parent_spki_pubkey_len,
                              child->tbs, child->tbs_len,
                              child->sig, child->sig_len);
}

int speer_x509_verify_chain(const speer_ca_store_t* store,
                              const speer_x509_t* leaf,
                              const speer_x509_t* intermediates, size_t num_intermediates,
                              const char* hostname,
                              int64_t now_utc) {
    if (now_utc < leaf->not_before_utc || now_utc > leaf->not_after_utc) return -1;
    if (hostname && speer_x509_match_hostname(leaf, hostname) != 0) return -1;
    if (!(leaf->ext_key_usage & X509_EKU_SERVER_AUTH) && leaf->ext_key_usage != 0) return -1;

    const speer_x509_t* current = leaf;
    for (size_t depth = 0; depth < num_intermediates; depth++) {
        const speer_x509_t* parent = NULL;
        for (size_t j = 0; j < num_intermediates; j++) {
            const speer_x509_t* cand = &intermediates[j];
            if (dn_eq(current->issuer_dn, current->issuer_dn_len,
                       cand->subject_dn, cand->subject_dn_len)) {
                parent = cand; break;
            }
        }
        if (!parent) break;
        if (now_utc < parent->not_before_utc || now_utc > parent->not_after_utc) return -1;
        if (!parent->is_ca) return -1;
        if (!(parent->key_usage & X509_KU_KEY_CERT_SIGN) && parent->key_usage != 0) return -1;
        if (verify_signed_by(current, parent->spki_pubkey, parent->spki_pubkey_len) != 0) return -1;
        current = parent;
    }

    for (size_t i = 0; i < store->count; i++) {
        const speer_ca_entry_t* ca = &store->entries[i];
        if (current->issuer_dn_len != ca->subject_len) continue;
        if (memcmp(current->issuer_dn, ca->der + ca->subject_offset, ca->subject_len) != 0) continue;
        if (now_utc < ca->not_before_utc || now_utc > ca->not_after_utc) continue;
        const uint8_t* ca_pub = ca->der + ca->spki_offset;
        size_t ca_pub_len = ca->spki_len;
        speer_asn1_t spki;
        if (speer_asn1_parse(ca_pub, ca_pub_len, &spki) != 0) continue;
        const uint8_t* sc; const uint8_t* se;
        if (speer_asn1_seq_iter_init(&spki, &sc, &se) != 0) continue;
        speer_asn1_t alg, pk;
        if (speer_asn1_seq_next(&sc, se, &alg) != 0) continue;
        if (speer_asn1_seq_next(&sc, se, &pk) != 0) continue;
        if (pk.tag != ASN1_BIT_STRING || pk.value_len < 1) continue;
        if (verify_signed_by(current, pk.value + 1, pk.value_len - 1) == 0) return 0;
    }
    return -1;
}
