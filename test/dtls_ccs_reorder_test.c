/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* DTLS CCS early-arrival tests */

#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

static unsigned int infinite_timer_cb(SSL *s, unsigned int timer_us)
{
    (void)s;

    if (timer_us == 0)
        return 999999999;
    return timer_us;
}

static int verify_accept_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;

    return 1;
}

static int tick_key_renew_cb(SSL *s, unsigned char key_name[16],
    unsigned char iv[EVP_MAX_IV_LENGTH],
    EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx,
    int enc)
{
    const unsigned char tick_aes_key[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    unsigned char tick_hmac_key[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    OSSL_PARAM params[2];
    EVP_CIPHER *aes128cbc = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    int ret;

    if (aes128cbc == NULL)
        return -1;

    memset(key_name, 0, 16);
    memset(iv, 0, AES_BLOCK_SIZE);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CipherInit_ex(ctx, aes128cbc, NULL, tick_aes_key, iv, enc)
        || !EVP_MAC_init(hctx, tick_hmac_key, sizeof(tick_hmac_key), params))
        ret = -1;
    else
        ret = enc ? 1 : 2;

    EVP_CIPHER_free(aes128cbc);
    return ret;
}

static int verify_data_transfer(SSL *writer, SSL *reader)
{
    const char msg[] = "CCS reorder test";
    char buf[sizeof(msg)];

    if (!TEST_int_eq(SSL_write(writer, msg, sizeof(msg)), (int)sizeof(msg))
        || !TEST_int_eq(SSL_read(reader, buf, sizeof(buf)), (int)sizeof(msg))
        || !TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        return 0;
    return 1;
}

/* Move CCS just before the handshake message given by before_hs_msg. */
static int reorder_ccs(BIO *bio, int before_hs_msg)
{
    int target_pkt = -1, target_rec = -1;
    int ccs_pkt = -1, ccs_rec = -1;
    int p;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec)))
        return 0;

    if (target_rec > 0
        && !TEST_true(mempacket_split_packet_at(bio, target_pkt, target_rec)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC, -1,
            &ccs_pkt, &ccs_rec)))
        return 0;

    if (ccs_rec > 0
        && !TEST_true(mempacket_split_packet_at(bio, ccs_pkt, ccs_rec)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC, -1,
            &ccs_pkt, &ccs_rec))
        || !TEST_int_eq(ccs_rec, 0))
        return 0;

    if (!TEST_true(mempacket_split_packet_at(bio, ccs_pkt, 1)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec))
        || !TEST_int_eq(target_rec, 0))
        return 0;

    if (ccs_pkt == target_pkt)
        return 0;

    if (ccs_pkt > target_pkt) {
        if (!TEST_true(mempacket_move_packet(bio, target_pkt, ccs_pkt)))
            return 0;
    } else {
        for (p = ccs_pkt; p + 1 < target_pkt; p++) {
            if (!TEST_true(mempacket_move_packet(bio, p, p + 1)))
                return 0;
        }
    }

    /* CCS packet should be at position target_pkt - 1 */
    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC,
            -1, &ccs_pkt, &ccs_rec))
        || !TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec))
        || !TEST_int_eq(ccs_pkt + 1, target_pkt)
        || !TEST_int_eq(ccs_rec, 0)
        || !TEST_int_eq(target_rec, 0))
        return 0;

    return 1;
}

/* Flight 5 (C->S): [CKE][CCS][Finished] -> [CCS][CKE][Finished] */
static int test_dtls_ccs_before_cke(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_CLIENT_KEY_EXCHANGE)))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    if (!TEST_true(verify_data_transfer(sssl, cssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* mTLS Flight 5 (C->S): move CCS before Certificate. */
static int test_dtls_ccs_before_cert_mtls(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    X509 *peer = NULL;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_accept_cb);

    if (!TEST_true(SSL_CTX_use_certificate_file(cctx, cert, SSL_FILETYPE_PEM))
        || !TEST_true(SSL_CTX_use_PrivateKey_file(cctx, privkey,
            SSL_FILETYPE_PEM)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_CERTIFICATE)))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    peer = SSL_get1_peer_certificate(sssl);
    if (!TEST_ptr(peer))
        goto end;

    if (!TEST_true(verify_data_transfer(sssl, cssl)))
        goto end;

    testresult = 1;
end:
    X509_free(peer);
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* mTLS Flight 5 (C->S): move CCS before CertificateVerify. */
static int test_dtls_ccs_before_cv_mtls(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    X509 *peer = NULL;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_accept_cb);

    if (!TEST_true(SSL_CTX_use_certificate_file(cctx, cert, SSL_FILETYPE_PEM))
        || !TEST_true(SSL_CTX_use_PrivateKey_file(cctx, privkey,
            SSL_FILETYPE_PEM)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio))
        goto end;

    if (!TEST_true(reorder_ccs(bio, SSL3_MT_CERTIFICATE_VERIFY)))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    peer = SSL_get1_peer_certificate(sssl);
    if (!TEST_ptr(peer))
        goto end;

    if (!TEST_true(verify_data_transfer(sssl, cssl)))
        goto end;

    testresult = 1;
end:
    X509_free(peer);
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Flight 6 (S->C): [NST][CCS][Finished] -> [CCS][NST][Finished] */
static int test_dtls_ccs_before_nst(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_NEWSESSION_TICKET)))
        goto end;

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    if (!TEST_true(verify_data_transfer(cssl, sssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Resumption (no ticket) Flight 2 (S->C): [SH][CCS][Finished] -> [CCS][SH][Finished] */
static int test_dtls_ccs_before_sh_resume(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    BIO *bio;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto end;

    sess = SSL_get1_session(cssl);
    if (!TEST_ptr(sess))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_true(SSL_set_session(cssl, sess)))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_SERVER_HELLO)))
        goto end;

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    if (!TEST_true(SSL_session_reused(cssl)))
        goto end;

    if (!TEST_true(verify_data_transfer(cssl, sssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_SESSION_free(sess);
    return testresult;
}

/* Resumption (ticket renewal) Flight 2 (S->C): move CCS before NST. */
static int test_dtls_ccs_before_nst_resume(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    BIO *bio;
    int testresult = 0, ret;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_VERSION, 0,
            &sctx, &cctx, cert, privkey)))
        return 0;

#ifndef OPENSSL_NO_DTLS1_2
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA")))
        goto end;
#else
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA:@SECLEVEL=0")))
        goto end;
#endif

    if (!TEST_true(SSL_CTX_set_tlsext_ticket_key_evp_cb(sctx,
            tick_key_renew_cb)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto end;

    sess = SSL_get1_session(cssl);
    if (!TEST_ptr(sess))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_true(SSL_set_session(cssl, sess)))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;

    if (!TEST_true(reorder_ccs(bio, SSL3_MT_NEWSESSION_TICKET)))
        goto end;

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    if (!TEST_true(SSL_session_reused(cssl)))
        goto end;

    if (!TEST_true(verify_data_transfer(cssl, sssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_SESSION_free(sess);
    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_dtls_ccs_before_cke);
    ADD_TEST(test_dtls_ccs_before_cert_mtls);
    ADD_TEST(test_dtls_ccs_before_cv_mtls);
    ADD_TEST(test_dtls_ccs_before_nst);
    ADD_TEST(test_dtls_ccs_before_sh_resume);
    ADD_TEST(test_dtls_ccs_before_nst_resume);

    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
