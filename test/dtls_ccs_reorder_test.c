/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Test DTLS CCS (ChangeCipherSpec) reordering tolerance */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

static int verify_accept_cb(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/* Test client CCS reorder: server receives Finished before CCS */
static int test_dtls_ccs_reorder_client(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0;

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

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(mempacket_swap_epoch(bio)))
        goto end;

    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test server CCS reorder: client receives Finished before CCS.
 * idx 0: tickets enabled  - server flight is [NST,CCS][Finished], use move_packet
 * idx 1: tickets disabled - server flight is [CCS,Finished], use swap_epoch only
 */
static int test_dtls_ccs_reorder_server(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0;

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

    if (idx == 1)
        SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;

    if (idx == 0) {
        if (!mempacket_move_packet(bio, 0, 1)
            && !TEST_true(mempacket_swap_epoch(bio)))
            goto end;
    } else {
        if (!TEST_true(mempacket_swap_epoch(bio)))
            goto end;
    }

    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Test session resumption with CCS reordering */
static int test_dtls_ccs_reorder_resumption(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    BIO *bio;
    int testresult = 0;

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

    if (idx == 0)
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

    if (!TEST_true(SSL_set_session(cssl, sess)))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio))
        goto end;

    if (!TEST_true(mempacket_swap_epoch(bio)))
        goto end;

    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_true(SSL_session_reused(cssl)))
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

/* Test duplicate CCS handling */
static int test_dtls_ccs_duplicate(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0;

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

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(mempacket_swap_epoch(bio))
        || !TEST_true(mempacket_dup_last_packet(bio)))
        goto end;

    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    /*
     * Force the server to read the duplicate CCS left in the queue.
     * The record layer silently discards it as an old-epoch record,
     * leaving SSL_ERROR_WANT_READ (no application data available).
     */
    {
        char buf[1];
        int ret;

        ret = SSL_read(sssl, buf, sizeof(buf));
        if (!TEST_int_le(ret, 0)
            || !TEST_int_eq(SSL_get_error(sssl, ret), SSL_ERROR_WANT_READ))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test mTLS with CCS reordering.
 * idx 0: swap_epoch only - CCS after Finished (Path A, TLS_ST_SR_CERT_VRFY)
 * idx 1: swap_epoch + move CCS to front - CCS before all handshake messages
 *        (Path B: cached at pre-flight state, consumed at TLS_ST_SR_CERT_VRFY)
 */
static int test_dtls_ccs_reorder_mtls(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    X509 *peer = NULL;
    int testresult = 0;

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

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(mempacket_swap_epoch(bio)))
        goto end;

    if (idx == 1) {
        int n = mempacket_get_count(bio);

        if (!TEST_true(mempacket_move_packet(bio, 0, n - 1)))
            goto end;
    }

    if (!TEST_int_gt(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_gt(SSL_connect(cssl), 0))
        goto end;

    peer = SSL_get1_peer_certificate(sssl);
    if (!TEST_ptr(peer))
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

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_dtls_ccs_reorder_client);
    ADD_ALL_TESTS(test_dtls_ccs_reorder_server, 2);
    ADD_ALL_TESTS(test_dtls_ccs_reorder_resumption, 2);
    ADD_TEST(test_dtls_ccs_duplicate);
    ADD_ALL_TESTS(test_dtls_ccs_reorder_mtls, 2);

    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
