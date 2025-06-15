#pragma once
#ifndef WS_CLIENT_UTILS_H
#define WS_CLIENT_UTILS_H

#include <stdbool.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C"
{
#endif

    bool has_incoming_data(int sockfd, int timeout_ms);
    bool has_incoming_data_poll(int sockfd, int timeout_ms);

    bool is_wifi_connected(void);

    int header_end_index(char *buf, size_t len);

    bool extract_pem_block(const char *pem_input, bool is_key, const unsigned char **out_buf, size_t *out_len);

    void free_tls_pem_buffer(const unsigned char **buf, size_t *len);

    bool parse_uri(const char *uri, char **host, int *port, bool *use_ssl);

#ifdef __cplusplus
    extern "C"
}
#endif
#endif
