#pragma once
#ifndef WS_CLIENT_H
#define WS_CLIENT_H

#include "esp_err.h"
#include <stdbool.h>

#define MAX_HTTP_REQUEST_SIZE (1024 * 4)
#define TUNNEL_DEFAULT_RX_BUFFER_SIZE MAX_HTTP_REQUEST_SIZE
#define TUNNEL_DEFAULT_TX_BUFFER_SIZE 4096
#define TUNNEL_BUFFER_MIN_SIZE 256

#define TUNNEL_SELECT_TIMEOUT_MKS 20000
#define TUNNEL_SELECT_TLS_TIMEOUT_MKS 50000
#define TUNNEL_LATENCY_MS 100
#define MAX_EAGAIN_ATTEMPTS 20

// Arduino wrap
#define ROOT_CERT 1
#define ESP_LOGI(TAG, fmt, ...) config->log_func(3, TAG, fmt, ##__VA_ARGS__)
#define ESP_LOGW(TAG, fmt, ...) config->log_func(2, TAG, fmt, ##__VA_ARGS__)
#define ESP_LOGE(TAG, fmt, ...) config->log_func(1, TAG, fmt, ##__VA_ARGS__)
#define ESP_LOGD(TAG, fmt, ...) config->log_func(4, TAG, fmt, ##__VA_ARGS__)
#define ESP_LOGV(TAG, fmt, ...) config->log_func(5, TAG, fmt, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C"
{
#endif
    // WebSocket opcodes
    typedef enum
    {
        WS_OPCODE_CONTINUATION = 0x00,
        WS_OPCODE_TEXT = 0x01,
        WS_OPCODE_BINARY = 0x02,
        WS_OPCODE_CLOSE = 0x08,
        WS_OPCODE_PING = 0x09,
        WS_OPCODE_PONG = 0x0a,
        WS_OPCODE_FIN = 0x80,
        WS_OPCODE_NONE = 0x100
    } ws_opcode_t;

    // Connection states
    typedef enum
    {
        WS_STATE_DISCONNECTED,
        // WS_STATE_CONNECTING,
        WS_STATE_CONNECTED,
        WS_STATE_CLOSING,
        WS_STATE_ERROR // Not used?
    } ws_state_t;

    typedef enum
    {
        TUNNEL_STATE_DISCONNECTED,
        TUNNEL_STATE_AUTHENTICATING,
        TUNNEL_STATE_AUTHENTICATED,
        TUNNEL_STATE_RUNNING,
        TUNNEL_STATE_SUSPEND,
    } tunnel_state_t;

    typedef enum
    {
        TUNNEL_RX_MARKER_EMPTY = 0x00,
        TUNNEL_RX_MARKER_START = 0x01,
        TUNNEL_RX_MARKER_CONTINUATION = 0x02,
        TUNNEL_RX_MARKER_END = 0x80,
        TUNNEL_RX_MARKER_EOF = 0x10,
        TUNNEL_RX_MARKER_ERROR = 0xff,
    } tunnel_rx_marker_t;

    typedef struct
    {
        tunnel_state_t tunnel_state;
        uint8_t *suspend_command;
        size_t suspend_command_len;
        uint8_t *eof_marker;
        size_t eof_marker_len;
        uint8_t is_primary;
    } tunnel_info_t;

    typedef int tunnel_tx_func_t(const char *data, size_t len, tunnel_rx_marker_t *marker);
    typedef int tunnel_rx_func_t(const char *data, size_t len);
    typedef void tunnel_log_func_t(int lvl, const char *TAG, const char *fmt, ...);

    typedef struct
    {
        const char *provider_URI; // WebSocket provider URI (e.g., wss://device-tunnel.top:3333)
        const char *domain;       // Client domain
        const char *secret;       // Your account secret
        const char *name;         // Any valid device name for routing

        const char *client_cert; // Client certificate for mutual TLS (optional)
        const char *client_key;  // Client key for mutual TLS (optional)

        int32_t reconnect_timeout_ms; // Reconnect timeout in milliseconds (0 to disable)

        size_t rx_buffer_size; // Receive buffer size
        size_t tx_buffer_size; // Transmit buffer size

        tunnel_rx_func_t *rx_func; // Manula function for receiving data (used if local server proxy is disabled)
        tunnel_tx_func_t *tx_func; // Manula function for sending data (used if local server proxy is disabled)

        uint16_t local_port; // 0 - disabled local server proxy (you need to provide custom tunnel_tx_func and tunnel_rx_func)
        uint8_t auto_eof;    // 0 - auto send EOF markers in responses
        uint8_t is_public;   // 0 - private, 1 - public
        uint8_t non_block;   // Socket mode (0 = blocking, 1 = non-blocking)

        tunnel_log_func_t *log_func;
    } tunnel_config_t;

#define TUNNEL_DEFAULT_CONFIG()                          \
    {                                                    \
        .provider_URI = "wss://device-tunnel.top:3333",  \
        .domain = NULL,                                  \
        .secret = NULL,                                  \
        .name = "ESP-32",                                \
        .client_cert = NULL,                             \
        .client_key = NULL,                              \
        .reconnect_timeout_ms = 30000,                   \
        .rx_buffer_size = MAX_HTTP_REQUEST_SIZE,         \
        .tx_buffer_size = TUNNEL_DEFAULT_TX_BUFFER_SIZE, \
        .rx_func = NULL,                                 \
        .tx_func = NULL,                                 \
        .local_port = 80,                                \
        .auto_eof = 1,                                   \
        .is_public = 0,                                  \
        .non_block = 1,                                  \
        .log_func = NULL}

    esp_err_t tunnel_init(tunnel_config_t *_config);
    void tunnel_get_info(tunnel_info_t *out_info);
    void tunnel_destroy(void);
    esp_err_t local_client_init();

    // void send_ping(void);
    void send_login_request(void);
    void send_start_request(void);
    void send_pause_request(void);

    esp_err_t ws_connect();
    esp_err_t ws_send_text(char *text);
    esp_err_t ws_send_frame(uint8_t *data, size_t len, ws_opcode_t opcode, bool fin);
    // esp_err_t ws_client_send_binary(void *data, size_t len, bool fin);

#ifdef ROOT_CERT
    static const char *root_cert = "-----BEGIN CERTIFICATE-----\n"
                                   "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n"
                                   "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n"
                                   "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n"
                                   "WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n"
                                   "ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n"
                                   "MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n"
                                   "h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n"
                                   "0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n"
                                   "A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n"
                                   "T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n"
                                   "B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n"
                                   "B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n"
                                   "KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n"
                                   "OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n"
                                   "jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n"
                                   "qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n"
                                   "rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n"
                                   "HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n"
                                   "hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n"
                                   "ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n"
                                   "3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n"
                                   "NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n"
                                   "ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n"
                                   "TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n"
                                   "jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n"
                                   "oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n"
                                   "4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n"
                                   "mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n"
                                   "emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n"
                                   "-----END CERTIFICATE-----";
#endif

#ifdef __cplusplus
}
#endif
#endif