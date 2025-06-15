#include "tunnel.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "esp_tls.h"
#include "esp_timer.h"
#include <sys/socket.h>
#include "utils.h"
#include "cJSON.h"

static const char *TAG = "WEB_TUNNEL";

static tunnel_config_t *config = NULL;
static tunnel_info_t info = {0}; // TUNNEL

// TLS connection
static esp_tls_t *tls;
static esp_tls_cfg_t tls_cfg = {0}; // todo move to local stack, not global
static int ws_sockfd;
// Local connection
static int local_sockfd;

// State management
static ws_state_t ws_state = WS_STATE_DISCONNECTED; // TODO move to info
static TaskHandle_t task_handle;
static uint64_t last_ping_dt = 0;
static uint64_t last_data_dt = 0;

// Message handling
static uint8_t *tx_buffer;
static char *rx_buffer;
static uint32_t rx_len = 0;
static uint16_t header_end = 0;

// URI// TODO move to info
static char *host;
static int port = 0;
static bool use_ssl = false;
static bool use_local = false;

static inline int ws_read(void *data, size_t len)
{
    return use_ssl ? esp_tls_conn_read(tls, data, len) : recv(ws_sockfd, data, len, MSG_DONTWAIT); // read(ws_sockfd, data, len);
}

static inline int ws_write(const void *data, size_t len)
{
    return use_ssl ? esp_tls_conn_write(tls, data, len) : send(ws_sockfd, data, len, MSG_DONTWAIT); // write(ws_sockfd, data, len);
}

esp_err_t ws_send_frame(uint8_t *data, size_t len, ws_opcode_t opcode, bool fin)
{
    if (!task_handle)
        return ESP_ERR_INVALID_STATE;
    if (ws_state != WS_STATE_CONNECTED)
    {
        ESP_LOGD(TAG, "tunnel not connected, continue");
        return ESP_OK;
    }
    if (len <= 0 && (opcode == WS_OPCODE_CONTINUATION || opcode == WS_OPCODE_BINARY || opcode == WS_OPCODE_TEXT))
    {
        ESP_LOGW(TAG, "logical error len = 0 in ws_send_frame");
        return ESP_OK;
    }

    uint8_t header[14];
    int header_len = 0;

    ESP_LOGD(TAG, "ws_send_frame: len=%d, fin=%d, opcode=%d", len, fin, opcode);

    // Первый байт: FIN + opcode
    header[header_len++] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);

    // Длина полезной нагрузки
    if (len < 126)
    {
        header[header_len++] = 0x80 | len; // mask bit + len
    }
    else if (len < 65536)
    {
        header[header_len++] = 0x80 | 126;
        header[header_len++] = (len >> 8) & 0xFF;
        header[header_len++] = len & 0xFF;
    }
    else
    {
        header[header_len++] = 0x80 | 127;
        for (int i = 0; i < 4; i++) // 64-bit payload length, first 4 bytes are zero.
            header[header_len++] = 0;
        header[header_len++] = (len >> 24) & 0xFF;
        header[header_len++] = (len >> 16) & 0xFF;
        header[header_len++] = (len >> 8) & 0xFF;
        header[header_len++] = len & 0xFF;
    }

    // Генерация и добавление маски
    uint8_t mask_key[4];
    esp_fill_random(mask_key, 4);
    memcpy(&header[header_len], mask_key, 4);
    header_len += 4;
    // Маскируем данные на месте/ не копируем, туннель один, обработка последовательна
    for (size_t i = 0; i < len; i++)
        data[i] ^= mask_key[i % 4];

    // Отправляем заголовок
    size_t written = 0;
    struct timeval tv = {0, (use_ssl ? TUNNEL_SELECT_TLS_TIMEOUT_MKS : TUNNEL_SELECT_TIMEOUT_MKS)};
    int attempts_eagain = 0; // Например, 20 * 50мс = 1 секундa таймаут
    while (written < header_len)
    {
        ssize_t w = ws_write(header + written, header_len - written);
        if (w < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                attempts_eagain++;
                if (attempts_eagain > MAX_EAGAIN_ATTEMPTS)
                {
                    ESP_LOGE(TAG, "header write timeout");
                    return ESP_FAIL;
                }
                // ждём готовности на запись
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(ws_sockfd, &wfds);
                select(ws_sockfd + 1, NULL, &wfds, NULL, &tv);
                continue;
            }
            else
            {
                ESP_LOGE(TAG, "header write error %d (%s)", errno, strerror(errno));
                return ESP_FAIL;
            }
        }
        // w == 0 — соединение закрыто
        if (w == 0)
        {
            ESP_LOGE(TAG, "header write returned 0, peer closed");
            return ESP_FAIL;
        }
        written += w;
    }

    // Отправляем payload
    size_t total_written = 0;
    attempts_eagain = 0;
    while (total_written < len)
    {
        int writen = ws_write(data + total_written, len - total_written);
        if (writen < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // Сокет не готов, ждем с помощью select()
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(ws_sockfd, &writefds);

                int activity = select(ws_sockfd + 1, NULL, &writefds, NULL, &tv);
                if (activity < 0)
                {
                    ESP_LOGE(TAG, "select() for ws write error: %d (%s)", errno, strerror(errno));
                    return ESP_FAIL;
                }
                else if (activity == 0)
                {
                    attempts_eagain++;
                    if (attempts_eagain > MAX_EAGAIN_ATTEMPTS)
                    {
                        ESP_LOGE(TAG, "Write to ws failed after %d EAGAIN attempts (timeout).", MAX_EAGAIN_ATTEMPTS);
                        return ESP_FAIL;
                    }
                    ESP_LOGD(TAG, "timeout ws waiting for write, attempt %d", attempts_eagain);
                }
                continue;
            }
            else
            {
                ESP_LOGE(TAG, "Write to ws error: %d (%s)", errno, strerror(errno));
                return ESP_FAIL;
            }
        }
        else if (writen == 0)
        {
            ESP_LOGE(TAG, "Write to ws returned 0 bytes. Peer has likely closed connection.");
            return ESP_FAIL;
        }
        else
        {
            total_written += writen;
            attempts_eagain = 0;
            ESP_LOGV(TAG, "sent %zu (%d) of %zu bytes to ws", total_written, writen, len);
        }
    }

    return total_written == len ? ESP_OK : ESP_FAIL;
}

static esp_err_t tunnel_on_error(bool ws, const char *error_msg)
{
    if (error_msg)
        ESP_LOGE(TAG, "%s", error_msg);

    rx_len = 0;
    header_end = 0;
    last_ping_dt = 0;

    if (use_local && local_sockfd > 0)
    {
        close(local_sockfd);
        local_sockfd = -1;
    }

    if (ws)
    { // TODO error chek
        info.tunnel_state = TUNNEL_STATE_DISCONNECTED;

        free(info.suspend_command);
        info.suspend_command = NULL;
        info.suspend_command_len = 0;

        free(info.eof_marker);
        info.eof_marker = NULL;
        info.eof_marker_len = 0;

        if (ws_state == WS_STATE_CONNECTED && ws_sockfd > 0)
        {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(ws_sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0)
                ws_send_frame(NULL, 0, WS_OPCODE_CLOSE, true);
            else
                ESP_LOGD(TAG, "ws state: %d (%s)", error, strerror(error));
        }

        ws_state = WS_STATE_CLOSING;
        if (use_ssl && tls)
            esp_tls_conn_destroy(tls);

        close(ws_sockfd);
        ws_sockfd = -1;
        tls = NULL;

        ESP_LOGI(TAG, "Connection closed");
        ws_state = WS_STATE_DISCONNECTED;
    }
    else
    {
        return ESP_OK;
    }

    return ESP_FAIL;
}

esp_err_t ws_send_text(char *text)
{
    if (!text)
        return ESP_ERR_INVALID_ARG;
    if (!task_handle)
        return ESP_ERR_INVALID_STATE;
    return ws_send_frame((uint8_t *)text, strlen(text), WS_OPCODE_TEXT, true);
}

static esp_err_t send_ping(void)
{
    return ws_send_frame(NULL, 0, WS_OPCODE_PING, true);
}

void send_login_request(void)
{
    cJSON *login = cJSON_CreateObject();
    cJSON_AddStringToObject(login, "type", "login");
    cJSON_AddStringToObject(login, "domain", config->domain);
    cJSON_AddStringToObject(login, "device", config->name);
    cJSON_AddStringToObject(login, "secret", config->secret);

    char *login_str = cJSON_PrintUnformatted(login);
    if (login_str && strlen(login_str) > 0)
    {
        ESP_LOGI(TAG, "Send login request");
        ws_send_text(login_str);
        free(login_str);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to send login request, invalid domain, device or secret");
    }
    cJSON_Delete(login);
}

void send_start_request(void)
{
    cJSON *start = cJSON_CreateObject();
    cJSON_AddStringToObject(start, "type", "start");
    cJSON_AddStringToObject(start, "usage", config->is_public ? "public" : "personal");

    char *start_str = cJSON_PrintUnformatted(start);
    if (start_str && strlen(start_str) > 0)
    {
        ESP_LOGI(TAG, "Send request to start tunnel");
        ws_send_text(start_str);
        free(start_str);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to send start request");
    }
    cJSON_Delete(start);
}

void send_pause_request(void)
{
    ESP_LOGI(TAG, "Send request to suspend tunnel");
    if (info.tunnel_state == TUNNEL_STATE_RUNNING)
    {
        ws_send_frame(info.suspend_command, info.suspend_command_len, WS_OPCODE_BINARY, true);
    }
    else
    {
        cJSON *stop = cJSON_CreateObject();
        cJSON_AddStringToObject(stop, "type", "stop");
        char *stop_str = cJSON_PrintUnformatted(stop);
        if (stop_str && strlen(stop_str) > 0)
        {
            ws_send_text(stop_str);
            free(stop_str);
        }
        else
        {
            ESP_LOGE(TAG, "Failed to send stop request");
        }
        cJSON_Delete(stop);
    }
    if (use_local && local_sockfd > 0)
    {
        close(local_sockfd);
        local_sockfd = -1;
    }
}

static void send_internal_error(const char *error_msg)
{
    const char error_page[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    uint16_t err_len = (error_msg ? strlen(error_msg) : 0);
    uint16_t total_len = sizeof(error_page) + err_len + info.eof_marker_len;
    char *message = malloc(total_len);
    if (!message)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for error page");
        return;
    }
    memcpy(message, error_page, sizeof(error_page) - 1);
    if (error_msg)
        memcpy(message + sizeof(error_page) - 1, error_msg, err_len);
    if (info.eof_marker_len > 0)
        memcpy(message + sizeof(error_page) - 1 + err_len, info.eof_marker, info.eof_marker_len);
    ws_send_frame((uint8_t *)message, total_len - 1, WS_OPCODE_BINARY, true);
    free(message);
}

static esp_err_t send_eof()
{
    if (info.eof_marker == NULL || info.eof_marker_len == 0 || !config->auto_eof)
        return ESP_OK;

    esp_err_t err = ws_send_frame(info.eof_marker, info.eof_marker_len, WS_OPCODE_CONTINUATION, true);
    if (err != ESP_OK)
    {
        tunnel_on_error(true, "Failed to send EOF marker");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t ws_connect()
{
    if (ws_state != WS_STATE_DISCONNECTED)
        return ESP_ERR_INVALID_STATE;

    // ws_state = WS_STATE_CONNECTING;
    ESP_LOGI(TAG, "Connecting to %s://%s:%d", use_ssl ? "wss" : "ws", host, port);

    tls = esp_tls_init();
    if (!tls)
    {
        ESP_LOGE(TAG, "Failed to initialize TLS");
        return ESP_FAIL;
    }

    int ret;
    if (use_ssl)
    {
        ret = esp_tls_conn_new_sync(host, strlen(host), port, &tls_cfg, tls);
        if (ret != 1)
        {
            esp_tls_error_handle_t err = {0};
            esp_tls_get_error_handle(tls, &err);
            ESP_LOGE(TAG, "Failed to establish connection with ret: %d, esp_tls_error: %s, (errno): %d",
                     ret, esp_err_to_name(err->last_error), err->esp_tls_error_code);
            esp_tls_conn_destroy(tls);
            tls = NULL;
            return ESP_FAIL;
        }

        esp_err_t err = esp_tls_get_conn_sockfd(tls, &ws_sockfd);
        if (err != ESP_OK)
            return err;

        // Информация о версии TLS/SSL
        mbedtls_ssl_context *ssl_ctx = esp_tls_get_ssl_context(tls);
        if (ssl_ctx)
        {
            const char *tls_version = mbedtls_ssl_get_version(ssl_ctx);
            const char *cipher_suite_name = mbedtls_ssl_get_ciphersuite(ssl_ctx);
            ESP_LOGD(TAG, "TLS version: %s, cipher suite: %s", tls_version, cipher_suite_name);
        }
    }
    else
    {
        esp_tls_last_error_t err = {0};
        esp_err_t ret = esp_tls_plain_tcp_connect(host, strlen(host), port, &tls_cfg, &err, &ws_sockfd);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "esp_tls_plain_tcp_connect failed with ret: %s,  esp_tls_error_code: %d (0x%08X), last_error (errno): %d (0x%08X)",
                     esp_err_to_name(ret), (int)err.esp_tls_error_code, (unsigned int)err.esp_tls_error_code,
                     (int)err.last_error, (unsigned int)err.last_error);
            return ESP_FAIL;
        }
        // Устанавливаем неблокирующий режим
        if (config->non_block)
        {
            int flags = fcntl(ws_sockfd, F_GETFL, 0);
            fcntl(ws_sockfd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    // Generate WebSocket key
    uint8_t key_bytes[16];
    esp_fill_random(key_bytes, 16);

    char key_b64[32] = {0};
    size_t key_len;
    mbedtls_base64_encode((unsigned char *)key_b64, sizeof(key_b64) - 1, &key_len, key_bytes, 16);

    // Send HTTP upgrade request
    char request[1024];
    int request_len = snprintf(request, sizeof(request),
                               "GET / HTTP/1.1\r\n"
                               "Host: %s:%d\r\n"
                               "Upgrade: websocket\r\n"
                               "Connection: Upgrade\r\n"
                               "Sec-WebSocket-Key: %s\r\n"
                               "Sec-WebSocket-Version: 13\r\n"
                               "\r\n",
                               host, port, key_b64);
    request[request_len] = '\0';

    ESP_LOGV(TAG, "Sending upgrade request: %s", request);
retry:
    if (ws_write(request, request_len) < request_len)
    {
        if (errno == EINPROGRESS)
        {
            ESP_LOGD(TAG, "Waiting for connection establishment...");
            vTaskDelay(pdMS_TO_TICKS(TUNNEL_LATENCY_MS));
            goto retry;
        }

        ESP_LOGE(TAG, "Failed to send upgrade request errno: %d, %s", errno, strerror(errno));
        goto fail;
    }

    char response[1024] = {0};
    int len = 0;
    for (int i = 0; i < 40; i++) // 8 seconds timeout //TODO calculate TUNNEL_LATENCY_MS
    {
        len = ws_read(response, sizeof(response) - 1);
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK)
        {
            vTaskDelay(pdMS_TO_TICKS(TUNNEL_LATENCY_MS));
            if (i % 10 == 0)
                ESP_LOGD(TAG, "Waiting for upgrade protocol...");
            continue;
        }
        if (len == 0)
        {
            vTaskDelay(pdMS_TO_TICKS(TUNNEL_LATENCY_MS));
            if (i % 10 == 0)
                ESP_LOGD(TAG, "Waiting for upgrade protocol...");
            continue;
        }
        if (len < 16)
        {
            ESP_LOGE(TAG, "Failed to establish connection, errno: %d (%s)", err, strerror(err));
            goto fail;
        }
        break;
    }
    response[len] = '\0';

    if (header_end_index(response, len) == -1)
    {
        ESP_LOGE(TAG, "Invalid upgrade protocol response: %s", response);
        goto fail;
    }
    ESP_LOGV(TAG, "Received upgrade response: %s", response);

    char *status_line = strtok(response, "\r\n");
    if (!status_line || !strstr(status_line, "101"))
    {
        if (!status_line)
            ESP_LOGE(TAG, "Invalid HTTP response format");
        else
        {
            ESP_LOGE(TAG, "Expected '101 Switching Protocols', got: %s", status_line);
            // Дополнительная диагностика для популярных ошибок
            if (strstr(status_line, "400"))
                ESP_LOGE(TAG, "Hint: Verify request format and headers");
            else if (strstr(status_line, "404"))
                ESP_LOGE(TAG, "Hint: Verify WebSocket endpoint path");
            else if (strstr(status_line, "403"))
                ESP_LOGE(TAG, "Hint: Verify authentication or origin");
        }
        goto fail;
    }

    // Check for Switching Protocols
    // Проверка обязательных заголовков
    bool upgrade_found = false;
    bool connection_found = false;
    bool accept_found = false;

    char *line = strtok(NULL, "\r\n");
    while (line)
    {
        if (strcasestr(line, "upgrade:") && strcasestr(line, "websocket"))
            upgrade_found = true;
        else if (strcasestr(line, "connection:") && strcasestr(line, "upgrade"))
            connection_found = true;
        else if (strcasestr(line, "sec-websocket-accept:"))
            accept_found = true;
        line = strtok(NULL, "\r\n");
    }
    // Проверка обязательных заголовков
    if (!upgrade_found)
    {
        ESP_LOGE(TAG, "Missing 'Upgrade: websocket' header");
        goto fail;
    }
    if (!connection_found)
    {
        ESP_LOGE(TAG, "Missing 'Connection: Upgrade' header");
        goto fail;
    }
    if (!accept_found)
    {
        ESP_LOGE(TAG, "Missing 'Sec-WebSocket-Accept' header");
        goto fail;
    }

    ws_state = WS_STATE_CONNECTED;
    last_data_dt = esp_timer_get_time();

    ESP_LOGI(TAG, "Tunnel connected, waiting for hello message");
    return ESP_OK;

fail:
    if (use_ssl)
        esp_tls_conn_destroy(tls);
    else
        close(ws_sockfd);
    tls = NULL;
    ws_sockfd = -1;
    return ESP_FAIL;
}

static esp_err_t tunnel_process_text_frame()
{
    rx_buffer[rx_len] = '\0';
    ESP_LOGD(TAG, "INCOMING message: %.*s", (int)(rx_len > 128 ? 128 : rx_len), rx_buffer);

    cJSON *json = cJSON_ParseWithLength(rx_buffer, rx_len);
    if (json)
    {
        cJSON *type = cJSON_GetObjectItem(json, "type");
        if (type && cJSON_IsString(type))
        {
            if (strcmp(type->valuestring, "hello") == 0)
            {
                info.tunnel_state = TUNNEL_STATE_AUTHENTICATING;
                send_login_request();
            }
            else if (strcmp(type->valuestring, "login") == 0)
            {
                cJSON *status = cJSON_GetObjectItem(json, "status");
                if (status && cJSON_IsString(status) && strcmp(status->valuestring, "ok") == 0)
                {
                    info.tunnel_state = TUNNEL_STATE_AUTHENTICATED;
                    cJSON *primary = cJSON_GetObjectItem(json, "primary");
                    if (primary && cJSON_IsString(primary))
                        info.is_primary = strcmp(primary->valuestring, "true") == 0 ? true : false;

                    send_start_request();
                }
                else
                {
                    ESP_LOGE(TAG, "Login failed, status: %s", status->valuestring);
                    tunnel_on_error(false, NULL);
                }
            }
            else if (strcmp(type->valuestring, "start") == 0)
            {
                cJSON *result = cJSON_GetObjectItem(json, "status");
                if (!result || !cJSON_IsString(result) || strcmp(result->valuestring, "ok") != 0)
                {
                    ESP_LOGE(TAG, "Start tunnel failed, status: %s", result->valuestring);
                    info.tunnel_state = TUNNEL_STATE_SUSPEND;
                    tunnel_on_error(false, NULL);
                }

                cJSON *suspend = cJSON_GetObjectItem(json, "suspend");
                cJSON *eof = cJSON_GetObjectItem(json, "eof");

                if (suspend && cJSON_IsString(suspend))
                { // Сохраняем команду приостановки туннеля
                    if (info.suspend_command)
                        free(info.suspend_command);
                    info.suspend_command_len = strlen(suspend->valuestring);
                    info.suspend_command = malloc(info.suspend_command_len);
                    if (info.suspend_command)
                        memcpy(info.suspend_command, suspend->valuestring, info.suspend_command_len);
                    else // TODO on error
                        ESP_LOGE(TAG, "Failed to allocate memory for suspend command");
                }

                if (eof && cJSON_IsString(eof))
                { // Сохраняем маркер конца файла
                    if (info.eof_marker)
                        free(info.eof_marker);
                    info.eof_marker_len = strlen(eof->valuestring);
                    info.eof_marker = malloc(info.eof_marker_len);
                    if (info.eof_marker)
                        memcpy(info.eof_marker, eof->valuestring, info.eof_marker_len);
                    else // TODO on error
                        ESP_LOGE(TAG, "Failed to allocate memory for eof marker");
                }

                info.tunnel_state = TUNNEL_STATE_RUNNING;
                if (info.is_primary)
                    ESP_LOGI(TAG, "Tunnel established, can linked at https://%s", config->domain);
                else
                    ESP_LOGI(TAG, "Tunnel established, can linked at https://%s/%s", config->domain, config->name);
                // local_client_init();
            }
            else if (strcmp(type->valuestring, "error") == 0)
            {
                cJSON *message = cJSON_GetObjectItem(json, "message");
                if (message && cJSON_IsString(message))
                    ESP_LOGW(TAG, "Incoming error: %s", message->valuestring);
                // tunnel_on_error(false, "Protocol error");
            }
            else if (strcmp(type->valuestring, "pause") == 0)
            {
                // TODO
            }
        }
        else
        {
            ESP_LOGW(TAG, "Message without type: %.*s", (int)(rx_len > 256 ? 256 : rx_len), rx_buffer);
        }
        cJSON_Delete(json);
    }
    else if (strncmp(rx_buffer, "->", 2) == 0)
    { // Эхо-сообщение или неразобранный JSON
        ESP_LOGI(TAG, "Echo: %s", rx_buffer + 2);
    }
    else
    {
        ESP_LOGW(TAG, "Unknown message: %.*s", (int)(rx_len > 256 ? 256 : rx_len), rx_buffer);
    }

    return ESP_OK;
}

static esp_err_t tunnel_process_bin_frame(bool fin)
{
    if (fin && rx_len == info.suspend_command_len && memcmp(rx_buffer, info.suspend_command, rx_len) == 0)
    {
        ESP_LOGI(TAG, "Tunnel suspended");
        if (use_local && local_sockfd > 0)
        {
            close(local_sockfd);
            local_sockfd = -1;
        }
        info.tunnel_state = TUNNEL_STATE_SUSPEND;
        return ESP_OK;
    }

    if (!use_local)
    {
        int count = config->rx_func(rx_buffer, rx_len);
        if (count < 0 || count != rx_len)
            return tunnel_on_error(false, "Cannot process incoming data");
        return ESP_OK;
    }

    if (header_end == 0)
    {
        header_end = header_end_index(rx_buffer, rx_len);
        if (header_end == 0 && rx_len >= MAX_HTTP_REQUEST_SIZE)
        {
            send_internal_error("Request headers not found or too long");
            return tunnel_on_error(false, "Header end not found, or too long");
        }
        ESP_LOGD(TAG, "INCOMING bin frame len=%lu, fin=%d message: %.*s",
                 rx_len, fin, (int)(rx_len > 64 ? 64 : rx_len), rx_buffer);
    }
    else
    {
        ESP_LOGD(TAG, "INCOMING bin frame chunk len=%lu, fin=%d", rx_len, fin);
    }

    // Write local server
    size_t total_written = 0;
    int attempts_eagain = 0; // Например, 100 * 50мс = 5 секунд таймаут
    while (total_written < rx_len)
    {
        int len = write(local_sockfd, rx_buffer + total_written, rx_len - total_written);
        if (len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                attempts_eagain++;
                if (attempts_eagain > MAX_EAGAIN_ATTEMPTS)
                {
                    ESP_LOGE(TAG, "Write to local failed after %d EAGAIN attempts (timeout).", MAX_EAGAIN_ATTEMPTS);
                    tunnel_on_error(true, NULL);
                    return ESP_FAIL; // Превышено количество попыток
                }

                // Сокет не готов, ждем с помощью select()
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(local_sockfd, &writefds);

                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 50000; // Ждем 50 миллисекунд (настройте по необходимости)

                int activity = select(local_sockfd + 1, NULL, &writefds, NULL, &tv);

                if (activity < 0)
                {
                    ESP_LOGE(TAG, "select() for write error: %d (%s)", errno, strerror(errno));
                    send_internal_error("Internal error");
                    tunnel_on_error(false, NULL);
                    return ESP_FAIL;
                }
                else if (activity == 0)
                {
                    // Таймаут select, сокет все еще не готов. Продолжаем цикл, attempts_eagain учтет это.
                    ESP_LOGD(TAG, "select() timeout waiting for write, attempt %d", attempts_eagain);
                    continue;
                }
                // Если activity > 0, сокет должен быть готов к записи (FD_ISSET(sockfd, &writefds))
                continue;
            }
            else
            { // Другая ошибка записи
                ESP_LOGE(TAG, "Write to local error: %d (%s)", errno, strerror(errno));
                send_internal_error("Local server busy.");
                return tunnel_on_error(true, NULL);
            }
        }
        else if (len == 0)
        {
            ESP_LOGE(TAG, "Write to local returned 0 bytes. Peer has likely closed connection.");
            send_internal_error("Local server has closed connection.");
            return tunnel_on_error(true, NULL);
        }
        else
        { // Успешно записана часть данных
            total_written += len;
            attempts_eagain = 0; // Сбрасываем счетчик EAGAIN после успешной записи
            ESP_LOGD(TAG, "Written %d bytes to local, total %zu/%lu", len, total_written, rx_len);
        }
    }
    ESP_LOGD(TAG, "Successfully wrote %zu of %lu bytes to local server", total_written, rx_len);

    if (fin)
        header_end = 0;

    return ESP_OK;
}

static esp_err_t tunnel_process_incoming_data()
{
    fd_set readfds;
    fd_set errfds;
    struct timeval tv = {0, use_ssl ? TUNNEL_SELECT_TLS_TIMEOUT_MKS : TUNNEL_SELECT_TIMEOUT_MKS}; // timeval использует микросекунды

    FD_ZERO(&readfds);
    FD_SET(ws_sockfd, &readfds);

    FD_ZERO(&errfds);           //   инициализация errfds
    FD_SET(ws_sockfd, &errfds); //  добавление сокета в errfds

    int activity = select(ws_sockfd + 1, &readfds, NULL, &errfds, &tv);
    if (activity < 0)
    {
        ESP_LOGE(TAG, "select() error: %d (%s)", errno, strerror(errno));
        return ESP_FAIL; // Ошибка самого select
    }

    if (FD_ISSET(ws_sockfd, &errfds))
    {
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        // Получаем конкретную ошибку сокета
        if (getsockopt(ws_sockfd, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0)
        {
            if (socket_error != 0)
            { // Если ошибка действительно есть
                ESP_LOGE(TAG, "Socket error: %d (%s)", socket_error, strerror(socket_error));
                tunnel_on_error(true, NULL);
                return ESP_FAIL; // Сокет не "жив" или в состоянии ошибки
            }
            // Если socket_error == 0, это может быть ложное срабатывание errfds (редко, но возможно на некоторых системах, если select вернул >0,
            // но ошибка разрешилась до вызова getsockopt).  В этом случае, если readfds также установлен, можно продолжить.
        }
        else
        {
            ESP_LOGE(TAG, "getsockopt(SO_ERROR) failed: %d (%s)", errno, strerror(errno));
            tunnel_on_error(true, NULL);
            return ESP_FAIL; // Не смогли определить ошибку, считаем сокет проблемным
        }
    }

    if (activity == 0)
        return ESP_OK; // No data or timeout

    // Read frame header (minimum 2 bytes)
    uint8_t header[14];
    int len = ws_read(header, 2);
    if (len < 2)
    {
        if (len == 0)
            return tunnel_on_error(true, "Connection closed by server");
        return ESP_OK; // Partial read, try again later
    }

    bool fin = header[0] & 0x80;
    ws_opcode_t opcode = header[0] & 0x0F;
    bool masked = header[1] & 0x80;
    uint64_t payload_len = header[1] & 0x7F;

    int header_len = 2;

    // Extended payload length
    if (payload_len == 126)
    {
        len = ws_read(&header[2], 2);
        if (len < 2)
            return ESP_OK;
        payload_len = (header[2] << 8) | header[3];
        header_len += 2;
    }
    else if (payload_len == 127)
    {
        len = ws_read(&header[2], 8);
        if (len < 8)
            return ESP_OK;
        // For simplicity, limit to 32-bit length
        payload_len = (header[6] << 24) | (header[7] << 16) | (header[8] << 8) | header[9];
        header_len += 8;
    }

    // Mask (from server should not be masked, but handle it)
    uint8_t mask[4] = {0};
    if (masked)
    {
        len = ws_read(mask, 4);
        if (len < 4)
            return ESP_OK;
        header_len += 4;
    }
    // Reset ping timer
    last_data_dt = esp_timer_get_time();
    last_ping_dt = 0;

    switch (opcode)
    {
    case WS_OPCODE_CONTINUATION:
    case WS_OPCODE_BINARY:
    case WS_OPCODE_TEXT:

        if (rx_len == 0 && opcode == WS_OPCODE_CONTINUATION)
            ESP_LOGW(TAG, "Received continuation frame without previous");
        if (info.tunnel_state == TUNNEL_STATE_RUNNING && opcode == WS_OPCODE_TEXT && rx_len > 0)
            return tunnel_on_error(false, "Received text message while tunnel processing request");
        if (info.tunnel_state != TUNNEL_STATE_RUNNING && opcode == WS_OPCODE_BINARY)
            return tunnel_on_error(false, "Received binary message while tunnel is not running");
        else if (rx_len > 0 && opcode != WS_OPCODE_CONTINUATION)
            return tunnel_on_error(false, "Received message while previous message is not processed");

        if (opcode == WS_OPCODE_BINARY && use_local)
        {
            esp_err_t err = local_client_init();
            if (err != ESP_OK)
            {
                tunnel_on_error(true, "Failed to init local client, close tunnel");
                return err;
            }
        }

        if (payload_len + rx_len > MAX_HTTP_REQUEST_SIZE && opcode == WS_OPCODE_TEXT)
        {
            ESP_LOGE(TAG, "WS Payload too large");
            return ESP_FAIL;
        }

        uint32_t total_readed = 0;
        while (total_readed < payload_len)
        {
            // Определяем сколько еще можем прочитать в буфер
            size_t buffer_space = config->rx_buffer_size - rx_len;
            size_t remaining_payload = payload_len - total_readed;
            size_t to_read = (remaining_payload < buffer_space) ? remaining_payload : buffer_space;

            // Читаем данные в буфер
            size_t readed = 0;
            int attempts = 0;

            while (readed < to_read && attempts < MAX_EAGAIN_ATTEMPTS)
            {
                ssize_t len = ws_read(rx_buffer + rx_len + readed, to_read - readed);
                if (len > 0)
                {
                    readed += len;
                    attempts = 0; // Сбрасываем счетчик после успешного чтения
                    ESP_LOGV(TAG, "WS Read %d (readed=%zu) bytes, total_readed=%lu of payload_len=%llu",
                             len, readed, total_readed, payload_len);
                }
                else if (len == 0)
                {
                    ESP_LOGE(TAG, "Tunnel connection closed by peer");
                    return tunnel_on_error(true, "Connection closed");
                }
                else // len < 0
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        // Сокет не готов, ждем
                        fd_set readfds;
                        FD_ZERO(&readfds);
                        FD_SET(ws_sockfd, &readfds);

                        // struct timeval tv;
                        // tv.tv_sec = 0;
                        // tv.tv_usec = TUNNEL_SELECT_TIMEOUT_MKS; // 50ms

                        int activity = select(ws_sockfd + 1, &readfds, NULL, NULL, &tv);
                        if (activity < 0)
                        {
                            ESP_LOGE(TAG, "select() error in ws_read: %d (%s)", errno, strerror(errno));
                            return tunnel_on_error(true, "Select error");
                        }
                        else if (activity == 0)
                        {
                            attempts++;
                            ESP_LOGD(TAG, "Read timeout, attempt %d/%d", attempts, MAX_EAGAIN_ATTEMPTS);
                        }
                        // Если activity > 0, пробуем читать снова
                    }
                    else
                    {
                        ESP_LOGE(TAG, "Failed to read WebSocket payload: %d (%s)", errno, strerror(errno));
                        return tunnel_on_error(true, "Read error");
                    }
                }
            }

            if (readed < to_read)
            {
                ESP_LOGE(TAG, "Failed to read ws payload: got %zu of %zu bytes after %d attempts",
                         readed, to_read, MAX_EAGAIN_ATTEMPTS);
                return tunnel_on_error(true, "Read timeout");
            }

            // Применяем маску если нужно (только к новым данным)
            if (masked)
                for (size_t i = 0; i < readed; i++)
                    rx_buffer[rx_len + i] ^= mask[(total_readed + i) % 4];

            total_readed += readed;
            rx_len += readed;

            // Проверяем нужно ли обработать данные
            bool is_payload_complete = (total_readed == payload_len);
            bool is_buffer_full = (rx_len >= config->rx_buffer_size);

            if (is_buffer_full || is_payload_complete)
            {
                if (opcode == WS_OPCODE_TEXT)
                {
                    esp_err_t result = tunnel_process_text_frame();
                    if (result != ESP_OK)
                        return result;
                }
                else
                {
                    esp_err_t result = tunnel_process_bin_frame(fin && is_payload_complete);
                    if (result != ESP_OK)
                        return result;
                }
                rx_len = 0;
            }
        }

        return ESP_OK;
    case WS_OPCODE_CLOSE:
        ws_state = WS_STATE_CLOSING;
        ssize_t len = ws_read(rx_buffer, payload_len > config->rx_buffer_size ? config->rx_buffer_size : payload_len);
        if (len > 0)
        {
            int code = rx_buffer[0] << 8 | rx_buffer[1];
            ESP_LOGI(TAG, "WS Received close message with code: %d message: %.*s", code, (int)len - 2, rx_buffer + 2);
        }
        else
            ESP_LOGI(TAG, "WS Received close without payload");
        return tunnel_on_error(true, NULL);
    case WS_OPCODE_PING:
        ESP_LOGD(TAG, "WS Received ping message");
        return ws_send_frame(NULL, 0, WS_OPCODE_PONG, true);
    case WS_OPCODE_PONG:
        ESP_LOGD(TAG, "WS Received pong message");
        return ESP_OK;
    default:
        ESP_LOGE(TAG, "WS Invalid opcode: %d", opcode);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t tunnel_outgoing_data_auto_eof(void)
{
    bool header_sent = false;
    int wait_max_count = MAX_EAGAIN_ATTEMPTS;
    // bool low_buf = false;
    uint64_t total_sent = 0;
    uint16_t tx_len = 0;
    while (true)
    {
        int bytes_read = recv(local_sockfd, tx_buffer + tx_len, config->tx_buffer_size - tx_len, MSG_DONTWAIT);

        if (bytes_read > 0)
        {
            tx_len += bytes_read;

            // Send data as WebSocket frame
            esp_err_t ret = ESP_OK;
            if (!header_sent)
            {
                if (header_end_index((char *)tx_buffer, tx_len) == -1)
                { // ждем полный заголовок
                    wait_max_count--;
                    if (wait_max_count <= 0)
                    {
                        send_internal_error("Local server not responding");
                        return tunnel_on_error(true, "Local server not responding");
                    }
                    vTaskDelay(pdMS_TO_TICKS(20));
                    continue;
                }

                ESP_LOGV(TAG, "Sending headers frame %.*s", tx_len > 64 ? 64 : tx_len, tx_buffer);
                ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_BINARY, false);
                header_sent = true;
            }
            else
            {
                // if (tx_len < TUNNEL_BUFFER_MIN_SIZE && !low_buf)
                // {
                //     low_buf = true;
                //     vTaskDelay(pdMS_TO_TICKS(20));
                //     continue;
                // }
                // low_buf = false;

                ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, false);
            }

            if (ret != ESP_OK)
                return tunnel_on_error(false, NULL);

            wait_max_count = MAX_EAGAIN_ATTEMPTS;
            total_sent += tx_len;
            tx_len = 0;
            continue;
        }
        else if (bytes_read == 0)
        {
            if (tx_len > 0)
            {
                if (!header_sent)
                    return ESP_OK;
                esp_err_t err = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, false);
                if (err != ESP_OK)
                    return tunnel_on_error(false, NULL);
                total_sent += tx_len;
                tx_len = 0;
            }
            if (total_sent == 0)
                return ESP_OK;

            total_sent += info.eof_marker_len;
            ESP_LOGI(TAG, "WS Response ended, sent %llu bytes (connection closed)", total_sent);
            return send_eof();
        }
        else if (bytes_read < 0)
        {
            wait_max_count--;
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK)
            { // No more data available (EAGAIN/EWOULDBLOCK)
                if (tx_len > 0 && header_sent)
                {
                    esp_err_t err = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, false);
                    if (err != ESP_OK)
                        return tunnel_on_error(false, NULL);
                    total_sent += tx_len;
                    tx_len = 0;
                    continue;
                }
                if (total_sent > 0)
                {
                    if (wait_max_count <= 0)
                    {
                        ESP_LOGI(TAG, "WS sent response %llu bytes", total_sent + info.eof_marker_len);
                        if (header_sent)
                            return send_eof();
                    }
                    vTaskDelay(pdMS_TO_TICKS(20));
                    continue;
                }
                else
                    return ESP_OK;
            }
            else
            {
                if (total_sent > 0 && header_sent)
                    send_eof();
                ESP_LOGW(TAG, "Error reading from local server: %s", strerror(err));
                return tunnel_on_error(false, NULL);
            }
        }
    }
}

static esp_err_t tunnel_outgoing_data_manual_eof(void)
{
    bool header_sent = false;
    // bool low_buf = false;
    uint64_t total_sent = 0;
    uint16_t tx_len = 0;
    int wait_max_count = MAX_EAGAIN_ATTEMPTS;

    const uint8_t *eof_marker = info.eof_marker;
    size_t eof_marker_len = info.eof_marker_len;

    while (true)
    {
        int bytes_read = recv(local_sockfd, tx_buffer + tx_len, config->tx_buffer_size - tx_len, MSG_DONTWAIT);
        if (bytes_read > 0)
        {
            tx_len += bytes_read;

            // Проверяем наличие EOF маркера
            if (eof_marker && eof_marker_len > 0 && tx_len >= eof_marker_len)
            { // Ищем EOF маркер в буфере
                for (size_t i = 0; i <= tx_len - eof_marker_len; i++)
                    if (memcmp(tx_buffer + i, eof_marker, eof_marker_len) == 0)
                    {
                        // Найден EOF маркер - отправляем данные до конца маркера и завершаем
                        size_t data_to_send = i + eof_marker_len;

                        esp_err_t ret = ESP_OK;
                        if (!header_sent)
                            ret = ws_send_frame(tx_buffer, data_to_send, WS_OPCODE_BINARY, true); // fin=true
                        else
                            ret = ws_send_frame(tx_buffer, data_to_send, WS_OPCODE_CONTINUATION, true); // fin=true

                        if (ret != ESP_OK)
                            return tunnel_on_error(false, NULL);

                        total_sent += data_to_send;
                        ESP_LOGI(TAG, "WS Sent response %llu bytes (EOF marker found)", total_sent);
                        return ESP_OK;
                    }
            }
        }

        if (bytes_read > 0)
        { // Если буфер заполнен, но EOF не найден - отправляем частично,  оставляем место для EOF маркера
            if (tx_len >= config->tx_buffer_size - eof_marker_len * 2)
            {
                wait_max_count = MAX_EAGAIN_ATTEMPTS;
                esp_err_t ret = ESP_OK;
                if (!header_sent)
                {
                    if (header_end_index((char *)tx_buffer, tx_len) == -1)
                    { // ждем полный заголовок
                        wait_max_count--;
                        if (wait_max_count <= 0)
                        {
                            send_internal_error("Local server not responding");
                            return tunnel_on_error(true, "Local server not responding");
                        }
                        vTaskDelay(pdMS_TO_TICKS(20));
                        continue;
                    }

                    ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_BINARY, false); // fin=false
                    header_sent = true;
                }
                else
                {
                    // Проверяем размер буфера для предотвращения отправки мелких пакетов
                    // if (tx_len < TUNNEL_BUFFER_MIN_SIZE && !low_buf)
                    // {
                    //     low_buf = true;
                    //     vTaskDelay(pdMS_TO_TICKS(20));
                    //     continue;
                    // }
                    // low_buf = false;

                    ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, false); // fin=false
                }

                if (ret != ESP_OK)
                    return tunnel_on_error(true, NULL);

                total_sent += tx_len;
                tx_len = 0;
            }
        }
        else if (bytes_read == 0)
        {
            // Соединение закрыто - отправляем оставшиеся данные с fin=true
            if (tx_len > 0)
            {
                esp_err_t ret = ESP_OK;
                if (!header_sent)
                {
                    ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_BINARY, true); // fin=true
                }
                else
                {
                    ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, true); // fin=true
                }

                if (ret != ESP_OK)
                    return tunnel_on_error(false, NULL);

                total_sent += tx_len;
            }

            ESP_LOGI(TAG, "WS Sent response %llu bytes (connection closed)", total_sent);
            return ESP_OK;
        }
        else
        {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK)
            {
                if (total_sent == 0 && tx_len == 0)
                    return ESP_OK; // Просто нет данных для чтения

                wait_max_count--;
                if (wait_max_count <= 0)
                {
                    // ESP_LOGW(TAG, "EoF marker receiving from local server timeout, ending response with auto eof");
                    memcpy(tx_buffer + tx_len, eof_marker, eof_marker_len);
                    tx_len += eof_marker_len;

                    esp_err_t ret = ESP_OK;
                    if (!header_sent)
                        ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_BINARY, true); // fin=true
                    else
                        ret = ws_send_frame(tx_buffer, tx_len, WS_OPCODE_CONTINUATION, true); // fin=true

                    if (ret != ESP_OK)
                        return tunnel_on_error(false, NULL);
                    total_sent += tx_len;

                    ESP_LOGI(TAG, "WS Sent response %llu bytes (EoF marker from local server timeout, using auto eof)", total_sent);
                    return ESP_OK;
                }
                // Нет данных для чтения - небольшая задержка
                vTaskDelay(pdMS_TO_TICKS(20));
                continue;
            }
            else
            {
                ESP_LOGW(TAG, "Error reading from local server: %s", strerror(err));
                return tunnel_on_error(false, NULL);
            }
        }
    }
}

static esp_err_t tunnel_process_outgoing_data(void)
{
    if (!use_local)
    {
        tunnel_rx_marker_t marker;
        int count = config->tx_func((char *)tx_buffer, config->tx_buffer_size, &marker);
        if (count == 0 || marker == TUNNEL_RX_MARKER_EMPTY)
            return ESP_OK;

        if (marker == TUNNEL_RX_MARKER_ERROR) // TDOO if flag  TUNNEL_RX_MARKER_START send error page
            return tunnel_on_error(false, NULL);

        if (marker == TUNNEL_RX_MARKER_EOF)
            return send_eof();

        return ws_send_frame(tx_buffer, count,
                             marker == TUNNEL_RX_MARKER_START ? WS_OPCODE_BINARY : WS_OPCODE_CONTINUATION,
                             marker == TUNNEL_RX_MARKER_END ? true : false);
    }

    if (local_sockfd <= 0)
        return ESP_OK;

    if (!has_incoming_data_poll(local_sockfd, 0))
        return ESP_OK;

    if (config->auto_eof)
        return tunnel_outgoing_data_auto_eof();
    else
        return tunnel_outgoing_data_manual_eof();
}

static void tunnel_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(1000));
    if (is_wifi_connected())
        ws_connect();

    while (1)
    {
        if (!is_wifi_connected())
        {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (local_sockfd > 0)
            if (tunnel_process_outgoing_data() != ESP_OK)
                vTaskDelay(pdMS_TO_TICKS(1000));

        if (ws_state == WS_STATE_DISCONNECTED)
        {
            if (config->reconnect_timeout_ms > 0)
            {
                vTaskDelay(pdMS_TO_TICKS(config->reconnect_timeout_ms));
                ws_connect();
            }
        }
        else if (ws_state == WS_STATE_CONNECTED)
        {
            if (info.tunnel_state != TUNNEL_STATE_RUNNING)
                vTaskDelay(pdMS_TO_TICKS(1000));

            if (ws_sockfd <= 0 || (use_ssl && !tls))
            {
                ESP_LOGE(TAG, "Tunnel connection closed, but not handled");
                ws_state = WS_STATE_DISCONNECTED;
                continue;
            }

            if (tunnel_process_incoming_data() != ESP_OK)
                vTaskDelay(pdMS_TO_TICKS(1000));

            // ping logic
            uint64_t now = esp_timer_get_time();
            uint32_t timeout_mks = config->reconnect_timeout_ms > 0 ? config->reconnect_timeout_ms * 1000 : 30000 * 1000;
            if (last_data_dt + timeout_mks < now)
            {
                if (last_ping_dt == 0)
                {
                    if (send_ping() != ESP_OK)
                    {
                        tunnel_on_error(true, NULL);
                        vTaskDelay(pdMS_TO_TICKS(1000));
                        continue;
                    }
                    last_ping_dt = now;
                }
                else if (last_ping_dt + timeout_mks < now)
                {
                    ESP_LOGE(TAG, "Tunnel not responding, pong timeout, closing");
                    tunnel_on_error(true, NULL);
                    vTaskDelay(pdMS_TO_TICKS(1000));
                    continue;
                }
            }
        }
        else if (info.tunnel_state == TUNNEL_STATE_SUSPEND)
        {
            ESP_LOGI(TAG, "Tunnel suspended, waiting 10 seconds to resume");
            vTaskDelay(pdMS_TO_TICKS(10000));
            send_start_request();
        }

        vTaskDelay(pdMS_TO_TICKS(TUNNEL_LATENCY_MS));
    }
}

esp_err_t local_client_init()
{
    if (local_sockfd >= 0)
    {
        int error = 0;
        socklen_t len = sizeof(error);
        int ret = getsockopt(local_sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (ret == 0 && error == 0)
        {
            return ESP_OK; // Сокет активен
        }
        else
        {
            ESP_LOGW(TAG, "Local socket is not active (error: %d), closing", error);
            close(local_sockfd);
            local_sockfd = -1;
        }
    }

    // Создаем сокет для подключения к локальному серверу
    local_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (local_sockfd < 0)
    {
        ESP_LOGE(TAG, "Failed to open local server connection:: %d, %s", errno, strerror(errno));
        return ESP_FAIL;
    }

    // Устанавливаем неблокирующий режим для recv
    int flags = fcntl(local_sockfd, F_GETFL, 0);
    fcntl(local_sockfd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(config->local_port > 0 ? config->local_port : 80);
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1

    // Временно делаем сокет блокирующим для connect
    fcntl(local_sockfd, F_SETFL, flags);

    if (connect(local_sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0)
    {
        ESP_LOGE(TAG, "Failed to connect local server: %d, %s", errno, strerror(errno));
        close(local_sockfd);
        local_sockfd = -1;
        return ESP_FAIL;
    }

    // Возвращаем неблокирующий режим
    if (config->non_block)
        fcntl(local_sockfd, F_SETFL, flags | O_NONBLOCK);

    ESP_LOGI(TAG, "Connected to local server");
    return ESP_OK;
}

static esp_err_t ws_client_init()
{
    if (task_handle)
    {
        ESP_LOGW(TAG, "Client already started");
        return ESP_ERR_INVALID_STATE;
    }

    if (!parse_uri(config->provider_URI, &host, &port, &use_ssl))
    {
        ESP_LOGE(TAG, "Invalid URI format");
        return ESP_ERR_INVALID_ARG;
    }

    ws_state = WS_STATE_DISCONNECTED;

    // TLS configuration
    if (use_ssl)
    {
#ifdef ROOT_CERT
        extract_pem_block(root_cert, false, &tls_cfg.cacert_buf, &tls_cfg.cacert_bytes);
        tls_cfg.use_global_ca_store = false;
        // tls_cfg.skip_common_name = true;
        // tls_cfg.common_name = "growe.ddns-ip.net";
        // tls_cfg.alpn_protos = NULL;

#else
        extern const uint8_t lets_encrypt_root_pem_start[] asm("_binary_lte_root_pem_start");
        extern const uint8_t lets_encrypt_root_pem_end[] asm("_binary_lte_root_pem_end");

        tls_cfg.cacert_buf = lets_encrypt_root_pem_start;
        tls_cfg.cacert_bytes = lets_encrypt_root_pem_end - lets_encrypt_root_pem_start;
        tls_cfg.skip_common_name = false; // false;
#endif

        // Client certificate and key (mutual TLS)
        if (config->client_cert && config->client_key)
        {
            if (!extract_pem_block(config->client_cert, false, &tls_cfg.clientcert_buf, &tls_cfg.clientcert_bytes))
            {
                ESP_LOGE(TAG, "Invalid client certificate format");
                free_tls_pem_buffer(&tls_cfg.clientcert_buf, &tls_cfg.clientcert_bytes);
                return ESP_ERR_INVALID_ARG;
            }
            if (!extract_pem_block(config->client_key, true, &tls_cfg.clientkey_buf, &tls_cfg.clientkey_bytes))
            {
                ESP_LOGE(TAG, "Invalid client key format");
                free_tls_pem_buffer(&tls_cfg.clientcert_buf, &tls_cfg.clientcert_bytes);
                free_tls_pem_buffer(&tls_cfg.clientkey_buf, &tls_cfg.clientkey_bytes);
                return ESP_ERR_INVALID_ARG;
            }
        }
    }

    tls_cfg.timeout_ms = 30000;
    tls_cfg.non_block = config->non_block; // true;
    tls_cfg.use_secure_element = false;

    tls_cfg.keep_alive_cfg = calloc(1, sizeof(tls_keep_alive_cfg_t));
    tls_cfg.keep_alive_cfg->keep_alive_enable = true;
    tls_cfg.keep_alive_cfg->keep_alive_idle = 5;
    tls_cfg.keep_alive_cfg->keep_alive_interval = 5;
    tls_cfg.keep_alive_cfg->keep_alive_count = 3;

    BaseType_t ret = xTaskCreatePinnedToCore(tunnel_task, "tunnel_task", 1024 * 8, NULL, tskIDLE_PRIORITY + 6, &task_handle, 1);
    if (ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create Tunnel task");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Tunnel client initialized for %s", config->provider_URI);

    return ESP_OK;
}

esp_err_t tunnel_init(tunnel_config_t *_config)
{
    if (!_config)
    {
        ESP_LOGE(TAG, "No tunnel config provided");
        return ESP_ERR_INVALID_ARG;
    }

    if (_config->provider_URI == NULL || _config->domain == NULL || _config->secret == NULL)
    {
        ESP_LOGE(TAG, "Invalid tunnel config");
        return ESP_ERR_INVALID_ARG;
    }

    if (task_handle)
    {
        ESP_LOGW(TAG, "Client already started");
        return ESP_ERR_INVALID_STATE;
    }

    config = malloc(sizeof(tunnel_config_t));
    if (config == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for config");
        return ESP_ERR_NO_MEM;
    }
    memcpy(config, _config, sizeof(tunnel_config_t));

    rx_buffer = (char *)malloc(config->rx_buffer_size >= TUNNEL_BUFFER_MIN_SIZE ? config->rx_buffer_size : TUNNEL_DEFAULT_RX_BUFFER_SIZE);
    tx_buffer = (uint8_t *)malloc(config->tx_buffer_size >= TUNNEL_BUFFER_MIN_SIZE ? config->tx_buffer_size : TUNNEL_DEFAULT_TX_BUFFER_SIZE);
    if (!rx_buffer || !tx_buffer)
    {
        free(rx_buffer);
        free(config);
        return ESP_ERR_NO_MEM;
    }

    // if (config->network_timeout_ms < 10000)
    //     config->network_timeout_ms = 10000;
    if (config->reconnect_timeout_ms != 0 && config->reconnect_timeout_ms < 30000)
    {
        ESP_LOGW(TAG, "Reconnect timeout too short, setting to 30 seconds");
        config->reconnect_timeout_ms = 30000;
    }

    use_local = !(config->rx_func && config->tx_func);

    esp_err_t err = ws_client_init();
    if (err != ESP_OK)
    {
        free(config);
        free(rx_buffer);
        free(tx_buffer);
        return err;
    }

    return ESP_OK;
}

void tunnel_destroy(void)
{
    tunnel_on_error(true, NULL);
    free(config);
    free(rx_buffer);
    free(tx_buffer);
}

void tunnel_get_info(tunnel_info_t *out_info)
{
    *out_info = info;
}