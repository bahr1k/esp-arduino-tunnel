#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/socket.h>
#include "esp_wifi.h"

bool has_incoming_data(int sockfd, int timeout_ms)
{
    if (sockfd <= 0)
        return false;

    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

    if (result > 0 && FD_ISSET(sockfd, &read_fds))
        return true;

    return false;
}

// Способ 2: Использование poll() (более современный)
bool has_incoming_data_poll(int sockfd, int timeout_ms)
{
    if (sockfd <= 0)
        return false;

    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int result = poll(&pfd, 1, timeout_ms);

    if (result > 0 && (pfd.revents & POLLIN))
        return true;

    return false;
}

int header_end_index(char *buf, size_t len)
{
    const char *hdr_end = "\r\n\r\n";
    for (size_t i = 0; i <= len - 4; i++)
    {
        if (memcmp(buf + i, hdr_end, 4) == 0)
            return i + 4;
    }
    return -1;
}

bool parse_uri(const char *uri, char **host, int *port, bool *use_ssl)
{
    if (strncmp(uri, "wss://", 6) == 0)
    {
        *use_ssl = true;
        const char *host_start = uri + 6;
        const char *path_start = strchr(host_start, '/');
        const char *port_start = strchr(host_start, ':');
        if (port_start && (!path_start || port_start < path_start))
        {
            // Порт указан, извлекаем его
            const char *port_end = path_start ? path_start : host_start + strlen(host_start);
            char port_str[6]; // Максимум 5 цифр для порта + '\0'
            size_t port_len = port_end - port_start - 1;
            if (port_len > 0 && port_len <= 5)
            {
                strncpy(port_str, port_start + 1, port_len);
                port_str[port_len] = '\0';
                *port = atoi(port_str);
            }
            else
            {
                return false;
            }
            // Извлекаем хост до двоеточия
            size_t host_len = port_start - host_start;
            *host = strndup(host_start, host_len);
        }
        else
        {
            // Порт не указан, используем значение по умолчанию для wss (443)
            *port = 443;
            size_t host_len = path_start ? path_start - host_start : strlen(host_start);
            *host = strndup(host_start, host_len);
        }
    }
    else if (strncmp(uri, "ws://", 5) == 0)
    {
        *use_ssl = false;
        const char *host_start = uri + 5;
        const char *path_start = strchr(host_start, '/');
        const char *port_start = strchr(host_start, ':');
        if (port_start && (!path_start || port_start < path_start))
        {
            // Порт указан, извлекаем его
            const char *port_end = path_start ? path_start : host_start + strlen(host_start);
            char port_str[6]; // Максимум 5 цифр для порта + '\0'
            size_t port_len = port_end - port_start - 1;
            if (port_len > 0 && port_len <= 5)
            {
                strncpy(port_str, port_start + 1, port_len);
                port_str[port_len] = '\0';
                *port = atoi(port_str);
            }
            else
            {
                return false;
            }
            // Извлекаем хост до двоеточия
            size_t host_len = port_start - host_start;
            *host = strndup(host_start, host_len);
        }
        else
        {
            // Порт не указан, используем значение по умолчанию для ws (80)
            *port = 80;
            size_t host_len = path_start ? path_start - host_start : strlen(host_start);
            *host = strndup(host_start, host_len);
        }
    }
    else
    {
        return false;
    }

    return true;
}

bool is_wifi_connected(void)
{
    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) != ESP_OK)
        return false;

    if (mode & WIFI_MODE_STA)
    {
        esp_netif_ip_info_t ip_info;
        esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        return (sta_netif &&
                esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK &&
                ip_info.ip.addr != 0);
    }
    return false;
}

static const char *find_pem_line(const char *input, const char *marker)
{
    if (!input || !marker)
        return NULL;

    const char *p = input;
    size_t marker_len = strlen(marker);

    while (*p)
    {
        // Ищем начало строки с дефисами
        if (*p == '-')
        {
            const char *line_start = p;

            // Пропускаем дефисы в начале
            while (*p == '-')
                p++;

            // Проверяем наш маркер
            if (strncmp(p, marker, marker_len) == 0)
            {
                p += marker_len;

                // Проверяем дефисы в конце
                while (*p == '-')
                    p++;

                // Должен быть конец строки или перенос
                if (*p == '\0' || *p == '\r' || *p == '\n')
                {
                    return line_start;
                }
            }

            // Если не подошло, ищем следующую строку
            while (*p && *p != '\n')
                p++;
            if (*p == '\n')
                p++;
        }
        else
        {
            // Переходим к следующему символу
            p++;
        }
    }

    return NULL;
}

bool extract_pem_block(const char *pem_input, bool is_key, const unsigned char **out_buf, size_t *out_len)
{
    if (!pem_input || !out_buf || !out_len)
    {
        return false;
    }

    *out_buf = NULL;
    *out_len = 0;

    // Определяем маркеры
    const char *begin_marker = is_key ? "BEGIN PRIVATE KEY" : "BEGIN CERTIFICATE";
    const char *end_marker = is_key ? "END PRIVATE KEY" : "END CERTIFICATE";

    // Ищем начало блока
    const char *begin_line = find_pem_line(pem_input, begin_marker);
    if (!begin_line)
    {
        return false;
    }

    // Ищем конец блока после начала
    const char *end_line = find_pem_line(begin_line + 1, end_marker);
    if (!end_line)
    {
        return false;
    }

    // Находим конец END строки
    const char *block_end = end_line;
    while (*block_end && *block_end != '\n' && *block_end != '\r')
    {
        block_end++;
    }
    if (*block_end == '\r')
        block_end++;
    if (*block_end == '\n')
        block_end++;

    // Вычисляем длину блока
    size_t block_len = block_end - begin_line;

    // Копируем блок с завершающим нулем
    unsigned char *result = malloc(block_len + 1);
    if (!result)
    {
        return false;
    }

    memcpy(result, begin_line, block_len);
    result[block_len] = '\0';

    *out_buf = result;
    *out_len = block_len + 1; // включаем завершающий \0 для ESP-IDF

    return true;
}

void free_tls_pem_buffer(const unsigned char **buf, size_t *len)
{
    if (buf && *buf)
    {
        free((void *)*buf);
        *buf = NULL;
    }
    if (len)
    {
        *len = 0;
    }
}

// bool extract_base64_from_pem(const char *pem_block,
//                              char **out_base64,
//                              size_t *out_len)
// {
//     if (!pem_block || !out_base64 || !out_len)
//         return false;

//     // Пропускаем первую строку (BEGIN)
//     const char *p = strchr(pem_block, '\n');
//     if (!p)
//         return false;
//     p++;

//     // Ищем последнюю строку (END)
//     const char *end_start = strstr(p, "-----END");
//     if (!end_start)
//         return false;

//     // Подсчитываем размер для base64 данных
//     size_t base64_size = 0;
//     for (const char *tmp = p; tmp < end_start; tmp++)
//     {
//         if (isalnum(*tmp) || *tmp == '+' || *tmp == '/' || *tmp == '=')
//         {
//             base64_size++;
//         }
//     }

//     char *base64 = malloc(base64_size + 1);
//     if (!base64)
//         return false;

//     // Копируем только base64 символы
//     size_t idx = 0;
//     for (const char *tmp = p; tmp < end_start; tmp++)
//     {
//         if (isalnum(*tmp) || *tmp == '+' || *tmp == '/' || *tmp == '=')
//         {
//             base64[idx++] = *tmp;
//         }
//     }
//     base64[idx] = '\0';

//     *out_base64 = base64;
//     *out_len = idx;
//     return true;
// }