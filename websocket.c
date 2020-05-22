/*
 * esp32-websocket - a websocket component on esp-idf
 * Copyright (C) 2019 Blake Felt - blake.w.felt@gmail.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <esp_system.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <string.h>
#include <esp_log.h>
#include <lwip/sockets.h>

#include "websocket.h"
#include "websocket_server.h"
#include "websocket_priv.h"

static const char *TAG = "ws";

static char *extract_http_header(const char *buffer, const char *key);
int ws_hash_handshake(char *handshake, char *dest, size_t dest_len);

esp_err_t ws_client_create(ws_client_handle_t *handle, int fd, const char *url) {
    ws_client_t *client = malloc(sizeof(ws_client_t));
    if (!client) {
        return ESP_ERR_NO_MEM;
    }

    *client = (ws_client_t) {
            .fd = fd,
            .url = url
    };

    *handle = client;

    return ESP_OK;
}

void ws_client_delete(ws_client_handle_t client) {
    if (client->fd >= 0) {
        shutdown(client->fd, SHUT_RDWR);
        close(client->fd);
    }
    client->fd = -1;

    free(client->buffer);
    free(client);
}

esp_err_t ws_client_accept(int sock, char **uri) {
    char buffer[512];
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        ESP_LOGE(TAG, "Could not receive from client: %d %s", errno, strerror(errno));
        goto _error;
    }
    buffer[len] = '\0';

    // Find URL requested by looking for GET /(%s)?
    *uri = extract_http_header(buffer, "GET ");
    if (*uri == NULL) {
        ESP_LOGW(TAG, "Client did not send GET request");

        char *response = "HTTP/1.1 405 Method Not Allowed\r\n" \
                "Allow: GET\r\n" \
                "\r\n";

        int err = write(sock, response, strlen(response));
        if (err < 0) ESP_LOGE(TAG, "Could not send response to client: %d %s", errno, strerror(errno));

        goto _error;
    }

    // Move to space or end of string (removing HTTP/1.1 from line)
    char *space = strstr(*uri, " ");
    if (space != NULL) *space = '\0';

    // Check required headers
    char *connection_header = extract_http_header(buffer, "Connection:");
    char *upgrade_header = extract_http_header(buffer, "Upgrade:");
    char *handshake_header = extract_http_header(buffer, "Sec-WebSocket-Key:");
    if ((connection_header == NULL || strcasecmp(connection_header, "Upgrade") != 0) ||
            (upgrade_header == NULL || strcasecmp(upgrade_header, "websocket") != 0) ||
            (handshake_header == NULL)) {
        ESP_LOGW(TAG, "Client did not send connection upgrade request, requested wrong protocol, or did not send handshake key");

        char *response = "HTTP/1.1 426 Upgrade Required\r\n" \
                "Upgrade: websocket\r\n" \
                "Connection: Upgrade\r\n" \
                "\r\n";

        int err = write(sock, response, strlen(response));
        if (err < 0) ESP_LOGE(TAG, "Could not send response to client: %d %s", errno, strerror(errno));

        free(connection_header);
        free(upgrade_header);
        free(handshake_header);

        goto _error;
    }
    free(connection_header);
    free(upgrade_header);

    // Calculate response handshake
    char hashed_key[32] = "";
    ws_hash_handshake(handshake_header, hashed_key, sizeof(hashed_key)); // TODO: Deal with failure here
    free(handshake_header);

    // Respond with protocol switch
    char *response;
    asprintf(&response, "HTTP/1.1 101 Switching Protocols\r\n" \
            "Connection: Upgrade\r\n" \
            "Upgrade: websocket\r\n" \
            "Sec-WebSocket-Accept: %s\r\n" \
            "\r\n", hashed_key);
    int err = write(sock, response, strlen(response));
    free(response);
    if (err < 0) {
        ESP_LOGE(TAG, "Could not send response to client: %d %s", errno, strerror(errno));
        goto _error;
    }

    return ESP_OK;

    _error:
    free(*uri);
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return ESP_FAIL;
}

const char *ws_client_url(ws_client_handle_t client) {
    return client->url;
}

bool ws_client_connected(ws_client_handle_t client) {
    return client->fd > 0;
}

static void ws_encrypt_decrypt(unsigned char *msg, size_t len, uint32_t mask) {
    for (unsigned int i = 0; i < len; i++) {
        msg[i] ^= ((uint8_t *)(&mask))[i % 4];
    }
}

websocket_status_t ws_client_disconnect(ws_client_handle_t client, websocket_status_t reason,
        uint8_t *message, size_t message_length) {
    if (message == NULL) {
        switch (reason) {
            default:
            case WEBSOCKET_STATUS_CLOSE_NONE:
            case WEBSOCKET_STATUS_CLOSE_NORMAL:
                break;
            case WEBSOCKET_STATUS_CLOSE_GOING_AWAY:
                message = (uint8_t *) "Server is being shut down";
                break;
            case WEBSOCKET_STATUS_CLOSE_PROTOCOL_ERROR:
                message = (uint8_t *) "Protocol error encountered";
                break;
            case WEBSOCKET_STATUS_CLOSE_UNSUPPORTED_DATA:
                message = (uint8_t *) "Unsupported data type received";
                break;
            case WEBSOCKET_STATUS_CLOSE_INVALID_FRAME_PAYLOAD_DATA:
                message = (uint8_t *) "Invalid frame payload data received";
                break;
            case WEBSOCKET_STATUS_CLOSE_POLICY_VIOLATION:
                message = (uint8_t *) "Server policy violated";
                break;
            case WEBSOCKET_STATUS_CLOSE_MESSAGE_TOO_BIG:
                message = (uint8_t *) "Message exceeding server maximum size received";
                break;
            case WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR:
                message = (uint8_t *) "Internal server error";
                break;
        }
        if (message != NULL) {
            message_length = strlen((const char *) message);
        }
    }
    return ws_client_send(client, WEBSOCKET_OPCODE_CLOSE, message, message_length, reason);
}

websocket_status_t ws_client_send(ws_client_t *client, websocket_opcode_t opcode,
        uint8_t *message, size_t message_length, uint16_t close_reason) {
    // TODO: Multipart messages
    ws_header_t header = {
            .FIN = true,
            .OPCODE = opcode,
            .MASK = false
    };

    // Message length
    if (message_length <= 125) {
        header.LEN = message_length;
    } else if (message_length < 65536) {
        header.LEN = 126;
    } else {
        header.LEN = 127;
    }

    // Write header
    int ret = write(client->fd, &header, sizeof(ws_header_t));
    if (ret != 1) goto _error;

    // Write additional length
    if (header.LEN == 126) {
        ret = write(client->fd, &message_length, 2);
        if (ret != 2) goto _error;
    } else if (header.LEN == 127) {
        ret = write(client->fd, &message_length, 8);
        if (ret != 8) goto _error;
    }

    // Write close reason
    if (opcode == WEBSOCKET_OPCODE_CLOSE && close_reason > 0) {
        ret = write(client->fd, &close_reason, 2);
        if (ret != 2) goto _error;
    }

    // Write message
    // TODO: Write all
    ret = write(client->fd, message, message_length);
    if (ret == message_length) return WEBSOCKET_STATUS_OK;

    _error:
    ESP_LOGE(TAG, "Could not write to socket: %d %s", errno, strerror(errno));
    return WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR;
}

static websocket_status_t ws_client_verify_preconditions(ws_client_handle_t client, websocket_opcode_t op, bool fin, size_t length) {
    // Check for unsupported operations
    switch (op) {
        case WEBSOCKET_OPCODE_CONT:
        case WEBSOCKET_OPCODE_CLOSE:
        case WEBSOCKET_OPCODE_TEXT:
        case WEBSOCKET_OPCODE_BIN:
        case WEBSOCKET_OPCODE_PING:
        case WEBSOCKET_OPCODE_PONG:
            break;
        default:
            ESP_LOGE(TAG, "Client sent frame with unsupported operation %d", op);
            return WEBSOCKET_STATUS_CLOSE_UNSUPPORTED_DATA;
    }

    bool control_message = op == WEBSOCKET_OPCODE_CLOSE || op == WEBSOCKET_OPCODE_PING || op == WEBSOCKET_OPCODE_PONG;

    // Check for max message size
    size_t max_length = control_message ? WEBSOCKET_CONTROL_MESSAGE_MAX_SIZE : WEBSOCKET_DATA_MESSAGE_MAX_SIZE;
    size_t full_length = length + op == WEBSOCKET_OPCODE_CONT ? client->buffer_len : 0;
    if (full_length > WEBSOCKET_DATA_MESSAGE_MAX_SIZE) {
        ESP_LOGE(TAG, "Could not receive message from client, " \
                "size (%d bytes) exceeds maximum permitted size (%d bytes) for %s message",
                length, max_length, control_message ? "control" : "data");
        return WEBSOCKET_STATUS_CLOSE_MESSAGE_TOO_BIG;
    }

    if (control_message) {
        // Control frames cannot be fragmented
        if (!fin) {
            ESP_LOGE(TAG, "Client attempted to send fragmented control frame %d", op);
            return WEBSOCKET_STATUS_CLOSE_PROTOCOL_ERROR;
        }
    } else {
        bool continuation_message = op == WEBSOCKET_OPCODE_CONT;

        // If continuing buffer must be present, and vice-versa
        if ((client->buffer == NULL) == continuation_message) {
            if (continuation_message) {
                ESP_LOGE(TAG, "Continuation message received without pending fragmented message");
            } else {
                ESP_LOGE(TAG, "Non-continuation message received with pending fragmented message");
            }
            return WEBSOCKET_STATUS_CLOSE_PROTOCOL_ERROR;
        }
    }

    return WEBSOCKET_STATUS_OK;
}

websocket_status_t ws_client_read(ws_client_handle_t client, websocket_opcode_t *opcode, uint8_t **message, size_t *message_length) {
    // TODO:
    char buf[512];
    size_t buf_len = sizeof(buf);
    int len = recv(client->fd, buf, buf_len, MSG_DONTWAIT);
    if (len < 0) {
        ESP_LOGE(TAG, "Could not receive from client: %d %s", errno, strerror(errno));
        return WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR;
    }

    // Extract header
    ws_header_t *header = (ws_header_t *) buf;
    memcpy(&header, buf, 2);
    bool fin = header->FIN;
    bool mask = header->MASK;
    size_t length = header->LEN;
    websocket_opcode_t op = header->OPCODE;

    // Message length
    int pos = 2;
    if (length <= 125) {
        // Keep value
    } else if (length == 126) {
        memcpy(&length, &buf[2], 2);
        pos = 4;
    } else { // length == 127
        memcpy(&length, &buf[2], 8);
        pos = 10;
    }

    // Check all possible failure modes
    websocket_status_t status = ws_client_verify_preconditions(client, op, fin, length);
    if (status != WEBSOCKET_STATUS_OK) return status;

    // Encryption key
    uint32_t masking_key;
    if (mask) {
        memcpy(&masking_key, &buf[pos], 4);
        pos += 4;
    } else {
        // Per RFC6455 Section 5.1, a CLOSE response with status code 1002 (protocol error) should be sent
    }

    uint8_t *buffer;
    uint8_t *buffer_write;
    if (op != WEBSOCKET_OPCODE_CONT) {
        // Create new buffer
        buffer = malloc(length);
        buffer_write = buffer;
    } else {
        // Can only continue if the original frame was received and buffer stored
        if (client->buffer == NULL) {
            ESP_LOGE(TAG, "Continuation message received without original message");
            return WEBSOCKET_STATUS_CLOSE_PROTOCOL_ERROR;
        }

        // Resize and append to previous buffer
        size_t new_length = client->buffer_len + length;
        client->buffer = realloc(client->buffer, new_length);
        buffer_write = client->buffer + client->buffer_len;
        client->buffer_len = new_length;
        buffer = client->buffer;
    }

    // Allocate message
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Could not allocate %d byte buffer", length);
        return WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR;
    }

    size_t cont_len = len - pos;
    memcpy(buffer_write, &buf[pos], cont_len);
    size_t cont_rem = length - cont_len;
    while (cont_rem > 0) {
        len = read(client->fd, buffer_write, cont_rem < buf_len ? cont_rem : buf_len);
        if (len < 0) {
            ESP_LOGE(TAG, "Could not receive from client: %d %s", errno, strerror(errno));
            free(buffer);
            return WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR;
        }

        buffer_write += len;
        cont_rem -= len;
    }

    if (mask) ws_encrypt_decrypt(buffer, length, masking_key);

    // Control frames are always processed immediately (regardless of fragmented frames)
    if (op == WEBSOCKET_OPCODE_CLOSE || op == WEBSOCKET_OPCODE_PING || op == WEBSOCKET_OPCODE_PONG) {
        *opcode = op;
        *message = buffer;
        *message_length = length;

        return ESP_OK;
    }

    // Continuation frame
    if (op == WEBSOCKET_OPCODE_CONT) {
        if (fin) {
            // End of fragmented message, return all
            *opcode = client->buffer_opcode;
            *message = client->buffer;
            *message_length = client->buffer_len;

            client->buffer = NULL;
            client->buffer_len = 0;
        } else {
            *opcode = WEBSOCKET_OPCODE_CONT;
        }
        return ESP_OK;
    }

    // Only opcodes remaining
    ESP_ERROR_CHECK(op == WEBSOCKET_OPCODE_TEXT || op == WEBSOCKET_OPCODE_BIN);


    if (fin) {
        // Single frame message
        *opcode = op;
        *message = buffer;
        *message_length = length;
    } else {
        // Beginning of fragmented message
        client->buffer = buffer;
        client->buffer_len = length;
        client->buffer_opcode = op;

        *opcode = WEBSOCKET_OPCODE_CONT;
    }

    return ESP_OK;
}

int ws_hash_handshake(char *handshake, char *dest, size_t dest_len) {
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const size_t magic_len = strlen(magic);
    const size_t handshake_len = strlen(handshake);

    char key[58];
    if (handshake_len + magic_len > sizeof(key)) return -1;

    // Concatenate handshake key and hash
    memcpy(key, handshake, handshake_len);
    memcpy(key + handshake_len, magic, magic_len);

    // SHA1 concatenated string
    uint8_t sha1[20];
    mbedtls_sha1((unsigned char *) key, handshake_len + magic_len, sha1);

    // Check if enough space is available in dest buffer
    size_t len;
    mbedtls_base64_encode(NULL, 0, &len, sha1, sizeof(sha1));
    if (len + 1 > dest_len) return -1;

    // Base64 encode outputted hash
    mbedtls_base64_encode((unsigned char *) dest, dest_len, &len, sha1, sizeof(sha1));
    dest[len++] = '\0';

    return len;
}

static char *extract_http_header(const char *buffer, const char *key) {
    // Need space for key, at least 1 character, and newline
    if (strlen(key) + 2 > strlen(buffer)) return NULL;

    // Cheap search ignores potential problems where searched key is suffix of another longer key
    char *start = strcasestr(buffer, key);
    if (!start) return NULL;
    start += strlen(key);

    char *end = strstr(start, "\r\n");
    if (!end) return NULL;

    // Trim whitespace at start and end
    while (isspace((unsigned char) *start) && start < end) start++;
    while (isspace((unsigned char) *(end - 1)) && start < end) end--;

    int len = (int) (end - start);
    if (len == 0) return NULL;

    char *header_value = malloc(len);
    if (header_value == NULL) return NULL;

    memcpy(header_value, start, len);
    return header_value;
}
