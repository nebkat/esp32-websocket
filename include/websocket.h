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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <lwip/api.h>
#include <sys/queue.h>

typedef struct ws_client *ws_client_handle_t;

#define WEBSOCKET_CONTROL_MESSAGE_MAX_SIZE 125
#define WEBSOCKET_DATA_MESSAGE_MAX_SIZE 8192

typedef enum {
    WEBSOCKET_STATUS_OK = 0,
    WEBSOCKET_STATUS_CLOSE_NONE = 0,
    WEBSOCKET_STATUS_CLOSE_NORMAL = 1000,
    WEBSOCKET_STATUS_CLOSE_GOING_AWAY = 1001,
    WEBSOCKET_STATUS_CLOSE_PROTOCOL_ERROR = 1002,
    WEBSOCKET_STATUS_CLOSE_UNSUPPORTED_DATA = 1003,
    WEBSOCKET_STATUS_CLOSE_INVALID_FRAME_PAYLOAD_DATA = 1007,
    WEBSOCKET_STATUS_CLOSE_POLICY_VIOLATION = 1008,
    WEBSOCKET_STATUS_CLOSE_MESSAGE_TOO_BIG = 1009,
    WEBSOCKET_STATUS_CLOSE_INTERNAL_SERVER_ERROR = 1011
} websocket_status_t;

typedef enum {
    WEBSOCKET_OPCODE_CONT = 0x0,
    WEBSOCKET_OPCODE_TEXT = 0x1,
    WEBSOCKET_OPCODE_BIN = 0x2,
    WEBSOCKET_OPCODE_CLOSE = 0x8,
    WEBSOCKET_OPCODE_PING = 0x9,
    WEBSOCKET_OPCODE_PONG = 0xA
} websocket_opcode_t;

typedef struct ws_message {
    websocket_opcode_t opcode;

    size_t length;
    uint8_t message[WEBSOCKET_DATA_MESSAGE_MAX_SIZE];
} ws_message_t;

#include "websocket_server.h"

const char *ws_client_url(ws_client_handle_t client);
bool ws_client_connected(ws_client_handle_t client);

#endif // ifndef WEBSOCKET_H

#ifdef __cplusplus
}
#endif
