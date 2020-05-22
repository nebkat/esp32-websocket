/* 
 * This file is part of the ESP32-XBee distribution (https://github.com/nebkat/esp32-xbee).
 * Copyright (c) 2020 Nebojsa Cvetkovic.
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

#ifndef WEBSOCKET_PRIV_H
#define WEBSOCKET_PRIV_H

#include <sys/queue.h>

#include "websocket.h"
#include "websocket_server.h"

typedef SLIST_HEAD(ws_server_client_list, ws_server_client) ws_server_client_list_t;

typedef struct ws_client {
    int fd;

    const char *url;
    char *protocol;

    bool ping;

    uint8_t *buffer;
    size_t buffer_len;
    websocket_opcode_t buffer_opcode;
} ws_client_t;

typedef struct ws_server {
    ws_server_config_t config;
    int fd;
    TaskHandle_t task;
    //ws_server_uri_t **uris;

    ws_server_client_list_t clients;
} ws_server_t;

typedef struct ws_server_client {
    ws_server_handle_t server;
    ws_client_handle_t client;

    SLIST_ENTRY(ws_server_client) next;
} ws_server_client_t;

// the header, useful for creating and quickly passing to functions
typedef struct {
    uint8_t LEN:7;     // bits 0..  6
    bool MASK:1;    // bit  7
    uint8_t OPCODE:4;  // bits 8..  11
    uint8_t :3;        // bits 12.. 14 reserved
    bool FIN:1;     // bit  15
} ws_header_t;

esp_err_t ws_client_create(ws_client_handle_t *handle, int fd, const char *url);
void ws_client_delete(ws_client_handle_t client);

esp_err_t ws_client_accept(int sock, char **url);

websocket_status_t ws_client_read(ws_client_handle_t client, websocket_opcode_t *opcode, uint8_t **message, size_t *message_length);
websocket_status_t ws_client_send(ws_client_t *client, websocket_opcode_t opcode, uint8_t *message, size_t message_length, uint16_t close_reason);

websocket_status_t
ws_client_disconnect(ws_client_handle_t client, websocket_status_t reason, uint8_t *message, size_t message_length);

#endif //WEBSOCKET_PRIV_H
