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

#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

typedef struct ws_server *ws_server_handle_t;
typedef struct ws_server_client *ws_server_client_handle_t;

#include "websocket.h"

ESP_EVENT_DECLARE_BASE(WS_SERVER_EVENTS);
#define WS_SERVER_EVENT_CLIENT_CONNECTED 0
#define WS_SERVER_EVENT_CLIENT_DISCONNECTED 1
#define WS_SERVER_EVENT_MESSAGE 2

typedef struct ws_server_message {
    ws_server_handle_t server;
    ws_server_client_handle_t client;

    ws_message_t message;
} ws_server_message_t;

typedef struct ws_server_config {
    unsigned    task_priority;
    size_t      stack_size;
    BaseType_t  core_id;

    uint16_t    server_port;

    uint8_t     max_clients;
    uint16_t    backlog_conn;
} ws_server_config_t;

esp_err_t ws_server_start(ws_server_handle_t *handle, const ws_server_config_t *config);
esp_err_t ws_server_stop(ws_server_handle_t handle);

int ws_server_len_url(ws_server_handle_t server, char *url); // returns the number of connected clients to url
int ws_server_len_all(ws_server_handle_t server); // returns the total number of connected clients

int ws_server_remove_client(ws_server_client_handle_t client); // removes the client with the set number
int ws_server_remove_clients(ws_server_handle_t server, char *url); // removes all clients connected to the specified url
int ws_server_remove_all(ws_server_handle_t server); // removes all clients from the server

esp_err_t ws_server_send_text_client(ws_server_client_handle_t client, uint8_t *message, size_t message_length); // send text to client with the set number
int ws_server_send_text_clients(ws_server_handle_t server, char *url, uint8_t *message, size_t message_length); // sends text to all clients with the set number
int ws_server_send_text_all(ws_server_handle_t server, uint8_t *message, size_t message_length); // sends text to all clients

int ws_server_send_bin_client(ws_server_client_handle_t client, uint8_t *message, size_t message_length);
int ws_server_send_bin_clients(ws_server_handle_t server, char *url, uint8_t *message, size_t message_length);
int ws_server_send_bin_all(ws_server_handle_t server, uint8_t *message, size_t message_length);

esp_err_t ws_server_send_text_client_from_callback(ws_server_client_handle_t client, uint8_t *message, size_t message_length);
int ws_server_send_text_clients_from_callback(ws_server_handle_t server, char *url, uint8_t *message, size_t message_length);
int ws_server_send_text_all_from_callback(ws_server_handle_t server, uint8_t *message, size_t message_length);

int ws_server_ping();

#endif

#ifdef __cplusplus
}
#endif
