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

#include <esp_event.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/param.h>

#include "websocket_priv.h"
#include "websocket_server.h"

static const char *TAG = "ws_server";

ESP_EVENT_DECLARE_BASE(WS_SERVER_EVENTS);

static SemaphoreHandle_t clients_semaphore;

static esp_err_t ws_server_init(ws_server_t *sd) {
    int fd = socket(PF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        ESP_LOGE(TAG, "Could not open socket: %d %s", errno, strerror(errno));
        return ESP_FAIL;
    }

    /* Enable SO_REUSEADDR to allow binding to the same
     * address and port when restarting the server */
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        /* This will fail if CONFIG_LWIP_SO_REUSE is not enabled. But
         * it does not affect the normal working of the WS Server */
        ESP_LOGW(TAG, "Could not set socket options: %d %s", errno, strerror(errno));
    }

    struct sockaddr_in6 srv_addr = {
            .sin6_family  = PF_INET6,
            .sin6_addr    = IN6ADDR_ANY_INIT,
            .sin6_port    = htons(sd->config.server_port)
    };

    int ret = bind(fd, (struct sockaddr *) &srv_addr, sizeof(srv_addr));
    if (ret < 0) {
        ESP_LOGE(TAG, "Could not bind socket: %d %s", errno, strerror(errno));
        close(fd);
        return ESP_FAIL;
    }

    ret = listen(fd, sd->config.backlog_conn);
    if (ret < 0) {
        ESP_LOGE(TAG, "Could not listen on socket: %d %s", errno, strerror(errno));
        close(fd);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t ws_server_accept(ws_server_t *sd) {
    struct sockaddr_in6 source_addr;
    uint addr_len = sizeof(source_addr);
    int sock = accept(sd->fd, (struct sockaddr *)&source_addr, &addr_len);
    if (sock < 0) {
        ESP_LOGE(TAG, "Could not accept new connection: %d %s", errno, strerror(errno));
        return ESP_FAIL;
    }

    char *url;
    esp_err_t err = ws_client_accept(sock, &url);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not perform client handshake");
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return err;
    }

    ws_client_t *client;
    err = ws_client_create(&client, sock, url);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not create client");
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return err;
    }

    ws_server_client_t *server_client = malloc(sizeof(ws_server_client_t));
    if (server_client == NULL) {
        ESP_LOGE(TAG, "Could not allocate server client");
        ws_client_delete(client);
    }

    SLIST_INSERT_HEAD(&sd->clients, server_client, next);

    return ESP_OK;
}

static void ws_server_client_read(ws_server_client_t *client) {
    websocket_opcode_t op;
    uint8_t *message;
    size_t length;
    websocket_status_t status = ws_client_read(client->client, &op, &message, &length);
    if (status != WEBSOCKET_STATUS_OK) {
        ws_client_disconnect(client->client, status, NULL, 0);
    }

    switch (op) {
        case WEBSOCKET_OPCODE_CONT:
            // Ignore, waiting for final message
            break;
        case WEBSOCKET_OPCODE_BIN:
            client->callback(client, WEBSOCKET_BIN, msg, header.length);
            break;
        case WEBSOCKET_OPCODE_TEXT:
            client->callback(client, WEBSOCKET_TEXT, msg, header.length);
            break;
        case WEBSOCKET_OPCODE_PING:
            // Respond with same message
            ws_client_send(client->client, WEBSOCKET_OPCODE_PONG, message, length, WEBSOCKET_STATUS_CLOSE_NONE);
            break;
        case WEBSOCKET_OPCODE_PONG:
            if (client->ping) {
                client->callback(client, WEBSOCKET_PONG, NULL, 0);
                client->ping = false;
            }
            break;
        case WEBSOCKET_OPCODE_CLOSE:
            // Respond with same message and code
            ws_client_disconnect(client->client, WEBSOCKET_STATUS_CLOSE_NONE, message, length);
        default:
            break;
    }
    free(msg);
}

static void ws_server_clients_receive(ws_server_t *sd, fd_set *socket_set) {
    ws_server_client_t *client, *client_tmp;
    SLIST_FOREACH_SAFE(client, &sd->clients, next, client_tmp) {
        if (!FD_ISSET(client->client->fd, socket_set)) continue;

        ws_server_client_read(client);
    }
}

static void ws_server_task(void *ctx) {
    ws_server_t *sd = (ws_server_t *) ctx;

    clients_semaphore = xSemaphoreCreateMutex();

    while (true) {
        fd_set socket_set;
        while (true) {
            // Reset all selected
            FD_ZERO(&socket_set);

            // New connections
            FD_SET(sd->fd, &socket_set);

            int maxfd = sd->fd;

            // Existing connections
            ws_server_client_t *client;
            SLIST_FOREACH(client, &sd->clients, next) {
                FD_SET(client->client->fd, &socket_set);
                maxfd = MAX(maxfd, client->client->fd);
            }

            // Wait for activity on one of selected
            int err = select(maxfd + 1, &socket_set, NULL, NULL, NULL);
            if (err < 0) {
                // TODO:
            }

            // Accept new connections
            if (FD_ISSET(sd->fd, &socket_set)) ws_server_accept(sd);

            // Read existing connections
            ws_server_clients_receive(sd, &socket_set);
        }
    }
}

static ws_server_t *ws_server_create(const ws_server_config_t *config) {
    /* Allocate memory for httpd instance data */
    ws_server_t *sd = calloc(1, sizeof(ws_server_t));
    if (!sd) {
        ESP_LOGE(TAG, "Failed to allocate memory for WS server instance");
        return NULL;
    }

    // Save the configuration for this instance
    sd->config = *config;
    return sd;
}

static void ws_server_client_disconnect(ws_server_client_handle_t client, websocket_status_t reason) {
    ws_client_disconnect(client->client, reason, NULL, 0);
    ws_client_delete(client->client);
    SLIST_REMOVE(&client->server->clients, client, ws_server_client, next);
    free(client);
}

static void ws_server_delete(ws_server_t *sd) {
    ws_server_client_t *client, *client_tmp;
    SLIST_FOREACH_SAFE(client, &sd->clients, next, client_tmp) {
        ws_client_disconnect(client->client, WEBSOCKET_STATUS_CLOSE_GOING_AWAY, NULL, 0);
        ws_client_delete(client->client);
        free(client);
    }

    free(sd);
}

esp_err_t ws_server_start(ws_server_handle_t *handle, const ws_server_config_t *config) {
    if (handle == NULL || config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ws_server_t *sd = ws_server_create(config);
    if (sd == NULL) {
        // Failed to allocate memory
        return ESP_ERR_NO_MEM;
    }

    // Initialize socket
    if (ws_server_init(sd) != ESP_OK) {
        ws_server_delete(sd);
        return ESP_FAIL;
    }

    // Start task
    if (xTaskCreatePinnedToCore(&ws_server_task, "ws_server_task",
            config->stack_size,
            sd,
            config->task_priority,
            &sd->task,
            config->core_id) != pdPASS) {
        ws_server_delete(sd);
        return ESP_FAIL;
    }

    *handle = sd;
    return ESP_OK;
}

esp_err_t ws_server_stop(ws_server_handle_t handle) {
    ws_server_t *sd = handle;
    if (sd == NULL) return ESP_ERR_INVALID_ARG;

    vTaskDelete(sd->task);

    ws_server_delete(sd);
    return ESP_OK;
}

int ws_server_len_url(ws_server_handle_t server, char *url) {
    int ret;
    ret = 0;
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    ws_server_client_t *client, *client_tmp;
    SLIST_FOREACH_SAFE(client, &server->clients, next, client_tmp) {
        if (client->client->url != NULL && strcmp(url, client->client->url) == 0) ret++;
    }
    xSemaphoreGive(clients_semaphore);
    return ret;
}

int ws_server_len_all(ws_server_handle_t server) {
    int ret = 0;
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    ws_server_client_t *client;
    SLIST_FOREACH(client, &server->clients, next) {
        ret++;
    }
    xSemaphoreGive(clients_semaphore);
    return ret;
}

esp_err_t ws_server_remove_client(ws_server_client_handle_t client) {
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    ws_server_client_disconnect(client, WEBSOCKET_STATUS_CLOSE_NORMAL);
    xSemaphoreGive(clients_semaphore);
    return ESP_OK;
}

int ws_server_remove_clients(ws_server_handle_t server, char *url) {
    int ret = 0;
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    ws_server_client_t *client, *client_tmp;
    SLIST_FOREACH_SAFE(client, &server->clients, next, client_tmp) {
        if (url != NULL && strcmp(url, client->client->url) != 0) continue;

        ws_server_client_disconnect(client, WEBSOCKET_STATUS_CLOSE_NORMAL);
        ret++;
    }
    xSemaphoreGive(clients_semaphore);
    return ret;
}

int ws_server_remove_all(ws_server_handle_t server) {
    return ws_server_remove_clients(server, NULL);
}

esp_err_t ws_server_send_text_client(ws_server_client_handle_t client, uint8_t *message, size_t message_length) {
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    esp_err_t ret = ws_server_send_text_client_from_callback(client, message, message_length);
    xSemaphoreGive(clients_semaphore);
    return ret;
}

int ws_server_send_text_clients(ws_server_handle_t server, char *url, uint8_t *message, size_t message_length) {
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    int ret = ws_server_send_text_clients_from_callback(server, url, message, message_length);
    xSemaphoreGive(clients_semaphore);
    return ret;
}

int ws_server_send_text_all(ws_server_handle_t server, uint8_t *message, size_t message_length) {
    xSemaphoreTake(clients_semaphore, portMAX_DELAY);
    int ret = ws_server_send_text_all_from_callback(server, message, message_length);
    xSemaphoreGive(clients_semaphore);
    return ret;
}

esp_err_t ws_server_send_text_client_from_callback(ws_server_client_handle_t client, uint8_t *message, size_t message_length) {
    websocket_status_t status = ws_client_send(client->client, WEBSOCKET_OPCODE_TEXT, message, message_length, 0);
    if (status != WEBSOCKET_STATUS_OK) {
        ws_server_client_disconnect(client, status);
        return ESP_FAIL;
    }

    return ESP_OK;
}

int ws_server_send_text_clients_from_callback(ws_server_handle_t server, char *url, uint8_t *message, size_t message_length) {
    int ret = 0;
    ws_server_client_t *client, *client_tmp;
    SLIST_FOREACH_SAFE(client, &server->clients, next, client_tmp) {
        if (url != NULL && (client->client->url == NULL || strcmp(client->client->url, url) != 0)) continue;

        esp_err_t err = ws_server_send_text_client_from_callback(client, message, message_length);
        ret += err == ESP_OK;
    }
    return ret;
}

int ws_server_send_text_all_from_callback(ws_server_handle_t server, uint8_t *message, size_t message_length) {
    return ws_server_send_text_clients_from_callback(server, NULL, message, message_length);
}