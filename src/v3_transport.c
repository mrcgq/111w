/*
 * v3_transport.c - Transport Layer Implementation (UDP and WSS)
 */
#include "v3.h"

struct v3_transport_s {
    v3_mode_t mode;
    const v3_client_config_t *config;

    union {
        // UDP-specific data
        struct {
            SOCKET sock;
            struct sockaddr_storage server_addr;
            int server_addr_len;
        } udp;

        // WSS-specific data
        struct {
            HINTERNET hSession;
            HINTERNET hConnect;
            HINTERNET hRequest;
            HINTERNET hWebSocket;
        } wss;
    } handle;
};

// --- WSS Transport Implementation ---

static int wss_connect(v3_transport_t *t) {
    const v3_client_config_t* cfg = t->config;
    
    t->handle.wss.hSession = WinHttpOpen(L"v3-client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!t->handle.wss.hSession) {
        V3_ERROR("WinHttpOpen failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    // Convert multi-byte server host to wide char for WinHttpConnect
    wchar_t w_host_server[256];
    mbstowcs(w_host_server, cfg->server_host, 256);

    t->handle.wss.hConnect = WinHttpConnect(t->handle.wss.hSession, w_host_server, cfg->server_port, 0);
    if (!t->handle.wss.hConnect) {
        V3_ERROR("WinHttpConnect failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }
    
    wchar_t w_path[256];
    mbstowcs(w_path, cfg->wss_path, 256);

    t->handle.wss.hRequest = WinHttpOpenRequest(t->handle.wss.hConnect, L"GET", w_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!t->handle.wss.hRequest) {
        V3_ERROR("WinHttpOpenRequest failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }
    
    if (!WinHttpSetOption(t->handle.wss.hRequest, WINHTTP_OPTION_UPGRADE_TO_WEBSOCKET, NULL, 0)) {
        V3_ERROR("WinHttpSetOption (WebSocket Upgrade) failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }
    
    // Set Host header if provided
    if (cfg->wss_host_header) {
       wchar_t w_host_header[512];
       swprintf(w_host_header, 512, L"Host: %hs", cfg->wss_host_header);
       if (!WinHttpAddRequestHeaders(t->handle.wss.hRequest, w_host_header, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {
           V3_WARN("Failed to add Host header: %lu", GetLastError());
       }
    }

    if (!WinHttpSendRequest(t->handle.wss.hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        V3_ERROR("WinHttpSendRequest failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    if (!WinHttpReceiveResponse(t->handle.wss.hRequest, NULL)) {
        V3_ERROR("WinHttpReceiveResponse failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    t->handle.wss.hWebSocket = WinHttpWebSocketCompleteUpgrade(t->handle.wss.hRequest, 0);
    if (!t->handle.wss.hWebSocket) {
        V3_ERROR("WinHttpWebSocketCompleteUpgrade failed: %lu", GetLastError());
        WinHttpCloseHandle(t->handle.wss.hRequest);
        t->handle.wss.hRequest = NULL;
        return V3_ERR_NETWORK;
    }
    
    WinHttpCloseHandle(t->handle.wss.hRequest);
    t->handle.wss.hRequest = NULL;
    V3_INFO("WSS connection established.");
    return V3_OK;
}

static int wss_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    DWORD error = WinHttpWebSocketSend(t->handle.wss.hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE, (PVOID)data, (DWORD)len);
    if (error != ERROR_SUCCESS) {
        V3_ERROR("WinHttpWebSocketSend failed: %lu", error);
        return V3_ERR_NETWORK;
    }
    return (int)len;
}

static int wss_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    DWORD bytesRead = 0;
    DWORD bufferType;
    
    // WinHttp doesn't have a direct timeout on recv. For a simple client, this is a limitation.
    (void)timeout_ms; 

    DWORD error = WinHttpWebSocketReceive(t->handle.wss.hWebSocket, buf, (DWORD)buf_len, &bytesRead, &bufferType);
    if (error != ERROR_SUCCESS) {
        if (error == ERROR_WINHTTP_WEB_SOCKET_CLOSE_RECEIVED) return V3_ERR_CLOSED;
        V3_ERROR("WinHttpWebSocketReceive failed: %lu", error);
        return V3_ERR_NETWORK;
    }
    return (int)bytesRead;
}

static void wss_close(v3_transport_t *t) {
    if (t->handle.wss.hWebSocket) WinHttpWebSocketClose(t->handle.wss.hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    if (t->handle.wss.hRequest) WinHttpCloseHandle(t->handle.wss.hRequest);
    if (t->handle.wss.hConnect) WinHttpCloseHandle(t->handle.wss.hConnect);
    if (t->handle.wss.hSession) WinHttpCloseHandle(t->handle.wss.hSession);
    memset(&t->handle.wss, 0, sizeof(t->handle.wss));
}

// --- UDP Transport Implementation ---

static int udp_connect(v3_transport_t *t) {
    const v3_client_config_t *cfg = t->config;
    
    struct sockaddr_in *addr4 = (struct sockaddr_in*)&t->handle.udp.server_addr;
    memset(&t->handle.udp.server_addr, 0, sizeof(t->handle.udp.server_addr));
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(cfg->server_port);
    if (inet_pton(AF_INET, cfg->server_host, &addr4->sin_addr) != 1) {
        struct addrinfo hints = {0}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(cfg->server_host, NULL, &hints, &res) != 0) {
            V3_ERROR("Cannot resolve: %s", cfg->server_host);
            return V3_ERR_NETWORK;
        }
        memcpy(&t->handle.udp.server_addr, res->ai_addr, res->ai_addrlen);
        addr4->sin_port = htons(cfg->server_port);
        freeaddrinfo(res);
    }
    t->handle.udp.server_addr_len = sizeof(struct sockaddr_in);

    t->handle.udp.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (t->handle.udp.sock == INVALID_SOCKET) {
        V3_ERROR("socket() failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }
    return V3_OK;
}

static int udp_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    int sent = sendto(t->handle.udp.sock, (const char*)data, (int)len, 0,
                      (const struct sockaddr*)&t->handle.udp.server_addr, t->handle.udp.server_addr_len);
    return (sent > 0) ? sent : V3_ERR_NETWORK;
}

static int udp_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    DWORD tv = timeout_ms;
    setsockopt(t->handle.udp.sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    struct sockaddr_storage from;
    int from_len = sizeof(from);
    int received = recvfrom(t->handle.udp.sock, (char*)buf, (int)buf_len, 0, (struct sockaddr*)&from, &from_len);

    if (received <= 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) return V3_ERR_TIMEOUT;
        return V3_ERR_NETWORK;
    }
    return received;
}

static void udp_close(v3_transport_t *t) {
    if (t->handle.udp.sock != INVALID_SOCKET) {
        closesocket(t->handle.udp.sock);
    }
    t->handle.udp.sock = INVALID_SOCKET;
}

// --- Public Transport API ---

v3_transport_t* v3_transport_create(const v3_client_config_t *cfg) {
    v3_transport_t *t = (v3_transport_t*)calloc(1, sizeof(v3_transport_t));
    if (!t) return NULL;
    t->mode = cfg->mode;
    t->config = cfg;
    return t;
}

void v3_transport_destroy(v3_transport_t *t) {
    if (!t) return;
    v3_transport_close(t);
    free(t);
}

int v3_transport_connect(v3_transport_t *t) {
    if (t->mode == V3_MODE_WSS) {
        return wss_connect(t);
    }
    return udp_connect(t);
}

void v3_transport_close(v3_transport_t *t) {
    if (t->mode == V3_MODE_WSS) {
        wss_close(t);
    } else {
        udp_close(t);
    }
}

int v3_transport_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    if (t->mode == V3_MODE_WSS) {
        return wss_send(t, data, len);
    }
    return udp_send(t, data, len);
}

int v3_transport_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    if (t->mode == V3_MODE_WSS) {
        return wss_recv(t, buf, buf_len, timeout_ms);
    }
    return udp_recv(t, buf, buf_len, timeout_ms);
}
