/*
 * v3_transport.c - Transport Layer Implementation (UDP and WSS)
 * 
 * 支持: UDP / WSS / DoH (DNS over HTTPS)
 */

#include "v3.h"

/* === FIX: 手动定义某些 MinGW winhttp.h 版本中缺失的错误码 === */
#ifndef ERROR_WINHTTP_WEB_SOCKET_CLOSE_RECEIVED
#define ERROR_WINHTTP_WEB_SOCKET_CLOSE_RECEIVED 12175
#endif

/* ============================================================
 * Transport 结构定义
 * ============================================================ */

struct v3_transport_s {
    v3_mode_t mode;
    const v3_client_config_t *config;
    char resolved_ip[64];  /* DoH 解析后的 IP 地址 */

    union {
        struct {
            SOCKET sock;
            struct sockaddr_storage server_addr;
            int server_addr_len;
        } udp;

        struct {
            HINTERNET hSession;
            HINTERNET hConnect;
            HINTERNET hRequest;
            HINTERNET hWebSocket;
        } wss;
    } handle;
};

/* ============================================================
 * DoH (DNS over HTTPS) 实现
 * ============================================================ */

/**
 * 执行 DoH 查询
 * 
 * @param doh_server  DoH 服务器 URL (如 "https://1.1.1.1/dns-query")
 * @param hostname    要解析的域名
 * @param out_ip      输出 IP 地址
 * @param out_ip_size 输出缓冲区大小
 * @return 0 成功, -1 失败
 */
static int perform_doh_query(const char *doh_server, const char *hostname, 
                             char *out_ip, size_t out_ip_size) {
    wchar_t w_doh_server[512] = {0};
    wchar_t w_hostname[256] = {0};
    URL_COMPONENTS urlComp;
    wchar_t szHostName[256];
    wchar_t szUrlPath[512];
    int ret = -1;

    /* 转换为宽字符 */
    MultiByteToWideChar(CP_UTF8, 0, doh_server, -1, w_doh_server, 512);
    MultiByteToWideChar(CP_UTF8, 0, hostname, -1, w_hostname, 256);

    /* 解析 DoH 服务器 URL */
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = szHostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = szUrlPath;
    urlComp.dwUrlPathLength = 512;

    if (!WinHttpCrackUrl(w_doh_server, 0, 0, &urlComp)) {
        V3_ERROR("DoH: Failed to parse DoH server URL: %s", doh_server);
        return -1;
    }

    /* 构建查询路径 (使用 JSON API 格式) */
    wchar_t final_path[1024];
    swprintf(final_path, 1024, L"%s?name=%s&type=A", szUrlPath, w_hostname);

    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    /* 创建 HTTP 会话 */
    hSession = WinHttpOpen(
        L"v3-doh-resolver/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession) {
        V3_ERROR("DoH: WinHttpOpen failed: %lu", GetLastError());
        goto cleanup;
    }

    /* 连接到 DoH 服务器 */
    INTERNET_PORT port = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) 
                         ? INTERNET_DEFAULT_HTTPS_PORT 
                         : INTERNET_DEFAULT_HTTP_PORT;
    hConnect = WinHttpConnect(hSession, szHostName, port, 0);
    if (!hConnect) {
        V3_ERROR("DoH: WinHttpConnect failed: %lu", GetLastError());
        goto cleanup;
    }

    /* 创建 HTTP 请求 */
    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        final_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );
    if (!hRequest) {
        V3_ERROR("DoH: WinHttpOpenRequest failed: %lu", GetLastError());
        goto cleanup;
    }

    /* 添加 Accept 头以请求 JSON 格式 */
    if (!WinHttpAddRequestHeaders(hRequest, L"Accept: application/dns-json", 
                                  (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {
        V3_WARN("DoH: Failed to add Accept header");
    }

    /* 发送请求 */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        V3_ERROR("DoH: WinHttpSendRequest failed: %lu", GetLastError());
        goto cleanup;
    }

    /* 接收响应 */
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        V3_ERROR("DoH: WinHttpReceiveResponse failed: %lu", GetLastError());
        goto cleanup;
    }

    /* 读取响应数据 */
    char response_buf[4096] = {0};
    DWORD bytesRead = 0;
    if (WinHttpReadData(hRequest, response_buf, sizeof(response_buf) - 1, &bytesRead)) {
        /* 简单解析 JSON 响应中的 IP 地址 */
        char *p = strstr(response_buf, "\"data\":\"");
        if (p) {
            p += 8;  /* 跳过 "data":" */
            char *end = strchr(p, '"');
            if (end) {
                *end = '\0';
                strncpy_s(out_ip, out_ip_size, p, _TRUNCATE);
                V3_INFO("DoH: Resolved %s -> %s via %s", hostname, out_ip, doh_server);
                ret = 0;
            }
        }
        
        if (ret != 0) {
            V3_DEBUG("DoH: Response parsing failed, raw response: %.200s", response_buf);
        }
    }

cleanup:
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ret;
}

/**
 * 使用 DoH 解析主机名
 * 
 * @param cfg         客户端配置
 * @param hostname    要解析的主机名
 * @param out_ip      输出 IP 地址
 * @param out_ip_size 输出缓冲区大小
 * @return 0 成功, -1 失败
 */
static int resolve_with_doh(const v3_client_config_t *cfg, const char *hostname,
                            char *out_ip, size_t out_ip_size) {
    /* 尝试主 DoH 服务器 */
    if (cfg->doh_server_1) {
        if (perform_doh_query(cfg->doh_server_1, hostname, out_ip, out_ip_size) == 0) {
            return 0;
        }
        V3_WARN("DoH: Primary server failed, trying backup...");
    }

    /* 尝试备用 DoH 服务器 */
    if (cfg->doh_server_2) {
        if (perform_doh_query(cfg->doh_server_2, hostname, out_ip, out_ip_size) == 0) {
            return 0;
        }
    }

    V3_ERROR("DoH: All DoH queries failed for %s", hostname);
    return -1;
}

/* ============================================================
 * WSS Transport 实现
 * ============================================================ */

static int wss_connect(v3_transport_t *t, const char *target_host) {
    const v3_client_config_t *cfg = t->config;

    /* 创建 WinHTTP 会话 */
    t->handle.wss.hSession = WinHttpOpen(
        L"v3-client/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!t->handle.wss.hSession) {
        V3_ERROR("WinHttpOpen failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 转换目标主机名为宽字符 */
    wchar_t w_target_host[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, target_host, -1, w_target_host, 256);

    /* 连接到服务器 */
    t->handle.wss.hConnect = WinHttpConnect(
        t->handle.wss.hSession,
        w_target_host,
        cfg->server_port,
        0
    );
    if (!t->handle.wss.hConnect) {
        V3_ERROR("WinHttpConnect failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 转换 WebSocket 路径 */
    wchar_t w_path[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, cfg->wss_path, -1, w_path, 256);

    /* 创建 HTTPS 请求 */
    t->handle.wss.hRequest = WinHttpOpenRequest(
        t->handle.wss.hConnect,
        L"GET",
        w_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );
    if (!t->handle.wss.hRequest) {
        V3_ERROR("WinHttpOpenRequest failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 设置 WebSocket 升级选项 */
    if (!WinHttpSetOption(t->handle.wss.hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        V3_ERROR("WinHttpSetOption (WebSocket Upgrade) failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 添加自定义 Host 头 (用于 CDN) */
    if (cfg->wss_host_header) {
        wchar_t w_host_header[512];
        swprintf(w_host_header, 512, L"Host: %hs", cfg->wss_host_header);
        if (!WinHttpAddRequestHeaders(t->handle.wss.hRequest, w_host_header, 
                                      (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {
            V3_WARN("Failed to add Host header: %lu", GetLastError());
        }
    }

    /* 发送请求 */
    if (!WinHttpSendRequest(t->handle.wss.hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 
                            0, NULL, 0, 0, 0)) {
        V3_ERROR("WinHttpSendRequest failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 接收响应 */
    if (!WinHttpReceiveResponse(t->handle.wss.hRequest, NULL)) {
        V3_ERROR("WinHttpReceiveResponse failed: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }

    /* 完成 WebSocket 升级 */
    t->handle.wss.hWebSocket = WinHttpWebSocketCompleteUpgrade(t->handle.wss.hRequest, 0);
    if (!t->handle.wss.hWebSocket) {
        V3_ERROR("WinHttpWebSocketCompleteUpgrade failed: %lu", GetLastError());
        WinHttpCloseHandle(t->handle.wss.hRequest);
        t->handle.wss.hRequest = NULL;
        return V3_ERR_NETWORK;
    }

    /* 关闭已升级的 HTTP 请求句柄 */
    WinHttpCloseHandle(t->handle.wss.hRequest);
    t->handle.wss.hRequest = NULL;

    V3_INFO("WSS connection established to %s:%d", target_host, cfg->server_port);
    return V3_OK;
}

static int wss_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    DWORD error = WinHttpWebSocketSend(
        t->handle.wss.hWebSocket,
        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
        (PVOID)data,
        (DWORD)len
    );

    if (error != ERROR_SUCCESS) {
        V3_ERROR("WinHttpWebSocketSend failed: %lu", error);
        return V3_ERR_NETWORK;
    }

    return (int)len;
}

static int wss_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;

    (void)timeout_ms;  /* TODO: 实现超时控制 */

    DWORD error = WinHttpWebSocketReceive(
        t->handle.wss.hWebSocket,
        buf,
        (DWORD)buf_len,
        &bytesRead,
        &bufferType
    );

    if (error != ERROR_SUCCESS) {
        if (error == ERROR_WINHTTP_WEB_SOCKET_CLOSE_RECEIVED) {
            return V3_ERR_CLOSED;
        }
        V3_ERROR("WinHttpWebSocketReceive failed: %lu", error);
        return V3_ERR_NETWORK;
    }

    return (int)bytesRead;
}

static void wss_close(v3_transport_t *t) {
    if (t->handle.wss.hWebSocket) {
        WinHttpWebSocketClose(t->handle.wss.hWebSocket, 
                              WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WinHttpCloseHandle(t->handle.wss.hWebSocket);
    }
    if (t->handle.wss.hRequest) {
        WinHttpCloseHandle(t->handle.wss.hRequest);
    }
    if (t->handle.wss.hConnect) {
        WinHttpCloseHandle(t->handle.wss.hConnect);
    }
    if (t->handle.wss.hSession) {
        WinHttpCloseHandle(t->handle.wss.hSession);
    }
    memset(&t->handle.wss, 0, sizeof(t->handle.wss));
}

/* ============================================================
 * UDP Transport 实现
 * ============================================================ */

static int udp_connect(v3_transport_t *t, const char *target_host) {
    const v3_client_config_t *cfg = t->config;

    struct sockaddr_in *addr4 = (struct sockaddr_in *)&t->handle.udp.server_addr;
    memset(&t->handle.udp.server_addr, 0, sizeof(t->handle.udp.server_addr));
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(cfg->server_port);

    /* 尝试直接解析为 IP 地址 */
    if (inet_pton(AF_INET, target_host, &addr4->sin_addr) != 1) {
        /* 解析失败，使用系统 DNS */
        struct addrinfo hints = {0};
        struct addrinfo *res = NULL;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(target_host, NULL, &hints, &res) != 0) {
            V3_ERROR("Cannot resolve: %s", target_host);
            return V3_ERR_NETWORK;
        }

        memcpy(&t->handle.udp.server_addr, res->ai_addr, res->ai_addrlen);
        addr4->sin_port = htons(cfg->server_port);
        freeaddrinfo(res);
    }

    t->handle.udp.server_addr_len = sizeof(struct sockaddr_in);

    /* 创建 UDP socket */
    t->handle.udp.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (t->handle.udp.sock == INVALID_SOCKET) {
        V3_ERROR("socket() failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }

    V3_INFO("UDP socket created for %s:%d", target_host, cfg->server_port);
    return V3_OK;
}

static int udp_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    int sent = sendto(
        t->handle.udp.sock,
        (const char *)data,
        (int)len,
        0,
        (const struct sockaddr *)&t->handle.udp.server_addr,
        t->handle.udp.server_addr_len
    );

    if (sent <= 0) {
        V3_ERROR("sendto() failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }

    return sent;
}

static int udp_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    /* 设置接收超时 */
    DWORD tv = (DWORD)timeout_ms;
    setsockopt(t->handle.udp.sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    struct sockaddr_storage from;
    int from_len = sizeof(from);

    int received = recvfrom(
        t->handle.udp.sock,
        (char *)buf,
        (int)buf_len,
        0,
        (struct sockaddr *)&from,
        &from_len
    );

    if (received <= 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) {
            return V3_ERR_TIMEOUT;
        }
        return V3_ERR_NETWORK;
    }

    return received;
}

static void udp_close(v3_transport_t *t) {
    if (t->handle.udp.sock != INVALID_SOCKET) {
        closesocket(t->handle.udp.sock);
        t->handle.udp.sock = INVALID_SOCKET;
    }
}

/* ============================================================
 * 公共 Transport API
 * ============================================================ */

v3_transport_t *v3_transport_create(const v3_client_config_t *cfg) {
    if (!cfg) {
        return NULL;
    }

    v3_transport_t *t = (v3_transport_t *)calloc(1, sizeof(v3_transport_t));
    if (!t) {
        return NULL;
    }

    t->mode = cfg->mode;
    t->config = cfg;
    t->resolved_ip[0] = '\0';

    return t;
}

void v3_transport_destroy(v3_transport_t *t) {
    if (!t) {
        return;
    }
    v3_transport_close(t);
    free(t);
}

int v3_transport_connect(v3_transport_t *t) {
    if (!t || !t->config) {
        return V3_ERR_INVALID_PARAM;
    }

    const v3_client_config_t *cfg = t->config;
    const char *target_host = cfg->server_host;

    /* 如果启用了 DoH，先进行 DNS 解析 */
    if (cfg->doh_enabled) {
        V3_INFO("DoH enabled, resolving %s...", cfg->server_host);

        if (resolve_with_doh(cfg, cfg->server_host, t->resolved_ip, sizeof(t->resolved_ip)) == 0) {
            target_host = t->resolved_ip;
            V3_INFO("Using DoH resolved IP: %s", target_host);
        } else {
            V3_WARN("DoH failed, falling back to system DNS");
        }
    }

    /* 根据模式连接 */
    if (t->mode == V3_MODE_WSS) {
        return wss_connect(t, target_host);
    }
    return udp_connect(t, target_host);
}

void v3_transport_close(v3_transport_t *t) {
    if (!t) {
        return;
    }

    if (t->mode == V3_MODE_WSS) {
        wss_close(t);
    } else {
        udp_close(t);
    }
}

int v3_transport_send(v3_transport_t *t, const uint8_t *data, size_t len) {
    if (!t || !data || len == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    if (t->mode == V3_MODE_WSS) {
        return wss_send(t, data, len);
    }
    return udp_send(t, data, len);
}

int v3_transport_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms) {
    if (!t || !buf || buf_len == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    if (t->mode == V3_MODE_WSS) {
        return wss_recv(t, buf, buf_len, timeout_ms);
    }
    return udp_recv(t, buf, buf_len, timeout_ms);
}
