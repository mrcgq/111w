/*
 * v3_socks5.c - SOCKS5 代理服务器
 */

#include "v3.h"

/* ============================================================
 * SOCKS5 常量
 * ============================================================ */

#define SOCKS5_VER          0x05
#define SOCKS5_AUTH_NONE    0x00
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ATYP_IPV4    0x01
#define SOCKS5_ATYP_DOMAIN  0x03
#define SOCKS5_ATYP_IPV6    0x04
#define SOCKS5_REP_OK       0x00
#define SOCKS5_REP_FAIL     0x01

/* ============================================================
 * 结构体
 * ============================================================ */

typedef struct {
    SOCKET          sock;
    uint16_t        stream_id;
    uint8_t         atyp;
    char            dst_host[256];
    uint16_t        dst_port;
    volatile bool   running;
    v3_session_t   *session;
} socks5_conn_t;

struct v3_socks5_s {
    SOCKET          listen_sock;
    uint16_t        port;
    v3_session_t   *session;
    volatile bool   running;
    uint16_t        next_stream;
    v3_socks5_log_fn log_fn;
    void           *userdata;
};

/* ============================================================
 * 内部函数
 * ============================================================ */

static int socks5_handshake(SOCKET sock) {
    uint8_t buf[256];
    
    int n = recv(sock, (char*)buf, 2, 0);
    if (n < 2 || buf[0] != SOCKS5_VER) return -1;
    
    int nmethods = buf[1];
    if (nmethods > 0) {
        recv(sock, (char*)buf, nmethods, 0);
    }
    
    uint8_t resp[2] = {SOCKS5_VER, SOCKS5_AUTH_NONE};
    send(sock, (char*)resp, 2, 0);
    
    return 0;
}

static int socks5_read_request(SOCKET sock, socks5_conn_t *conn) {
    uint8_t buf[512];
    
    int n = recv(sock, (char*)buf, 4, 0);
    if (n < 4 || buf[0] != SOCKS5_VER || buf[1] != SOCKS5_CMD_CONNECT) {
        return -1;
    }
    
    conn->atyp = buf[3];
    
    switch (conn->atyp) {
        case SOCKS5_ATYP_IPV4: {
            n = recv(sock, (char*)buf, 4, 0);
            if (n < 4) return -1;
            struct in_addr addr;
            memcpy(&addr, buf, 4);
            inet_ntop(AF_INET, &addr, conn->dst_host, sizeof(conn->dst_host));
            break;
        }
        case SOCKS5_ATYP_DOMAIN: {
            n = recv(sock, (char*)buf, 1, 0);
            if (n < 1) return -1;
            int dlen = buf[0];
            n = recv(sock, (char*)conn->dst_host, dlen, 0);
            if (n < dlen) return -1;
            conn->dst_host[dlen] = '\0';
            break;
        }
        case SOCKS5_ATYP_IPV6: {
            n = recv(sock, (char*)buf, 16, 0);
            if (n < 16) return -1;
            struct in6_addr addr;
            memcpy(&addr, buf, 16);
            inet_ntop(AF_INET6, &addr, conn->dst_host, sizeof(conn->dst_host));
            break;
        }
        default:
            return -1;
    }
    
    n = recv(sock, (char*)buf, 2, 0);
    if (n < 2) return -1;
    conn->dst_port = (buf[0] << 8) | buf[1];
    
    return 0;
}

static void socks5_reply(SOCKET sock, uint8_t rep) {
    uint8_t buf[10] = {SOCKS5_VER, rep, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0};
    send(sock, (char*)buf, 10, 0);
}

/* ============================================================
 * 转发线程
 * ============================================================ */

static DWORD WINAPI forward_thread(LPVOID param) {
    socks5_conn_t *conn = (socks5_conn_t*)param;
    
    /* 构建目标地址包 */
    uint8_t addr_buf[256];
    size_t addr_len = 0;
    
    addr_buf[addr_len++] = conn->atyp;
    
    if (conn->atyp == SOCKS5_ATYP_DOMAIN) {
        size_t hlen = strlen(conn->dst_host);
        addr_buf[addr_len++] = (uint8_t)hlen;
        memcpy(addr_buf + addr_len, conn->dst_host, hlen);
        addr_len += hlen;
    } else if (conn->atyp == SOCKS5_ATYP_IPV4) {
        struct in_addr addr;
        inet_pton(AF_INET, conn->dst_host, &addr);
        memcpy(addr_buf + addr_len, &addr, 4);
        addr_len += 4;
    }
    
    addr_buf[addr_len++] = (conn->dst_port >> 8) & 0xFF;
    addr_buf[addr_len++] = conn->dst_port & 0xFF;
    
    /* 发送连接请求 */
    v3_session_send(conn->session, conn->stream_id, addr_buf, addr_len);
    
    uint8_t buf[4096];
    fd_set readfds;
    struct timeval tv;
    
    while (conn->running) {
        FD_ZERO(&readfds);
        FD_SET(conn->sock, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int ret = select(0, &readfds, NULL, NULL, &tv);
        
        /* 从客户端读取 -> 发送到 v3 */
        if (ret > 0 && FD_ISSET(conn->sock, &readfds)) {
            int n = recv(conn->sock, (char*)buf, sizeof(buf), 0);
            if (n <= 0) {
                V3_DEBUG("Client disconnected (stream %d)", conn->stream_id);
                break;
            }
            v3_session_send(conn->session, conn->stream_id, buf, n);
        }
        
        /* 从 v3 接收 -> 发送到客户端 */
        uint16_t stream_id;
        int n = v3_session_recv(conn->session, &stream_id, buf, sizeof(buf), 10);
        if (n > 0 && stream_id == conn->stream_id) {
            send(conn->sock, (char*)buf, n, 0);
        }
    }
    
    closesocket(conn->sock);
    free(conn);
    return 0;
}

/* ============================================================
 * 公共 API
 * ============================================================ */

v3_socks5_t* v3_socks5_create(const v3_socks5_config_t *cfg) {
    if (!cfg || !cfg->session) return NULL;
    
    v3_socks5_t *s = (v3_socks5_t*)calloc(1, sizeof(v3_socks5_t));
    if (!s) return NULL;
    
    s->port = cfg->listen_port ? cfg->listen_port : V3_DEFAULT_LOCAL_PORT;
    s->session = cfg->session;
    s->log_fn = cfg->log_fn;
    s->userdata = cfg->userdata;
    s->next_stream = 1;
    
    /* 创建监听 socket */
    s->listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_sock == INVALID_SOCKET) {
        free(s);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(s->listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(cfg->listen_addr ? cfg->listen_addr : "127.0.0.1");
    addr.sin_port = htons(s->port);
    
    if (bind(s->listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        V3_ERROR("bind failed on port %d: %d", s->port, WSAGetLastError());
        closesocket(s->listen_sock);
        free(s);
        return NULL;
    }
    
    if (listen(s->listen_sock, 32) == SOCKET_ERROR) {
        closesocket(s->listen_sock);
        free(s);
        return NULL;
    }
    
    V3_INFO("SOCKS5 listening on 127.0.0.1:%d", s->port);
    return s;
}

void v3_socks5_destroy(v3_socks5_t *s) {
    if (!s) return;
    v3_socks5_stop(s);
    free(s);
}

void v3_socks5_stop(v3_socks5_t *s) {
    if (!s) return;
    s->running = false;
    if (s->listen_sock != INVALID_SOCKET) {
        closesocket(s->listen_sock);
        s->listen_sock = INVALID_SOCKET;
    }
}

int v3_socks5_run(v3_socks5_t *s) {
    if (!s) return V3_ERR_INVALID_PARAM;
    
    s->running = true;
    
    while (s->running) {
        struct sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        
        SOCKET client = accept(s->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client == INVALID_SOCKET) {
            if (s->running) {
                V3_DEBUG("accept failed: %d", WSAGetLastError());
            }
            continue;
        }
        
        /* SOCKS5 握手 */
        if (socks5_handshake(client) != 0) {
            closesocket(client);
            continue;
        }
        
        /* 创建连接 */
        socks5_conn_t *conn = (socks5_conn_t*)calloc(1, sizeof(socks5_conn_t));
        if (!conn) {
            closesocket(client);
            continue;
        }
        
        conn->sock = client;
        conn->session = s->session;
        conn->stream_id = s->next_stream++;
        conn->running = true;
        
        /* 读取请求 */
        if (socks5_read_request(client, conn) != 0) {
            socks5_reply(client, SOCKS5_REP_FAIL);
            closesocket(client);
            free(conn);
            continue;
        }
        
        V3_INFO("CONNECT %s:%d (stream %d)", conn->dst_host, conn->dst_port, conn->stream_id);
        
        /* 回复成功 */
        socks5_reply(client, SOCKS5_REP_OK);
        
        /* 启动转发线程 */
        CreateThread(NULL, 0, forward_thread, conn, 0, NULL);
    }
    
    return V3_OK;
}
