/*
 * v3_session.c - 会话管理
 */

#include "v3.h"

/* ============================================================
 * 会话结构
 * ============================================================ */

struct v3_session_s {
    /* 密钥 */
    uint8_t     key[V3_KEY_SIZE];
    
    /* 会话信息 */
    uint64_t    session_id;
    uint32_t    sequence;
    uint64_t    nonce_counter;
    
    /* 网络 */
    SOCKET      sock;
    struct sockaddr_storage server_addr;
    int         server_addr_len;
    bool        connected;
    
    /* 统计 */
    v3_session_stats_t stats;
    
    /* 同步 */
    CRITICAL_SECTION lock;
};

/* ============================================================
 * 创建/销毁
 * ============================================================ */

v3_session_t* v3_session_create(const uint8_t key[V3_KEY_SIZE]) {
    v3_session_t *s = (v3_session_t*)calloc(1, sizeof(v3_session_t));
    if (!s) return NULL;
    
    memcpy(s->key, key, V3_KEY_SIZE);
    v3_random_bytes((uint8_t*)&s->session_id, sizeof(s->session_id));
    s->sock = INVALID_SOCKET;
    
    InitializeCriticalSection(&s->lock);
    
    V3_DEBUG("Session created, id=%016llX", (unsigned long long)s->session_id);
    return s;
}

void v3_session_destroy(v3_session_t *s) {
    if (!s) return;
    
    if (s->sock != INVALID_SOCKET) {
        closesocket(s->sock);
    }
    
    v3_secure_zero(s->key, V3_KEY_SIZE);
    DeleteCriticalSection(&s->lock);
    free(s);
}

/* ============================================================
 * 服务器地址
 * ============================================================ */

int v3_session_set_server(v3_session_t *s, const char *host, uint16_t port) {
    if (!s || !host) return V3_ERR_INVALID_PARAM;
    
    struct sockaddr_in *addr4 = (struct sockaddr_in*)&s->server_addr;
    
    memset(&s->server_addr, 0, sizeof(s->server_addr));
    addr4->sin_family = AF_INET;
    addr4->sin_port = htons(port);
    
    /* 尝试直接解析 IP */
    if (inet_pton(AF_INET, host, &addr4->sin_addr) != 1) {
        /* DNS 解析 */
        struct addrinfo hints = {0}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        
        if (getaddrinfo(host, NULL, &hints, &res) != 0) {
            V3_ERROR("Cannot resolve: %s", host);
            return V3_ERR_NETWORK;
        }
        
        memcpy(&s->server_addr, res->ai_addr, res->ai_addrlen);
        addr4->sin_port = htons(port);
        freeaddrinfo(res);
    }
    
    s->server_addr_len = sizeof(struct sockaddr_in);
    return V3_OK;
}

/* ============================================================
 * 连接
 * ============================================================ */

int v3_session_connect(v3_session_t *s) {
    if (!s || s->server_addr_len == 0) return V3_ERR_INVALID_PARAM;
    
    /* 创建 UDP socket */
    s->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s->sock == INVALID_SOCKET) {
        V3_ERROR("socket() failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }
    
    /* 设置缓冲区 */
    int bufsize = 4 * 1024 * 1024;
    setsockopt(s->sock, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(bufsize));
    setsockopt(s->sock, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(bufsize));
    
    /* 设置非阻塞 */
    u_long nonblock = 1;
    ioctlsocket(s->sock, FIONBIO, &nonblock);
    
    /* 发送初始化包 */
    uint8_t init_pkt[V3_HEADER_SIZE];
    size_t init_len;
    
    EnterCriticalSection(&s->lock);
    {
        v3_header_t *hdr = (v3_header_t*)init_pkt;
        v3_metadata_t meta = {
            .session_id = s->session_id,
            .stream_id = 0,
            .flags = V3_FLAG_INIT,
            .sequence = s->sequence++
        };
        
        hdr->magic = v3_current_magic(s->key);
        v3_random_bytes(hdr->nonce, V3_NONCE_SIZE);
        
        uint8_t meta_raw[16];
        memcpy(meta_raw, &meta.session_id, 8);
        meta_raw[8] = meta.stream_id & 0xFF;
        meta_raw[9] = (meta.stream_id >> 8) & 0xFF;
        meta_raw[10] = meta.flags & 0xFF;
        meta_raw[11] = (meta.flags >> 8) & 0xFF;
        meta_raw[12] = meta.sequence & 0xFF;
        meta_raw[13] = (meta.sequence >> 8) & 0xFF;
        meta_raw[14] = (meta.sequence >> 16) & 0xFF;
        meta_raw[15] = (meta.sequence >> 24) & 0xFF;
        
        uint8_t aad[8];
        memset(aad, 0, 8);
        memcpy(aad + 4, &hdr->magic, 4);
        
        v3_aead_encrypt(hdr->enc_meta, hdr->tag, meta_raw, 16, aad, 8, hdr->nonce, s->key);
        hdr->payload_hint = 0;
        hdr->reserved = 0;
        
        init_len = V3_HEADER_SIZE;
    }
    LeaveCriticalSection(&s->lock);
    
    int sent = sendto(s->sock, (char*)init_pkt, (int)init_len, 0,
                      (struct sockaddr*)&s->server_addr, s->server_addr_len);
    
    if (sent <= 0) {
        V3_WARN("Failed to send init packet");
    }
    
    s->connected = true;
    V3_INFO("Connected to server");
    return V3_OK;
}

void v3_session_close(v3_session_t *s) {
    if (!s) return;
    
    if (s->sock != INVALID_SOCKET) {
        closesocket(s->sock);
        s->sock = INVALID_SOCKET;
    }
    s->connected = false;
}

bool v3_session_is_connected(v3_session_t *s) {
    return s && s->connected;
}

/* ============================================================
 * 发送
 * ============================================================ */

int v3_session_send(v3_session_t *s, uint16_t stream_id, const uint8_t *data, size_t len) {
    if (!s || !s->connected) return V3_ERR_INVALID_PARAM;
    if (len + V3_HEADER_SIZE > V3_MAX_PACKET) return V3_ERR_INVALID_PARAM;
    
    uint8_t packet[V3_MAX_PACKET];
    size_t packet_len;
    
    EnterCriticalSection(&s->lock);
    {
        v3_header_t *hdr = (v3_header_t*)packet;
        v3_metadata_t meta = {
            .session_id = s->session_id,
            .stream_id = stream_id,
            .flags = V3_FLAG_DATA,
            .sequence = s->sequence++
        };
        
        hdr->magic = v3_current_magic(s->key);
        v3_random_bytes(hdr->nonce, V3_NONCE_SIZE);
        
        uint8_t meta_raw[16];
        memcpy(meta_raw, &meta.session_id, 8);
        meta_raw[8] = meta.stream_id & 0xFF;
        meta_raw[9] = (meta.stream_id >> 8) & 0xFF;
        meta_raw[10] = meta.flags & 0xFF;
        meta_raw[11] = (meta.flags >> 8) & 0xFF;
        meta_raw[12] = meta.sequence & 0xFF;
        meta_raw[13] = (meta.sequence >> 8) & 0xFF;
        meta_raw[14] = (meta.sequence >> 16) & 0xFF;
        meta_raw[15] = (meta.sequence >> 24) & 0xFF;
        
        uint8_t aad[8];
        uint16_t hint = (len <= 255) ? (uint16_t)len : 0;
        memcpy(aad, &hint, 2);
        memset(aad + 2, 0, 2);
        memcpy(aad + 4, &hdr->magic, 4);
        
        v3_aead_encrypt(hdr->enc_meta, hdr->tag, meta_raw, 16, aad, 8, hdr->nonce, s->key);
        hdr->payload_hint = hint;
        hdr->reserved = 0;
        
        if (data && len > 0) {
            memcpy(packet + V3_HEADER_SIZE, data, len);
        }
        packet_len = V3_HEADER_SIZE + len;
        
        s->stats.packets_sent++;
        s->stats.bytes_sent += packet_len;
    }
    LeaveCriticalSection(&s->lock);
    
    int sent = sendto(s->sock, (char*)packet, (int)packet_len, 0,
                      (struct sockaddr*)&s->server_addr, s->server_addr_len);
    
    return (sent > 0) ? (int)len : V3_ERR_NETWORK;
}

/* ============================================================
 * 接收
 * ============================================================ */

int v3_session_recv(v3_session_t *s, uint16_t *stream_id, uint8_t *buf, size_t buf_len, int timeout_ms) {
    if (!s || !s->connected || !buf) return V3_ERR_INVALID_PARAM;
    
    /* 设置超时 */
    DWORD tv = timeout_ms;
    setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    
    uint8_t packet[V3_MAX_PACKET];
    struct sockaddr_storage from;
    int from_len = sizeof(from);
    
    int received = recvfrom(s->sock, (char*)packet, sizeof(packet), 0,
                            (struct sockaddr*)&from, &from_len);
    
    if (received <= 0) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) {
            return V3_ERR_TIMEOUT;
        }
        return V3_ERR_NETWORK;
    }
    
    if (received < V3_HEADER_SIZE) {
        return V3_ERR_PROTOCOL;
    }
    
    v3_header_t *hdr = (v3_header_t*)packet;
    
    /* 验证 Magic */
    if (!v3_verify_magic(s->key, hdr->magic, 1)) {
        V3_DEBUG("Invalid magic: 0x%08X", hdr->magic);
        return V3_ERR_PROTOCOL;
    }
    
    /* 解密元数据 */
    uint8_t aad[8];
    memcpy(aad, &hdr->payload_hint, 2);
    memcpy(aad + 2, &hdr->reserved, 2);
    memcpy(aad + 4, &hdr->magic, 4);
    
    uint8_t meta_raw[16];
    if (v3_aead_decrypt(meta_raw, hdr->enc_meta, 16, hdr->tag, aad, 8, hdr->nonce, s->key) != V3_OK) {
        V3_DEBUG("AEAD decrypt failed");
        return V3_ERR_AUTH_FAILED;
    }
    
    /* 解析元数据 */
    uint64_t sess_id;
    memcpy(&sess_id, meta_raw, 8);
    uint16_t sid = meta_raw[8] | (meta_raw[9] << 8);
    
    if (stream_id) *stream_id = sid;
    
    /* 复制 payload */
    size_t payload_len = received - V3_HEADER_SIZE;
    if (payload_len > buf_len) payload_len = buf_len;
    
    if (payload_len > 0) {
        memcpy(buf, packet + V3_HEADER_SIZE, payload_len);
    }
    
    EnterCriticalSection(&s->lock);
    s->stats.packets_recv++;
    s->stats.bytes_recv += received;
    LeaveCriticalSection(&s->lock);
    
    return (int)payload_len;
}

/* ============================================================
 * 统计
 * ============================================================ */

void v3_session_get_stats(v3_session_t *s, v3_session_stats_t *stats) {
    if (!s || !stats) return;
    
    EnterCriticalSection(&s->lock);
    memcpy(stats, &s->stats, sizeof(v3_session_stats_t));
    LeaveCriticalSection(&s->lock);
}
