/*
 * v3_session.c - 会话管理 (Refactored to use Transport Layer)
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
    
    /* === 修改点: 使用 transport 对象替代 socket === */
    v3_transport_t *transport; 
    bool        connected;
    
    /* 统计 */
    v3_session_stats_t stats;
    
    /* 同步 */
    CRITICAL_SECTION lock;
};

/* ============================================================
 * 内部协议函数
 * ============================================================ */
static int v3_session_build_and_send_packet(v3_session_t *s, uint16_t stream_id, uint16_t flags, const uint8_t *data, size_t len) {
    uint8_t packet[V3_MAX_PACKET];
    
    v3_header_t *hdr = (v3_header_t*)packet;
    hdr->magic = v3_current_magic(s->key);
    v3_random_bytes(hdr->nonce, V3_NONCE_SIZE);

    v3_metadata_t meta = {
        .session_id = s->session_id,
        .stream_id = stream_id,
        .flags = flags,
        .sequence = s->sequence++
    };
    uint8_t meta_raw[16];
    memcpy(meta_raw + 0, &meta.session_id, 8);
    memcpy(meta_raw + 8, &meta.stream_id, 2);
    memcpy(meta_raw + 10, &meta.flags, 2);
    memcpy(meta_raw + 12, &meta.sequence, 4);

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
    size_t packet_len = V3_HEADER_SIZE + len;

    int sent = v3_transport_send(s->transport, packet, packet_len);
    if (sent > 0) {
        s->stats.packets_sent++;
        s->stats.bytes_sent += packet_len;
        return (int)len;
    }
    return V3_ERR_NETWORK;
}

/* ============================================================
 * 创建/销毁
 * ============================================================ */

v3_session_t* v3_session_create(const uint8_t key[V3_KEY_SIZE], const v3_client_config_t *cfg) {
    v3_session_t *s = (v3_session_t*)calloc(1, sizeof(v3_session_t));
    if (!s) return NULL;
    
    memcpy(s->key, key, V3_KEY_SIZE);
    v3_random_bytes((uint8_t*)&s->session_id, sizeof(s->session_id));
    
    s->transport = v3_transport_create(cfg);
    if (!s->transport) {
        free(s);
        return NULL;
    }
    
    InitializeCriticalSection(&s->lock);
    V3_DEBUG("Session created, id=%016llX", (unsigned long long)s->session_id);
    return s;
}

void v3_session_destroy(v3_session_t *s) {
    if (!s) return;
    v3_transport_destroy(s->transport);
    v3_secure_zero(s->key, V3_KEY_SIZE);
    DeleteCriticalSection(&s->lock);
    free(s);
}

/* ============================================================
 * 连接
 * ============================================================ */

int v3_session_connect(v3_session_t *s) {
    if (!s || !s->transport) return V3_ERR_INVALID_PARAM;
    
    if (v3_transport_connect(s->transport) != V3_OK) {
        return V3_ERR_NETWORK;
    }
    
    EnterCriticalSection(&s->lock);
    v3_session_build_and_send_packet(s, 0, V3_FLAG_INIT, NULL, 0);
    LeaveCriticalSection(&s->lock);
    
    s->connected = true;
    V3_INFO("Session connected to server.");
    return V3_OK;
}

void v3_session_close(v3_session_t *s) {
    if (!s) return;
    v3_transport_close(s->transport);
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
    
    int result;
    EnterCriticalSection(&s->lock);
    result = v3_session_build_and_send_packet(s, stream_id, V3_FLAG_DATA, data, len);
    LeaveCriticalSection(&s->lock);
    
    return result;
}

/* ============================================================
 * 接收
 * ============================================================ */

int v3_session_recv(v3_session_t *s, uint16_t *stream_id, uint8_t *buf, size_t buf_len, int timeout_ms) {
    if (!s || !s->connected || !buf) return V3_ERR_INVALID_PARAM;
    
    uint8_t packet[V3_MAX_PACKET];
    int received = v3_transport_recv(s->transport, packet, sizeof(packet), timeout_ms);
    
    if (received <= 0) {
        return received;
    }
    
    if (received < V3_HEADER_SIZE) {
        return V3_ERR_PROTOCOL;
    }
    
    v3_header_t *hdr = (v3_header_t*)packet;
    
    if (!v3_verify_magic(s->key, hdr->magic, 1)) {
        V3_DEBUG("Invalid magic: 0x%08X", hdr->magic);
        return V3_ERR_PROTOCOL;
    }
    
    uint8_t aad[8];
    memcpy(aad, &hdr->payload_hint, 2);
    memcpy(aad + 2, &hdr->reserved, 2);
    memcpy(aad + 4, &hdr->magic, 4);
    
    uint8_t meta_raw[16];
    if (v3_aead_decrypt(meta_raw, hdr->enc_meta, 16, hdr->tag, aad, 8, hdr->nonce, s->key) != V3_OK) {
        V3_DEBUG("AEAD decrypt failed");
        return V3_ERR_AUTH_FAILED;
    }
    
    v3_metadata_t meta;
    memcpy(&meta.session_id, meta_raw + 0, 8);
    memcpy(&meta.stream_id, meta_raw + 8, 2);
    memcpy(&meta.flags, meta_raw + 10, 2);
    memcpy(&meta.sequence, meta_raw + 12, 4);
    
    if (stream_id) *stream_id = meta.stream_id;
    
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
