
/*
 * v3.h - v3 Protocol Core (Windows Only, WSS/DoH Enabled)
 * 
 * 单线设计，专为 Windows 优化
 * 支持: MSVC / MinGW-w64
 * 功能: UDP / WSS / DoH
 */

#ifndef V3_H
#define V3_H

/* === 定义 Windows 版本以启用新 API (必须放在所有 include 之前) === */
#define _WIN32_WINNT 0x0A00 // Windows 10

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* === 头文件 === */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* === 链接库 (仅 MSVC) === */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * 版本信息
 * ============================================================ */

#define V3_VERSION_MAJOR    1
#define V3_VERSION_MINOR    0
#define V3_VERSION_PATCH    0
#define V3_VERSION_STRING   "1.0.0"

/* ============================================================
 * 常量
 * ============================================================ */

#define V3_HEADER_SIZE          52
#define V3_KEY_SIZE             32
#define V3_NONCE_SIZE           12
#define V3_TAG_SIZE             16
#define V3_MAX_PACKET           1500
#define V3_MAGIC_WINDOW_SEC     60
#define V3_DEFAULT_PORT         51820
#define V3_DEFAULT_LOCAL_PORT   10808
#define V3_BUFFER_SIZE          4096
#define V3_MAX_CONNECTIONS      1024

/* ============================================================
 * 错误码
 * ============================================================ */

typedef enum {
    V3_OK               = 0,
    V3_ERR_INVALID_PARAM = -1,
    V3_ERR_NO_MEMORY    = -2,
    V3_ERR_NETWORK      = -3,
    V3_ERR_CRYPTO       = -4,
    V3_ERR_PROTOCOL     = -5,
    V3_ERR_TIMEOUT      = -6,
    V3_ERR_CLOSED       = -7,
    V3_ERR_WOULD_BLOCK  = -8,
    V3_ERR_AUTH_FAILED  = -9,
} v3_error_t;

/* ============================================================
 * 日志
 * ============================================================ */

typedef enum {
    V3_LOG_DEBUG = 0,
    V3_LOG_INFO  = 1,
    V3_LOG_WARN  = 2,
    V3_LOG_ERROR = 3,
} v3_log_level_t;

void v3_log_init(v3_log_level_t level, const char *file);
void v3_log(v3_log_level_t level, const char *fmt, ...);

#define V3_DEBUG(...)   v3_log(V3_LOG_DEBUG, __VA_ARGS__)
#define V3_INFO(...)    v3_log(V3_LOG_INFO, __VA_ARGS__)
#define V3_WARN(...)    v3_log(V3_LOG_WARN, __VA_ARGS__)
#define V3_ERROR(...)   v3_log(V3_LOG_ERROR, __VA_ARGS__)

/* ============================================================
 * 工具函数
 * ============================================================ */

uint64_t v3_time_ms(void);
uint64_t v3_time_sec(void);
int v3_random_bytes(uint8_t *buf, size_t len);
int v3_hex_encode(char *out, size_t out_len, const uint8_t *data, size_t len);
int v3_hex_decode(uint8_t *out, size_t out_len, const char *hex);
void v3_secure_zero(void *ptr, size_t len);
int v3_secure_compare(const void *a, const void *b, size_t len);

/* ============================================================
 * 加密模块
 * ============================================================ */

int v3_aead_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[V3_TAG_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[V3_NONCE_SIZE],
    const uint8_t key[V3_KEY_SIZE]
);

int v3_aead_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[V3_TAG_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[V3_NONCE_SIZE],
    const uint8_t key[V3_KEY_SIZE]
);

uint32_t v3_derive_magic(const uint8_t key[V3_KEY_SIZE], uint64_t window);
uint32_t v3_current_magic(const uint8_t key[V3_KEY_SIZE]);
bool v3_verify_magic(const uint8_t key[V3_KEY_SIZE], uint32_t magic, int tolerance);

/* ============================================================
 * 协议结构
 * ============================================================ */

#pragma pack(push, 1)

typedef struct {
    uint32_t    magic;
    uint8_t     nonce[12];
    uint8_t     enc_meta[16];
    uint8_t     tag[16];
    uint16_t    payload_hint;
    uint16_t    reserved;
} v3_header_t;

typedef struct {
    uint64_t    session_id;
    uint16_t    stream_id;
    uint16_t    flags;
    uint32_t    sequence;
} v3_metadata_t;

#pragma pack(pop)

#define V3_FLAG_NONE        0x0000
#define V3_FLAG_INIT        0x0001
#define V3_FLAG_FIN         0x0002
#define V3_FLAG_ACK         0x0004
#define V3_FLAG_DATA        0x0008

/* ============================================================
 * 传输模式
 * ============================================================ */

typedef enum {
    V3_MODE_UDP = 0,
    V3_MODE_WSS = 1
} v3_mode_t;

/* ============================================================
 * 客户端配置
 * ============================================================ */

typedef struct {
    /* 服务器配置 */
    const char *server_host;
    uint16_t    server_port;
    
    /* 密钥配置 */
    const char *key_hex;
    uint8_t     key[V3_KEY_SIZE];
    bool        key_is_hex;
    
    /* 本地配置 */
    uint16_t    local_port;
    
    /* 传输模式 */
    v3_mode_t   mode;
    
    /* WSS 配置 */
    const char *wss_host_header;
    const char *wss_path;
    
    /* DoH 配置 */
    bool        doh_enabled;
    const char *doh_server_1;
    const char *doh_server_2;
    
    /* 调试配置 */
    bool        verbose;
    const char *log_file;
} v3_client_config_t;

/* ============================================================
 * Transport Layer (UDP / WSS)
 * ============================================================ */

typedef struct v3_transport_s v3_transport_t;

v3_transport_t* v3_transport_create(const v3_client_config_t *cfg);
void v3_transport_destroy(v3_transport_t *t);
int v3_transport_connect(v3_transport_t *t);
void v3_transport_close(v3_transport_t *t);
int v3_transport_send(v3_transport_t *t, const uint8_t *data, size_t len);
int v3_transport_recv(v3_transport_t *t, uint8_t *buf, size_t buf_len, int timeout_ms);

/* ============================================================
 * 会话管理
 * ============================================================ */

typedef struct v3_session_s v3_session_t;

v3_session_t* v3_session_create(const uint8_t key[V3_KEY_SIZE], const v3_client_config_t *cfg);
void v3_session_destroy(v3_session_t *s);
int v3_session_connect(v3_session_t *s);
void v3_session_close(v3_session_t *s);
bool v3_session_is_connected(v3_session_t *s);
int v3_session_send(v3_session_t *s, uint16_t stream_id, const uint8_t *data, size_t len);
int v3_session_recv(v3_session_t *s, uint16_t *stream_id, uint8_t *buf, size_t buf_len, int timeout_ms);

typedef struct {
    uint64_t    packets_sent;
    uint64_t    packets_recv;
    uint64_t    bytes_sent;
    uint64_t    bytes_recv;
    uint64_t    errors;
    uint64_t    rtt_us;
} v3_session_stats_t;

void v3_session_get_stats(v3_session_t *s, v3_session_stats_t *stats);

/* ============================================================
 * SOCKS5 代理服务器
 * ============================================================ */

typedef struct v3_socks5_s v3_socks5_t;
typedef void (*v3_socks5_log_fn)(const char *msg, void *userdata);

typedef struct {
    uint16_t            listen_port;
    const char         *listen_addr;
    v3_session_t       *session;
    v3_socks5_log_fn    log_fn;
    void               *userdata;
} v3_socks5_config_t;

v3_socks5_t* v3_socks5_create(const v3_socks5_config_t *cfg);
void v3_socks5_destroy(v3_socks5_t *s);
int v3_socks5_run(v3_socks5_t *s);
void v3_socks5_stop(v3_socks5_t *s);

/* ============================================================
 * 客户端主函数
 * ============================================================ */

int v3_client_run(const v3_client_config_t *cfg);
void v3_client_stop(void);

/* ============================================================
 * 初始化/清理
 * ============================================================ */

int v3_init(void);
void v3_cleanup(void);
const char* v3_version(void);

#ifdef __cplusplus
}
#endif

#endif /* V3_H */
