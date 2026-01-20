/*
 * v3.h - v3 Protocol Core (Windows Only)
 * 
 * 单线设计，专为 Windows 优化
 * 支持: MSVC / MinGW-w64
 */

#ifndef V3_H
#define V3_H

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* === 修改点 1: 调整头文件引用顺序并增加 wincrypt.h === */
#include <winsock2.h>   /* 必须在 windows.h 之前包含，防止重定义 */
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <wincrypt.h>   /* 必须包含此文件以支持 CryptGenRandom */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* === 修改点 2: 仅在 MSVC 编译器下使用 pragma comment === */
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "advapi32.lib")
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
    V3_OK = 0,
    V3_ERR_INVALID_PARAM = -1,
    V3_ERR_NO_MEMORY = -2,
    V3_ERR_NETWORK = -3,
    V3_ERR_CRYPTO = -4,
    V3_ERR_PROTOCOL = -5,
    V3_ERR_TIMEOUT = -6,
    V3_ERR_CLOSED = -7,
    V3_ERR_WOULD_BLOCK = -8,
    V3_ERR_AUTH_FAILED = -9,
} v3_error_t;

/* ============================================================
 * 日志
 * ============================================================ */

typedef enum {
    V3_LOG_DEBUG = 0,
    V3_LOG_INFO = 1,
    V3_LOG_WARN = 2,
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

/* 时间 */
uint64_t v3_time_ms(void);
uint64_t v3_time_sec(void);

/* 随机数 */
int v3_random_bytes(uint8_t *buf, size_t len);

/* 十六进制 */
int v3_hex_encode(char *out, size_t out_len, const uint8_t *data, size_t len);
int v3_hex_decode(uint8_t *out, size_t out_len, const char *hex);

/* 安全内存 */
void v3_secure_zero(void *ptr, size_t len);
int v3_secure_compare(const void *a, const void *b, size_t len);

/* ============================================================
 * 加密模块
 * ============================================================ */

/* ChaCha20-Poly1305 AEAD */
int v3_aead_encrypt(
    uint8_t *ciphertext,            /* 输出: 密文 (与明文等长) */
    uint8_t tag[V3_TAG_SIZE],       /* 输出: 认证标签 */
    const uint8_t *plaintext,       /* 输入: 明文 */
    size_t plaintext_len,           /* 输入: 明文长度 */
    const uint8_t *aad,             /* 输入: 附加数据 */
    size_t aad_len,                 /* 输入: 附加数据长度 */
    const uint8_t nonce[V3_NONCE_SIZE],
    const uint8_t key[V3_KEY_SIZE]
);

int v3_aead_decrypt(
    uint8_t *plaintext,             /* 输出: 明文 */
    const uint8_t *ciphertext,      /* 输入: 密文 */
    size_t ciphertext_len,          /* 输入: 密文长度 */
    const uint8_t tag[V3_TAG_SIZE], /* 输入: 认证标签 */
    const uint8_t *aad,             /* 输入: 附加数据 */
    size_t aad_len,
    const uint8_t nonce[V3_NONCE_SIZE],
    const uint8_t key[V3_KEY_SIZE]
);

/* Magic 派生 */
uint32_t v3_derive_magic(const uint8_t key[V3_KEY_SIZE], uint64_t window);
uint32_t v3_current_magic(const uint8_t key[V3_KEY_SIZE]);
bool v3_verify_magic(const uint8_t key[V3_KEY_SIZE], uint32_t magic, int tolerance);

/* ============================================================
 * 协议结构
 * ============================================================ */

/* v3 数据包头 (52 字节, 网络序) */
#pragma pack(push, 1)
typedef struct {
    uint32_t    magic;              /* 时间派生的 Magic */
    uint8_t     nonce[12];          /* 随机 Nonce */
    uint8_t     enc_meta[16];       /* 加密的元数据 */
    uint8_t     tag[16];            /* Poly1305 认证标签 */
    uint16_t    payload_hint;       /* Payload 长度提示 */
    uint16_t    reserved;           /* 保留 */
} v3_header_t;

/* 元数据 (16 字节, 加密后存于 enc_meta) */
typedef struct {
    uint64_t    session_id;         /* 会话 ID */
    uint16_t    stream_id;          /* 流 ID */
    uint16_t    flags;              /* 标志 */
    uint32_t    sequence;           /* 序列号 */
} v3_metadata_t;
#pragma pack(pop)

/* 标志位 */
#define V3_FLAG_NONE        0x0000
#define V3_FLAG_INIT        0x0001
#define V3_FLAG_FIN         0x0002
#define V3_FLAG_ACK         0x0004
#define V3_FLAG_DATA        0x0008

/* ============================================================
 * 会话管理
 * ============================================================ */

typedef struct v3_session_s v3_session_t;

/* 创建/销毁 */
v3_session_t* v3_session_create(const uint8_t key[V3_KEY_SIZE]);
void v3_session_destroy(v3_session_t *s);

/* 设置服务器地址 */
int v3_session_set_server(v3_session_t *s, const char *host, uint16_t port);

/* 连接 */
int v3_session_connect(v3_session_t *s);
void v3_session_close(v3_session_t *s);
bool v3_session_is_connected(v3_session_t *s);

/* 发送/接收 */
int v3_session_send(v3_session_t *s, uint16_t stream_id, const uint8_t *data, size_t len);
int v3_session_recv(v3_session_t *s, uint16_t *stream_id, uint8_t *buf, size_t buf_len, int timeout_ms);

/* 统计 */
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

/* 回调函数 */
typedef void (*v3_socks5_log_fn)(const char *msg, void *userdata);

/* 配置 */
typedef struct {
    uint16_t    listen_port;        /* 监听端口 */
    const char *listen_addr;        /* 监听地址 (NULL = 127.0.0.1) */
    v3_session_t *session;          /* v3 会话 */
    v3_socks5_log_fn log_fn;        /* 日志回调 (可选) */
    void *userdata;                 /* 用户数据 */
} v3_socks5_config_t;

/* 创建/销毁 */
v3_socks5_t* v3_socks5_create(const v3_socks5_config_t *cfg);
void v3_socks5_destroy(v3_socks5_t *s);

/* 运行 (阻塞) */
int v3_socks5_run(v3_socks5_t *s);

/* 停止 */
void v3_socks5_stop(v3_socks5_t *s);

/* ============================================================
 * 客户端一体化接口
 * ============================================================ */

typedef struct {
    /* 服务器 */
    const char *server_host;
    uint16_t    server_port;
    
    /* 密钥 */
    const char *key_hex;            /* 64字符十六进制 */
    uint8_t     key[V3_KEY_SIZE];   /* 或直接二进制 */
    bool        key_is_hex;
    
    /* 本地 */
    uint16_t    local_port;
    
    /* 选项 */
    bool        verbose;
    const char *log_file;
} v3_client_config_t;

/* 运行客户端 (阻塞, 直到收到停止信号) */
int v3_client_run(const v3_client_config_t *cfg);

/* 请求停止 */
void v3_client_stop(void);

/* ============================================================
 * 初始化/清理
 * ============================================================ */

/* 全局初始化 (在使用任何 v3 函数前调用) */
int v3_init(void);

/* 全局清理 */
void v3_cleanup(void);

/* 获取版本字符串 */
const char* v3_version(void);

#ifdef __cplusplus
}
#endif

#endif /* V3_H */

