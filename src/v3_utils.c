/*
 * v3_utils.c - 工具函数实现
 */

#include "v3.h"
#include <stdarg.h>

/* ============================================================
 * 全局状态
 * ============================================================ */

static struct {
    bool            initialized;
    v3_log_level_t  log_level;
    FILE           *log_file;
    CRITICAL_SECTION log_lock;
} g_v3 = {0};

/* ============================================================
 * 初始化/清理
 * ============================================================ */

int v3_init(void) {
    if (g_v3.initialized) return V3_OK;
    
    /* Winsock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return V3_ERR_NETWORK;
    }
    
    /* 日志锁 */
    InitializeCriticalSection(&g_v3.log_lock);
    g_v3.log_level = V3_LOG_INFO;
    g_v3.log_file = NULL;
    
    g_v3.initialized = true;
    return V3_OK;
}

void v3_cleanup(void) {
    if (!g_v3.initialized) return;
    
    if (g_v3.log_file) {
        fclose(g_v3.log_file);
        g_v3.log_file = NULL;
    }
    
    DeleteCriticalSection(&g_v3.log_lock);
    WSACleanup();
    
    g_v3.initialized = false;
}

const char* v3_version(void) {
    return V3_VERSION_STRING;
}

/* ============================================================
 * 日志
 * ============================================================ */

void v3_log_init(v3_log_level_t level, const char *file) {
    g_v3.log_level = level;
    
    if (file && file[0]) {
        g_v3.log_file = fopen(file, "a");
    }
}

void v3_log(v3_log_level_t level, const char *fmt, ...) {
    if (level < g_v3.log_level) return;
    
    static const char *level_names[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    
    EnterCriticalSection(&g_v3.log_lock);
    
    /* 时间戳 */
    SYSTEMTIME st;
    GetLocalTime(&st);
    char time_buf[32];
    sprintf(time_buf, "%02d:%02d:%02d.%03d", 
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    /* 格式化消息 */
    char msg[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    /* 输出 */
    char line[1200];
    sprintf(line, "[%s] [%s] %s\n", time_buf, level_names[level], msg);
    
    printf("%s", line);
    fflush(stdout);
    
    if (g_v3.log_file) {
        fputs(line, g_v3.log_file);
        fflush(g_v3.log_file);
    }
    
    LeaveCriticalSection(&g_v3.log_lock);
}

/* ============================================================
 * 时间
 * ============================================================ */

uint64_t v3_time_ms(void) {
    return GetTickCount64();
}

uint64_t v3_time_sec(void) {
    return (uint64_t)time(NULL);
}

/* ============================================================
 * 随机数
 * ============================================================ */

int v3_random_bytes(uint8_t *buf, size_t len) {
    HCRYPTPROV hProv;
    
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, 
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return V3_ERR_CRYPTO;
    }
    
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    
    return ok ? V3_OK : V3_ERR_CRYPTO;
}

/* ============================================================
 * 十六进制
 * ============================================================ */

int v3_hex_encode(char *out, size_t out_len, const uint8_t *data, size_t len) {
    if (out_len < len * 2 + 1) return V3_ERR_INVALID_PARAM;
    
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[data[i] & 0xF];
    }
    out[len * 2] = '\0';
    return V3_OK;
}

int v3_hex_decode(uint8_t *out, size_t out_len, const char *hex) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return V3_ERR_INVALID_PARAM;
    if (out_len < hex_len / 2) return V3_ERR_INVALID_PARAM;
    
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi, lo;
        char c = hex[i * 2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return V3_ERR_INVALID_PARAM;
        
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return V3_ERR_INVALID_PARAM;
        
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return V3_OK;
}

/* ============================================================
 * 安全内存
 * ============================================================ */

void v3_secure_zero(void *ptr, size_t len) {
    SecureZeroMemory(ptr, len);
}

int v3_secure_compare(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t*)a;
    const volatile uint8_t *pb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    
    return diff == 0 ? 0 : -1;
}
