/*
 * v3_main.c - v3 客户端主入口
 */

#include "v3.h"
#include <signal.h>

static volatile bool g_stop = false;
static v3_socks5_t *g_socks5 = NULL;

static void signal_handler(int sig) {
    (void)sig;
    g_stop = true;
    V3_INFO("Received signal, stopping...");
    if (g_socks5) v3_socks5_stop(g_socks5);
}

static void print_usage(const char *prog) {
    printf("\n");
    printf("v3 Client v%s (Windows)\n", V3_VERSION_STRING);
    printf("\n");
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -s, --server HOST    Server address (required)\n");
    printf("  -p, --port PORT      Server port (default: %d)\n", V3_DEFAULT_PORT);
    printf("  -l, --local PORT     Local SOCKS5 port (default: %d)\n", V3_DEFAULT_LOCAL_PORT);
    printf("  -t, --token KEY      Master key (64 hex chars)\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help\n");
    printf("\n");
}

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf("   v3 Client v%s\n", V3_VERSION_STRING);
    printf("   Windows Edition (Single Build)\n");
    printf("========================================\n");
    printf("\n");
}

int v3_client_run(const v3_client_config_t *cfg) {
    if (!cfg || !cfg->server_host) {
        V3_ERROR("Invalid config");
        return V3_ERR_INVALID_PARAM;
    }
    
    /* 初始化 */
    if (v3_init() != V3_OK) {
        V3_ERROR("v3_init failed");
        return V3_ERR_NETWORK;
    }
    
    v3_log_init(cfg->verbose ? V3_LOG_DEBUG : V3_LOG_INFO, cfg->log_file);
    
    print_banner();
    
    /* 处理密钥 */
    uint8_t key[V3_KEY_SIZE];
    if (cfg->key_is_hex && cfg->key_hex) {
        if (strlen(cfg->key_hex) != 64) {
            V3_ERROR("Key must be 64 hex chars");
            return V3_ERR_INVALID_PARAM;
        }
        if (v3_hex_decode(key, V3_KEY_SIZE, cfg->key_hex) != V3_OK) {
            V3_ERROR("Invalid hex key");
            return V3_ERR_INVALID_PARAM;
        }
    } else if (cfg->key[0] != 0) {
        memcpy(key, cfg->key, V3_KEY_SIZE);
    } else {
        V3_WARN("No key specified, generating random");
        v3_random_bytes(key, V3_KEY_SIZE);
    }
    
    V3_INFO("Server: %s:%d", cfg->server_host, 
            cfg->server_port ? cfg->server_port : V3_DEFAULT_PORT);
    V3_INFO("Local:  127.0.0.1:%d", 
            cfg->local_port ? cfg->local_port : V3_DEFAULT_LOCAL_PORT);
    
    /* 创建会话 */
    v3_session_t *session = v3_session_create(key);
    if (!session) {
        V3_ERROR("Failed to create session");
        return V3_ERR_NO_MEMORY;
    }
    
    if (v3_session_set_server(session, cfg->server_host, 
            cfg->server_port ? cfg->server_port : V3_DEFAULT_PORT) != V3_OK) {
        V3_ERROR("Failed to set server");
        v3_session_destroy(session);
        return V3_ERR_NETWORK;
    }
    
    if (v3_session_connect(session) != V3_OK) {
        V3_ERROR("Failed to connect");
        v3_session_destroy(session);
        return V3_ERR_NETWORK;
    }
    
    /* 创建 SOCKS5 */
    v3_socks5_config_t socks_cfg = {
        .listen_port = cfg->local_port ? cfg->local_port : V3_DEFAULT_LOCAL_PORT,
        .listen_addr = "127.0.0.1",
        .session = session
    };
    
    g_socks5 = v3_socks5_create(&socks_cfg);
    if (!g_socks5) {
        V3_ERROR("Failed to create SOCKS5 server");
        v3_session_close(session);
        v3_session_destroy(session);
        return V3_ERR_NETWORK;
    }
    
    V3_INFO("Ready! Use SOCKS5 proxy at 127.0.0.1:%d", socks_cfg.listen_port);
    
    /* 运行 */
    v3_socks5_run(g_socks5);
    
    /* 清理 */
    v3_socks5_destroy(g_socks5);
    g_socks5 = NULL;
    
    v3_session_close(session);
    v3_session_destroy(session);
    
    V3_INFO("Goodbye!");
    return V3_OK;
}

void v3_client_stop(void) {
    g_stop = true;
    if (g_socks5) v3_socks5_stop(g_socks5);
}

/* ============================================================
 * main
 * ============================================================ */

int main(int argc, char **argv) {
    v3_client_config_t cfg = {0};
    cfg.server_port = V3_DEFAULT_PORT;
    cfg.local_port = V3_DEFAULT_LOCAL_PORT;
    
    /* 解析参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            cfg.verbose = true;
        }
        else if ((strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--server") == 0) && i+1 < argc) {
            cfg.server_host = argv[++i];
        }
        else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) && i+1 < argc) {
            cfg.server_port = (uint16_t)atoi(argv[++i]);
        }
        else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--local") == 0) && i+1 < argc) {
            cfg.local_port = (uint16_t)atoi(argv[++i]);
        }
        else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--token") == 0) && i+1 < argc) {
            cfg.key_hex = argv[++i];
            cfg.key_is_hex = true;
        }
    }
    
    if (!cfg.server_host) {
        print_usage(argv[0]);
        return 1;
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    return v3_client_run(&cfg);
}
