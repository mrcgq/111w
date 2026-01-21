/*
 * v3_main.c - v3 客户端主入口
 * 
 * 支持: UDP / WSS / DoH
 */

#include "v3.h"
#include <signal.h>

static volatile bool g_stop = false;
static v3_socks5_t *g_socks5 = NULL;

static void signal_handler(int sig) {
    (void)sig;
    g_stop = true;
    V3_INFO("Received signal, stopping...");
    if (g_socks5) {
        v3_socks5_stop(g_socks5);
    }
}

static void print_usage(const char *prog) {
    printf("\n");
    printf("v3 Client v%s (Windows, UDP/WSS/DoH)\n", V3_VERSION_STRING);
    printf("\n");
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -s, --server HOST    Server address (required)\n");
    printf("  -p, --port PORT      Server port (default: %d)\n", V3_DEFAULT_PORT);
    printf("  -l, --local PORT     Local SOCKS5 port (default: %d)\n", V3_DEFAULT_LOCAL_PORT);
    printf("  -t, --token KEY      Master key (64 hex chars)\n");
    printf("  -m, --mode MODE      Transport mode: udp or wss (default: udp)\n");
    printf("  -H, --host HOST      (WSS only) Host header for CDN\n");
    printf("  -P, --path PATH      (WSS only) WebSocket path (default: /)\n");
    printf("  --dns1 URL           Primary DNS-over-HTTPS server\n");
    printf("  --dns2 URL           Backup DNS-over-HTTPS server\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -s example.com -t <key>\n", prog);
    printf("  %s -s example.com -m wss -H cdn.example.com\n", prog);
    printf("  %s -s example.com --dns1 https://1.1.1.1/dns-query\n", prog);
    printf("\n");
}

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf("   v3 Client v%s\n", V3_VERSION_STRING);
    printf("   Windows Edition (UDP/WSS/DoH)\n");
    printf("========================================\n");
    printf("\n");
}

/* ============================================================
 * 客户端主运行逻辑
 * ============================================================ */

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
    
    /* 解析密钥 */
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
    
    /* 打印配置信息 */
    V3_INFO("Server: %s:%d", cfg->server_host, cfg->server_port);
    V3_INFO("Local:  127.0.0.1:%d", cfg->local_port);
    V3_INFO("Mode:   %s", cfg->mode == V3_MODE_WSS ? "WSS" : "UDP");
    
    if (cfg->mode == V3_MODE_WSS) {
        V3_INFO("WSS Path: %s", cfg->wss_path);
        if (cfg->wss_host_header) {
            V3_INFO("WSS Host: %s", cfg->wss_host_header);
        }
    }
    
    if (cfg->doh_enabled) {
        V3_INFO("DoH: Enabled");
        if (cfg->doh_server_1) {
            V3_INFO("DoH Primary:   %s", cfg->doh_server_1);
        }
        if (cfg->doh_server_2) {
            V3_INFO("DoH Backup:    %s", cfg->doh_server_2);
        }
    }
    
    /* 创建会话 */
    v3_session_t *session = v3_session_create(key, cfg);
    if (!session) {
        V3_ERROR("Failed to create session");
        return V3_ERR_NO_MEMORY;
    }
    
    /* 连接服务器 */
    if (v3_session_connect(session) != V3_OK) {
        V3_ERROR("Failed to connect");
        v3_session_destroy(session);
        return V3_ERR_NETWORK;
    }
    
    /* 启动 SOCKS5 代理 */
    v3_socks5_config_t socks_cfg = {
        .listen_port = cfg->local_port,
        .listen_addr = "127.0.0.1",
        .session = session,
        .log_fn = NULL,
        .userdata = NULL
    };
    
    g_socks5 = v3_socks5_create(&socks_cfg);
    if (!g_socks5) {
        V3_ERROR("Failed to create SOCKS5 server");
        v3_session_close(session);
        v3_session_destroy(session);
        return V3_ERR_NETWORK;
    }
    
    V3_INFO("Ready! Use SOCKS5 proxy at 127.0.0.1:%d", socks_cfg.listen_port);
    
    /* 阻塞运行 */
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
    if (g_socks5) {
        v3_socks5_stop(g_socks5);
    }
}

/* ============================================================
 * main - 命令行入口
 * ============================================================ */

int main(int argc, char **argv) {
    v3_client_config_t cfg = {0};
    
    /* 默认值 */
    cfg.server_port = V3_DEFAULT_PORT;
    cfg.local_port  = V3_DEFAULT_LOCAL_PORT;
    cfg.mode        = V3_MODE_UDP;
    cfg.wss_path    = "/";
    cfg.doh_enabled = false;
    
    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        
        /* 帮助 */
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        /* 详细模式 */
        else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            cfg.verbose = true;
        }
        /* 服务器地址 */
        else if ((strcmp(arg, "-s") == 0 || strcmp(arg, "--server") == 0) && i + 1 < argc) {
            cfg.server_host = argv[++i];
        }
        /* 服务器端口 */
        else if ((strcmp(arg, "-p") == 0 || strcmp(arg, "--port") == 0) && i + 1 < argc) {
            cfg.server_port = (uint16_t)atoi(argv[++i]);
        }
        /* 本地端口 */
        else if ((strcmp(arg, "-l") == 0 || strcmp(arg, "--local") == 0) && i + 1 < argc) {
            cfg.local_port = (uint16_t)atoi(argv[++i]);
        }
        /* 密钥 */
        else if ((strcmp(arg, "-t") == 0 || strcmp(arg, "--token") == 0) && i + 1 < argc) {
            cfg.key_hex = argv[++i];
            cfg.key_is_hex = true;
        }
        /* 传输模式 */
        else if ((strcmp(arg, "-m") == 0 || strcmp(arg, "--mode") == 0) && i + 1 < argc) {
            const char *mode = argv[++i];
            if (_stricmp(mode, "wss") == 0) {
                cfg.mode = V3_MODE_WSS;
            } else {
                cfg.mode = V3_MODE_UDP;
            }
        }
        /* WSS Host 头 */
        else if ((strcmp(arg, "-H") == 0 || strcmp(arg, "--host") == 0) && i + 1 < argc) {
            cfg.wss_host_header = argv[++i];
        }
        /* WSS 路径 */
        else if ((strcmp(arg, "-P") == 0 || strcmp(arg, "--path") == 0) && i + 1 < argc) {
            cfg.wss_path = argv[++i];
        }
        /* DoH 主服务器 */
        else if (strcmp(arg, "--dns1") == 0 && i + 1 < argc) {
            cfg.doh_server_1 = argv[++i];
            cfg.doh_enabled = true;
        }
        /* DoH 备用服务器 */
        else if (strcmp(arg, "--dns2") == 0 && i + 1 < argc) {
            cfg.doh_server_2 = argv[++i];
            cfg.doh_enabled = true;
        }
        /* 未知参数 */
        else if (arg[0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", arg);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    /* 检查必须参数 */
    if (!cfg.server_host) {
        fprintf(stderr, "Error: Server address is required.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    /* 注册信号处理 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    return v3_client_run(&cfg);
}
