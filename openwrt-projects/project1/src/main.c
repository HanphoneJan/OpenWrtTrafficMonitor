#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>

// 定义统计数据结构
typedef struct {
    char src_ip[16];
    char dst_ip[16];
    unsigned long long rx_bytes;    // Received traffic
    unsigned long long tx_bytes;    // Transmitted traffic
    unsigned long long peak_rx;     // Peak received traffic
    unsigned long long peak_tx;     // Peak transmitted traffic
    unsigned long long last_2s_rx;  // Last 2s average received
    unsigned long long last_10s_rx; // Last 10s average received
    unsigned long long last_40s_rx; // Last 40s average received
    unsigned long long last_2s_tx;  // Last 2s average transmitted
    unsigned long long last_10s_tx; // Last 10s average transmitted
    unsigned long long last_40s_tx; // Last 40s average transmitted
    time_t last_update;             // Last update time
} flow_stats_t;

// 定义数据包历史记录结构
typedef struct {
    unsigned long long bytes;
    time_t timestamp;
} packet_history_t;

// 定义过滤规则结构
typedef struct {
    int enabled;
    char src_ip[16];
    char dst_ip[16];
    int protocol;  // 0=any, 6=TCP, 17=UDP, etc.
} filter_rule_t;

// HTTP服务器配置
#define MAX_CLIENTS 5
#define BUFFER_SIZE 4096
int http_port = 8080; // 放在全局变量区域

// 全局变量
flow_stats_t flow_stats;
packet_history_t rx_history[40]; // 存储40秒的接收历史
packet_history_t tx_history[40]; // 存储40秒的发送历史
int rx_history_index = 0;
int tx_history_index = 0;
pthread_mutex_t stats_mutex;
volatile int running = 1;
pcap_t *handle; // 声明为全局变量
filter_rule_t filter; // 过滤规则
int strict_mode = 0;  // 严格模式标志
char router_ip[16] = "192.168.1.1"; // 默认路由器IP
int http_socket = -1; // HTTP服务器套接字

// 初始化统计数据
void init_stats() {
    memset(&flow_stats, 0, sizeof(flow_stats_t));
    memset(rx_history, 0, sizeof(packet_history_t) * 40);
    memset(tx_history, 0, sizeof(packet_history_t) * 40);
    pthread_mutex_init(&stats_mutex, NULL);
    flow_stats.last_update = time(NULL);
    
    // 初始化过滤规则
    memset(&filter, 0, sizeof(filter_rule_t));
    filter.enabled = 0; // 默认禁用过滤
}

// 更新流量统计
void update_stats(const char* src_ip, const char* dst_ip, unsigned long long bytes, int is_rx) {
    time_t now = time(NULL);
    pthread_mutex_lock(&stats_mutex);
    
    // 更新源IP和目的IP
    if (strlen(flow_stats.src_ip) == 0 && strlen(src_ip) > 0) {
        strncpy(flow_stats.src_ip, src_ip, 15);
        flow_stats.src_ip[15] = '\0';
    }
    
    if (strlen(flow_stats.dst_ip) == 0 && strlen(dst_ip) > 0) {
        strncpy(flow_stats.dst_ip, dst_ip, 15);
        flow_stats.dst_ip[15] = '\0';
    }
    
    // 更新流量统计
    if (is_rx) {
        flow_stats.rx_bytes += bytes;
        if (bytes > flow_stats.peak_rx) {
            flow_stats.peak_rx = bytes;
        }
        
        // 更新接收历史
        rx_history[rx_history_index].bytes = bytes;
        rx_history[rx_history_index].timestamp = now;
        rx_history_index = (rx_history_index + 1) % 40;
    } else {
        flow_stats.tx_bytes += bytes;
        if (bytes > flow_stats.peak_tx) {
            flow_stats.peak_tx = bytes;
        }
        
        // 更新发送历史
        tx_history[tx_history_index].bytes = bytes;
        tx_history[tx_history_index].timestamp = now;
        tx_history_index = (tx_history_index + 1) % 40;
    }
    
    flow_stats.last_update = now;
    pthread_mutex_unlock(&stats_mutex);
}

// 计算平均流量
void calculate_average_flow() {
    time_t now = time(NULL);
    pthread_mutex_lock(&stats_mutex);
    
    // 重置平均值
    flow_stats.last_2s_rx = 0;
    flow_stats.last_10s_rx = 0;
    flow_stats.last_40s_rx = 0;
    flow_stats.last_2s_tx = 0;
    flow_stats.last_10s_tx = 0;
    flow_stats.last_40s_tx = 0;
    
    // 计算接收平均流量
    for (int i = 0; i < 40; i++) {
        int age = now - rx_history[i].timestamp;
        if (age >= 0 && age < 40) {
            flow_stats.last_40s_rx += rx_history[i].bytes;
            if (age < 10) {
                flow_stats.last_10s_rx += rx_history[i].bytes;
                if (age < 2) {
                    flow_stats.last_2s_rx += rx_history[i].bytes;
                }
            }
        }
    }
    
    // 计算发送平均流量
    for (int i = 0; i < 40; i++) {
        int age = now - tx_history[i].timestamp;
        if (age >= 0 && age < 40) {
            flow_stats.last_40s_tx += tx_history[i].bytes;
            if (age < 10) {
                flow_stats.last_10s_tx += tx_history[i].bytes;
                if (age < 2) {
                    flow_stats.last_2s_tx += tx_history[i].bytes;
                }
            }
        }
    }
    
    pthread_mutex_unlock(&stats_mutex);
}

// 生成JSON格式的流量数据
void generate_json_data(char *buffer, size_t buffer_size) {
    calculate_average_flow();
    pthread_mutex_lock(&stats_mutex);
    
    snprintf(buffer, buffer_size, 
        "{"
        "\"source_ip\":\"%s\","
        "\"destination_ip\":\"%s\","
        "\"total_received\":%llu,"
        "\"total_transmitted\":%llu,"
        "\"peak_received\":%llu,"
        "\"peak_transmitted\":%llu,"
        "\"last_2s_rx\":%llu,"
        "\"last_10s_rx\":%llu,"
        "\"last_40s_rx\":%llu,"
        "\"last_2s_tx\":%llu,"
        "\"last_10s_tx\":%llu,"
        "\"last_40s_tx\":%llu,"
        "\"timestamp\":%lu"
        "}",
        flow_stats.src_ip,
        flow_stats.dst_ip,
        flow_stats.rx_bytes,
        flow_stats.tx_bytes,
        flow_stats.peak_rx,
        flow_stats.peak_tx,
        flow_stats.last_2s_rx,
        flow_stats.last_10s_rx,
        flow_stats.last_40s_rx,
        flow_stats.last_2s_tx,
        flow_stats.last_10s_tx,
        flow_stats.last_40s_tx,
        (unsigned long)flow_stats.last_update
    );
    
    pthread_mutex_unlock(&stats_mutex);
}

// 处理HTTP请求
void handle_http_request(int client_socket) {
    char request_buffer[BUFFER_SIZE] = {0};
    char response_buffer[BUFFER_SIZE] = {0};
    int bytes_received = recv(client_socket, request_buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_received > 0) {
        // 解析请求方法和路径
        char method[10] = {0};
        char path[100] = {0};
        sscanf(request_buffer, "%s %s", method, path);
        
        // 处理OPTIONS请求（CORS预检请求）
        if (strcmp(method, "OPTIONS") == 0) {
            char http_response[] = 
                "HTTP/1.1 200 OK\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(client_socket, http_response, strlen(http_response), 0);
        }
        // 处理GET请求
        else if (strcmp(method, "GET") == 0) {
            if (strcmp(path, "/api/data") == 0 || strcmp(path, "/api/data/") == 0) {
                // 生成JSON响应
                generate_json_data(response_buffer, BUFFER_SIZE);
                
                // 构建HTTP响应，添加CORS头部
                char http_response[BUFFER_SIZE * 2] = {0};
                snprintf(http_response, sizeof(http_response), 
                    "HTTP/1.1 200 OK\r\n"
                    "Access-Control-Allow-Origin: *\r\n" // 允许任意域名访问
                    "Access-Control-Allow-Methods: GET, OPTIONS\r\n" // 允许的HTTP方法
                    "Access-Control-Allow-Headers: Content-Type\r\n" // 允许的请求头
                    "Content-Type: application/json\r\n"
                    "Content-Length: %lu\r\n"
                    "Connection: close\r\n\r\n%s",
                    (unsigned long)strlen(response_buffer), response_buffer);
                
                send(client_socket, http_response, strlen(http_response), 0);
            } else {
                // 处理其他路径
                char http_response[] = 
                    "HTTP/1.1 404 Not Found\r\n"
                    "Access-Control-Allow-Origin: *\r\n" // 添加CORS头部
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 13\r\n"
                    "Connection: close\r\n\r\nNot Found";
                send(client_socket, http_response, strlen(http_response), 0);
            }
        } else {
            // 处理不支持的方法
            char http_response[] = 
                "HTTP/1.1 405 Method Not Allowed\r\n"
                "Access-Control-Allow-Origin: *\r\n" // 添加CORS头部
                "Content-Type: text/plain\r\n"
                "Content-Length: 21\r\n"
                "Connection: close\r\n\r\nMethod Not Allowed";
            send(client_socket, http_response, strlen(http_response), 0);
        }
    }
    
    close(client_socket);
}

// HTTP服务器线程函数
void* http_server_thread(void* arg) {
    // 创建套接字
    http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0) {
        perror("Failed to create HTTP socket");
        return NULL;
    }
    
    // 设置套接字选项
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Failed to set socket options");
        close(http_socket);
        return NULL;
    }
    
    // 绑定地址
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(http_port);
    
    if (bind(http_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind HTTP socket");
        close(http_socket);
        return NULL;
    }
    
    // 监听连接
    if (listen(http_socket, MAX_CLIENTS) < 0) {
        perror("Failed to listen on HTTP socket");
        close(http_socket);
        return NULL;
    }
    
    printf("HTTP server started on port %d with CORS enabled\n", http_port);
    
    while (running) {
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_socket = accept(http_socket, (struct sockaddr *)&client_address, &client_len);
        
        if (client_socket < 0) {
            if (running) {
                perror("Failed to accept connection");
            }
            continue;
        }
        
        // 处理HTTP请求
        handle_http_request(client_socket);
    }
    
    // 关闭套接字
    close(http_socket);
    http_socket = -1;
    return NULL;
}

// 显示统计信息
void display_stats() {
    calculate_average_flow();
    
    pthread_mutex_lock(&stats_mutex);
    printf("\n=== Traffic Monitoring Statistics ===\n");
    printf("Source IP: %s\n", flow_stats.src_ip);
    printf("Destination IP: %s\n", flow_stats.dst_ip);
    printf("Total Received: %llu bytes\n", flow_stats.rx_bytes);
    printf("Total Transmitted: %llu bytes\n", flow_stats.tx_bytes);
    printf("Peak Received: %llu bytes\n", flow_stats.peak_rx);
    printf("Peak Transmitted: %llu bytes\n", flow_stats.peak_tx);
    printf("Last 2s Avg Received: %llu bytes\n", flow_stats.last_2s_rx);
    printf("Last 10s Avg Received: %llu bytes\n", flow_stats.last_10s_rx);
    printf("Last 40s Avg Received: %llu bytes\n", flow_stats.last_40s_rx);
    printf("Last 2s Avg Transmitted: %llu bytes\n", flow_stats.last_2s_tx);
    printf("Last 10s Avg Transmitted: %llu bytes\n", flow_stats.last_10s_tx);
    printf("Last 40s Avg Transmitted: %llu bytes\n", flow_stats.last_40s_tx);
    pthread_mutex_unlock(&stats_mutex);
}

// 检查数据包是否符合过滤规则
int check_filter(const char* src_ip, const char* dst_ip, int protocol) {
    if (!filter.enabled) return 1; // 过滤规则未启用，默认通过
    
    // 检查源IP
    if (strlen(filter.src_ip) > 0 && strcmp(src_ip, filter.src_ip) != 0) {
        return 0;
    }
    
    // 检查目的IP
    if (strlen(filter.dst_ip) > 0 && strcmp(dst_ip, filter.dst_ip) != 0) {
        return 0;
    }
    
    // 检查协议
    if (filter.protocol > 0 && protocol != filter.protocol) {
        return 0;
    }
    
    return 1; // 通过过滤
}

// 判断IP是否为多播地址
int is_multicast_ip(const char* ip) {
    unsigned char addr[4];
    if (inet_pton(AF_INET, ip, addr) <= 0) {
        return 0; // 不是有效的IPv4地址
    }
    return (addr[0] & 0xF0) == 0xE0; // 224.0.0.0/4 是多播地址范围
}

// 从物理层判断数据包方向
int determine_direction_from_physical(const u_char *packet) {
    // 提取MAC地址
    const u_char *dst_mac = packet;
    const u_char *src_mac = packet + 6;
    
    // 尝试获取本地MAC地址（简化处理）
    static u_char local_mac[6] = {0};
    static int mac_initialized = 0;
    
    if (!mac_initialized) {
        // 实际应用中应该通过ioctl获取接口MAC地址
        mac_initialized = 1;
    }
    
    // 检查是否是广播帧
    int is_broadcast = (
        dst_mac[0] == 0xFF && 
        dst_mac[1] == 0xFF && 
        dst_mac[2] == 0xFF && 
        dst_mac[3] == 0xFF && 
        dst_mac[4] == 0xFF && 
        dst_mac[5] == 0xFF
    );
    
    // 检查是否是多播帧
    int is_multicast = (dst_mac[0] & 0x01) != 0 && !is_broadcast;
    
    // 根据MAC地址判断方向（简化处理）
    // 实际应用中需要比较本地MAC地址
    return (is_broadcast || is_multicast) ? -1 : 0; // -1表示无法确定，0表示入站
}

// 从IP层判断数据包方向
int determine_direction_from_ip(const char* src_ip, const char* dst_ip) {
    // 检查是否是多播地址
    if (is_multicast_ip(src_ip) || is_multicast_ip(dst_ip)) {
        return -1; // 多播流量，无法确定方向
    }
    
    // 检查源IP是否是路由器IP
    if (strcmp(src_ip, router_ip) == 0) {
        return 1; // 出站流量
    }
    
    // 检查目的IP是否是路由器IP
    if (strcmp(dst_ip, router_ip) == 0) {
        return 0; // 入站流量
    }
    
    // 地址大小比较（简化处理）
    unsigned long src_addr = inet_addr(src_ip);
    unsigned long dst_addr = inet_addr(dst_ip);
    
    if (src_addr > dst_addr) {
        return 1; // 源地址大，认为是出站
    } else {
        return 0; // 目的地址大，认为是入站
    }
}

// 数据包处理回调函数
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 以太网帧头长度
    const int ETHER_HEADER_LEN = 14;
    
    // 检查数据包长度
    if (pkthdr->len < ETHER_HEADER_LEN + 20) {
        return;
    }
    
    // 过滤规则检查
    if (filter.enabled) {
        // 此处简化处理，实际应解析IP头后再检查过滤规则
        // 完整实现需要提取协议、源IP、目的IP等信息
    }
    
    // 跳过以太网头，获取IP头
    const u_char *ip_header = packet + ETHER_HEADER_LEN;
    
    // 检查IP版本
    if ((*ip_header & 0xf0) != 0x40) {
        return; // 不是IPv4
    }
    
    // 获取IP头长度
    int ip_header_len = (*ip_header & 0x0f) * 4;
    
    // 检查IP头长度
    if (ip_header_len < 20 || pkthdr->len < ETHER_HEADER_LEN + ip_header_len) {
        return;
    }
    
    // 获取IP协议
    int protocol = ip_header[9];
    
    // 获取源IP和目的IP
    struct in_addr src_addr, dst_addr;
    memcpy(&src_addr, ip_header + 12, 4);
    memcpy(&dst_addr, ip_header + 16, 4);
    
    char src_ip_str[16], dst_ip_str[16];
    inet_ntop(AF_INET, &src_addr, src_ip_str, 16);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, 16);
    
    // 应用过滤规则
    if (!check_filter(src_ip_str, dst_ip_str, protocol)) {
        return; // 未通过过滤，丢弃数据包
    }
    
    // 从物理层判断方向
    int direction = determine_direction_from_physical(packet);
    
    // 如果物理层无法确定方向，从IP层判断
    if (direction < 0) {
        direction = determine_direction_from_ip(src_ip_str, dst_ip_str);
    }
    
    // 严格模式检查
    if (strict_mode && direction < 0) {
        return; // 严格模式下无法确定方向，丢弃数据包
    }
    
    // 确定是入站还是出站流量
    int is_rx = (direction == 0);
    
    // 更新统计数据
    update_stats(src_ip_str, dst_ip_str, pkthdr->len, is_rx);
}

// 统计显示线程函数
void* display_thread_func(void* arg) {
    while (running) {
        display_stats();
        // 分多次检查running，避免长时间sleep
        for (int i = 0; i < 2 && running; i++) {
            sleep(1);
        }
    }
    return NULL;
}

// 改进的信号处理函数
void signal_handler(int sig) {
    printf("Received signal %d, preparing to terminate...\n", sig);
    running = 0;
    if (handle) {
        pcap_breakloop(handle); // 中断pcap_loop
    }
    // 等待线程结束（可选）
    // exit(0);
}

// 从命令行参数解析配置
void parse_arguments(int argc, char *argv[]) {
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--filter") == 0 && i + 3 < argc) {
            // 启用过滤规则
            filter.enabled = 1;
            strncpy(filter.src_ip, argv[i+1], 15);
            strncpy(filter.dst_ip, argv[i+2], 15);
            filter.protocol = atoi(argv[i+3]);
            i += 3;
        } else if (strcmp(argv[i], "--strict") == 0) {
            // 启用严格模式
            strict_mode = 1;
        } else if (strcmp(argv[i], "--router") == 0 && i + 1 < argc) {
            // 设置路由器IP
            strncpy(router_ip, argv[i+1], 15);
            i += 1;
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            // 设置HTTP端口
            http_port = atoi(argv[i+1]);
            i += 1;
        }
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t display_thread, http_thread;
    
    // 初始化统计数据
    init_stats();
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 解析命令行参数
    parse_arguments(argc, argv);
    
    // 检查参数
    if (argc < 2) {
        printf("Usage: %s <network interface> [--filter <src_ip> <dst_ip> <protocol>] [--strict] [--router <ip>] [--http-port <port>]\n", argv[0]);
        return 1;
    }
    
    printf("Monitoring interface: %s\n", argv[1]);
    printf("Router IP: %s\n", router_ip);
    printf("Filter enabled: %s\n", filter.enabled ? "Yes" : "No");
    printf("Strict mode: %s\n", strict_mode ? "Enabled" : "Disabled");
    printf("HTTP server port: %d\n", http_port);
    
    // 打开网络接口进行捕获
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open interface %s: %s\n", argv[1], errbuf);
        return 1;
    }
    
    // 创建HTTP服务器线程
    pthread_create(&http_thread, NULL, http_server_thread, NULL);
    
    // 创建显示线程
    pthread_create(&display_thread, NULL, display_thread_func, NULL);
    
    // 开始捕获数据包
    printf("Starting traffic capture on interface %s...\n", argv[1]);
    printf("HTTP server running on port %d with CORS support\n", http_port);
    printf("Press Ctrl+C to stop capture\n");
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // 等待线程结束
    pthread_join(display_thread, NULL);
    pthread_join(http_thread, NULL);
    
    // 清理资源
    pcap_close(handle);
    pthread_mutex_destroy(&stats_mutex);
    
    printf("Program terminated successfully\n");
    return 0;
}
