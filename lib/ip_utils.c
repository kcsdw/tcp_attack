#include <linux/if_arp.h>
// #include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// 生成随机MAC地址
void generate_random_mac(unsigned char *mac) {
	for (int i = 0; i < 6; i++) {
		mac[i] = rand() % 256;
	}
}

// 设置网络接口的MAC地址
int set_mac_address(const char *interface, const unsigned char *mac) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("Failed to create socket");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
	memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

	if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
		perror("Failed to set MAC address");
		close(sock);
		return -1;
	}

	close(sock);
	return 0;
}

// 计算校验和
unsigned short checksum(void *b, int len) {
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2) {
		sum += *buf++;
	}
	if (len == 1) {
		sum += *(unsigned char *)buf;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}
