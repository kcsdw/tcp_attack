#include <ifaddrs.h>
#include <linux/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ip_utils.h"

void print_interface_info(struct ifaddrs *ifa) {
	printf("Interface: %-8s", ifa->ifa_name);

	if (ifa->ifa_addr == NULL) {
		printf(" - No address\n");
		return;
	}

	// 获取地址族 (IPv4, IPv6, 等)
	int family = ifa->ifa_addr->sa_family;
	char host[NI_MAXHOST];

	if (family == AF_INET || family == AF_INET6) {
		int s = getnameinfo(ifa->ifa_addr,
							(family == AF_INET) ? sizeof(struct sockaddr_in)
												: sizeof(struct sockaddr_in6),
							host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (s == 0) {
			printf(" - %s %s", (family == AF_INET) ? "IPv4" : "IPv6", host);

			// 检查接口状态
			if (ifa->ifa_flags & IFF_UP) {
				printf(" [UP]");
			}
			if (ifa->ifa_flags & IFF_RUNNING) {
				printf(" [RUNNING]");
			}
			if (ifa->ifa_flags & IFF_LOOPBACK) {
				printf(" [LOOPBACK]");
			}
			printf("\n");
		}
	} else {
		printf(" - Address Family: %d\n", family);
	}
}

void print_active_interfaces() {
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	printf("Active network interfaces:\n");
	// 只显示活动的接口
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		// 跳过没有地址的接口
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		// 只显示 IPv4 或 IPv6 接口
		int family = ifa->ifa_addr->sa_family;
		if (family != AF_INET && family != AF_INET6) {
			continue;
		}
		// 检查是否是活动的、运行的接口
		if ((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)) {
			print_interface_info(ifa);
		}
	}
	freeifaddrs(ifaddr);
}

void parse_mac_address(const char *mac_str, unsigned char *mac) {
	sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2],
		   &mac[3], &mac[4], &mac[5]);
}

void my_set_mac_address(const char *interface, const char *mac_addr) {
	unsigned char mac[6];
	parse_mac_address(mac_addr, mac);

	if (set_mac_address(interface, mac) == 0) {
		printf("MAC address for %s set to %s\n", interface, mac_addr);
	} else {
		printf("Failed to set MAC address for %s\n", interface);
	}
}

void interactive_mode() {
	char interface[IFNAMSIZ];
	char mac_addr[18];

	print_active_interfaces();

	printf("\nEnter interface name: ");
	if (scanf("%s", interface) != 1) {
		printf("Invalid input\n");
		return;
	}

	printf("Enter new MAC address (XX:XX:XX:XX:XX:XX): ");
	if (scanf("%s", mac_addr) != 1) {
		printf("Invalid input\n");
		return;
	}

	my_set_mac_address(interface, mac_addr);
}

int main(int argc, char *argv[]) {
	if (argc == 1) {
		// Interactive mode
		interactive_mode();
	} else if (argc == 3) {
		// Command line mode
		my_set_mac_address(argv[1], argv[2]);
	} else {
		printf("Usage: %s [interface] [mac_address]\n", argv[0]);
		printf("       %s (for interactive mode)\n", argv[0]);
		printf("Example: %s wlan0 00:11:22:33:44:55\n", argv[0]);
		return 1;
	}

	return 0;
}