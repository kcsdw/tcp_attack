#include <stdio.h>

unsigned short checksum(void *b, int len);
void generate_random_mac(unsigned char *mac);
int set_mac_address(const char *interface, const unsigned char *mac);