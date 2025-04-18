#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>
#define ETHERTYPE_IP 0x0800

int comparing_function(const void *a, const void *b) {
	uint32_t mask1 = ntohl(((struct route_table_entry *)a)->mask);
	uint32_t mask2 = ntohl(((struct route_table_entry *)b)->mask);

	if (mask1 != mask2) {
		return mask1 - mask2;
	}

	return (ntohl(((struct route_table_entry *)a)->prefix) & mask1) -
		   (ntohl(((struct route_table_entry *)b)->prefix) & mask2);
}

struct route_table_entry *get_best_route_binary_search(struct route_table_entry *rtable, uint32_t ip_dest, int rtable_len) {
	// catuare binara prin faptul ca adresa ip & masca trebuie sa fie prefixul
	int left = 0, right = rtable_len - 1;
	struct route_table_entry *best_match = NULL;

	while (left <= right) {
		int mid = (left + right) / 2;
		uint32_t mid_prefix = rtable[mid].prefix;
		uint32_t mid_mask = rtable[mid].mask;

		if ((ip_dest & mid_mask) == mid_prefix) {
			best_match = &rtable[mid];
			left = mid + 1;
		}
		else if (ntohl(mid_prefix) < ntohl(ip_dest & mid_mask)) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	return best_match;
}

struct arp_table_entry *get_arp_entry(struct arp_table_entry *mac_table, uint32_t given_ip, int mac_table_len) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip)
			return &mac_table[i];
	}
	return NULL;
}

void sort_route_table(struct route_table_entry *route_table, int length) {
	qsort(route_table, length, sizeof(struct route_table_entry), comparing_function);
}

int verify_checksum(struct ip_hdr *ip_header) {
	uint16_t old_checksum = ntohs(ip_header->checksum);
	ip_header->checksum = 0;
	uint16_t calculated_checksum = checksum((uint16_t *)ip_header, sizeof(struct ip_hdr));
	if (old_checksum == calculated_checksum) {
		return 1;
	} else {
		return 0;
	}
}

void alloc_tables(struct route_table_entry **route_table, struct arp_table_entry **arp_table, int *route_table_length, int *arp_table_length, char *path_to_root_table) {
	*route_table = calloc(75000, sizeof(struct route_table_entry));
	*arp_table = calloc(25, sizeof(struct arp_table_entry));

	*route_table_length = read_rtable(path_to_root_table, *route_table);
	*arp_table_length = 0;

	// sortez tabela de rutare in functie de prefix si masca
	sort_route_table(*route_table, *route_table_length);
}

void create_ether_header_for_icmp(struct ether_hdr *header, uint8_t *dest_mac, uint8_t *source_mac) {
	memcpy(header->ethr_dhost, dest_mac, 6);
	memcpy(header->ethr_shost, source_mac, 6);
	header->ethr_type = htons(ETHERTYPE_IP);
}

void create_ip_header_for_icmp(struct ip_hdr *header, uint32_t dest_ip, uint32_t source_ip, char *buffer) {
	header->proto = 1;
	header->checksum = 0;
	header->source_addr = source_ip;
	u_int16_t newChecksum = htons(checksum((uint16_t *)header, sizeof(struct ip_hdr)));
	header->checksum = newChecksum;
	header->dest_addr = dest_ip;
	header->ttl = 64;
	header->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
}

void create_icmp_header(struct icmp_hdr *header, char *buffer, uint8_t type) {
	header->check = 0;
	header->check = htons(checksum((uint16_t *)header, sizeof(struct icmp_hdr)));
	header->mcode = 0;
	header->mtype = type;
}

char *create_icmp_buffer(struct ether_hdr *ether_header, struct ip_hdr *ip_header, uint8_t *router_mac, uint32_t router_ip, uint8_t type) {
	char *buffer = malloc(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
	memset(buffer, 0, sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
	struct ether_hdr *icmp_ether_header = (struct ether_hdr *)buffer;
	create_ether_header_for_icmp(icmp_ether_header, ether_header->ethr_shost, router_mac);
	struct ip_hdr *icmp_ip_header = (struct ip_hdr *)(buffer + sizeof(struct ether_hdr));
	create_ip_header_for_icmp(icmp_ip_header, ip_header->source_addr, router_ip, buffer + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buffer + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	create_icmp_header(icmp_header, buffer + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), type);

	return buffer;
}

void swap(u_int32_t *a, u_int32_t *b) {
	uint32_t temp = *a;
	*a = *b;
	*b = temp;
}

void arp_reply(struct arp_table_entry *arp_table, int *arp_table_len, char *buffer, int length, int interface, struct ether_hdr *ether_header, struct arp_hdr *arp_header) {

	uint8_t mac[6];
	get_interface_mac(interface, mac);

	for (int i = 0; i < 6; i++) {
		ether_header->ethr_dhost[i] = ether_header->ethr_shost[i];
	}

	for (int i = 0; i < 6; i++) {
		ether_header->ethr_shost[i] = mac[i];
	}
	arp_header->opcode = htons(2);
	uint32_t spa = arp_header->sprotoa;
	uint32_t tpa = arp_header->tprotoa;
	swap(&spa, &tpa);
	arp_header->sprotoa = spa;
	arp_header->tprotoa = tpa;

	for (int i = 0; i < 6; i++) {
		arp_header->thwa[i] = arp_header->shwa[i];
	}

	for (int i = 0; i < 6; i++) {
		arp_header->shwa[i] = mac[i];
	}

	send_to_link(length, buffer, interface);
}

void arp_request(int interface, struct route_table_entry *route, struct ether_hdr *ether_header, struct arp_hdr *arp_header, char *request_buffer) {

	char *mac_zero = "00:00:00:00:00:00";
	char *broadcast_mac = "ff:ff:ff:ff:ff:ff";
	hwaddr_aton(broadcast_mac, ether_header->ethr_dhost);
	get_interface_mac(route->interface, ether_header->ethr_shost);
	ether_header->ethr_type = htons(0X0806);

	arp_header->hw_type = htons(1);
	arp_header->hw_len = 6;
	arp_header->proto_len = 4;
	arp_header->proto_type = htons(0x0800);
	arp_header->sprotoa = inet_addr(get_interface_ip(route->interface));
	arp_header->opcode = htons(1);
	arp_header->tprotoa = route->next_hop;
	get_interface_mac(route->interface, arp_header->shwa);
	hwaddr_aton(mac_zero, arp_header->thwa);
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), request_buffer, route->interface);
}

int main(int argc, char *argv[]) {
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	struct route_table_entry *route_table = NULL;
	struct arp_table_entry *arp_table_entry = NULL;
	int route_table_length, arp_table_length;

	// alocarea tabelelor
	alloc_tables(&route_table, &arp_table_entry, &route_table_length, &arp_table_length, argv[1]);
	queue queue_packet = create_queue();

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// TODO: Implement the router forwarding logic
		struct ether_hdr *ether_header = (struct ether_hdr *)buf;

		struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

		if (ether_header->ethr_type == htons(0X0806)) {
			switch (ntohs(arp_header->opcode)) {
			case 1:
				struct ether_hdr *ether_header = (struct ether_hdr *)buf;
				struct arp_hdr *arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
				arp_reply(arp_table_entry, &arp_table_length, buf, len, interface, ether_header, arp_header);
				continue;
			case 2:
				struct arp_hdr *aux_arp_header = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
				struct arp_table_entry new_arp_entry;
				new_arp_entry.ip = aux_arp_header->sprotoa;
				for (int i = 0; i < 6; i++) {
					new_arp_entry.mac[i] = aux_arp_header->shwa[i];
				}
				arp_table_entry[arp_table_length] = new_arp_entry;
				arp_table_length++;
				if (queue_empty(queue_packet)) {
					continue;
				}
				void *packet = queue_deq(queue_packet);
				size_t packet_len = *(size_t *)packet;
				int interface = *(int *)((char *)packet + sizeof(size_t));
				char *packet_buffer = (char *)((char *)packet + sizeof(size_t) + sizeof(int));
				struct ether_hdr *packet_ether_header = (struct ether_hdr *)packet_buffer;
				for (int i = 0; i < 6; i++) {
					packet_ether_header->ethr_dhost[i] = aux_arp_header->shwa[i];
				}
				send_to_link(packet_len, packet_buffer, interface);
				continue;
			}
		}

		struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

		if (ether_header->ethr_type != htons(ETHERTYPE_IP)) {
			continue;
		}

		uint32_t router_ip = inet_addr(get_interface_ip(interface));
		uint8_t *router_mac = malloc(6 * sizeof(uint8_t));
		memset(router_mac, 0, 6);
		get_interface_mac(interface, router_mac);

		if (ip_header->dest_addr == router_ip) {
			char *buffer = create_icmp_buffer(ether_header, ip_header, router_mac, router_ip, 0);
			send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), buffer, interface);
			continue;
		}

		// verificarea ip-ului cu checksum
		int check = verify_checksum(ip_header);
		if (check == 0) {
			continue;
		}

		// verificarea TTL-ului
		if (ip_header->ttl <= 1) {
			char *buffer = create_icmp_buffer(ether_header, ip_header, router_mac, router_ip, 11);
			send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), buffer, interface);
			continue;
		} else {
			ip_header->ttl--;
		}
		ip_header->checksum = htons(checksum((uint16_t *)ip_header, sizeof(struct ip_hdr)));

		// cautarea celei mai bune rute cu binary_search pentru eficienta
		struct route_table_entry *best_route = get_best_route_binary_search(route_table, ip_header->dest_addr, route_table_length);
		if (best_route == NULL) {
			char *buffer = create_icmp_buffer(ether_header, ip_header, router_mac, router_ip, 3);
			send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), buffer, interface);
			continue;
		}

		// updatarea adresei sursa si cautarea adresei MAC a urmatoarei destinatii in tabela de routare
		struct arp_table_entry *arp_entry = get_arp_entry(arp_table_entry, ip_header->dest_addr, arp_table_length);
		if (arp_entry == NULL) {
			char *temp_buffer = malloc(len * sizeof(char) + sizeof(int) + sizeof(size_t));
			for (int i = 0; i < len; i++) {
				temp_buffer[sizeof(int) + sizeof(size_t) + i] = buf[i];
			}

			for (int i = 0; i < sizeof(size_t); i++) {
				temp_buffer[i] = ((char *)&len)[i];
			}

			for (int i = 0; i < sizeof(int); i++) {
				temp_buffer[sizeof(size_t) + i] = ((char *)&best_route->interface)[i];
			}
			char *request_buffer = malloc(sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
			struct ether_hdr *ether_header_for_req = (struct ether_hdr *)request_buffer;
			struct arp_hdr *arp_header_for_req = (struct arp_hdr *)(request_buffer + sizeof(struct ether_hdr));
			queue_enq(queue_packet, temp_buffer);
			arp_request(interface, best_route, ether_header_for_req, arp_header_for_req, request_buffer);
			continue;
		} else {
			// daca am gasit Mac-ul cautat continuam cu trimiterea pachetului
			memcpy(ether_header->ethr_dhost, arp_entry->mac, 6);	// se inlocuieste adr MAC a destinatei din headerul eth
			get_interface_mac(interface, ether_header->ethr_shost); // se inlocuieste adresa MAC a sursei in headerul eth
			send_to_link(len, buf, best_route->interface);
		}

		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */
	}
}
