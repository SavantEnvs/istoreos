/*
 * Known-answer test for the ead daemon's packet handling
 * (package/network/services/ead/src/ead.c), built by build.sh with normal
 * flags and run by test.sh.
 *
 * Feeds hand-built frames to handle_packet() (the pcap_dispatch callback) and
 * checks the replies the daemon hands to pcap_sendpacket(): types, lengths,
 * payload fields, and that malformed / out-of-order requests get no reply.
 * (Logging in as a user with an md5 entry is not tested: prepare_password()
 * writes the `static const` password buffer, which faults with this compiler.)
 * Usage: ead_selftest <passwd file>
 */
#include <sys/wait.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define main ead_main
#include "../../package/network/services/ead/src/ead.c"
#undef main

pcap_t *pcap_create(const char *s, char *e) { (void)s; (void)e; return NULL; }
int pcap_set_snaplen(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_promisc(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_timeout(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_protocol_linux(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_buffer_size(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_activate(pcap_t *p) { (void)p; return 0; }
int pcap_get_selectable_fd(pcap_t *p) { (void)p; return -1; }
void pcap_close(pcap_t *p) { (void)p; }
int pcap_setfilter(pcap_t *p, struct bpf_program *f) { (void)p; (void)f; return 0; }
int pcap_dispatch(pcap_t *p, int c, pcap_handler cb, u_char *u) { (void)p; (void)c; (void)cb; (void)u; return -1; }

static u_char reply[PCAP_MRU];
static int reply_len = -1;

int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
	(void)p;
	if (size < 0 || size > (int)sizeof(reply))
		size = sizeof(reply);
	memcpy(reply, buf, size);
	reply_len = size;
	return 0;
}

static int passed, failed;

#define CHECK(name, cond) do {                                  \
	if (cond) { passed++; printf("PASS %s\n", name); }      \
	else { failed++; printf("FAIL %s\n", name); }           \
} while (0)

static void send_frame(uint32_t type, const void *payload, uint32_t plen, uint32_t msg_len, uint16_t sid)
{
	u_char buf[PCAP_MRU];
	struct ead_packet *pkt = (struct ead_packet *)buf;
	struct pcap_pkthdr hdr;
	size_t len = sizeof(struct ead_packet) + plen;

	memset(buf, 0, sizeof(buf));
	memset(pkt->eh.ether_dhost, 0xff, 6);
	memcpy(pkt->eh.ether_shost, "\x02\x00\x00\x00\x00\x01", 6);
	pkt->eh.ether_type = htons(ETHERTYPE_IP);
	pkt->vhl = 0x45;
	pkt->ttl = 64;
	pkt->proto = UIP_PROTO_UDP;
	pkt->srcport = htons(40000);
	pkt->destport = htons(EAD_PORT);
	pkt->msg.magic = htonl(EAD_MAGIC);
	pkt->msg.len = htonl(msg_len);
	pkt->msg.type = htonl(type);
	pkt->msg.nid = 0xffff;
	pkt->msg.sid = htons(sid);
	pkt->msg.ip = htonl(0x0a000002);
	if (plen)
		memcpy(pkt->msg.data, payload, plen);

	memset(&hdr, 0, sizeof(hdr));
	hdr.caplen = hdr.len = len;
	reply_len = -1;
	handle_packet(NULL, &hdr, buf);
}

static struct ead_msg *reply_msg(void)
{
	return &((struct ead_packet *)reply)->msg;
}

int main(int argc, char **argv)
{
	static struct ead_instance in;
	char user[32];
	unsigned char a[1 + 64];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <passwd>\n", argv[0]);
		return 2;
	}
	passwd_file = argv[1];
	INIT_LIST_HEAD(&instances);
	strcpy(in.ifname, "eth0");
	instance = &in;

	/* PING -> PONG carrying the device name and MD5 auth type */
	send_frame(EAD_TYPE_PING, NULL, 0, 0, 0);
	CHECK("ping gets a reply", reply_len > 0);
	CHECK("pong type", ntohl(reply_msg()->type) == EAD_TYPE_PONG);
	CHECK("pong device name", strcmp(reply_msg()->data[0].pong.name, DEFAULT_DEVNAME) == 0);
	CHECK("pong auth type md5", ntohs(reply_msg()->data[0].pong.auth_type) == EAD_AUTH_MD5);
	CHECK("pong udp ports swapped", ((struct ead_packet *)reply)->destport == htons(40000) &&
	      ((struct ead_packet *)reply)->srcport == htons(EAD_PORT));

	/* frames the filter must drop */
	send_frame(EAD_TYPE_PING, NULL, 0, 4096, 0);
	CHECK("msg.len beyond frame dropped", reply_len < 0);

	/* GET_PRIME before a username: out of order, no reply */
	send_frame(EAD_TYPE_GET_PRIME, NULL, 0, 0, 0);
	CHECK("get_prime out of order dropped", reply_len < 0);

	/* unknown user: username acked, but no SRP session, so no prime */
	memset(user, 0, sizeof(user));
	strcpy(user, "admin");
	send_frame(EAD_TYPE_SET_USERNAME, user, sizeof(user), sizeof(user), 0);
	CHECK("unknown user acked", reply_len > 0 && ntohl(reply_msg()->type) == EAD_TYPE_ACK_USERNAME);
	send_frame(EAD_TYPE_GET_PRIME, NULL, 0, 0, 0);
	CHECK("unknown user gets no prime", reply_len < 0);

	/* a non-md5 passwd entry is not usable for SRP either */
	memset(user, 0, sizeof(user));
	strcpy(user, "nobody");
	send_frame(EAD_TYPE_SET_USERNAME, user, sizeof(user), sizeof(user), 0);
	CHECK("nobody acked", reply_len > 0 && ntohl(reply_msg()->type) == EAD_TYPE_ACK_USERNAME);
	send_frame(EAD_TYPE_GET_PRIME, NULL, 0, 0, 0);
	CHECK("nobody gets no prime", reply_len < 0);

	/* SEND_A outside its state is dropped */
	memset(a, 0x5a, sizeof(a));
	send_frame(EAD_TYPE_SEND_A, a, sizeof(a), sizeof(a), 0);
	CHECK("send_a out of order dropped", reply_len < 0);

	/* session id of another instance is ignored */
	send_frame(EAD_TYPE_SET_USERNAME, user, sizeof(user), sizeof(user), 0x1000);
	CHECK("other instance sid ignored", reply_len < 0);

	/* reply header: magic and node id */
	send_frame(EAD_TYPE_PING, NULL, 0, 0, 0);
	CHECK("ping still answered", reply_len > 0 && ntohs(reply_msg()->nid) == 0xffff &&
	      ntohl(reply_msg()->magic) == EAD_MAGIC);

	printf("SUMMARY %d passed %d failed\n", passed, failed);
	return failed ? 1 : 0;
}
