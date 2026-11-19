/*
 * ead: OpenWrt Emergency Access Daemon (package/network/services/ead/src).
 *
 * ead answers unauthenticated broadcast UDP frames captured with libpcap; the
 * wire entry point is handle_packet(), the pcap_dispatch() callback. This
 * harness feeds it a sequence of raw Ethernet frames so the session state
 * machine can advance (SET_USERNAME -> GET_PRIME -> SEND_A -> SEND_AUTH),
 * reaching parse_message(), every handler, the tinysrp SRP server
 * (t_serveropenraw / t_servergenexp / t_servergetkey / t_serververify) and the
 * reply builder ead_send_packet_clone().
 *
 * Input: repeated [u16 big-endian frame length][frame bytes]; a short final
 * frame takes whatever bytes remain. Each frame is copied into a heap buffer
 * of exactly its captured length (at most the daemon's snaplen, PCAP_MRU), so
 * any read past the captured frame is caught by ASan.
 *
 * Environment set up as main() does for one interface (`ead -d eth0 -p
 * <passwd>`): one instance with id 0, the default node id, and a passwd file
 * with a `root:$1$...` md5 entry (upstream's sample `passwd`), written to a
 * scratch file under $TMPDIR at start-up. libpcap is replaced by no-op stubs:
 * the harness is the capture source, and replies (pcap_sendpacket) are
 * dropped.
 *
 * Per-input reset: the session state is returned to SET_USERNAME through the
 * daemon's own set_state() (which closes the SRP server), and username, A, B
 * and the reply buffer are cleared. Kept on purpose: tinysrp's random pool
 * (seeded once from /dev/urandom, as in the daemon), and ead-crypt's AES/IV
 * state, which is only set after a successful SRP proof that a fuzzer cannot
 * produce (it needs the password-derived session key).
 */
#include <sys/wait.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define main ead_main
#include "../../package/network/services/ead/src/ead.c"
#undef main

/* ---- libpcap stand-ins (environment mock; ead never opens a device here) ---- */
pcap_t *pcap_create(const char *source, char *errbuf) { (void)source; (void)errbuf; return NULL; }
int pcap_set_snaplen(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_promisc(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_timeout(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_protocol_linux(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_set_buffer_size(pcap_t *p, int n) { (void)p; (void)n; return 0; }
int pcap_activate(pcap_t *p) { (void)p; return 0; }
int pcap_get_selectable_fd(pcap_t *p) { (void)p; return -1; }
void pcap_close(pcap_t *p) { (void)p; }
int pcap_setfilter(pcap_t *p, struct bpf_program *f) { (void)p; (void)f; return 0; }
int pcap_dispatch(pcap_t *p, int cnt, pcap_handler cb, u_char *user)
{ (void)p; (void)cnt; (void)cb; (void)user; return -1; }
int pcap_sendpacket(pcap_t *p, const u_char *buf, int size)
{
	/* Touch every byte of the reply the daemon built, so an out-of-bounds
	 * reply length is caught here as it would be by the kernel copy. */
	volatile u_char sink = 0;
	(void)p;
	for (int i = 0; i < size; i++)
		sink ^= buf[i];
	(void)sink;
	return 0;
}

static const char fuzz_passwd[] =
	"root:$1$MCGAgYw.$Ip1GcyeUliId3wzVcKR/e/:0:0:root:/root:/bin/ash\n"
	"nobody:*:65534:65534:nobody:/var:/bin/false\n"
	"daemon:*:65534:65534:daemon:/var:/bin/false\n";

static struct ead_instance fuzz_instance;
static char fuzz_passwd_path[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *dir = getenv("TMPDIR");
	int fd;

	(void)argc; (void)argv;
	if (!dir || !*dir)
		dir = "/tmp";
	snprintf(fuzz_passwd_path, sizeof(fuzz_passwd_path), "%s/ead-passwd-XXXXXX", dir);
	fd = mkstemp(fuzz_passwd_path);
	if (fd < 0 || write(fd, fuzz_passwd, sizeof(fuzz_passwd) - 1) !=
			(ssize_t)(sizeof(fuzz_passwd) - 1)) {
		perror("ead passwd fixture");
		abort();
	}
	close(fd);

	INIT_LIST_HEAD(&instances);
	memset(&fuzz_instance, 0, sizeof(fuzz_instance));
	strcpy(fuzz_instance.ifname, "eth0");
	fuzz_instance.id = 0;
	instance = &fuzz_instance;
	passwd_file = fuzz_passwd_path;
	return 0;
}

static void reset_session(void)
{
	set_state(EAD_TYPE_SET_USERNAME);
	if (ts) {
		t_serverclose(ts);
		ts = NULL;
	}
	state = EAD_TYPE_SET_USERNAME;
	memset(username, 0, sizeof(username));
	B = NULL;
	memset(&A, 0, sizeof(A));
	memset(pktbuf_b, 0, sizeof(pktbuf_b));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t off = 0;

	reset_session();
	while (off + 2 <= size) {
		size_t len = ((size_t)data[off] << 8) | data[off + 1];
		struct pcap_pkthdr hdr;
		u_char *frame;

		off += 2;
		if (len > size - off)
			len = size - off;
		if (len > PCAP_MRU)
			len = PCAP_MRU;
		frame = malloc(len ? len : 1);
		if (!frame)
			abort();
		memcpy(frame, data + off, len);
		off += len;

		memset(&hdr, 0, sizeof(hdr));
		hdr.caplen = (bpf_u_int32)len;
		hdr.len = (bpf_u_int32)len;
		handle_packet(NULL, &hdr, frame);
		free(frame);
	}
	return 0;
}
