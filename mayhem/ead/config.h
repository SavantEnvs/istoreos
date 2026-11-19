/* config.h for tinysrp (package/network/services/ead/src/tinysrp), as its
 * autoconf configure.in would generate it on Linux x86_64 / glibc.
 * Shipped under mayhem/ so build.sh never runs upstream's configure in-tree
 * (which would leave untracked, non-ignored configure state behind). */
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1
#define RETSIGTYPE void
#define SHA1HANDSOFF 1
#define POSIX_TERMIOS 1
#define SIZEOF_SHORT 2
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define HAVE_MEMCPY 1
#define HAVE_SIGACTION 1
#define HAVE_STRCHR 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_UNISTD_H 1
#define PACKAGE "libtinysrp"
#define VERSION "0.7.5"
