#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

/* NBD protocol constants. */
#define NBD_INIT_PASSWD         "NBDMAGIC"
#define NBD_OPTS_MAGIC          0x49484156454f5054ULL /* "IHAVEOPT" */

#define NBD_FLAG_FIXED_NEWSTYLE (1U << 0)
#define NBD_FLAG_NO_ZEROES      (1U << 1)

#define NBD_FLAG_C_FIXED_NEWSTYLE (1U << 0)
#define NBD_FLAG_C_NO_ZEROES      (1U << 1)

#define NBD_FLAG_HAS_FLAGS      (1U << 0)
#define NBD_FLAG_READ_ONLY      (1U << 1)
#define NBD_FLAG_SEND_FLUSH     (1U << 2)
#define NBD_FLAG_SEND_FUA       (1U << 3)

#define NBD_OPT_EXPORT_NAME      1U
#define NBD_OPT_ABORT             2U
#define NBD_OPT_LIST              3U
#define NBD_OPT_STARTTLS          5U
#define NBD_OPT_INFO              6U
#define NBD_OPT_GO                7U
#define NBD_OPT_STRUCTURED_REPLY 8U

#define NBD_REP_ACK             1U
#define NBD_REP_SERVER          2U
#define NBD_REP_INFO            3U
#define NBD_REP_ERR_UNSUP       (0x80000000U | 1U)
#define NBD_REP_ERR_POLICY      (0x80000000U | 2U)
#define NBD_REP_ERR_INVALID     (0x80000000U | 3U)
#define NBD_REP_ERR_PLATFORM    (0x80000000U | 4U)
#define NBD_REP_ERR_UNKNOWN     (0x80000000U | 6U)
#define NBD_REP_ERR_TOO_BIG     (0x80000000U | 9U)

#define NBD_INFO_EXPORT          0U

#define NBD_REQUEST_MAGIC       0x25609513U
#define NBD_SIMPLE_REPLY_MAGIC  0x67446698U

#define NBD_CMD_READ             0U
#define NBD_CMD_WRITE            1U
#define NBD_CMD_DISC             2U
#define NBD_CMD_FLUSH            3U
#define NBD_CMD_TRIM             4U
#define NBD_CMD_CACHE            5U
#define NBD_CMD_WRITE_ZEROES     6U

#define NBD_CMD_FLAG_FUA         (1U << 0)
#define NBD_CMD_FLAG_NO_HOLE     (1U << 1)
#define NBD_CMD_FLAG_DF          (1U << 2)

#define MAX_OPTION_PAYLOAD      (64U * 1024U)
#define MAX_IO_PAYLOAD          (8U * 1024U * 1024U)

/*
 * NBD option header:
 *   64-bit IHAVEOPT
 *   32-bit option
 *   32-bit data length
 */
struct nbd_opt_request {
    uint64_t magic;
    uint32_t option;
    uint32_t length;
} __attribute__((packed));

/*
 * NBD option reply header:
 *   64-bit reply magic
 *   32-bit option
 *   32-bit reply type
 *   32-bit data length
 */
struct nbd_opt_reply {
    uint64_t magic;
    uint32_t option;
    uint32_t reply_type;
    uint32_t length;
} __attribute__((packed));

/*
 * NBD transmission request:
 *   32-bit magic
 *   16-bit command flags
 *   16-bit command type
 *   64-bit handle
 *   64-bit offset
 *   32-bit length
 */
struct nbd_request {
    uint32_t magic;
    uint16_t flags;
    uint16_t type;
    uint64_t handle;
    uint64_t offset;
    uint32_t length;
} __attribute__((packed));

struct nbd_reply {
    uint32_t magic;
    uint32_t error;
    uint64_t handle;
} __attribute__((packed));

static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;

static uint64_t htonll_u64(uint64_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(v);
#else
    return v;
#endif
}

static uint64_t ntohll_u64(uint64_t v)
{
    return htonll_u64(v);
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
}

static int read_full(int fd, void *buf, size_t len)
{
    unsigned char *p = (unsigned char *)buf;

    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n == 0) {
            return 0;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 1;
}

static int write_full(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            errno = EPIPE;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int discard_bytes(int fd, uint32_t len)
{
    unsigned char buf[4096];

    while (len > 0) {
        size_t chunk = len < sizeof(buf) ? len : sizeof(buf);
        int rc = read_full(fd, buf, chunk);
        if (rc <= 0) {
            return rc == 0 ? 0 : -1;
        }
        len -= (uint32_t)chunk;
    }
    return 1;
}

static int get_device_size(int fd, uint64_t *size)
{
    struct stat st;

    if (fstat(fd, &st) < 0) {
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        if (st.st_size < 0) {
            errno = EINVAL;
            return -1;
        }
        *size = (uint64_t)st.st_size;
        return 0;
    }

    if (ioctl(fd, BLKGETSIZE64, size) == 0) {
        return 0;
    }

    /* Some kernels/filesystems may support seeking to the end. */
    off_t end = lseek(fd, 0, SEEK_END);
    if (end >= 0 && lseek(fd, 0, SEEK_SET) >= 0) {
        *size = (uint64_t)end;
        return 0;
    }

    return -1;
}

static int range_ok(uint64_t offset, uint32_t len, uint64_t export_size)
{
    if (offset > export_size) {
        return 0;
    }
    if ((uint64_t)len > export_size - offset) {
        return 0;
    }
    return 1;
}

static uint32_t errno_to_nbd_error(int err)
{
    if (err <= 0) {
        return 0;
    }
    return (uint32_t)err;
}

static int send_simple_reply(int sock, uint64_t handle, int error)
{
    struct nbd_reply rep;

    rep.magic = htonl(NBD_SIMPLE_REPLY_MAGIC);
    rep.error = htonl(errno_to_nbd_error(error));
    rep.handle = htonll_u64(handle);

    return write_full(sock, &rep, sizeof(rep));
}

/* NBD option reply magic (NBD_OPT_REPLY_MAGIC). */

static int send_option_reply(int sock,
                             uint32_t option,
                             uint32_t type,
                             const void *data,
                             uint32_t len)
{
    struct {
        uint64_t magic;
        uint32_t option;
        uint32_t reply_type;
        uint32_t length;
    } __attribute__((packed)) rep;

    rep.magic = htonll_u64(0x3e889045565a9ULL);
    rep.option = htonl(option);
    rep.reply_type = htonl(type);
    rep.length = htonl(len);

    if (write_full(sock, &rep, sizeof(rep)) < 0) {
        return -1;
    }
    if (len > 0 && data != NULL) {
        return write_full(sock, data, len);
    }
    return 0;
}

static int send_error_reply(int sock, uint32_t option, uint32_t error, const char *msg)
{
    uint32_t len = 0;

    if (msg != NULL) {
        size_t n = strlen(msg);
        if (n > 4095) {
            n = 4095;
        }
        len = (uint32_t)n;
    }

    return send_option_reply(sock, option, error, msg, len);
}

static int send_export_info(int sock,
                            uint32_t option,
                            uint64_t export_size,
                            uint16_t transmission_flags)
{
    unsigned char data[12];
    uint16_t info = htons(NBD_INFO_EXPORT);
    uint64_t size = htonll_u64(export_size);
    uint16_t flags = htons(transmission_flags);

    memcpy(data + 0, &info, sizeof(info));
    memcpy(data + 2, &size, sizeof(size));
    memcpy(data + 10, &flags, sizeof(flags));

    return send_option_reply(sock, option, NBD_REP_INFO, data, sizeof(data));
}

static int send_list_entry(int sock, uint32_t option, const char *name)
{
    uint32_t name_len = (uint32_t)strlen(name);
    uint32_t reply_len = 4 + name_len;
    unsigned char *reply = (unsigned char *)malloc(reply_len);

    if (reply == NULL) {
        errno = ENOMEM;
        return -1;
    }

    uint32_t net_len = htonl(name_len);
    memcpy(reply, &net_len, 4);
    memcpy(reply + 4, name, name_len);

    int rc = send_option_reply(sock, option, NBD_REP_SERVER, reply, reply_len);
    free(reply);
    return rc;
}

/*
 * Send the classic EXPORT_NAME reply:
 *   64-bit export size
 *   16-bit transmission flags
 *   124 bytes reserved (unless C_NO_ZEROES)
 */
static int enter_transmission_export_name(int sock,
                                          uint64_t export_size,
                                          uint16_t transmission_flags,
                                          uint32_t client_flags)
{
    uint64_t size = htonll_u64(export_size);
    uint16_t flags = htons(transmission_flags);

    if (write_full(sock, &size, sizeof(size)) < 0 ||
        write_full(sock, &flags, sizeof(flags)) < 0) {
        return -1;
    }

    if ((client_flags & NBD_FLAG_C_NO_ZEROES) == 0) {
        unsigned char zeroes[124] = {0};
        if (write_full(sock, zeroes, sizeof(zeroes)) < 0) {
            return -1;
        }
    }

    return 0;
}

static int parse_info_go(const unsigned char *data,
                         uint32_t len,
                         char **name_out)
{
    uint32_t name_len;
    uint16_t nr_info;
    uint32_t pos;
    char *name;

    if (len < 6) {
        errno = EINVAL;
        return -1;
    }

    memcpy(&name_len, data, sizeof(name_len));
    name_len = ntohl(name_len);

    if (name_len > len - 6) {
        errno = EINVAL;
        return -1;
    }

    pos = 4 + name_len;
    if (pos + 2 > len) {
        errno = EINVAL;
        return -1;
    }

    name = (char *)malloc((size_t)name_len + 1);
    if (name == NULL) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(name, data + 4, name_len);
    name[name_len] = '\0';

    memcpy(&nr_info, data + pos, sizeof(nr_info));
    nr_info = ntohs(nr_info);
    pos += 2;

    if ((uint64_t)pos + (uint64_t)nr_info * 2ULL > len) {
        free(name);
        errno = EINVAL;
        return -1;
    }

    /*
     * We currently expose only NBD_INFO_EXPORT.  Unknown information
     * requests are explicitly allowed to be ignored by the protocol.
     */
    *name_out = name;
    return 0;
}

static int handle_transmission(int sock,
                               int disk_fd,
                               uint64_t export_size,
                               int read_only)
{
    unsigned char *buffer = NULL;

    if (posix_memalign((void **)&buffer, 4096, MAX_IO_PAYLOAD) != 0) {
        errno = ENOMEM;
        return -1;
    }

    for (;;) {
        struct nbd_request req;
        int rc = read_full(sock, &req, sizeof(req));
        if (rc <= 0) {
            free(buffer);
            return rc == 0 ? 0 : -1;
        }

        if (ntohl(req.magic) != NBD_REQUEST_MAGIC) {
            fprintf(stderr, "nbd: invalid request magic\n");
            free(buffer);
            errno = EPROTO;
            return -1;
        }

        uint16_t flags = ntohs(req.flags);
        uint16_t type = ntohs(req.type);
        uint64_t handle = ntohll_u64(req.handle);
        uint64_t offset = ntohll_u64(req.offset);
        uint32_t len = ntohl(req.length);

        int cmd_error = 0;

        if ((uint32_t)len > MAX_IO_PAYLOAD) {
            cmd_error = EOVERFLOW;
        }

        switch (type) {
        case NBD_CMD_READ:
            if ((flags & ~(NBD_CMD_FLAG_FUA | NBD_CMD_FLAG_DF)) != 0) {
                cmd_error = EINVAL;
            }
            if (!range_ok(offset, len, export_size)) {
                cmd_error = EINVAL;
            }
            if (cmd_error == 0 && len > 0) {
                uint32_t done = 0;
                while (done < len) {
                    ssize_t n = pread(disk_fd, buffer + done, len - done,
                                      (off_t)(offset + done));
                    if (n < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        cmd_error = errno;
                        break;
                    }
                    if (n == 0) {
                        cmd_error = EIO;
                        break;
                    }
                    done += (uint32_t)n;
                }
            }

            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }

            if (cmd_error == 0 && len > 0) {
                if (write_full(sock, buffer, len) < 0) {
                    free(buffer);
                    return -1;
                }
            }
            break;

        case NBD_CMD_WRITE:
            if (read_only) {
                cmd_error = EROFS;
            }
            if ((flags & ~(NBD_CMD_FLAG_FUA)) != 0) {
                cmd_error = EINVAL;
            }
            if (!range_ok(offset, len, export_size)) {
                cmd_error = EINVAL;
            }

            if (len > 0) {
                int rr = read_full(sock, buffer, len);
                if (rr <= 0) {
                    free(buffer);
                    return rr == 0 ? 0 : -1;
                }
            }

            if (cmd_error == 0 && len > 0) {
                uint32_t done = 0;
                while (done < len) {
                    ssize_t n = pwrite(disk_fd, buffer + done, len - done,
                                       (off_t)(offset + done));
                    if (n < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        cmd_error = errno;
                        break;
                    }
                    if (n == 0) {
                        cmd_error = EIO;
                        break;
                    }
                    done += (uint32_t)n;
                }
            }

            if (cmd_error == 0 && (flags & NBD_CMD_FLAG_FUA)) {
                if (fsync(disk_fd) < 0) {
                    cmd_error = errno;
                }
            }

            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;

        case NBD_CMD_FLUSH:
            if (flags != 0 || offset != 0 || len != 0) {
                cmd_error = EINVAL;
            } else if (fsync(disk_fd) < 0) {
                cmd_error = errno;
            }

            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;

        case NBD_CMD_TRIM:
            /* We do not advertise TRIM, so the client should never send it. */
            cmd_error = EOPNOTSUPP;
            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;

        case NBD_CMD_CACHE:
            /* Cache is not advertised; treating it as a successful no-op is safe. */
            cmd_error = 0;
            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;

        case NBD_CMD_WRITE_ZEROES:
            /* Not advertised; do not accept it. */
            cmd_error = EOPNOTSUPP;
            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;

        case NBD_CMD_DISC:
            free(buffer);
            return 0;

        default:
            cmd_error = EINVAL;
            if (send_simple_reply(sock, handle, cmd_error) < 0) {
                free(buffer);
                return -1;
            }
            break;
        }
    }
}

static int handle_client(int sock,
                         const char *export_name,
                         int disk_fd,
                         uint64_t export_size,
                         int read_only)
{
    unsigned char password[8];
    uint64_t magic;
    uint16_t server_flags;
    uint32_t client_flags_net;
    uint32_t client_flags;

    /*
     * Advertise fixed-newstyle and C_NO_ZEROES support.  This is a plain
     * NOTLS server; STARTTLS is explicitly rejected later.
     */
    server_flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;

    memcpy(password, NBD_INIT_PASSWD, 8);
    if (write_full(sock, password, sizeof(password)) < 0) {
        return -1;
    }

    magic = htonll_u64(NBD_OPTS_MAGIC);
    if (write_full(sock, &magic, sizeof(magic)) < 0) {
        return -1;
    }

    uint16_t sf = htons(server_flags);
    if (write_full(sock, &sf, sizeof(sf)) < 0) {
        return -1;
    }

    if (read_full(sock, &client_flags_net, sizeof(client_flags_net)) <= 0) {
        return -1;
    }
    client_flags = ntohl(client_flags_net);

    /*
     * We support fixed-newstyle option haggling only when the client opted
     * into it.  A client lacking this bit can still use EXPORT_NAME.
     */
    int fixed = (client_flags & NBD_FLAG_C_FIXED_NEWSTYLE) != 0;

    uint16_t tx_flags = NBD_FLAG_HAS_FLAGS;
    if (read_only) {
        tx_flags |= NBD_FLAG_READ_ONLY;
    } else {
        tx_flags |= NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA;
    }

    if (!fixed) {
        /* Old clients have only EXPORT_NAME available in this mode. */
        struct nbd_opt_request opt;
        int rc = read_full(sock, &opt, sizeof(opt));
        if (rc <= 0) {
            return -1;
        }

        if (ntohll_u64(opt.magic) != NBD_OPTS_MAGIC) {
            errno = EPROTO;
            return -1;
        }

        uint32_t option = ntohl(opt.option);
        uint32_t len = ntohl(opt.length);
        if (option != NBD_OPT_EXPORT_NAME || len > MAX_OPTION_PAYLOAD) {
            if (len <= MAX_OPTION_PAYLOAD) {
                (void)discard_bytes(sock, len);
            }
            errno = EPROTO;
            return -1;
        }

        if (discard_bytes(sock, len) <= 0) {
            return -1;
        }
        return enter_transmission_export_name(sock, export_size, tx_flags, client_flags);
    }

    for (;;) {
        struct nbd_opt_request opt;
        int rc = read_full(sock, &opt, sizeof(opt));
        if (rc <= 0) {
            return -1;
        }

        if (ntohll_u64(opt.magic) != NBD_OPTS_MAGIC) {
            fprintf(stderr, "nbd: invalid option magic\n");
            errno = EPROTO;
            return -1;
        }

        uint32_t option = ntohl(opt.option);
        uint32_t len = ntohl(opt.length);

        if (len > MAX_OPTION_PAYLOAD) {
            (void)send_error_reply(sock, option, NBD_REP_ERR_TOO_BIG, "option too large");
            return -1;
        }

        unsigned char *payload = NULL;
        if (len > 0) {
            payload = (unsigned char *)malloc(len);
            if (payload == NULL) {
                (void)send_error_reply(sock, option, NBD_REP_ERR_PLATFORM, "out of memory");
                return -1;
            }
            if (read_full(sock, payload, len) <= 0) {
                free(payload);
                return -1;
            }
        }

        if (option == NBD_OPT_ABORT) {
            free(payload);
            (void)send_option_reply(sock, option, NBD_REP_ACK, NULL, 0);
            return 0;
        }

        if (option == NBD_OPT_STARTTLS) {
            free(payload);
            (void)send_error_reply(sock, option, NBD_REP_ERR_UNSUP, "TLS is not supported");
            continue;
        }

        if (option == NBD_OPT_STRUCTURED_REPLY) {
            if (len != 0) {
                (void)send_error_reply(sock, option, NBD_REP_ERR_INVALID,
                                       "structured-reply option must have no payload");
            } else {
                (void)send_error_reply(sock, option, NBD_REP_ERR_UNSUP,
                                       "structured replies are not supported");
            }
            free(payload);
            continue;
        }

        if (option == NBD_OPT_LIST) {
            if (len != 0) {
                (void)send_error_reply(sock, option, NBD_REP_ERR_INVALID,
                                       "LIST takes no payload");
            } else if (send_list_entry(sock, option, export_name) < 0 ||
                       send_option_reply(sock, option, NBD_REP_ACK, NULL, 0) < 0) {
                free(payload);
                return -1;
            }
            free(payload);
            continue;
        }

        if (option == NBD_OPT_INFO || option == NBD_OPT_GO) {
            char *requested_name = NULL;
            if (parse_info_go(payload, len, &requested_name) < 0) {
                free(payload);
                (void)send_error_reply(sock, option, NBD_REP_ERR_INVALID,
                                       "invalid INFO/GO payload");
                continue;
            }

            /*
             * An empty name denotes the default export.  For simplicity this
             * server has one export and accepts either empty or canonical name.
             */
            int name_ok = (requested_name[0] == '\0' ||
                           strcmp(requested_name, export_name) == 0);

            if (!name_ok) {
                free(requested_name);
                free(payload);
                (void)send_error_reply(sock, option, NBD_REP_ERR_UNKNOWN,
                                       "unknown export");
                continue;
            }

            free(requested_name);

            if (send_export_info(sock, option, export_size, tx_flags) < 0 ||
                send_option_reply(sock, option, NBD_REP_ACK, NULL, 0) < 0) {
                free(payload);
                return -1;
            }

            free(payload);

            if (option == NBD_OPT_GO) {
                return handle_transmission(sock, disk_fd, export_size, read_only);
            }
            continue;
        }

        if (option == NBD_OPT_EXPORT_NAME) {
            char *name = NULL;

            if (len > 0) {
                name = (char *)malloc((size_t)len + 1);
                if (name == NULL) {
                    free(payload);
                    return -1;
                }
                memcpy(name, payload, len);
                name[len] = '\0';
            }

            int name_ok = (len == 0 ||
                           (name != NULL && strcmp(name, export_name) == 0));

            if (!name_ok) {
                free(name);
                free(payload);
                /*
                 * EXPORT_NAME has no error reply mechanism; the protocol
                 * requires terminating the session.
                 */
                return -1;
            }

            free(name);
            free(payload);

            return enter_transmission_export_name(sock, export_size, tx_flags,
                                                  client_flags);
        }

        /*
         * Unknown option: consume payload (already consumed) and let current
         * nbd-client fall back when appropriate.
         */
        (void)send_error_reply(sock, option, NBD_REP_ERR_UNSUP,
                               "option not supported");
        free(payload);
    }
}

static int make_listener(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 4) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [options] PORT DEVICE\n"
            "\n"
            "Default mode is read-only.\n"
            "\n"
            "Options:\n"
            "  -w, --rw           export read-write\n"
            "  -n, --name NAME    NBD export name (default: android)\n"
            "  -v, --verbose      log connections\n"
            "  -h, --help         show this help\n"
            "\n"
            "Example:\n"
            "  su -c '%s -n android 10809 /dev/block/mmcblk1'\n"
            "  su -c '%s --rw 10809 /dev/block/mmcblk1'\n",
            argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
    int read_only = 1;
    int verbose = 0;
    const char *export_name = "android";
    int opt;

    static const struct option long_opts[] = {
        {"rw", no_argument, NULL, 'w'},
        {"name", required_argument, NULL, 'n'},
        {"verbose", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    while ((opt = getopt_long(argc, argv, "wn:vh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'w':
            read_only = 0;
            break;
        case 'n':
            export_name = optarg;
            if (export_name[0] == '\0') {
                fprintf(stderr, "nbd: export name must not be empty when advertised\n");
                return 2;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }

    if (argc - optind != 2) {
        usage(argv[0]);
        return 2;
    }

    char *end = NULL;
    unsigned long port_ul = strtoul(argv[optind], &end, 10);
    if (end == argv[optind] || *end != '\0' || port_ul == 0 || port_ul > 65535) {
        fprintf(stderr, "nbd: invalid port: %s\n", argv[optind]);
        return 2;
    }
    uint16_t port = (uint16_t)port_ul;

    const char *device = argv[optind + 1];
    int disk_fd = open(device, read_only ? O_RDONLY : O_RDWR);
    if (disk_fd < 0) {
        perror("nbd: open device");
        return 1;
    }

    uint64_t export_size;
    if (get_device_size(disk_fd, &export_size) < 0) {
        perror("nbd: cannot determine device size");
        close(disk_fd);
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    g_listen_fd = make_listener(port);
    if (g_listen_fd < 0) {
        perror("nbd: listen");
        close(disk_fd);
        return 1;
    }

    fprintf(stderr,
            "android-nbd-server: device=%s size=%llu bytes mode=%s port=%u name=%s\n",
            device,
            (unsigned long long)export_size,
            read_only ? "read-only" : "read-write",
            (unsigned)port,
            export_name);

    while (!g_stop) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client = accept(g_listen_fd, (struct sockaddr *)&peer, &peer_len);

        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (g_stop) {
                break;
            }
            perror("nbd: accept");
            continue;
        }

        if (verbose) {
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
            fprintf(stderr, "nbd: connection from %s:%u\n",
                    ip, (unsigned)ntohs(peer.sin_port));
        }

        (void)handle_client(client, export_name, disk_fd, export_size, read_only);
        close(client);

        if (verbose) {
            fprintf(stderr, "nbd: connection closed\n");
        }
    }

    close(disk_fd);
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
    }

    return 0;
}
