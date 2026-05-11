#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <zlib.h>

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_VLAN 0x8100
#define ETH_TYPE_QINQ 0x88A8
#define IP_PROTO_TCP  6

typedef enum { FTP_MODE_NONE = 0, FTP_MODE_PORT, FTP_MODE_PASV } FtpMode;
typedef enum { TRANS_UNKNOWN = 0, TRANS_RETR, TRANS_STOR } TransferCmd;

typedef struct {
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
} Segment;

typedef struct {
    Segment *items;
    size_t count;
    size_t capacity;
} SegmentVec;

typedef struct {
    uint64_t file_size;
    char md5[33];
    char sha1[41];
    char sha256[65];
    char crc32_hex[9];
} ChecksumResult;

typedef struct {
    SegmentVec segs;

    int has_control_pair;
    uint32_t client_ip;
    uint32_t server_ip;

    int has_username;
    int has_password;
    char username[256];
    char password[256];

    int has_data_endpoint;
    uint32_t data_ip;
    uint16_t data_port;
    FtpMode mode;

    TransferCmd cmd;
    int has_filename;
    char filename[512];

    uint64_t total_packets;
    uint64_t ftp_control_messages;
    uint64_t data_segments;
    uint64_t data_bytes;
} Context;

static uint16_t read_be16(const uint8_t *p) { uint16_t v; memcpy(&v, p, sizeof(v)); return ntohs(v); }
static uint32_t read_be32(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return ntohl(v); }

static const char *basename_from_path(const char *path) {
    const char *p1 = strrchr(path, '/');
    const char *p2 = strrchr(path, '\\');
    const char *p = p1 > p2 ? p1 : p2;
    return p ? p + 1 : path;
}

static void ip_to_str(uint32_t ip_host, char *buf, size_t buflen) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_host);
    if (inet_ntop(AF_INET, &addr, buf, buflen) == NULL) snprintf(buf, buflen, "");
}

static void trim_right(char *s) {
    size_t n = strlen(s);
    while (n > 0) {
        unsigned char ch = (unsigned char)s[n - 1];
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') s[--n] = '\0';
        else break;
    }
}

static void trim_copy_after_command(char *dst, size_t dst_size, const char *line, size_t prefix_len) {
    const char *p = line + prefix_len;
    while (*p == ' ' || *p == '\t') p++;
    snprintf(dst, dst_size, "%s", p);
    trim_right(dst);
}

static const char *ftp_mode_to_str(FtpMode mode) {
    if (mode == FTP_MODE_PORT) return "PORT";
    if (mode == FTP_MODE_PASV) return "PASV";
    return "";
}

static void segment_vec_free(SegmentVec *vec) {
    if (!vec) return;
    for (size_t i = 0; i < vec->count; i++) free(vec->items[i].data);
    free(vec->items);
    vec->items = NULL;
    vec->count = 0;
    vec->capacity = 0;
}

static int segment_vec_push(SegmentVec *vec, uint32_t seq, const uint8_t *data, uint32_t len) {
    if (len == 0) return 0;
    for (size_t i = 0; i < vec->count; i++) {
        if (vec->items[i].seq == seq && vec->items[i].len == len) return 0;
    }
    if (vec->count == vec->capacity) {
        size_t new_cap = vec->capacity == 0 ? 128 : vec->capacity * 2;
        Segment *new_items = (Segment *)realloc(vec->items, new_cap * sizeof(Segment));
        if (!new_items) { fprintf(stderr, "[ERROR] realloc failed\n"); return -1; }
        vec->items = new_items;
        vec->capacity = new_cap;
    }
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy) { fprintf(stderr, "[ERROR] malloc failed\n"); return -1; }
    memcpy(copy, data, len);
    vec->items[vec->count].seq = seq;
    vec->items[vec->count].len = len;
    vec->items[vec->count].data = copy;
    vec->count++;
    return 0;
}

static int cmp_segment_by_seq(const void *a, const void *b) {
    const Segment *sa = (const Segment *)a;
    const Segment *sb = (const Segment *)b;
    if (sa->seq < sb->seq) return -1;
    if (sa->seq > sb->seq) return 1;
    if (sa->len < sb->len) return -1;
    if (sa->len > sb->len) return 1;
    return 0;
}

static int parse_six_numbers(const char *s, int nums[6]) {
    const char *p = strchr(s, '(');
    p = p ? p + 1 : s;
    while (*p && !isdigit((unsigned char)*p)) p++;
    int ret = sscanf(p, "%d,%d,%d,%d,%d,%d", &nums[0], &nums[1], &nums[2], &nums[3], &nums[4], &nums[5]);
    if (ret != 6) return 0;
    for (int i = 0; i < 6; i++) if (nums[i] < 0 || nums[i] > 255) return 0;
    return 1;
}

static uint32_t make_ip_host_order(int a, int b, int c, int d) {
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | ((uint32_t)d);
}

static void remember_control_pair(Context *ctx, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    if (ctx->has_control_pair) return;
    if (dst_port == 21) {
        ctx->client_ip = src_ip;
        ctx->server_ip = dst_ip;
        ctx->has_control_pair = 1;
    } else if (src_port == 21) {
        ctx->client_ip = dst_ip;
        ctx->server_ip = src_ip;
        ctx->has_control_pair = 1;
    }
    if (ctx->has_control_pair) {
        char client[64], server[64];
        ip_to_str(ctx->client_ip, client, sizeof(client));
        ip_to_str(ctx->server_ip, server, sizeof(server));
        printf("[FTP] control pair: client=%s, server=%s\n", client, server);
    }
}

static void parse_ftp_line(Context *ctx, const char *line) {
    int nums[6];
    if (strncasecmp(line, "USER ", 5) == 0) {
        trim_copy_after_command(ctx->username, sizeof(ctx->username), line, 5);
        ctx->has_username = 1;
        printf("[FTP] username: %s\n", ctx->username);
        return;
    }
    if (strncasecmp(line, "PASS ", 5) == 0) {
        trim_copy_after_command(ctx->password, sizeof(ctx->password), line, 5);
        ctx->has_password = 1;
        printf("[FTP] password: %s\n", ctx->password);
        return;
    }
    if (strncasecmp(line, "PORT ", 5) == 0) {
        if (parse_six_numbers(line, nums)) {
            ctx->data_ip = make_ip_host_order(nums[0], nums[1], nums[2], nums[3]);
            ctx->data_port = (uint16_t)(nums[4] * 256 + nums[5]);
            ctx->mode = FTP_MODE_PORT;
            ctx->has_data_endpoint = 1;
            char ipbuf[64]; ip_to_str(ctx->data_ip, ipbuf, sizeof(ipbuf));
            printf("[FTP] PORT mode data endpoint: %s:%u\n", ipbuf, ctx->data_port);
        }
        return;
    }
    if (strncasecmp(line, "PASV", 4) == 0) {
        printf("[FTP] PASV request detected\n");
        return;
    }
    if (strncmp(line, "227", 3) == 0 && parse_six_numbers(line, nums)) {
        ctx->data_ip = make_ip_host_order(nums[0], nums[1], nums[2], nums[3]);
        ctx->data_port = (uint16_t)(nums[4] * 256 + nums[5]);
        ctx->mode = FTP_MODE_PASV;
        ctx->has_data_endpoint = 1;
        char ipbuf[64]; ip_to_str(ctx->data_ip, ipbuf, sizeof(ipbuf));
        printf("[FTP] PASV mode data endpoint: %s:%u\n", ipbuf, ctx->data_port);
        return;
    }
    if (strncasecmp(line, "RETR ", 5) == 0) {
        trim_copy_after_command(ctx->filename, sizeof(ctx->filename), line, 5);
        ctx->cmd = TRANS_RETR;
        ctx->has_filename = 1;
        printf("[FTP] transfer command: RETR(download), filename: %s\n", ctx->filename);
        return;
    }
    if (strncasecmp(line, "STOR ", 5) == 0) {
        trim_copy_after_command(ctx->filename, sizeof(ctx->filename), line, 5);
        ctx->cmd = TRANS_STOR;
        ctx->has_filename = 1;
        printf("[FTP] transfer command: STOR(upload), filename: %s\n", ctx->filename);
        return;
    }
}

static void handle_ftp_control(Context *ctx, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, uint32_t payload_len) {
    remember_control_pair(ctx, src_ip, dst_ip, src_port, dst_port);
    char *buf = (char *)malloc(payload_len + 1);
    if (!buf) { fprintf(stderr, "[ERROR] malloc failed for FTP control buffer\n"); return; }
    memcpy(buf, payload, payload_len);
    buf[payload_len] = '\0';
    char *saveptr = NULL;
    char *line = strtok_r(buf, "\n", &saveptr);
    while (line) {
        trim_right(line);
        if (strlen(line) > 0) {
            ctx->ftp_control_messages++;
            printf("[FTP-CTRL] %s\n", line);
            parse_ftp_line(ctx, line);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(buf);
}

static int is_current_data_payload(Context *ctx, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t payload_len) {
    if (!ctx->has_data_endpoint || payload_len == 0) return 0;
    if (src_port != ctx->data_port && dst_port != ctx->data_port) return 0;
    if (ctx->has_control_pair && ctx->cmd != TRANS_UNKNOWN) {
        if (ctx->cmd == TRANS_RETR) return src_ip == ctx->server_ip && dst_ip == ctx->client_ip;
        if (ctx->cmd == TRANS_STOR) return src_ip == ctx->client_ip && dst_ip == ctx->server_ip;
    }
    return 1;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    Context *ctx = (Context *)user;
    ctx->total_packets++;
    uint32_t caplen = header->caplen;
    if (caplen < 14) return;
    uint32_t l2_len = 14;
    uint16_t eth_type = read_be16(packet + 12);
    while (eth_type == ETH_TYPE_VLAN || eth_type == ETH_TYPE_QINQ) {
        if (caplen < l2_len + 4) return;
        eth_type = read_be16(packet + l2_len + 2);
        l2_len += 4;
    }
    if (eth_type != ETH_TYPE_IPV4) return;
    if (caplen < l2_len + 20) return;
    const uint8_t *ip = packet + l2_len;
    uint8_t version = ip[0] >> 4;
    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (version != 4 || ihl < 20) return;
    if (caplen < l2_len + ihl) return;
    uint16_t total_len = read_be16(ip + 2);
    if (total_len < ihl) return;
    uint16_t frag_off = read_be16(ip + 6);
    if ((frag_off & 0x3FFF) != 0) return;
    if (ip[9] != IP_PROTO_TCP) return;
    uint32_t src_ip = read_be32(ip + 12);
    uint32_t dst_ip = read_be32(ip + 16);
    uint32_t tcp_offset = l2_len + ihl;
    if (caplen < tcp_offset + 20) return;
    const uint8_t *tcp = packet + tcp_offset;
    uint16_t src_port = read_be16(tcp + 0);
    uint16_t dst_port = read_be16(tcp + 2);
    uint32_t seq = read_be32(tcp + 4);
    uint8_t tcp_header_len = (tcp[12] >> 4) * 4;
    if (tcp_header_len < 20) return;
    if (caplen < tcp_offset + tcp_header_len) return;
    if (total_len < ihl + tcp_header_len) return;
    uint32_t payload_len = total_len - ihl - tcp_header_len;
    uint32_t payload_offset = tcp_offset + tcp_header_len;
    if (payload_offset > caplen) return;
    if (payload_len > caplen - payload_offset) payload_len = caplen - payload_offset;
    const uint8_t *payload = packet + payload_offset;
    if ((src_port == 21 || dst_port == 21) && payload_len > 0) {
        handle_ftp_control(ctx, src_ip, dst_ip, src_port, dst_port, payload, payload_len);
        return;
    }
    if (is_current_data_payload(ctx, src_ip, dst_ip, src_port, dst_port, payload_len)) {
        if (segment_vec_push(&ctx->segs, seq, payload, payload_len) == 0) {
            ctx->data_segments++;
            ctx->data_bytes += payload_len;
            char srcbuf[64], dstbuf[64];
            ip_to_str(src_ip, srcbuf, sizeof(srcbuf));
            ip_to_str(dst_ip, dstbuf, sizeof(dstbuf));
            printf("[DATA] %s:%u -> %s:%u, seq=%u, len=%u\n", srcbuf, src_port, dstbuf, dst_port, seq, payload_len);
        }
    }
}

static int write_reassembled_file(Context *ctx, const char *out_path) {
    if (ctx->segs.count == 0) { fprintf(stderr, "[ERROR] no FTP data segments collected\n"); return -1; }
    qsort(ctx->segs.items, ctx->segs.count, sizeof(Segment), cmp_segment_by_seq);
    FILE *fp = fopen(out_path, "wb");
    if (!fp) { perror("[ERROR] fopen output"); return -1; }
    uint32_t expected_seq = ctx->segs.items[0].seq;
    uint64_t written = 0;
    for (size_t i = 0; i < ctx->segs.count; i++) {
        Segment *seg = &ctx->segs.items[i];
        int32_t diff = (int32_t)(seg->seq - expected_seq);
        if (diff > 0) {
            fprintf(stderr, "[WARN] TCP gap detected: expected_seq=%u, got_seq=%u, gap=%d bytes\n", expected_seq, seg->seq, diff);
            expected_seq = seg->seq;
            diff = 0;
        }
        uint32_t offset = 0;
        if (diff < 0) {
            offset = (uint32_t)(expected_seq - seg->seq);
            if (offset >= seg->len) continue;
        }
        uint32_t write_len = seg->len - offset;
        if (fwrite(seg->data + offset, 1, write_len, fp) != write_len) { fprintf(stderr, "[ERROR] fwrite failed\n"); fclose(fp); return -1; }
        expected_seq += write_len;
        written += write_len;
    }
    fclose(fp);
    printf("\n[OK] reassembled file written: %s\n", out_path);
    printf("[OK] bytes written: %llu\n", (unsigned long long)written);
    return 0;
}

static void bytes_to_hex(const unsigned char *bytes, unsigned int len, char *out, int uppercase) {
    const char *hex = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    for (unsigned int i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

static int digest_init_or_fail(EVP_MD_CTX **ctx, const EVP_MD *md, const char *name) {
    *ctx = EVP_MD_CTX_new();
    if (*ctx == NULL) { fprintf(stderr, "[ERROR] EVP_MD_CTX_new failed for %s\n", name); return -1; }
    if (EVP_DigestInit_ex(*ctx, md, NULL) != 1) { fprintf(stderr, "[ERROR] EVP_DigestInit_ex failed for %s\n", name); EVP_MD_CTX_free(*ctx); *ctx = NULL; return -1; }
    return 0;
}

static int compute_file_checksums(const char *path, ChecksumResult *result) {
    memset(result, 0, sizeof(*result));
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("[ERROR] fopen for checksum"); return -1; }
    EVP_MD_CTX *md5_ctx = NULL, *sha1_ctx = NULL, *sha256_ctx = NULL;
    if (digest_init_or_fail(&md5_ctx, EVP_md5(), "MD5") != 0 || digest_init_or_fail(&sha1_ctx, EVP_sha1(), "SHA1") != 0 || digest_init_or_fail(&sha256_ctx, EVP_sha256(), "SHA256") != 0) {
        fclose(fp); if (md5_ctx) EVP_MD_CTX_free(md5_ctx); if (sha1_ctx) EVP_MD_CTX_free(sha1_ctx); if (sha256_ctx) EVP_MD_CTX_free(sha256_ctx); return -1;
    }
    unsigned char buf[8192];
    size_t n;
    uLong crc = crc32(0L, Z_NULL, 0);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        result->file_size += n;
        EVP_DigestUpdate(md5_ctx, buf, n);
        EVP_DigestUpdate(sha1_ctx, buf, n);
        EVP_DigestUpdate(sha256_ctx, buf, n);
        crc = crc32(crc, buf, (uInt)n);
    }
    if (ferror(fp)) { fprintf(stderr, "[ERROR] fread failed during checksum\n"); fclose(fp); EVP_MD_CTX_free(md5_ctx); EVP_MD_CTX_free(sha1_ctx); EVP_MD_CTX_free(sha256_ctx); return -1; }
    fclose(fp);
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(md5_ctx, digest, &digest_len) != 1) return -1;
    bytes_to_hex(digest, digest_len, result->md5, 1);
    if (EVP_DigestFinal_ex(sha1_ctx, digest, &digest_len) != 1) return -1;
    bytes_to_hex(digest, digest_len, result->sha1, 0);
    if (EVP_DigestFinal_ex(sha256_ctx, digest, &digest_len) != 1) return -1;
    bytes_to_hex(digest, digest_len, result->sha256, 0);
    snprintf(result->crc32_hex, sizeof(result->crc32_hex), "%08lX", crc & 0xFFFFFFFFUL);
    EVP_MD_CTX_free(md5_ctx); EVP_MD_CTX_free(sha1_ctx); EVP_MD_CTX_free(sha256_ctx);
    return 0;
}

static void json_write_string(FILE *fp, const char *s) {
    fputc('"', fp);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            switch (*p) {
                case '\\': fputs("\\\\", fp); break;
                case '"': fputs("\\\"", fp); break;
                case '\n': fputs("\\n", fp); break;
                case '\r': fputs("\\r", fp); break;
                case '\t': fputs("\\t", fp); break;
                default:
                    if (*p < 0x20) fprintf(fp, "\\u%04x", *p);
                    else fputc(*p, fp);
            }
        }
    }
    fputc('"', fp);
}

static void json_write_kv_string(FILE *fp, const char *key, const char *value, int comma) {
    fprintf(fp, "  "); json_write_string(fp, key); fprintf(fp, ": "); json_write_string(fp, value ? value : ""); fprintf(fp, "%s\n", comma ? "," : "");
}
static void json_write_kv_u64(FILE *fp, const char *key, uint64_t value, int comma) {
    fprintf(fp, "  "); json_write_string(fp, key); fprintf(fp, ": %llu%s\n", (unsigned long long)value, comma ? "," : "");
}

static int write_tcp_info_json(const char *json_path, const char *pcap_path, const char *out_path, const Context *ctx, const ChecksumResult *sum) {
    FILE *fp = fopen(json_path, "w");
    if (!fp) { perror("[ERROR] fopen tcp_info.json"); return -1; }
    char client_ip[64] = "", server_ip[64] = "", data_ip[64] = "";
    if (ctx->has_control_pair) { ip_to_str(ctx->client_ip, client_ip, sizeof(client_ip)); ip_to_str(ctx->server_ip, server_ip, sizeof(server_ip)); }
    if (ctx->has_data_endpoint) ip_to_str(ctx->data_ip, data_ip, sizeof(data_ip));
    char data_port_buf[32] = "";
    if (ctx->has_data_endpoint) snprintf(data_port_buf, sizeof(data_port_buf), "%u", ctx->data_port);
    fprintf(fp, "{\n");
    json_write_kv_string(fp, "班级", "", 1);
    json_write_kv_string(fp, "学号", "", 1);
    json_write_kv_string(fp, "姓名", "", 1);
    json_write_kv_string(fp, "截包文件名", basename_from_path(pcap_path), 1);
    json_write_kv_string(fp, "重组输出文件", basename_from_path(out_path), 1);
    json_write_kv_string(fp, "客户端 IP", client_ip, 1);
    json_write_kv_string(fp, "服务器 IP", server_ip, 1);
    json_write_kv_string(fp, "用户名", ctx->has_username ? ctx->username : "", 1);
    json_write_kv_string(fp, "口令", ctx->has_password ? ctx->password : "", 1);
    json_write_kv_string(fp, "传输文件名", ctx->has_filename ? ctx->filename : "", 1);
    json_write_kv_string(fp, "数据连接模式", ftp_mode_to_str(ctx->mode), 1);
    json_write_kv_string(fp, "数据连接监听 IP", data_ip, 1);
    json_write_kv_string(fp, "数据连接监听端口", data_port_buf, 1);
    json_write_kv_string(fp, "文件 MD5", sum->md5, 1);
    json_write_kv_u64(fp, "文件大小", sum->file_size, 1);
    json_write_kv_string(fp, "文件 SHA1", sum->sha1, 1);
    json_write_kv_string(fp, "文件 SHA256", sum->sha256, 1);
    json_write_kv_string(fp, "文件 CRC32", sum->crc32_hex, 1);
    json_write_kv_u64(fp, "总数据包数", ctx->total_packets, 1);
    json_write_kv_u64(fp, "FTP控制消息数", ctx->ftp_control_messages, 1);
    json_write_kv_u64(fp, "数据连接TCP段数", ctx->data_segments, 1);
    json_write_kv_u64(fp, "数据连接原始字节数", ctx->data_bytes, 0);
    fprintf(fp, "}\n");
    fclose(fp);
    printf("[OK] tcp info json written: %s\n", json_path);
    return 0;
}

static void print_summary(const Context *ctx, const ChecksumResult *sum) {
    char client_ip[64] = "", server_ip[64] = "", data_ip[64] = "";
    if (ctx->has_control_pair) { ip_to_str(ctx->client_ip, client_ip, sizeof(client_ip)); ip_to_str(ctx->server_ip, server_ip, sizeof(server_ip)); }
    if (ctx->has_data_endpoint) ip_to_str(ctx->data_ip, data_ip, sizeof(data_ip));
    printf("\n========== TCP / FTP INFO ==========\n");
    printf("client IP:             %s\n", client_ip);
    printf("server IP:             %s\n", server_ip);
    printf("username:              %s\n", ctx->has_username ? ctx->username : "");
    printf("password:              %s\n", ctx->has_password ? ctx->password : "");
    printf("transfer filename:     %s\n", ctx->has_filename ? ctx->filename : "");
    printf("data mode:             %s\n", ftp_mode_to_str(ctx->mode));
    printf("data listen IP:        %s\n", data_ip);
    printf("data listen port:      %u\n", ctx->has_data_endpoint ? ctx->data_port : 0);
    printf("data segments:         %llu\n", (unsigned long long)ctx->data_segments);
    printf("raw data bytes:        %llu\n", (unsigned long long)ctx->data_bytes);
    printf("====================================\n");
    printf("\n========== FILE CHECKSUM ==========\n");
    printf("SIZE:                  %llu\n", (unsigned long long)sum->file_size);
    printf("MD5:                   %s\n", sum->md5);
    printf("SHA1:                  %s\n", sum->sha1);
    printf("SHA256:                %s\n", sum->sha256);
    printf("CRC32:                 %s\n", sum->crc32_hex);
    printf("===================================\n");
}

int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s <input.pcap|input.pcapng> <output_file> [tcp_info.json]\n", argv[0]);
        fprintf(stderr, "Example: %s sample2026.pcapng recovered_sample tcp_info.json\n", argv[0]);
        return 1;
    }
    const char *pcap_path = argv[1];
    const char *out_path = argv[2];
    const char *json_path = argc == 4 ? argv[3] : "tcp_info.json";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) { fprintf(stderr, "[ERROR] pcap_open_offline failed: %s\n", errbuf); return 1; }
    int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) { fprintf(stderr, "[ERROR] only Ethernet link type is supported now. pcap_datalink=%d\n", dlt); pcap_close(handle); return 1; }
    Context ctx;
    memset(&ctx, 0, sizeof(ctx));
    printf("[INFO] processing: %s\n", pcap_path);
    int ret = pcap_loop(handle, 0, packet_handler, (u_char *)&ctx);
    if (ret < 0) { fprintf(stderr, "[ERROR] pcap_loop failed: %s\n", pcap_geterr(handle)); segment_vec_free(&ctx.segs); pcap_close(handle); return 1; }
    pcap_close(handle);
    if (write_reassembled_file(&ctx, out_path) != 0) { segment_vec_free(&ctx.segs); return 1; }
    ChecksumResult sum;
    if (compute_file_checksums(out_path, &sum) != 0) { segment_vec_free(&ctx.segs); return 1; }
    print_summary(&ctx, &sum);
    if (write_tcp_info_json(json_path, pcap_path, out_path, &ctx, &sum) != 0) { segment_vec_free(&ctx.segs); return 1; }
    segment_vec_free(&ctx.segs);
    printf("\nNext:\n  file %s\n  cat %s\n  copy %s to the same directory as the IDA database/input binary\n", out_path, json_path, json_path);
    return 0;
}
