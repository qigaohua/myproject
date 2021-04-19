#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>


#define SP_LOGE(fmt, ...) do {  \
    fprintf(stderr, "%s:%d :"fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    syslog(LOG_ERR, "%s:%d :"fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)

#define SP_LOGM(fmt, ...) do {  \
    fprintf(stdout, "%s:%d :"fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
    syslog(LOG_INFO, "%s:%d :"fmt"\r\n", __FILE__, __LINE__, ##__VA_ARGS__); \
} while(0)


static pthread_mutex_t save_packet_lock = PTHREAD_MUTEX_INITIALIZER;
static int save_packet_fd = -1;
static int capture_count;
static int capture_count_now;
static time_t capture_start_time;
static time_t capture_stop_time;
static char capture_save_path[512];


static int get_current_absolute_path(char *current_absolute_path, const int path_len)
{
    //获取当前程序绝对路径
    int cnt = readlink("/proc/self/exe", current_absolute_path, path_len);
    if (cnt < 0 || cnt >= path_len)
    {
        SP_LOGE("Call readlink() failed: %m");
        return -1;
    }

    //获取当前目录绝对路径，即去掉程序名
    for (; cnt >= 0; --cnt) {
        if (current_absolute_path[cnt] == '/') {
            current_absolute_path[cnt] = '\0';
            break;
        }
    }

    return cnt;
}


int start_save_packet(char *capture_save_dir, int want_capture_count)
{
    struct my_pcap_filehdr {
        uint32_t magic;
        uint16_t minor_version;
        uint16_t magot_version;
        uint32_t timezone;
        uint32_t sigflags;
        uint32_t snaplen;
        uint32_t linktype;
    } header = {
        0xa1b2c3d4,
        0x0002,
        0x0004,
        0x00000000,
        0x00000000,
        0x00040000,
        0x00000001,
    };

    pthread_mutex_lock(&save_packet_lock);
    if (save_packet_fd < 0) {
        char dir[256] = {0};
        if (capture_save_dir == NULL || capture_save_dir[0] != '/') {
            if (0 > get_current_absolute_path(dir, sizeof(dir))) {
                SP_LOGE("The capture_save_dir is invailed.");
                pthread_mutex_unlock(&save_packet_lock);
                return -1;
            }
        }
        snprintf(capture_save_path, sizeof(capture_save_path), "%s/packet_%lu.pcap",
                dir[0] != '\0' ? dir:capture_save_dir, time(NULL));
        save_packet_fd = open(capture_save_path, O_WRONLY | O_CREAT, S_IRWXU | S_IROTH);
        if (save_packet_fd < 0) {
            SP_LOGE("Call open(%s) failed: %m", capture_save_path);
            pthread_mutex_unlock(&save_packet_lock);
            return -1;
        }

        if (write(save_packet_fd, &header, sizeof(header)) != sizeof(header)) {
            SP_LOGE("Call write() failed: %m");
        }

        capture_count = want_capture_count;
        capture_count_now = 0;
        capture_start_time = time(NULL);
        capture_stop_time = 0;
    }
    else
        SP_LOGM("You call start_save_packet() twice.");
    pthread_mutex_unlock(&save_packet_lock);
    return 0;
}


void stop_save_packet(void)
{
    pthread_mutex_lock(&save_packet_lock);
    if (save_packet_fd >= 0)
        close(save_packet_fd);
    pthread_mutex_unlock(&save_packet_lock);

    save_packet_fd = -1;
    capture_stop_time = time(NULL);
    SP_LOGM("Stop save packet, save_packet_path: %s, save packet count: %d",
            capture_save_path,  capture_count_now);
    memset(capture_save_path, 0, sizeof(capture_save_path));
    capture_count = 0;
    capture_count_now = 0;
}



/**
 * @brief save_packet 保持数据包
 *
 * @param data 数据包
 * @param len  数据包长度
 * @param type "i:" 表示接口名  后面三个参数主要是标识作用
 * @param tail 一般为接口名，如"eth0"
 * @param tail_len 接口名长度
 */
void save_packet(const void *data, int len, const void *type, const void *tail, int tail_len)
{
    struct my_pcap_pkthdr {
        uint32_t sec;
        uint32_t usec;
        uint32_t caplen;
        uint32_t len;
    } pcap_frame_head;

    if (capture_count_now >= capture_count)
        return;
    if (save_packet_fd < 0) { SP_LOGE("save_packet_fd < 0\n"); return; }

    struct timeval  tv;
    gettimeofday(&tv, NULL);
    pcap_frame_head.sec = (uint32_t)tv.tv_sec;
    pcap_frame_head.usec = (uint32_t)tv.tv_usec;
    pcap_frame_head.caplen = len+2+tail_len;
    pcap_frame_head.len    = len+2+tail_len;

    pthread_mutex_lock(&save_packet_lock);
    if (write(save_packet_fd, &pcap_frame_head, sizeof(pcap_frame_head)) != sizeof(pcap_frame_head))
        SP_LOGE("Call write() failed: %m\n");
    if (write(save_packet_fd, data, len) != len)
        SP_LOGE("Call write() failed: %m\n");
    if (write(save_packet_fd, type, 2) != 2)
        SP_LOGE("Call write() failed: %m\n");
    if (write(save_packet_fd, tail, tail_len) != tail_len)
        SP_LOGE("Call write() failed: %m\n");
    pthread_mutex_unlock(&save_packet_lock);

    capture_count_now++;
    // pthread_mutex_unlock(&save_packet_lock);
    if (capture_count_now >= capture_count)
        stop_save_packet();
}



