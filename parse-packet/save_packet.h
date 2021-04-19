#ifndef __SAVE_PACKET_H_
#define __SAVE_PACKET_H_




int start_save_packet(char *capture_save_dir, int want_capture_count);
void stop_save_packet(void);
void save_packet(const void *data, int len, const void *type, const void *tail, int tail_len);



#endif
