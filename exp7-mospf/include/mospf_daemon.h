#ifndef __MOSPF_DAEMON_H__
#define __MOSPF_DAEMON_H__

#include "base.h"
#include "types.h"
#include "list.h"

void mospf_init();

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);
void mospf_run();
void handle_mospf_packet(iface_info_t *iface, char *packet, int len);

#define ROUTER_NUM 4
extern u32 router_list[ROUTER_NUM];
extern int graph[ROUTER_NUM][ROUTER_NUM];
#endif
