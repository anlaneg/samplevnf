#ifndef MBUF_HDR_ROOM_H 
#define MBUF_HDR_ROOM_H
#include <stdint.h>
#define DPDK_17_05_MBUF_HDR_ROOM(pkt) (pkt->data_off + ((int)( (uint8_t*)pkt->buf_addr - (uint8_t*)pkt)))

#endif
