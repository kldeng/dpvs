/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2017 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef __DPVS_VXLAN_H__
#define __DPVS_VXLAN_H__

#include <stdint.h>
#include "common.h"
#include "inet.h"
#include "route.h"
#include "ipv4.h"
#include "dpdk.h"
#include "ipvs/conn.h"

#define IP_VERSION 0x40
#define IP_HDRLEN  0x05 /* default IP header length == five 32-bits words. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)

#define PORT_MIN        49152
#define PORT_MAX        65535
#define PORT_RANGE ((PORT_MAX - PORT_MIN) + 1)
#define VXLAN_HF_VNI 0x08000000

#define VXLAN_PORT_MIN  1025
#define VXLAN_PORT_MAX  65535

struct dp_vs_vxlan_info {
    uint32_t            vx_vni_vip;
    uint32_t            vx_vni_rs;
    union inet_addr     vtep_peer_addr;
    struct ether_addr   smac_inner;
} __rte_aligned(RTE_MBUF_PRIV_ALIGN);

static inline uint16_t
dp_vs_vxlan_info_size(void) {
    return sizeof(struct dp_vs_vxlan_info);
}

static inline struct dp_vs_vxlan_info *
get_priv(const struct rte_mbuf *m) {
    return RTE_PTR_ADD(m, sizeof(struct rte_mbuf));
}

int vxlan_encap(struct rte_mbuf *mbuf, 
                    int dir, 
                    uint32_t vx_vni_vip, 
                    uint32_t vx_vni_rs, 
                    union inet_addr dest_addr, 
                    struct ether_addr dmac);

#endif /* __DPVS_VXLAN_H__ */
