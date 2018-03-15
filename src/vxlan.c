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
#include "vxlan.h"

extern int g_vxlan_port_inbound;
extern int g_vxlan_port_outbound;

int vxlan_encap(struct rte_mbuf *mbuf, 
                int dir, 
                uint32_t vx_vni_vip, 
                uint32_t vx_vni_rs, 
                union inet_addr daddr,
                struct ether_addr dmac) 
{
    struct flow4 fl4;
    int err;
    struct route_entry *rt;
    struct ipv4_hdr *iph = ip4_hdr(mbuf);
    struct netif_port *dev = netif_port_get(mbuf->port);
    memset(&fl4, 0, sizeof(struct flow4));
    uint32_t old_len = mbuf->pkt_len, hash;
    uint8_t tos = iph->type_of_service;
    uint16_t df = iph->fragment_offset & htons(IPV4_HDR_DF_FLAG);
    struct ether_hdr *phdr = (struct ether_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct ether_hdr));

    /* fill L2 header */
    ether_addr_copy(&dev->addr, &phdr->s_addr);
    fl4.daddr = daddr.in;
    ether_addr_copy(&dmac, &phdr->d_addr);

    phdr->ether_type = rte_cpu_to_be_16(0x0800);

    fl4.tos = tos;
    rt = route4_output(&fl4);
    if (!rt) {
        err = EDPVS_NOROUTE;
        goto errout;
    }
    mbuf->userdata = rt;

    /*Allocate space for new ethernet, IPv4, UDP and VXLAN headers*/
    struct ipv4_hdr *oiph = (struct ipv4_hdr *) rte_pktmbuf_prepend(mbuf,
            sizeof(struct ipv4_hdr)
            + sizeof(struct udp_hdr) + sizeof(struct vxlan_hdr));

    struct udp_hdr *oudph = (struct udp_hdr *) &oiph[1];
    struct vxlan_hdr *vxlan = (struct vxlan_hdr *) &oudph[1];

    oiph->version_ihl = IP_VHL_DEF;
    oiph->type_of_service = tos;
    oiph->packet_id = 0;
    oiph->fragment_offset = df;
    oiph->time_to_live = iph->time_to_live;
    oiph->next_proto_id = IPPROTO_UDP;
    oiph->hdr_checksum = 0;
    oiph->src_addr = rt->src.s_addr;

    oiph->dst_addr = daddr.in.s_addr;
    oiph->total_length = rte_cpu_to_be_16(mbuf->pkt_len);

    if (rt->port && rt->port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD) {
        RTE_LOG(DEBUG, IPVS, "%s: checksum of vxlan outer l3 header will calculated by hw\n", __func__);
        mbuf->ol_flags |= PKT_TX_IP_CKSUM;
        oiph->hdr_checksum = 0;
    } else {
        RTE_LOG(DEBUG, IPVS, "%s: checksum of vxlan outer l3 header will calculated by sw\n", __func__);
        ip4_send_csum(oiph);
    }

    /* UDP HEADER */
    oudph->dgram_cksum = 0;
    oudph->dgram_len = rte_cpu_to_be_16(old_len + sizeof(struct ether_hdr)
            + sizeof(struct udp_hdr)
            + sizeof(struct vxlan_hdr));

    if (dir == DPVS_CONN_DIR_OUTBOUND)
        oudph->dst_port = rte_cpu_to_be_16(g_vxlan_port_inbound);
    else
        oudph->dst_port = rte_cpu_to_be_16(g_vxlan_port_outbound);

    hash = rte_hash_crc(phdr, 2 * ETHER_ADDR_LEN, phdr->ether_type);
    oudph->src_port = rte_cpu_to_be_16((((uint64_t) hash * PORT_RANGE) >> 32)
            + PORT_MIN);

    /*VXLAN HEADER*/
    if (dir == DPVS_CONN_DIR_OUTBOUND) {
        vxlan->vx_vni = rte_cpu_to_be_32(vx_vni_vip << 8);
        vxlan->vx_flags = rte_cpu_to_be_32(VXLAN_HF_VNI);
    } else {
        vxlan->vx_vni = rte_cpu_to_be_32(vx_vni_rs << 8);
        vxlan->vx_flags = rte_cpu_to_be_32(VXLAN_HF_VNI | vx_vni_vip); //use reserved option in vxlan flags to save vip's vni
    }

    return EDPVS_OK;

errout:
    rte_pktmbuf_free(mbuf);
    return err;
}

