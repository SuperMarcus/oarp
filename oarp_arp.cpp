/**
 *  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *  Version 2, December 2004
 *
 *  Copyright (C) 2017 Marcus Zhou <other.marcus@icloud.com>
 *
 *  You must agree to the license before using.
 *  See LICENSE file in this folder for more information
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#ifdef BSD

#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>

#ifdef __FreeBSD__	/* XXX */
#define ether_addr_octet octet
#endif

#else /* !BSD */
#include <sys/ioctl.h>
#ifndef __linux__
#include <sys/sockio.h>
#endif
#endif /* !BSD */

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <cstdlib>
#include <cstring>
#include <utility>

#include <libnet.h>
#include <pcap.h>

#include "oarp.h"

#ifdef BSD

int oarp::cache_lookup(shared_ptr<in_addr_t> ip, shared_ptr<ether_addr> ether) {
    int mib[6];
    size_t len;
    char *buf, *next, *end;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;

    if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0)
        return (-1);

    if ((buf = (char *)(malloc(len))) == nullptr)
        return (-1);

    if (sysctl(mib, 6, buf, &len, nullptr, 0) < 0) {
        free(buf);
        return (-1);
    }
    end = buf + len;

    for (next = buf ; next < end ; next += rtm->rtm_msglen) {
        rtm = reinterpret_cast<rt_msghdr *>(next);
        sin = reinterpret_cast<sockaddr_inarp *>(rtm + 1);
        sdl = reinterpret_cast<sockaddr_dl *>(sin + 1);

        //If matches the 32 bits ip
        if (sin->sin_addr.s_addr == *ip && sdl->sdl_alen) {
            memcpy(ether->ether_addr_octet, LLADDR(sdl), ETHER_ADDR_LEN);
            free(buf);
            return (0);
        }
    }
    free(buf);

    return (-1);
}

#else /* !BSD */

#ifndef ETHER_ADDR_LEN	/* XXX - Solaris */
#define ETHER_ADDR_LEN	6
#endif

int arp_cache_lookup(in_addr_t ip, struct ether_addr *ether) {
    int sock;
    struct arpreq ar;
    struct sockaddr_in *sin;

    memset((char *)&ar, 0, sizeof(ar));
#ifdef __linux__
    strncpy(ar.arp_dev, intf, strlen(intf));
#endif
    sin = (struct sockaddr_in *)&ar.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return (-1);
    }
    if (ioctl(sock, SIOCGARP, (caddr_t)&ar) == -1) {
        close(sock);
        return (-1);
    }
    close(sock);
    memcpy(ether->ether_addr_octet, ar.arp_ha.sa_data, ETHER_ADDR_LEN);

    return (0);
}

#endif /* !BSD */

#ifdef __linux__
//Send a packet to target host to force the kernel to discover the host
int oarp::force(in_addr_t dst) {
	struct sockaddr_in sin;
	int i, fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);

	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)(&sin), sizeof(sin));

	close(fd);

	return (i == 0);
}
#endif

int oarp::find(in_addr_t ip, shared_ptr<ether_addr> mac) {
    int i = 0;

    auto ipp = make_shared<in_addr_t>(ip);

    do {
        if (cache_lookup(ipp, mac) == 0)
            return (1);
#ifdef __linux__
        /* XXX - force the kernel to arp. feh. */
		force(ip);
#else
        arp_send(ARPOP_REQUEST, nullptr, 0, nullptr, shared_ptr<in_addr_t>(&ip));
#endif
        sleep(1);
    }
    while (i++ < 3);

    return (0);
}

int oarp::arp_send(const int op, const shared_ptr<ether_addr> &sha, const shared_ptr<in_addr_t> spa,
                   const shared_ptr<ether_addr> &tha, const shared_ptr<in_addr_t> tpa){
    auto sourceHardware = sha ? sha.get() : reinterpret_cast<ether_addr *>(libnet_get_hwaddr(netContext));
    auto targetHardware = tha ? tha.get() : (ether_addr *) "\xff\xff\xff\xff\xff\xff";
    auto sourceInet = spa ? *spa : libnet_get_ipaddr4(netContext);//Default to host addr
    auto targetInet = *tpa;//At least you should know target inet

    //Cannot get host inet/mac addr
    if (sourceInet == -1) return -1;
    if (sourceHardware == nullptr) return -1;

    //Build arp packet
    libnet_autobuild_arp(
            static_cast<uint16_t>(op),
            reinterpret_cast<const uint8_t *>(sourceHardware),
            reinterpret_cast<const uint8_t *>(&sourceInet),
            reinterpret_cast<const uint8_t *>(targetHardware),
            reinterpret_cast<uint8_t *>(&targetInet), netContext);

    //Build ethernet packet
    libnet_build_ethernet(
            reinterpret_cast<const uint8_t *>(targetHardware),
            reinterpret_cast<const uint8_t *>(sourceHardware),
            ETHERTYPE_ARP,
            nullptr,
            0,
            netContext,
            0);

    if (op == ARPOP_REQUEST) {
        fprintf(stderr, "%s ===> %s\n\twho has %s, tell %s\n",
                ether_ntoa(sourceHardware),
                ether_ntoa(targetHardware),
                libnet_addr2name4(targetInet, LIBNET_DONT_RESOLVE),
                libnet_addr2name4(sourceInet, LIBNET_DONT_RESOLVE));
    } else {
        fprintf(stderr, "%s ===> %s\n\t%s is-at %s\n",
                ether_ntoa(sourceHardware),
                ether_ntoa(targetHardware),
                libnet_addr2name4(sourceInet, LIBNET_DONT_RESOLVE),
                ether_ntoa(sourceHardware));
    }

    //Send packet
    auto retval = libnet_write(netContext);

    //Debug
    if (retval == -1) fprintf(stderr, "libnet_write(): %s\n", libnet_geterror(netContext));

    //Flush buffer
    libnet_clear_packet(netContext);

    return retval;
}
