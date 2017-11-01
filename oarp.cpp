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

oarp::oarp(const char * interface) {
    dispatching = true;

    auto pcap_ebuf = std::make_shared<char>(PCAP_ERRBUF_SIZE);
    auto libnet_ebuf = std::make_shared<char>(LIBNET_ERRBUF_SIZE);

    //Lookup default interface
    if ((intf = interface) == nullptr && !(intf = pcap_lookupdev(pcap_ebuf.get()))){
        fprintf(stderr, "pcap_lookupdev: %s", pcap_ebuf.get());
    }

    if (!(netContext = libnet_init(LIBNET_LINK, interface, libnet_ebuf.get()))){
        fprintf(stderr, "libnet_init: %s", libnet_ebuf.get());
    }
}

void oarp::destory() {
#ifdef OARP_USE_THREAD
    dispatching = false;
    threadHandle->join();
    threadHandle = nullptr;
#endif
    libnet_destroy(netContext);
    netContext = nullptr;
}

shared_ptr<oarp_target> oarp::addTarget(shared_ptr<in_addr_t> targetIp) {
    auto instance = shared_ptr<oarp_target>(
            new oarp_target(shared_from_this(), std::move(targetIp)));
#ifdef OARP_USE_THREAD
    globalMutex.lock();
#endif
    pool.push_back(instance);
#ifdef OARP_USE_THREAD
    globalMutex.unlock();
#endif
    return instance;
}

shared_ptr<oarp_target> oarp::addTarget(in_addr_t targetIp) {
    return addTarget(make_shared<in_addr_t>(targetIp));
}

shared_ptr<oarp_target> oarp::addTarget(const char * targetHost) {
    auto ip = resolveHost(targetHost);
    return ip ? addTarget(ip) : nullptr;
}

void oarp::doLoop() {
    uint64_t ticker = 0;
    while (dispatching){
        internalLoop(ticker);
        usleep(400000);
        ticker++;
    }
}

void oarp::internalLoop(uint64_t tk) {
#ifdef OARP_USE_THREAD
    globalMutex.lock();
#endif
    for(const auto &t : pool){
        t->update(tk);
    }
#ifdef OARP_USE_THREAD
    globalMutex.unlock();
#endif
}

shared_ptr<in_addr_t> oarp::resolveHost(const char * targetHost) {
    char hostBuffer[64];
    memset(hostBuffer, 0, 64);
    strcpy(hostBuffer, targetHost);
    in_addr_t targetIp = libnet_name2addr4(netContext, hostBuffer, LIBNET_RESOLVE);
    return targetIp == -1 ? nullptr : make_shared<in_addr_t>(targetIp);
}

void oarp::start() {
#ifdef OARP_USE_THREAD
    threadHandle = std::make_unique<std::thread>(&oarp::doLoop, this);
    dispatching = true;
#endif
}
