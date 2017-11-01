/**
 *  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *  Version 2, December 2004
 *
 *  Copyright (C) 2017 Marcus Zhou <other.marcus@icloud.com>
 *
 *  You must agree to the license before using.
 *  See LICENSE file in this folder for more information
 */

#ifndef OARP_OARP_H
#define OARP_OARP_H

#include "macros.h"

#ifdef OARP_USE_THREAD
#include <thread>
#endif

#include <cctype>
#include <memory>
#include <utility>
#include <net/ethernet.h>
#include <functional>
#include <vector>
#include <libnet.h>

using namespace std;

class oarp_target;

class oarp : public std::enable_shared_from_this<oarp> {
public:
    int find(in_addr_t ip, shared_ptr<ether_addr> mac);
    shared_ptr<oarp_target> addTarget(shared_ptr<in_addr_t> targetIp);
    shared_ptr<oarp_target> addTarget(in_addr_t targetIp);
    shared_ptr<oarp_target> addTarget(const char * targetHost);

    void doLoop();
    void start();

    explicit oarp(const char * interface = nullptr);
    void destory();

private:
#ifdef OARP_USE_THREAD
    unique_ptr<std::thread> threadHandle = nullptr;
    atomic_bool dispatching;
    mutex globalMutex;
#else
    bool dispatching;
#endif
    libnet_t * netContext;
    const char *intf;
    vector<shared_ptr<oarp_target>> pool;

    int cache_lookup(shared_ptr<in_addr_t > ip, shared_ptr<ether_addr> ether);
    /* Send ARP Packet */
    int arp_send(int op, const shared_ptr<ether_addr> &sha, shared_ptr<in_addr_t> spa, const shared_ptr<ether_addr> &tha,
                 shared_ptr<in_addr_t> tpa);
    void internalLoop(uint64_t);
    shared_ptr<in_addr_t> resolveHost(const char * host);

#ifdef __linux__
    //Force ARP Lookup, for linux only
    int force(in_addr_t dst);
#endif

    friend class oarp_target;
};

class oarp_target : public std::enable_shared_from_this<oarp_target> {
public:
    bool ready();
    shared_ptr<oarp_target> spoofAs(in_addr_t disguise);
    shared_ptr<oarp_target> spoofAs(shared_ptr<in_addr_t> disguise);
    shared_ptr<oarp_target> spoofAs(const char * disguise);

    shared_ptr<oarp_target> disguiseAs(shared_ptr<ether_addr> disguise);
    shared_ptr<oarp_target> disguiseAsHost();

    shared_ptr<oarp_target> resume();
    shared_ptr<oarp_target> halt();
    shared_ptr<oarp_target> restore();

    shared_ptr<oarp_target> addTasks(uint32_t tasks);
    shared_ptr<oarp_target> removeTasks(uint32_t tasks);

private:
    shared_ptr<ether_addr> targetMac = nullptr;
    shared_ptr<ether_addr> spoofMac = nullptr;
    shared_ptr<ether_addr> originalMac = nullptr;
    shared_ptr<in_addr_t> targetIp = nullptr;
    shared_ptr<in_addr_t> spoofIp = nullptr;
    shared_ptr<oarp> parent;

#ifdef OARP_USE_THREAD
    atomic_bool working;
    atomic_uint32_t tasks;
#else
    bool working;
    uint32_t tasks = 0;
#endif

    explicit oarp_target(shared_ptr<oarp> parent, shared_ptr<in_addr_t> targetIp);

    void update(uint64_t tick);
    void sendSpoof();
    void sendRestore();

    friend class oarp;
};

#endif //OARP_OARP_H
