/**
 *  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
 *  Version 2, December 2004
 *
 *  Copyright (C) 2017 Marcus Zhou <other.marcus@icloud.com>
 *
 *  You must agree to the license before using.
 *  See LICENSE file in this folder for more information
 */

#include "oarp.h"

bool oarp_target::ready() {
    return (targetMac != nullptr);
}

oarp_target::oarp_target(shared_ptr<oarp> parent, shared_ptr<in_addr_t> targetIp) {
    this->parent = move(parent);
    this->targetIp = move(targetIp);
    working = false;
    tasks = 0;
}

void oarp_target::update(uint64_t tick) {
    if (ready()){
        if(working){
            if(tasks & OARP_TASK_SPOOF) sendSpoof();
            if(tasks & OARP_TASK_RESTORE) sendRestore();
        }
    }else{
        //Mac address found
        auto macShared = make_shared<ether_addr>();
        if (parent->cache_lookup(targetIp, macShared) == 0){
            targetMac = std::move(macShared);
            return;
        }

#ifdef __linux__
        this->force(targetIp);
#else
        //Send ARP Request from IP Packet
        parent->arp_send(ARPOP_REQUEST, nullptr, nullptr, nullptr, targetIp);
#endif
    }
}

void oarp_target::sendSpoof() {
    if (ready() && spoofIp != nullptr){
        //Default spoof to host
        parent->arp_send(ARPOP_REPLY, spoofMac, spoofIp, targetMac, targetIp);
    }
}

shared_ptr<oarp_target> oarp_target::spoofAs(shared_ptr<in_addr_t> disguise) {
#ifdef OARP_USE_THREAD
    parent->globalMutex.lock();
#endif
    spoofIp = std::move(disguise);
#ifdef OARP_USE_THREAD
    parent->globalMutex.unlock();
#endif
    tasks = OARP_TASK_SPOOF;
    addTasks(OARP_TASK_SPOOF);
    removeTasks(OARP_TASK_RESTORE);
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::spoofAs(in_addr_t disguise) {
    return spoofAs(std::make_shared<in_addr_t>(disguise));
}

shared_ptr<oarp_target> oarp_target::spoofAs(const char *disguise) {
    auto ip = parent->resolveHost(disguise);
    if(ip) spoofAs(ip);
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::resume() {
    working = true;
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::halt() {
    working = false;
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::restore() {
    addTasks(OARP_TASK_RESTORE);
    removeTasks(OARP_TASK_SPOOF);
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::disguiseAs(shared_ptr<ether_addr> disguise) {
#ifdef OARP_USE_THREAD
    parent->globalMutex.lock();
#endif
    spoofMac = std::move(disguise);
#ifdef OARP_USE_THREAD
    parent->globalMutex.unlock();
#endif
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::disguiseAsHost() {
    return disguiseAs(nullptr);
}

shared_ptr<oarp_target> oarp_target::addTasks(uint32_t tasks) {
    this->tasks |= tasks;
    return shared_from_this();
}

shared_ptr<oarp_target> oarp_target::removeTasks(uint32_t tasks) {
    this->tasks &= ~tasks;
    return shared_from_this();
}

void oarp_target::sendRestore() {
    if(ready()){
        if (originalMac == nullptr){
            auto bufMac = make_shared<ether_addr>();
            parent->cache_lookup(spoofIp, bufMac);
            if (bufMac) originalMac = std::move(bufMac);
            else parent->arp_send(ARPOP_REQUEST, nullptr, nullptr, nullptr, spoofIp);
        }else parent->arp_send(ARPOP_REPLY, originalMac, spoofIp, targetMac, targetIp);
    }
}
