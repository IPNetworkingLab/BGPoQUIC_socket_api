//
// Created by thomas on 25/10/22.
//
/* needed for stick_this_thread_to_core */
#define _GNU_SOURCE

#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include "util_common_sock.h"
#include <errno.h>

#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#include <stdio.h>


unsigned int iface_name_to_idx(const char *dev_name) {
    return if_nametoindex(dev_name);
}

unsigned int ifidx_from_addr(const struct sockaddr *addr, char *dev_name, size_t *dev_name_len) {
    const void *ip_addr_arg;
    const void *ip_addr;
    size_t ip_addr_len;
    struct ifaddrs *iface;
    struct ifaddrs *ifap;
    size_t name_len;
    unsigned int ret;

    ret = 0;

    switch (addr->sa_family) {
        case AF_INET:
            ip_addr_arg = &((const struct sockaddr_in *) addr)->sin_addr;
            break;
        case AF_INET6:
            ip_addr_arg = &((const struct sockaddr_in6 *) addr)->sin6_addr;
            break;
        default:
            errno = EAFNOSUPPORT;
            return 0;
    }


    if (getifaddrs(&ifap) == -1) {
        return 0;
    }

    for (iface = ifap; iface != NULL; iface = iface->ifa_next) {
        if (iface->ifa_addr == NULL || iface->ifa_addr->sa_family != addr->sa_family)
            continue;

        if (addr->sa_family == AF_INET) {
            ip_addr = &((struct sockaddr_in *) iface->ifa_addr)->sin_addr;
            ip_addr_len = sizeof(((struct sockaddr_in *) iface->ifa_addr)->sin_addr);
        } else {
            ip_addr = &((struct sockaddr_in6 *) iface->ifa_addr)->sin6_addr;
            ip_addr_len = sizeof(((struct sockaddr_in6 *) iface->ifa_addr)->sin6_addr);
        }

        if (memcmp(ip_addr_arg, ip_addr, ip_addr_len) != 0) {
            continue;
        }

        if (dev_name) {
            name_len = strnlen(iface->ifa_name, IF_NAMESIZE);

            if (name_len > *dev_name_len) {
                ret = 0;
                goto end;
            }

            *dev_name_len = name_len;
            strncpy(dev_name, iface->ifa_name, name_len);
            dev_name[name_len] = 0;
        }

        ret = if_nametoindex(iface->ifa_name);
        break;
    }

    end:
    if (ifap) freeifaddrs(ifap);
    return ret;
}

int iface_from_ipv6_link_local(struct sockaddr *addr, char *dev_name, size_t *dev_name_len) {
    const struct sockaddr_in6 *addr_in6;
    struct sockaddr_in6 *curr_addr;
    struct ifaddrs *iface;
    struct ifaddrs *ifap;
    size_t name_len;
    int ret;

    iface = NULL;
    ifap = NULL;
    ret = -1;

    if (addr->sa_family != AF_INET6) {
        goto end;
    }

    if (!dev_name_len) goto end;

    addr_in6 = (struct sockaddr_in6 *) addr;

    if (getifaddrs(&ifap) == -1) {
        goto end;
    }


    for (iface = ifap; iface != NULL; iface = iface->ifa_next) {
        if (iface->ifa_addr == NULL || iface->ifa_addr->sa_family != AF_INET6) continue;

        curr_addr = (struct sockaddr_in6 *) iface->ifa_addr;

        if (!IN6_IS_ADDR_LINKLOCAL(&curr_addr->sin6_addr)) {
            continue;
        }
        if (memcmp(&addr_in6->sin6_addr, &curr_addr->sin6_addr, sizeof(addr_in6->sin6_addr)) != 0) {
            continue;
        }

        name_len = strnlen(iface->ifa_name, IF_NAMESIZE);

        if (name_len > *dev_name_len) {
            goto end;
        }

        *dev_name_len = name_len;
        strncpy(dev_name, iface->ifa_name, name_len);
        dev_name[name_len] = 0;
        ret = 0;
        break;

    }

    end:
    if (ifap) freeifaddrs(ifap);
    return ret;
}


int stick_this_thread_to_core(long core_id) {
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (core_id < 0 || core_id >= num_cores)
        return EINVAL;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t current_thread = pthread_self();
    return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

unsigned long get_affinity(int pid, unsigned long *core_array, size_t core_array_len) {
    unsigned int i, j;
    cpu_set_t cpuset;
    unsigned long num_cores = sysconf(_SC_NPROCESSORS_ONLN);

    if (core_array_len < num_cores)
        return -1;

    CPU_ZERO(&cpuset);

    if (sched_getaffinity(pid, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_getaffinity");
        return -1;
    }

    for (i = 0, j = 0; i < num_cores; i++) {
        if (CPU_ISSET(i, &cpuset)) {
            core_array[j++] = i;
        }
    }

    return j;
}