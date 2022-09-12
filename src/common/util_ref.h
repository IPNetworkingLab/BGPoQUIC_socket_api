//
// Created by thomas on 12/09/22.
//

#ifndef QUIC_SOCK_UTIL_REF_H
#define QUIC_SOCK_UTIL_REF_H


#include "uthash.h"

typedef void (clean_fn)(void *);

struct sh_ref {
    int ref_nb;
    void *ref;

    clean_fn *clean;
};

struct sh_ref *sh_ref_new(void *ref);

void sh_ref_set_clean_fn(struct sh_ref *sh_ref, clean_fn *fn);

void sh_ref_lock(struct sh_ref *sh_ref);

void sh_ref_unlock(struct sh_ref *sh_ref);

#endif //QUIC_SOCK_UTIL_REF_H
