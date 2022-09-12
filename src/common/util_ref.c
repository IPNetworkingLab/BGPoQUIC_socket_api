//
// Created by thomas on 12/09/22.
//

#include "util_ref.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

struct sh_ref *sh_ref_new(void *ref) {
    struct sh_ref *new_ref;

    new_ref = calloc(1, sizeof(*new_ref));

    if (!new_ref) {
        perror("malloc");
        return NULL;
    }

    new_ref->ref = ref;
    new_ref->ref_nb = 0;

    return new_ref;
}

void sh_ref_set_clean_fn(struct sh_ref *sh_ref, clean_fn *fn) {
    sh_ref->clean = fn;
}

void sh_ref_lock(struct sh_ref *sh_ref) {
    if (!sh_ref) return;
    sh_ref->ref_nb += 1;
}

void sh_ref_unlock(struct sh_ref *sh_ref) {
    if (!sh_ref) return;

    assert(sh_ref->ref_nb > 0);

    sh_ref->ref_nb -= 1;

    if (sh_ref->ref_nb == 0) {
        if (sh_ref->clean) sh_ref->clean(sh_ref->ref);
        free(sh_ref);
    }
}