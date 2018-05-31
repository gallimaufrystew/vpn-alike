
#include "atun_mem.h"

//static mp_pool_t *mem;

void atun_mem_init()
{
    //mem = mp_create_pool(4 * 1024 * 1024);
}

void *atun_alloc(size_t size)
{
    return calloc(1, size);
    //return mp_alloc(mem, size);
}

void atun_alloc_free(void *p)
{
    free(p);
    //mp_free(mem, p);
}

void atun_mem_reset()
{
    //mp_reset_pool(mem);
}

void atun_free_large()
{
    //mp_free_all(mem);
}

void atun_destroy()
{
    //mp_destroy_pool(mem);
}

#if (0)

#include "atun_mem.h"

static ncx_slab_pool_t *sp;
static ncx_slab_stat_t stat;
static u_char *space;

void atun_mem_init()
{
    size_t  pool_size = 4096000;  //2M
    space = (u_char *)malloc(pool_size);

    sp = (ncx_slab_pool_t *) space;

    sp->addr = space;
    sp->min_shift = 3;
    sp->end = space + pool_size;

    ncx_slab_init(sp);
}

void *atun_alloc(size_t size)
{
    return ncx_slab_alloc(sp, size);
}

void atun_alloc_free(void *p)
{
    ncx_slab_free(sp, p);
}

void atun_mem_stat()
{
    ncx_slab_stat(sp, &stat);
}

void atun_free()
{
    free(space);
}

#endif
