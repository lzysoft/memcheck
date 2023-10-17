#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include "heaphook.h"
#include "addr2line.h"
#include "logger.h"

#ifdef MEM_LEAK_DETECT
#define USE_BACKTRACE
#define USE_HOOK
#endif

//#define BOARDER_CHECK

#define MAGIC 0x12e1678

typedef struct{
    uint32_t magic;
    uint32_t size;
} EXT_INFO;

static int enable_malloc_hook;
static int enable_realloc_hook;
static int enable_free_hook;

#define NO_FREE_TIMEOUT 600
#define INIT_ENABLE 0

#define MAX_BT_NUM 8

typedef struct{
    void *ptr;
    size_t size;
    time_t malloc_time;
    int print_cnt;
    int bt_cnt;
    void *bt_stack[MAX_BT_NUM];
} HEAPHOOK_ITEM;

#define BUCKET_NUM         0x1000
#define BUCKET_ITEM_NUM    0x10

static HEAPHOOK_ITEM heaphook_item[BUCKET_NUM][BUCKET_ITEM_NUM];

static pthread_mutex_t heaphook_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;

static time_t oldest_time;

malloc_t sys_malloc = NULL;
free_t sys_free = NULL;
realloc_t sys_realloc = NULL;

static unsigned int hash(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

static int get_bucket(void *ptr)
{
    return hash((unsigned int)ptr) % BUCKET_NUM;
}

static void add_item(void *ptr, size_t size)
{
    int empty_slot = -1;
    int old_slot = -1;
    time_t old_time = 0;
    time_t now_time = time(NULL);
    int bt_cnt;
    void *bt_stack[MAX_BT_NUM];
    int bucket = get_bucket(ptr);
    HEAPHOOK_ITEM *bucket_item = heaphook_item[bucket];

#ifdef USE_BACKTRACE
    bt_cnt = backtrace(bt_stack, MAX_BT_NUM);
    //if(bt_cnt < 2)
    //{
    //    return;
    //}
#else
    bt_cnt = 2;
#endif

    for(int i = 0; i < BUCKET_ITEM_NUM; i++)
    {
        if(bucket_item[i].ptr == NULL)
        {
            empty_slot = i;
            break;
        }
        time_t malloc_time = bucket_item[i].malloc_time;
        if(old_time == 0)
        {
            old_time = malloc_time;
            old_slot = i;
        }
        else if(old_time > malloc_time)
        {
            old_time = malloc_time;
            old_slot = i;
        }
    }

    int slot  = empty_slot;

    if(slot < 0)
    {
        slot = old_slot;
        //printf("replace %d:%d time %d\n", bucket, old_slot, now_time - old_time);
    }
    
    oldest_time = old_time;

    HEAPHOOK_ITEM *item = &bucket_item[slot];
    item->ptr = ptr;
    item->size = size;
    item->malloc_time = now_time;
    item->print_cnt = 0;
    item->bt_cnt = bt_cnt;
    memcpy(item->bt_stack, bt_stack, sizeof(void *) * item->bt_cnt);
}

static HEAPHOOK_ITEM *get_item(void *ptr)
{
    int bucket = get_bucket(ptr);
    HEAPHOOK_ITEM *bucket_item = heaphook_item[bucket];

    for(int i = 0; i < BUCKET_ITEM_NUM; i++)
    {
        if(bucket_item[i].ptr == ptr)
        {
            return &bucket_item[i];
        }
    }

    return NULL;
}

static void del_item(void *ptr)
{
    int bucket = get_bucket(ptr);
    HEAPHOOK_ITEM *bucket_item = heaphook_item[bucket];

    for(int i = 0; i < BUCKET_ITEM_NUM; i++)
    {
        if(bucket_item[i].ptr == ptr)
        {
            HEAPHOOK_ITEM *item = &bucket_item[i];
            item->ptr = NULL;
            break;
        }
    }
}

void heaphook_init(void)
{
    enable_malloc_hook = INIT_ENABLE;
    enable_realloc_hook = INIT_ENABLE;
    sys_malloc = dlsym(RTLD_NEXT, "malloc");
    sys_free = dlsym(RTLD_NEXT, "free");
    sys_realloc = dlsym(RTLD_NEXT, "realloc");
    addr2line_init();
}

void heaphook_enable(void)
{
    pthread_mutex_lock(&heaphook_mutex);
    enable_malloc_hook = 1;
    enable_realloc_hook = 1;
    enable_free_hook = 1;
    pthread_mutex_unlock(&heaphook_mutex);
}

void heaphook_disable(void)
{
    pthread_mutex_lock(&heaphook_mutex);
    enable_malloc_hook = 0;
    enable_realloc_hook = 0;
    enable_free_hook = 0;
    pthread_mutex_unlock(&heaphook_mutex);
}

void print_bt(void *ptr)
{
    static int in = 0;

    if(in)
        return;
    
    in = 1;
    HEAPHOOK_ITEM *item = get_item(ptr);
    if(item)
    {
        fprintf(stdout, "memory error backtrace from malloc:\n");
        addr2line_print(stdout, item->bt_stack, item->bt_cnt);
        fprintf(stdout, "\n");
    }

    void *bt_stack[32];
    fprintf(stdout, "memory error backtrace from free:\n");
    int bt_cnt = backtrace(bt_stack, 32);
    addr2line_print(stdout, bt_stack, bt_cnt);
    fprintf(stdout, "\n");
    fprintf(stdout, "%s\n", (char *)ptr + 8);
    in = 0;
}

#ifdef USE_HOOK
void *malloc(size_t size)
{
    if(sys_malloc == NULL)
    {
        heaphook_init();
    }

#ifdef BOARDER_CHECK
    void *ptr = sys_malloc(size + sizeof(EXT_INFO) * 2);
    if(!ptr)
        return NULL;
    EXT_INFO *head = ptr;
    void *user_ptr = ptr + sizeof(EXT_INFO);
    EXT_INFO *tail = user_ptr + size;
    
    head->magic = MAGIC;
    head->size = size;
    tail->magic = MAGIC;
    tail->size = size;
#else
    void *ptr = sys_malloc(size);
    void *user_ptr = ptr;
#endif

    if(enable_malloc_hook && ptr)
    {
        pthread_mutex_lock(&heaphook_mutex);
        enable_malloc_hook = 0;
        add_item(ptr, size);
        enable_malloc_hook = 1;
        pthread_mutex_unlock(&heaphook_mutex);
    }
    return user_ptr;
}

void free(void * p)
{
    if(!p)
        return;

#ifdef BOARDER_CHECK
    void *ext_ptr = p - sizeof(EXT_INFO);
    EXT_INFO *head = ext_ptr;
    if(head->magic != MAGIC)
    {
        sys_free(p);
        return;
    }

    EXT_INFO *tail = p + head->size;
    if(tail->magic != MAGIC)
    {
        print_bt(head);
        sys_free(head);
        return;
    }
#else
    void *ext_ptr = p;
#endif

    sys_free(ext_ptr);
    if(enable_free_hook && ext_ptr)
    {
        pthread_mutex_lock(&heaphook_mutex);
        enable_free_hook = 0;
        del_item(ext_ptr);
        enable_free_hook = 1;
        pthread_mutex_unlock(&heaphook_mutex);
    }
}

void *realloc(void *p, size_t size)
{
    if(sys_realloc == NULL)
    {
        heaphook_init();
    }

#ifdef BOARDER_CHECK
    void *ext_old_ptr = NULL;
    void *ext_new_ptr = NULL;

    if(p)
    {
        EXT_INFO *head = p - sizeof(EXT_INFO);
        if(head->magic != MAGIC)
        {
            return sys_realloc(p, size);
        }
        else
        {
            ext_old_ptr = head;
            EXT_INFO *tail = p + head->size;
            if(tail->magic != MAGIC)
            {
                print_bt(head);
                return sys_realloc(p, size);
            }
            ext_new_ptr = sys_realloc(head, size + sizeof(EXT_INFO) * 2);
        }
    }
    else
        ext_new_ptr = sys_realloc(NULL, size + sizeof(EXT_INFO) * 2);
    
    if(!ext_new_ptr)
        return NULL;

    EXT_INFO *head = ext_new_ptr;
    void *user_ptr = ext_new_ptr + sizeof(EXT_INFO);
    EXT_INFO *tail = user_ptr + size;
    
    head->magic = MAGIC;
    head->size = size;
    tail->magic = MAGIC;
    tail->size = size;
#else
    void *ext_old_ptr = p;
    void *ext_new_ptr = sys_realloc(p, size);
#endif

    if(enable_realloc_hook && ext_new_ptr)
    {
        pthread_mutex_lock(&heaphook_mutex);
        enable_realloc_hook = 0;
        if(ext_old_ptr)
            del_item(ext_old_ptr);
        add_item(ext_new_ptr, size);
        enable_realloc_hook = 1;
        pthread_mutex_unlock(&heaphook_mutex);
    }

    return user_ptr;
}
#endif

void heaphook_dump_leak(void)
{
    //printf("heaphook_dump_leak\n");
    time_t now_time = time(NULL);
    for(int i = 0; i < BUCKET_NUM; i++)
    {
        for(int j = 0; j < BUCKET_ITEM_NUM; j++)
        {
            HEAPHOOK_ITEM *item = &heaphook_item[i][j];
            time_t diff = now_time - item->malloc_time;
            //printf("%d %d\n", now_time, item->malloc_time);
            if(item->ptr && diff > NO_FREE_TIMEOUT && item->print_cnt == 0)
            {
                #if 1
                if(g_logger)
                {
                    FILE *fp = logger_get_fp(g_logger);
                    logger_lock(g_logger);
                    fprintf(fp, "Long time no free:%p size:%d time:%d bt_cnt:%d, oldest_time:%d\n", item->ptr, item->size, diff, item->bt_cnt, now_time - oldest_time);
                    addr2line_print(fp, item->bt_stack, item->bt_cnt);
                    fprintf(fp, "\n");
                    logger_unlock(g_logger);
                }
                #endif
                if(stdout)
                {
                    FILE *fp = stdout;
                    fprintf(fp, "Long time no free:%p size:%d time:%d bt_cnt:%d, oldest_time:%d\n", item->ptr, item->size, diff, item->bt_cnt, now_time - oldest_time);
                    addr2line_print(fp, item->bt_stack, item->bt_cnt);
                    fprintf(fp, "\n");
                }

                item->print_cnt++;
            }
        }
    }
}

void heaphook_handle_exception(int signum)
{
    void *bt_stack[32];

    system("sleep 3 && killall -9 flexipc&");

#if 1
    if(g_logger)
    {
        FILE *fp = logger_get_fp(g_logger);
        logger_lock(g_logger);
        fprintf(fp, "exception backtrace:\n");
        int bt_cnt = backtrace(bt_stack, 32);
        addr2line_print(fp, bt_stack, bt_cnt);
        fprintf(fp, "\n");
        logger_unlock(g_logger);
        fclose(fp);
        sync();
    }
#endif
    if(stdout)
    {
        FILE *fp = stdout;
        fprintf(fp, "exception backtrace:\n");
        int bt_cnt = backtrace(bt_stack, 32);
        addr2line_print(fp, bt_stack, bt_cnt);
        fprintf(fp, "\n");
    }

    //system("sleep 5 && killall -9 flexipc&");
    _exit(1);
}
