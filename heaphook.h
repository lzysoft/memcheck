void heaphook_dump_leak(void);

typedef void *(*malloc_t)(size_t size);
extern malloc_t sys_malloc;
typedef void (*free_t)(void* p);
extern free_t sys_free;
typedef void *(*realloc_t)(void *p, size_t size);
extern realloc_t sys_realloc;

void heaphook_enable(void);
void heaphook_disable(void);
void heaphook_handle_exception(int signum);
