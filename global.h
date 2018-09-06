#ifdef GLOBAL_MAIN
#define GLOBAL
#define GLOBAL_VAL(X) = X
#else
#define GLOBAL extern
#define GLOBAL_VAL(X)
#endif

GLOBAL char const *BIND_ADDR GLOBAL_VAL("localhost");
GLOBAL char const *BIND_PORT GLOBAL_VAL("9000");
GLOBAL char const *UPSTREAM_ADDR GLOBAL_VAL("localhost");
GLOBAL char const *UPSTREAM_PORT GLOBAL_VAL("9050");

GLOBAL void (*pelog_th)(int priority, char const *format, ...);
GLOBAL void (*vpelog)(int priority, char const *format, va_list ap);
GLOBAL void (*pelog)(int priority, char const *format, ...);

GLOBAL pthread_key_t sock_cleaner;
