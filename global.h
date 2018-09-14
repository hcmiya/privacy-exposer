#ifdef GLOBAL_MAIN
#define GLOBAL
#define GLOBAL_VAL(X) = X
#else
#define GLOBAL extern
#define GLOBAL_VAL(X)
#endif

GLOBAL void (*pelog_th)(int priority, char const *format, ...);
GLOBAL void (*vpelog)(int priority, char const *format, va_list ap);
GLOBAL void (*pelog)(int priority, char const *format, ...);

GLOBAL char const *rule_file_path;
GLOBAL pthread_key_t sock_cleaner;
