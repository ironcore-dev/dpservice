#include "dp_log.h"

#include <string.h>
#include <time.h>
#include <rte_log.h>

#include "dp_error.h"

#define TIMESTAMP_FMT "%Y-%m-%d %H:%M:%S"
#define TIMESTAMP_NUL "0000-00-00 00:00:00.000"
#define TIMESTAMP_MAXSIZE sizeof(TIMESTAMP_NUL)

// more readable thread ids, pthread_self() is not usable
static uint16_t thread_id_generator = 0;
static __thread uint16_t thread_id = 0;
static __thread char thread_name[16] = "thread";


void dp_log_set_thread_name(const char *name)
{
	snprintf(thread_name, sizeof(thread_name), "%s", name);
}


static inline int get_timestamp(char *buf)
{
	struct timespec now;
	struct tm tmnow;
	size_t offset;

	// coarse time is enough unless we want < 1ms precision
	if (clock_gettime(CLOCK_REALTIME_COARSE, &now) < 0 || !gmtime_r(&now.tv_sec, &tmnow))
		return DP_ERROR;

	offset = strftime(buf, TIMESTAMP_MAXSIZE, TIMESTAMP_FMT, &tmnow);
	if (!offset)
		return DP_ERROR;

	offset += snprintf(buf+offset, TIMESTAMP_MAXSIZE-offset, ".%.03lu", now.tv_nsec / 1000000);
	if (offset >= TIMESTAMP_MAXSIZE)
		return DP_ERROR;

	return DP_OK;
}

void _dp_log(unsigned int level, unsigned int logtype,
#ifdef DEBUG
			  const char *file, unsigned int line, const char *function,
#endif
			  const char *format, ...)
{
	char timestamp[TIMESTAMP_MAXSIZE];
	va_list args;
	FILE *f;

	if (!rte_log_can_log(logtype, level))
		return;

	if (DP_FAILED(get_timestamp(timestamp)))
		memcpy(timestamp, TIMESTAMP_NUL, TIMESTAMP_MAXSIZE);  // including \0

	// generate a new thread ID if this is the first log in a thread
	if (!thread_id)
		thread_id = __sync_add_and_fetch(&thread_id_generator, 1);

	f = rte_log_get_stream();

	flockfile(f);

	fprintf(f, "%s %u(%s) ", timestamp, thread_id, thread_name);

	va_start(args, format);
	vfprintf(f, format, args);
	va_end(args);

#ifdef DEBUG
	fprintf(f, " [%s:%u:%s()]", file, line, function);
#endif

	fputc('\n', f);

	fflush(f);

	funlockfile(f);
}
