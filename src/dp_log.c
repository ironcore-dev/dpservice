#include "dp_log.h"

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <rte_log.h>

#include "dp_error.h"
#include "dp_conf.h"

#define TIMESTAMP_FMT "%Y-%m-%d %H:%M:%S"
#define TIMESTAMP_NUL "0000-00-00 00:00:00.000"
#define TIMESTAMP_MAXSIZE sizeof(TIMESTAMP_NUL)

static bool log_colors = false;
// more readable thread ids, pthread_self() is not usable
static uint16_t thread_id_generator = 0;
static __thread uint16_t thread_id = 0;
static __thread char thread_name[16] = "thread";

void dp_log_set_thread_name(const char *name)
{
	snprintf(thread_name, sizeof(thread_name), "%s", name);
}


int dp_log_init()
{
	enum dp_conf_color color_mode = dp_conf_get_color();
	int ret;

	ret = rte_openlog_stream(stdout);
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot open logging stream\n");
		return ret;
	}

	log_colors = color_mode == DP_CONF_COLOR_ALWAYS
			 || (color_mode == DP_CONF_COLOR_AUTO && isatty(1));

	return DP_OK;
}


static __rte_always_inline void set_color(FILE *f, int level)
{
#define COLOR_ERR     "\x1B[0;31m"
#define COLOR_WARNING "\x1B[0;33m"
#define COLOR_DEBUG   "\x1B[0;36m"
	switch (level) {
	case RTE_LOG_ERR:
		fwrite(COLOR_ERR, 1, sizeof(COLOR_ERR)-1, f);
		break;
	case RTE_LOG_WARNING:
		fwrite(COLOR_WARNING, 1, sizeof(COLOR_WARNING)-1, f);
		break;
	case RTE_LOG_DEBUG:
		fwrite(COLOR_DEBUG, 1, sizeof(COLOR_DEBUG)-1, f);
		break;
	default:
		break;
	}
}

static __rte_always_inline void clear_color(FILE *f)
{
#define COLOR_END "\x1B[0m"
	fwrite(COLOR_END, 1, sizeof(COLOR_END)-1, f);
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

	if (log_colors)
		set_color(f, level);

	fprintf(f, "%s %u(%s) ", timestamp, thread_id, thread_name);

	va_start(args, format);
	vfprintf(f, format, args);
	va_end(args);

#ifdef DEBUG
	fprintf(f, " [%s:%u:%s()]", file, line, function);
#endif

	if (log_colors)
		clear_color(f);

	fputc('\n', f);

	fflush(f);

	funlockfile(f);
}
