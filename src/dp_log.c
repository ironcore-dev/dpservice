#include "dp_log.h"

#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <rte_log.h>

#include "dp_error.h"
#include "dp_conf.h"

#define TIMESTAMP_FMT "%Y-%m-%d %H:%M:%S"
#define TIMESTAMP_NUL "0000-00-00 00:00:00.000"
#define TIMESTAMP_MAXSIZE sizeof(TIMESTAMP_NUL)

// prevent unnecessary `if (log_json)`
#define FORMAT_HEADER log_formatter[0]
#define FORMAT_CALLER log_formatter[1]
#define FORMAT_ENDLINE log_formatter[2]
#define FORMAT_STR log_formatter[3]
#define FORMAT_INT log_formatter[4]
#define FORMAT_UINT log_formatter[5]
#define FORMAT_IPV4 log_formatter[6]
// TODO phase this out
#define FORMAT_OLDHEADER log_formatter[7]
static const char *const log_formatter_text[] = {
	/* header  */ "%s %u(%s) %.1s %s: %s",
	/* caller  */ " [%s:%u:%s()]",
	/* endline */ "\n",
	/* str     */ ", %s: %s",
	/* int     */ ", %s: %d",
	/* uint    */ ", %s: %u",
	/* ipv4    */ ", %s: %u.%u.%u.%u",
	// TODO phase this out
	/* oldhead */ "%s %u(%s) %.1s %s: ",
};
static const char *const log_formatter_json[] = {
	/* header  */ "{ \"ts\": \"%s\", \"thread_id\": %u, \"thread_name\": \"%s\", \"level\": \"%s\", \"logger\": \"%s\", \"msg\": \"%s\"",
	/* caller  */ ", \"caller\": \"%s:%u:%s()\"",
	/* endline */ " }\n",
	/* str     */ ", \"%s\": \"%s\"",
	/* int     */ ", \"%s\": %d",
	/* uint    */ ", \"%s\": %u",
	/* ipv4    */ ", \"%s\": \"%u.%u.%u.%u\"",
	// TODO phase this out
	/* oldhead */ "{ \"ts\": \"%s\", \"thread_id\": %u, \"thread_name\": \"%s\", \"level\": \"%s\", \"logger\": \"%s\"",
};
static const char *const log_types_text[] = {
	"SERVICE", "GRAPH", "GRPC"
};
static const char *const log_types_json[] = {
	"service", "graph", "grpc"
};

static const char *const log_levels[] = {
	"Success", "Unusable", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"
};
static_assert(RTE_DIM(log_levels) == RTE_LOG_MAX+1);

static bool log_colors = false;
static bool log_json = false;
static const char *const *log_formatter = log_formatter_text;
static const char *const *log_types = log_types_text;

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
		DP_EARLY_ERR("Cannot open logging stream %s", dp_strerror(ret));
		return ret;
	}

	log_json = dp_conf_get_log_format() == DP_CONF_LOG_FORMAT_JSON;
	if (log_json) {
		log_formatter = log_formatter_json;
		log_types = log_types_json;
	} else {
		log_colors = color_mode == DP_CONF_COLOR_ALWAYS
				 || (color_mode == DP_CONF_COLOR_AUTO && isatty(1));
	}

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

// TODO(plague): remove this once completely phased-out
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

	fprintf(f, FORMAT_OLDHEADER, timestamp, thread_id, thread_name, log_levels[level], log_types[logtype-RTE_LOGTYPE_USER1]);

	// TODO this of course needs JSON-encoding, but as this function will be phased out, I'm not implementing it
	if (dp_conf_get_log_format() == DP_CONF_LOG_FORMAT_JSON)
		fputs(", \"msg\": \"", f);

	// In JSON this is just one big lump of course
	va_start(args, format);
	vfprintf(f, format, args);
	va_end(args);

	// TODO dtto as above
	if (dp_conf_get_log_format() == DP_CONF_LOG_FORMAT_JSON)
		fputc('"', f);

#ifdef DEBUG
	fprintf(f, FORMAT_CALLER, file, line, function);
#endif

	if (log_colors)
		clear_color(f);

	fputs(FORMAT_ENDLINE, f);

	fflush(f);

	funlockfile(f);
}

static const char *json_escape(const char *message, char *buf, size_t bufsize)
{
	int bufpos = 0;
	char c;
	uint8_t hi, lo;

	for (const char *input = message; *input; ++input) {
		c = *input;
		if (c < 0x20) {
			if (bufpos + 6 >= bufsize)
				break;
			hi = c >> 4;
			lo = c & 0xF;
			buf[bufpos++] = '\\';
			buf[bufpos++] = 'u';
			buf[bufpos++] = '0';
			buf[bufpos++] = '0';
			buf[bufpos++] = '0' + hi;
			buf[bufpos++] = lo >= 10 ? 'a' + (lo-10) : '0' + lo;
		} else if (c == '\\' || c == '\"') {
			if (bufpos + 2 >= bufsize)
				break;
			buf[bufpos++] = '\\';
			buf[bufpos++] = c;
		} else {
			if (bufpos + 1 >= bufsize)
				break;
			buf[bufpos++] = c;
		}
	}

	buf[bufpos] = '\0';
	return buf;
}
static __rte_always_inline const char *escape_message(const char *message, char *buf, size_t bufsize)
{
	if (log_json)
		return json_escape(message, buf, bufsize);

	return message;
}

void _dp_log_structured(unsigned int level, unsigned int logtype,
#ifdef DEBUG
						const char *file, unsigned int line, const char *function,
#endif
						const char *message, ...)
{
	char timestamp[TIMESTAMP_MAXSIZE];
	va_list args;
	FILE *f;
	const char *key;
	int format;
	char escaped[3072];  // worst-case: 512 encoded characters (\u1234)
	const char *str_value;
	rte_be32_t ipv4_value;

	if (!rte_log_can_log(logtype, level))
		return;

	if (DP_FAILED(get_timestamp(timestamp)))
		memcpy(timestamp, TIMESTAMP_NUL, TIMESTAMP_MAXSIZE);  // including \0

	// generate a new thread ID if this is the first log in a thread
	if (!thread_id)
		thread_id = __sync_add_and_fetch(&thread_id_generator, 1);

	f = rte_log_get_stream();  // cannot fail (will return stderr instead)

	flockfile(f);

	if (log_colors)
		set_color(f, level);

	// everything except the message value is JSON-safe
	assert(level > 0 && level < RTE_DIM(log_levels));
	assert(logtype >= RTE_LOGTYPE_USER1 && logtype <= RTE_LOGTYPE_USER1 + RTE_DIM(log_types_text));
	fprintf(f, FORMAT_HEADER, timestamp, thread_id, thread_name,
			log_levels[level], log_types[logtype-RTE_LOGTYPE_USER1],
			escape_message(message, escaped, sizeof(escaped)));

	va_start(args, message);

	// this is pretty dangrous as there are no typechecks possible (that's varargs)
	// but all logging should be done via wrapper macros, that should not allow the caller to mess up
	while ((key = va_arg(args, const char *))) {
		// custom format identifier with canary values should prevent some stack errors
		format = va_arg(args, int);
		switch (format) {
		case _DP_LOG_FMT_STR:
			str_value = escape_message(va_arg(args, const char *), escaped, sizeof(escaped));
			fprintf(f, FORMAT_STR, key, str_value);
			break;
		case _DP_LOG_FMT_INT:
			fprintf(f, FORMAT_INT, key, va_arg(args, int));
			break;
		case _DP_LOG_FMT_UINT:
			fprintf(f, FORMAT_UINT, key, va_arg(args, unsigned int));
			break;
		case _DP_LOG_FMT_IPV4:
			ipv4_value = va_arg(args, rte_be32_t);
			fprintf(f, FORMAT_IPV4, key, (ipv4_value) & 0xFF,
										((ipv4_value) >> 8) & 0xFF,
										((ipv4_value) >> 16) & 0xFF,
										((ipv4_value) >> 24) & 0xFF);
			break;
		case _DP_LOG_FMT_IPV6:
			// re-use the escaping buffer for IP conversion
			str_value = inet_ntop(AF_INET6, va_arg(args, const uint8_t *), escaped, INET6_ADDRSTRLEN);
			fprintf(f, FORMAT_STR, key, str_value);
			break;
		default:
			assert(false);
			goto parse_error;
		}
	}
parse_error:
	va_end(args);

#ifdef DEBUG
	// everything here should be JSON-safe
	fprintf(f, FORMAT_CALLER, file, line, function);
#endif

	if (log_colors)
		clear_color(f);

	fputs(FORMAT_ENDLINE, f);

	fflush(f);

	funlockfile(f);
}

void _dp_log_early(FILE *f, const char *format, ...)
{
	va_list args;

	flockfile(f);

	va_start(args, format);
	vfprintf(f, format, args);
	va_end(args);

	fputc('\n', f);

	fflush(f);

	funlockfile(f);
}
