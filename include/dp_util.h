#ifndef __INCLUDE_DP_UTIL_H__
#define __INCLUDE_DP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

int dp_parse_args(int argc, char **argv);
char *dp_get_pf0_name();
char *dp_get_pf1_name();
int dp_is_stats_enabled();
int dp_is_offload_enabled();

#ifdef __cplusplus
}
#endif
#endif