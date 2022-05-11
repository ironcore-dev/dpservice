#ifndef __INCLUDE_DP_UTIL_H__
#define __INCLUDE_DP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define VM_MACHINE_ID_STR_LEN 64
#define VM_MACHINE_PXE_STR_LEN 32

#define DP_OP_ENV_HARDWARE 1
#define DP_OP_ENV_SCAPYTEST 2


int dp_parse_args(int argc, char **argv);
char *dp_get_pf0_name();
char *dp_get_pf1_name();
char *dp_get_vf_pattern();
int dp_is_stats_enabled();
int dp_is_offload_enabled();
int dp_is_conntrack_enabled();

uint16_t dp_get_pf1_port_id();
uint16_t dp_get_pf0_port_id();
bool dp_is_pf_port_id(uint16_t id);
void dp_add_pf_port_id(uint16_t id);
int dp_get_num_of_vfs();

int get_overlay_type();
int get_op_env();

int dp_is_wcmp_enabled();

double dp_get_wcmp_frac();


#ifdef __cplusplus
}
#endif
#endif