#ifndef __INCLUDE_DP_MULTI_PATH_H
#define __INCLUDE_DP_MULTI_PATH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void dp_multipath_init(void);

uint16_t dp_multipath_get_pf_id(uint32_t hash);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DP_MULTI_PATH_H */
