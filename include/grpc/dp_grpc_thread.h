#ifndef __INCLUDE_GRPC_THREAD_H__
#define __INCLUDE_GRPC_THREAD_H__

#ifdef __cplusplus
extern "C" {
#endif

int dp_grpc_thread_start();
int dp_grpc_thread_join();
int dp_grpc_thread_cancel();

#ifdef __cplusplus
}
#endif
#endif
