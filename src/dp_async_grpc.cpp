#include "dp_async_grpc.h"
#include "dp_grpc_impl.h"
#include <rte_mbuf.h>

int HelloCall::Proceed()
{
	dp_request request;
	dp_reply reply;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new HelloCall(service_, cq_);
		//Fill from request_ into request
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.hello = 0xdeadbeef;
		printf("GRPC Hello sent %x \n", request.hello);
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC Hello received %x \n", reply.hello);
		// Fill into reply_ from reply
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}