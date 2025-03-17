// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRPC_HEALTH_H__
#define __INCLUDE_DP_GRPC_HEALTH_H__

#include "../proto/health.grpc.pb.h"
#include <mutex>
#include <condition_variable>

class HealthService final : public grpc::health::v1::Health::Service {
private:
	std::mutex status_mutex_;
	std::condition_variable status_condition_;
	grpc::health::v1::HealthCheckResponse::ServingStatus status_ = grpc::health::v1::HealthCheckResponse::NOT_SERVING;

public:
	void SetServingStatus(grpc::health::v1::HealthCheckResponse::ServingStatus newStatus);
	grpc::Status Check(grpc::ServerContext* context, const grpc::health::v1::HealthCheckRequest* request,
					   grpc::health::v1::HealthCheckResponse* response);
	grpc::Status Watch(grpc::ServerContext* context, const grpc::health::v1::HealthCheckRequest* request,
                       grpc::ServerWriter<grpc::health::v1::HealthCheckResponse>* writer);
};

#endif
