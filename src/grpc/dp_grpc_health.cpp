// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_health.hpp"
#include "../proto/dpdk.grpc.pb.h"

void HealthService::SetServingStatus(grpc::health::v1::HealthCheckResponse::ServingStatus newStatus)
{
	std::lock_guard<std::mutex> lock(status_mutex_);
	if (newStatus != status_) {
		status_ = newStatus;
		status_condition_.notify_all();
	}
}

grpc::Status HealthService::Check(grpc::ServerContext* /*context*/, const grpc::health::v1::HealthCheckRequest* request,
								  grpc::health::v1::HealthCheckResponse* response)
{
	if (!request->service().empty() && request->service() != dpdkironcore::v1::DPDKironcore::service_full_name()) {
		response->set_status(grpc::health::v1::HealthCheckResponse::SERVICE_UNKNOWN);
	} else {
		std::lock_guard<std::mutex> lock(status_mutex_);
		response->set_status(status_);
	}
	return grpc::Status::OK;
}

grpc::Status HealthService::Watch(grpc::ServerContext* context, const grpc::health::v1::HealthCheckRequest* request,
								  grpc::ServerWriter<grpc::health::v1::HealthCheckResponse>* writer)
{
	if (!request->service().empty() && request->service() != dpdkironcore::v1::DPDKironcore::service_full_name())
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "Service not found");

	grpc::health::v1::HealthCheckResponse response;

	// return the current status first
	{
		std::lock_guard<std::mutex> lock(status_mutex_);
		response.set_status(status_);
	}
	writer->Write(response);

	// only report changes after that
	while (!context->IsCancelled()) {
		{
			std::unique_lock<std::mutex> lock(status_mutex_);
			while (status_ == response.status() && !context->IsCancelled())
				status_condition_.wait(lock);
			if (context->IsCancelled())
				break;
			response.set_status(status_);
		}
		writer->Write(response);
	}

	return grpc::Status(grpc::StatusCode::CANCELLED, "Client disconnected");
}
