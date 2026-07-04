// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRPC_SERVICE_ONMETAL_H__
#define __INCLUDE_DP_GRPC_SERVICE_ONMETAL_H__

#ifdef __cplusplus

#include "grpc/dp_grpc_service.hpp"
#include "../proto/dpdk_onmetal.grpc.pb.h"

class GRPCServiceOnmetal final : public dpdkonmetal::v1::DPDKonmetal::AsyncService {
private:
	static GRPCServiceOnmetal* instance;
	GRPCService* ironcore_service_;

public:
	GRPCServiceOnmetal() {};
	GRPCServiceOnmetal(const GRPCServiceOnmetal& obj) = delete;
	static GRPCServiceOnmetal* GetInstance();
	static void Cleanup();

	const char* GetUUID() { return ironcore_service_->GetUUID(); }
	void SetInitStatus(bool status) { ironcore_service_->SetInitStatus(status); }
	bool IsInitialized() { return ironcore_service_->IsInitialized(); }
	grpc::ServerCompletionQueue* GetCq() { return ironcore_service_->GetCq(); }

	void ConnectIroncoreService(GRPCService* service) { ironcore_service_ = service; }

	void InitRpcs();
};

#endif  // __cplusplus

#endif
