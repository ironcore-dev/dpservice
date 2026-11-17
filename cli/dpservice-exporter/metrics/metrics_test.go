// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"maps"
	"testing"
)

func TestGraphNodeStatsReadsAllBlocks(t *testing.T) {
	sample := `{"/dp_service/graph/obj_count": {"Node_0_to_255": {"rx-0-0": 5, "drop": 2}, "Node_256_to_511": {"ipv4_lookup": 7}}}`

	var response GraphStats
	if err := json.Unmarshal([]byte(sample), &response); err != nil {
		t.Fatalf("failed to unmarshal sample: %v", err)
	}

	want := NodeData{"rx-0-0": 5, "drop": 2, "ipv4_lookup": 7}
	if got := graphNodeStats(response, "/dp_service/graph/obj_count"); !maps.Equal(got, want) {
		t.Errorf("graphNodeStats() = %v, want %v", got, want)
	}
}
