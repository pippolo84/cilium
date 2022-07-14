// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"errors"
	"fmt"
	"path"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cilium/cilium/pkg/datapath/fake"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	controlplane "github.com/cilium/cilium/test/control-plane"
)

type goldenCiliumNodesValidator struct {
	step int
}

func NewGoldenCiliumNodesValidator(stateFile string, update bool) controlplane.Validator {
	var v goldenCiliumNodesValidator
	fmt.Sscanf(path.Base(stateFile), "state%d.yaml", &v.step)
	return &v
}

func getNodeLabels(proxy *controlplane.K8sObjsProxy, name string) (map[string]string, error) {
	nodeObj, err := proxy.Get(
		schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"},
		"",
		name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get %q Node: %w", name, err)
	}
	node, ok := nodeObj.(*v1.Node)
	if !ok {
		return nil, errors.New("type assertion failed for Node obj")
	}

	return node.GetLabels(), nil
}

func getCiliumNodeLabels(proxy *controlplane.K8sObjsProxy, name string) (map[string]string, error) {
	ciliumNodeObj, err := proxy.Get(
		schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnodes"},
		"",
		name,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get %q CiliumNode: %w", name, err)
	}
	ciliumNode, ok := ciliumNodeObj.(*v2.CiliumNode)
	if !ok {
		return nil, errors.New("type assertion failed for CiliumNode obj")
	}

	return ciliumNode.GetLabels(), nil
}

func (v *goldenCiliumNodesValidator) Validate(datapath *fake.FakeDatapath, proxy *controlplane.K8sObjsProxy) error {
	nodeLabels, err := getNodeLabels(proxy, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("validation failed in step %d: %w", v.step, err)
	}

	ciliumNodeLabels, err := getCiliumNodeLabels(proxy, "cilium-nodes-worker")
	if err != nil {
		return fmt.Errorf("validation failed in step %d: %w", v.step, err)
	}

	label, value := "test-label", "test-value"

	switch v.step {
	case 1:
		nodeLabelValue, ok := nodeLabels[label]
		if !ok {
			return fmt.Errorf("no label %q found in Node object in step %d", label, v.step)
		}
		if nodeLabelValue != value {
			return fmt.Errorf("unexpected value %q for Node label %q in step %d", nodeLabelValue, label, v.step)
		}

		ciliumNodeLabelValue, ok := ciliumNodeLabels[label]
		if !ok {
			return fmt.Errorf("no label %q found in CiliumNode object in step %d", label, v.step)
		}
		if ciliumNodeLabelValue != value {
			return fmt.Errorf("unexpected value %q for CiliumNode label %q in step %d", ciliumNodeLabelValue, label, v.step)
		}
	case 2:
		if _, ok := nodeLabels[label]; ok {
			return fmt.Errorf("unexpected label %q in Node object in step %d", label, v.step)
		}

		if _, ok := ciliumNodeLabels[label]; ok {
			return fmt.Errorf("unexpected label %q in CiliumNode object in step %d", label, v.step)
		}
	default:
		return fmt.Errorf("unexpected test step: %d", v.step)
	}

	return nil
}
