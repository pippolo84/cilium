package leak

import (
	"testing"
	"time"

	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/cidr"
	agentOption "github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/test/controlplane/suite"
)

var (
	podCIDR = cidr.MustParseCIDR("10.0.1.0/24")

	node = &corev1.Node{
		TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "operator-goroutine-leak"},
		Spec: corev1.NodeSpec{
			PodCIDR:  podCIDR.String(),
			PodCIDRs: []string{podCIDR.String()},
		},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeHostName, Address: "operator-goroutine-leak"},
			},
		},
	}
)

func init() {
	suite.AddTestCase("Operator/GoroutineLeak", func(t *testing.T) {
		defer goleak.VerifyNone(t)

		test := suite.NewControlPlaneTest(t, "operator-goroutine-leak", "1.24")
		test.
			UpdateObjects(node).
			SetupEnvironment(func(*agentOption.DaemonConfig, *operatorOption.OperatorConfig) {}).
			StartAgent().
			StartOperator()
		test.StopOperator()
		test.StopAgent()

		// cooldown time
		time.Sleep(100 * time.Millisecond)
	})
}
