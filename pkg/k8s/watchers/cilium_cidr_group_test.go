// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestHasCIDRGroupRef(t *testing.T) {
	testCases := [...]struct {
		name      string
		cnp       *types.SlimCNP
		cidrGroup string
		expected  bool
	}{
		{
			name: "nil Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "nil Ingress",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{},
					Specs: api.Rules{
						{},
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "nil FromCIDRGroupRef",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
						},
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  false,
		},
		{
			name: "missing CIDRGroup",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-3",
			expected:  false,
		},
		{
			name: "CIDRGroup in Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-1",
			expected:  true,
		},
		{
			name: "CIDRGroup in Specs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
			cidrGroup: "cidr-group-2",
			expected:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasCIDRGroupRef(tc.cnp, tc.cidrGroup)
			if got != tc.expected {
				t.Fatalf("expected hasCIDRGroupRef to return %t, got %t", tc.expected, got)
			}
		})
	}
}

func TestCIDRGroupRefsGet(t *testing.T) {
	testCases := [...]struct {
		name     string
		cnp      *types.SlimCNP
		expected []string
	}{
		{
			name: "nil Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
				},
			},
			expected: nil,
		},
		{
			name: "nil Ingress",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{},
					Specs: api.Rules{
						{},
					},
				},
			},
			expected: nil,
		},
		{
			name: "nil FromCIDRGroupRef",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
						},
					},
				},
			},
			expected: nil,
		},
		{
			name: "non empty fromCIDRGroupRefs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
			expected: []string{"cidr-group-1", "cidr-group-2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getCIDRGroupRefs(tc.cnp)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected cidr group refs to be %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestCIDRGroupRefsTranslate(t *testing.T) {
	testCases := [...]struct {
		name      string
		cnp       *types.SlimCNP
		cidrsSets map[string][]api.CIDR
		expected  *types.SlimCNP
	}{
		{
			name: "nil Spec",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
				},
			},
		},
		{
			name: "nil Ingress",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{},
					Specs: api.Rules{
						{},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{},
					Specs: api.Rules{
						{},
					},
				},
			},
		},
		{
			name: "nil FromCIDRGroupRef",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{},
			expected: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{},
						},
					},
				},
			},
		},

		{
			name: "non empty fromCIDRGroupRefs",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-3"},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2": {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
				"cidr-group-3": {"6.6.6.6/32"},
			},
			expected: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDR:         api.CIDRSlice{"1.1.1.1/32", "2.2.2.2/32"},
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDR:         api.CIDRSlice{"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDR:         api.CIDRSlice{"6.6.6.6/32"},
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-3"},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "non empty FromCIDR",
			cnp: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDR:         api.CIDRSlice{"1.1.1.1/32"},
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDR:         api.CIDRSlice{"4.4.4.4/32"},
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
			cidrsSets: map[string][]api.CIDR{
				"cidr-group-1": {"2.2.2.2/32", "3.3.3.3/32"},
				"cidr-group-2": {"5.5.5.5/32"},
			},
			expected: &types.SlimCNP{
				CiliumNetworkPolicy: &cilium_v2.CiliumNetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNetworkPolicy",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policy",
						Namespace: "test-namespace",
					},
					Spec: &api.Rule{
						Ingress: []api.IngressRule{
							{
								IngressCommonRule: api.IngressCommonRule{
									FromCIDR:         api.CIDRSlice{"1.1.1.1/32", "2.2.2.2/32", "3.3.3.3/32"},
									FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-1"},
								},
							},
						},
					},
					Specs: api.Rules{
						{
							Ingress: []api.IngressRule{
								{
									IngressCommonRule: api.IngressCommonRule{
										FromCIDR:         api.CIDRSlice{"4.4.4.4/32", "5.5.5.5/32"},
										FromCIDRGroupRef: api.CIDRGroupRefSlice{"cidr-group-2"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := translateCIDRGroupRefs(tc.cnp, tc.cidrsSets)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected translated cnp to be\n%v\n, got\n%v\n", tc.expected, got)
			}
		})
	}
}

func TestCIDRGroupRefsToCIDRsSets(t *testing.T) {
	testCases := [...]struct {
		name     string
		refs     []string
		cache    map[string]*cilium_v2_alpha1.CiliumCIDRGroup
		expected map[string][]api.CIDR
		err      error
	}{
		{
			name:     "nil refs",
			refs:     nil,
			cache:    map[string]*cilium_v2_alpha1.CiliumCIDRGroup{},
			expected: map[string][]api.CIDR{},
		},
		{
			name: "with refs",
			refs: []string{"cidr-group-1", "cidr-group-2"},
			cache: map[string]*cilium_v2_alpha1.CiliumCIDRGroup{
				"cidr-group-1": {
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2alpha1",
						Kind:       "CiliumCIDRGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "cidr-group-1",
					},
					Spec: cilium_v2_alpha1.CiliumCIDRGroupSpec{
						ExternalCIDRs: []api.CIDR{api.CIDR("1.1.1.1/32"), api.CIDR("2.2.2.2/32")},
					},
				},
				"cidr-group-2": {
					TypeMeta: metav1.TypeMeta{
						APIVersion: "cilium.io/v2alpha1",
						Kind:       "CiliumCIDRGroup",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "cidr-group-2",
					},
					Spec: cilium_v2_alpha1.CiliumCIDRGroupSpec{
						ExternalCIDRs: []api.CIDR{api.CIDR("3.3.3.3/32"), api.CIDR("4.4.4.4/32"), api.CIDR("5.5.5.5/32")},
					},
				},
			},
			expected: map[string][]api.CIDR{
				"cidr-group-1": {"1.1.1.1/32", "2.2.2.2/32"},
				"cidr-group-2": {"3.3.3.3/32", "4.4.4.4/32", "5.5.5.5/32"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cidrGroupRefsToCIDRsSets(tc.refs, tc.cache)
			if err != nil {
				t.Fatalf("unexpected error from cidrGroupRefsToCIDRsSets: %s", err)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Fatalf("expected cidr sets to be %v, got %v", tc.expected, got)
			}
		})
	}
}
