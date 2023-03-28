// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"errors"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (k *K8sWatcher) onUpsertCIDRGroup(
	cidrGroup *cilium_v2_alpha1.CiliumCIDRGroup,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
) error {
	oldCidrGroup, ok := cidrGroupCache[cidrGroup.Name]
	if ok && oldCidrGroup.Spec.DeepEqual(&cidrGroup.Spec) {
		return nil
	}

	cidrGroupCpy := cidrGroup.DeepCopy()
	cidrGroupCache[cidrGroup.Name] = cidrGroupCpy

	err := k.updateCIDRGroupRefPolicies(cidrGroup.Name, cidrGroupCache, cnpCache, cs)

	return err
}

func (k *K8sWatcher) onDeleteCIDRGroup(
	cidrGroupName string,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
) error {
	delete(cidrGroupCache, cidrGroupName)

	err := k.updateCIDRGroupRefPolicies(cidrGroupName, cidrGroupCache, cnpCache, cs)

	return err
}

func (k *K8sWatcher) updateCIDRGroupRefPolicies(
	cidrGroup string,
	cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup,
	cnpCache map[resource.Key]*types.SlimCNP,
	cs client.Clientset,
) error {
	var errs []error
	for key, cnp := range cnpCache {
		if !hasCIDRGroupRef(cnp, cidrGroup) {
			continue
		}

		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.Name,
			logfields.K8sAPIVersion:           cnp.APIVersion,
			logfields.K8sNamespace:            cnp.Namespace,
			logfields.CIDRGroupRef:            cidrGroup,
		}).Info("Referenced CiliumCIDRGroup updated or deleted, recalculating CiliumNetworkPolicy rules")

		initialRecvTime := time.Now()

		// We need to deepcopy this structure because we are writing
		// fields.
		// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
		cnpCpy := cnp.DeepCopy()

		translatedCNP := resolveCIDRGroupRef(cnpCpy, cidrGroupCache)

		err := k.updateCiliumNetworkPolicyV2(cs, cnpCpy, translatedCNP, initialRecvTime)
		if err == nil {
			cnpCache[key] = cnpCpy
		}

		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func resolveCIDRGroupRef(cnp *types.SlimCNP, cidrGroupCache map[string]*cilium_v2_alpha1.CiliumCIDRGroup) *types.SlimCNP {
	refs := getCIDRGroupRefs(cnp)
	if len(refs) == 0 {
		return cnp
	}

	cidrsSets, err := cidrGroupRefsToCIDRsSets(refs, cidrGroupCache)
	if err != nil {
		log.WithFields(logrus.Fields{
			logfields.K8sAPIVersion:           cnp.TypeMeta.APIVersion,
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
			logfields.CIDRGroupRefs:           refs,
		}).WithError(err).Warning("unable to translate all cidr groups to cidrs")
	}
	translated := translateCIDRGroupRefs(cnp, cidrsSets)

	return translated
}

func hasCIDRGroupRef(cnp *types.SlimCNP, cidrGroup string) bool {
	if specHasCIDRGroupRef(cnp.Spec, cidrGroup) {
		return true
	}
	for _, spec := range cnp.Specs {
		if specHasCIDRGroupRef(spec, cidrGroup) {
			return true
		}
	}
	return false
}

func specHasCIDRGroupRef(spec *api.Rule, cidrGroup string) bool {
	if spec == nil {
		return false
	}
	for _, ingress := range spec.Ingress {
		for _, cidrGroupRef := range ingress.FromCIDRGroupRef {
			if string(cidrGroupRef) == cidrGroup {
				return true
			}
		}
	}
	return false
}

func getCIDRGroupRefs(cnp *types.SlimCNP) []string {
	var cidrGroupRefs []string

	if cnp.Spec != nil {
		for _, ingress := range cnp.Spec.Ingress {
			for _, cidrGroupRef := range ingress.FromCIDRGroupRef {
				cidrGroupRefs = append(cidrGroupRefs, string(cidrGroupRef))
			}
		}
	}
	for _, spec := range cnp.Specs {
		for _, ingress := range spec.Ingress {
			for _, cidrGroupRef := range ingress.FromCIDRGroupRef {
				cidrGroupRefs = append(cidrGroupRefs, string(cidrGroupRef))
			}
		}
	}

	return cidrGroupRefs
}

func translateCIDRGroupRefs(cnp *types.SlimCNP, cidrsSets map[string][]api.CIDR) *types.SlimCNP {
	cnpCpy := cnp.DeepCopy()

	if cnpCpy.Spec != nil {
		for i := range cnpCpy.Spec.Ingress {
			for _, cidrGroupRef := range cnpCpy.Spec.Ingress[i].FromCIDRGroupRef {
				cnpCpy.Spec.Ingress[i].FromCIDR = append(cnpCpy.Spec.Ingress[i].FromCIDR, cidrsSets[string(cidrGroupRef)]...)
			}
		}
	}
	for i := range cnpCpy.Specs {
		for j := range cnpCpy.Specs[i].Ingress {
			for _, cidrGroupRef := range cnpCpy.Specs[i].Ingress[j].FromCIDRGroupRef {
				cnpCpy.Specs[i].Ingress[j].FromCIDR = append(cnpCpy.Specs[i].Ingress[j].FromCIDR, cidrsSets[string(cidrGroupRef)]...)
			}
		}
	}

	return cnpCpy
}

func cidrGroupRefsToCIDRsSets(cidrGroupRefs []string, cache map[string]*cilium_v2_alpha1.CiliumCIDRGroup) (map[string][]api.CIDR, error) {
	var errs []error
	cidrsSet := make(map[string][]api.CIDR)
	for _, cidrGroupRef := range cidrGroupRefs {
		var found bool
		for cidrGroupName, cidrGroup := range cache {
			if cidrGroupName == cidrGroupRef {
				cidrs := make([]api.CIDR, 0, len(cidrGroup.Spec.ExternalCIDRs))
				for _, cidr := range cidrGroup.Spec.ExternalCIDRs {
					cidrs = append(cidrs, api.CIDR(cidr))
				}
				cidrsSet[cidrGroupRef] = cidrs
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("cidr group %s not found, skipping translation", cidrGroupRef))
		}
	}
	return cidrsSet, errors.Join(errs...)
}
