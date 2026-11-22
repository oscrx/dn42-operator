// Package v1alpha1 contains the DN42Peer API.
//
// +kubebuilder:object:generate=true
// +groupName=dn42.oscarr.nl
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of the DN42Peer API.
	GroupVersion = schema.GroupVersion{Group: "dn42.oscarr.nl", Version: "v1alpha1"}

	// SchemeBuilder registers the types of this package. Plain apimachinery,
	// so importing the API doesn't pull in controller-runtime.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types of this package to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &DN42Peer{}, &DN42PeerList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
