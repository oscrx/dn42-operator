// Package v1alpha1 contains the DN42Peer API.
//
// +kubebuilder:object:generate=true
// +groupName=dn42.oscarr.nl
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group and version of the DN42Peer API.
	GroupVersion = schema.GroupVersion{Group: "dn42.oscarr.nl", Version: "v1alpha1"}

	// SchemeBuilder registers the types of this package.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types of this package to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
