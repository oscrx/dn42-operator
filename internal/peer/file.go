package peer

import (
	"errors"

	kjson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"
)

// DecodeFile decodes a peer file (YAML) into v the way the API server reads
// it: field names match case-sensitively, and unknown or duplicate fields
// are errors. A plain encoding/json decode matches names case-insensitively
// with the last key winning, so `keyRef: a` plus `keyref: ""` would read as
// no keyRef while the cluster applies "a"; every check of a peer file must
// see what the cluster sees.
func DecodeFile(b []byte, v any) error {
	j, err := yaml.YAMLToJSON(b)
	if err != nil {
		return err
	}
	strict, err := kjson.UnmarshalStrict(j, v)
	if err != nil {
		return err
	}
	return errors.Join(strict...)
}
