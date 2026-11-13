// Package baseline provides a mechanism for applying baseline overrides to Go structs
package baseline

import (
	"reflect"

	"github.com/huandu/go-clone"
)

func isByReferenceMutable(t reflect.Type) bool {
	return t.Kind() == reflect.Pointer || t.Kind() == reflect.Interface || t.Kind() == reflect.Map || t.Kind() == reflect.Slice
}

// Apply applies a baseline to the destination struct.
//
// For every field in the destination struct that is not set to its zero value,
// it sets the corresponding field in the destination struct to the value in the source struct.
// The value of the source struct is cloned if it contains a pass-by-reference type with interior mutability
// so that the original source value is not modified by changes to the applied baseline in the destination struct.
//
// Only directly exported fields are considered.
func Apply[T any](dst, src *T) {
	var (
		dstVal = reflect.ValueOf(dst).Elem()
		srcVal = reflect.ValueOf(src).Elem()
	)

	for i := range dstVal.NumField() {
		var (
			dstField = dstVal.Field(i)
			srcField = srcVal.Field(i)
		)

		if !dstField.CanSet() || !dstField.IsZero() {
			continue
		}

		// Source value type is passed by reference and has interior mutability, clone it
		if isByReferenceMutable(srcField.Type()) {
			srcField = reflect.ValueOf(clone.Clone(srcField.Interface()))
		}

		dstField.Set(srcField)
	}
}
