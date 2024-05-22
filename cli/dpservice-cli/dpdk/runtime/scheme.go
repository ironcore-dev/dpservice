// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"reflect"
)

type Scheme struct {
	typeByKind map[string]reflect.Type
	kindByType map[reflect.Type]string
}

func NewScheme() *Scheme {
	return &Scheme{
		typeByKind: make(map[string]reflect.Type),
		kindByType: make(map[reflect.Type]string),
	}
}

func (s *Scheme) Add(objs ...any) error {
	for _, obj := range objs {
		t := reflect.TypeOf(obj)
		if t.Kind() != reflect.Ptr {
			return fmt.Errorf("object %T must be a pointer to a struct", obj)
		}

		t = t.Elem()
		if err := s.AddWithKind(t.Name(), obj); err != nil {
			return fmt.Errorf("[name %s] %w", t.Name(), err)
		}
	}
	return nil
}

func (s *Scheme) AddWithKind(name string, obj any) error {
	t := reflect.TypeOf(obj)
	if t.Kind() != reflect.Ptr {
		return fmt.Errorf("object %T must be a pointer to a struct", obj)
	}

	s.typeByKind[name] = t.Elem()
	s.kindByType[t.Elem()] = name
	return nil
}

func (s *Scheme) KindFor(obj any) (string, error) {
	t := reflect.TypeOf(obj)
	if t.Kind() != reflect.Ptr {
		return "", fmt.Errorf("object %T must be a pointer to a struct", obj)
	}

	kind, ok := s.kindByType[t.Elem()]
	if !ok {
		return "", fmt.Errorf("no kind registered for type %T", obj)
	}
	return kind, nil
}

func (s *Scheme) New(name string) (any, error) {
	typ, ok := s.typeByKind[name]
	if !ok {
		return nil, fmt.Errorf("no type %q registered", name)
	}
	return reflect.New(typ).Interface(), nil
}
