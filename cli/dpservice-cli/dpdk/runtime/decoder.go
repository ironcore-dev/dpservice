// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"fmt"
	"io"

	yaml2 "github.com/ghodss/yaml"
	dpsvcio "github.com/ironcore-dev/dpservice-cli/io"
	"gopkg.in/yaml.v2"
)

type Decoder interface {
	Decode(v any) error
}

type KindDecoder struct {
	scheme  *Scheme
	decoder PeekDecoder
}

func NewKindDecoder(scheme *Scheme, decoder PeekDecoder) *KindDecoder {
	return &KindDecoder{
		scheme:  scheme,
		decoder: decoder,
	}
}

type PeekDecoder interface {
	Decoder
	Undecode() error
}

type peekDecoder struct {
	decoded bool
	decoder Decoder
	reader  *dpsvcio.CheckpointReader
}

func (d *peekDecoder) Decode(v any) error {
	d.decoded = true
	d.reader.Checkpoint()
	return d.decoder.Decode(v)
}

func (d *peekDecoder) Undecode() error {
	if !d.decoded {
		return fmt.Errorf("must call Decode before Undecode")
	}
	d.decoded = false
	if _, err := d.reader.Unread(); err != nil {
		return err
	}
	return nil
}

func NewPeekDecoder(rd io.Reader, newDecoder func(rd io.Reader) Decoder) PeekDecoder {
	reader := dpsvcio.NewCheckpointReader(rd)
	return &peekDecoder{
		decoder: newDecoder(reader),
		reader:  reader,
	}
}

func (d *KindDecoder) Next() (any, error) {
	obj := &struct {
		Kind     string `json:"kind" yaml:"kind"`
		Metadata any    `json:"metadata" yaml:"metadata"`
		Spec     any    `json:"spec" yaml:"spec"`
	}{}
	if err := d.decoder.Decode(&obj); err != nil {
		return nil, err
	}
	res, err := d.scheme.New(obj.Kind)
	if err != nil {
		return nil, fmt.Errorf("error creating new %s: %w", obj.Kind, err)
	}
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("error marshaling %s: %w", obj.Kind, err)
	}
	err = json.Unmarshal(jsonObj, res)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling %s: %w", obj.Kind, err)
	}

	return res, nil
}

func NewExtDecoderFactory(ext string) (func(reader io.Reader) Decoder, error) {
	switch ext {
	case "json", ".json":
		return func(rd io.Reader) Decoder {
			return json.NewDecoder(rd)
		}, nil
	case "yaml", ".yaml", "yml", ".yml":
		return func(rd io.Reader) Decoder {
			return NewYAMLToJSONDecoder(rd)
		}, nil
	default:
		return nil, fmt.Errorf("unsupported extension %q", ext)
	}
}

type YAMLToJSONDecoder struct {
	decoder *yaml.Decoder
}

func NewYAMLToJSONDecoder(rd io.Reader) *YAMLToJSONDecoder {
	return &YAMLToJSONDecoder{decoder: yaml.NewDecoder(rd)}
}

func (d *YAMLToJSONDecoder) Decode(v any) error {
	obj := &struct {
		Kind     string `yaml:"kind"`
		Metadata any    `yaml:"metadata"`
		Spec     any    `yaml:"spec"`
	}{}
	if err := d.decoder.Decode(obj); err != nil {
		return err
	}

	yamlData, err := yaml.Marshal(obj)
	if err != nil {
		return err
	}

	jsonData, err := yaml2.YAMLToJSON(yamlData)
	if err != nil {
		return err
	}

	return json.Unmarshal(jsonData, &v)
}
