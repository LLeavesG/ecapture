// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package profileinspector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gojue/ecapture/internal/probe/openssl"
)

const RecipeCatalogVersion = 1

// RecipeCatalog carries validated, reusable private ABI descriptions. An
// offset entry must be pinned to an ELF Build ID. A symbol entry may be
// portable, but can also be pinned when a vendor changes an exported ABI
// without changing its name.
type RecipeCatalog struct {
	Version int             `json:"version"`
	Recipes []CatalogRecipe `json:"recipes"`
}

type CatalogRecipe struct {
	Name        string      `json:"name"`
	LibraryGlob string      `json:"library_glob,omitempty"`
	BuildID     string      `json:"build_id,omitempty"`
	Symbol      string      `json:"symbol,omitempty"`
	Offset      string      `json:"offset,omitempty"`
	Family      string      `json:"family"`
	Layer       string      `json:"layer"`
	Role        string      `json:"role"`
	Confidence  string      `json:"confidence"`
	Priority    int         `json:"priority"`
	ABI         string      `json:"abi,omitempty"`
	Recipe      *HookRecipe `json:"recipe"`
	Notes       string      `json:"notes,omitempty"`

	parsedOffset uint64
}

func LoadRecipeCatalog(path string) (*RecipeCatalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open recipe catalog %q: %w", path, err)
	}
	defer file.Close()
	catalog, err := DecodeRecipeCatalog(file)
	if err != nil {
		return nil, fmt.Errorf("decode recipe catalog %q: %w", path, err)
	}
	return catalog, nil
}

func DecodeRecipeCatalog(reader io.Reader) (*RecipeCatalog, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var catalog RecipeCatalog
	if err := decoder.Decode(&catalog); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("recipe catalog contains trailing JSON values")
		}
		return nil, err
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	return &catalog, nil
}

func (c *RecipeCatalog) Validate() error {
	if c == nil {
		return fmt.Errorf("recipe catalog is nil")
	}
	if c.Version != RecipeCatalogVersion {
		return fmt.Errorf(
			"unsupported recipe catalog version %d, want %d",
			c.Version,
			RecipeCatalogVersion,
		)
	}
	if len(c.Recipes) == 0 {
		return fmt.Errorf("recipe catalog requires at least one recipe")
	}
	seen := make(map[string]struct{}, len(c.Recipes))
	for index := range c.Recipes {
		recipe := &c.Recipes[index]
		recipe.Name = strings.TrimSpace(recipe.Name)
		recipe.Symbol = strings.TrimSpace(recipe.Symbol)
		recipe.Offset = strings.TrimSpace(recipe.Offset)
		recipe.LibraryGlob = strings.TrimSpace(recipe.LibraryGlob)
		recipe.Family = strings.TrimSpace(recipe.Family)
		recipe.Layer = strings.ToLower(strings.TrimSpace(recipe.Layer))
		recipe.Role = strings.TrimSpace(recipe.Role)
		recipe.Confidence = strings.ToLower(strings.TrimSpace(recipe.Confidence))
		recipe.BuildID = normalizeCatalogBuildID(recipe.BuildID)
		if recipe.Name == "" || recipe.Family == "" || recipe.Role == "" {
			return fmt.Errorf(
				"recipes[%d] requires name, family, and role",
				index,
			)
		}
		if (recipe.Symbol == "") == (recipe.Offset == "") {
			return fmt.Errorf(
				"recipe %q requires exactly one of symbol or offset",
				recipe.Name,
			)
		}
		if recipe.LibraryGlob != "" {
			if _, err := filepath.Match(recipe.LibraryGlob, recipe.LibraryGlob); err != nil {
				return fmt.Errorf(
					"recipe %q invalid library_glob: %w",
					recipe.Name,
					err,
				)
			}
		}
		if recipe.BuildID != "" {
			if _, err := hex.DecodeString(recipe.BuildID); err != nil {
				return fmt.Errorf("recipe %q invalid build_id: %w", recipe.Name, err)
			}
		}
		if recipe.Offset != "" {
			if recipe.BuildID == "" {
				return fmt.Errorf(
					"offset recipe %q requires build_id",
					recipe.Name,
				)
			}
			offset, err := strconv.ParseUint(recipe.Offset, 0, 64)
			if err != nil || offset == 0 {
				return fmt.Errorf(
					"recipe %q has invalid non-zero offset %q",
					recipe.Name,
					recipe.Offset,
				)
			}
			recipe.parsedOffset = offset
		}
		switch recipe.Layer {
		case LayerSemantic, LayerPlaintext, LayerCrypto, LayerTransport:
		default:
			return fmt.Errorf("recipe %q has unsupported layer %q", recipe.Name, recipe.Layer)
		}
		switch recipe.Confidence {
		case ConfidenceExact, ConfidenceStrong:
		default:
			return fmt.Errorf(
				"recipe %q confidence must be exact or strong",
				recipe.Name,
			)
		}
		if recipe.Priority < 1 || recipe.Priority > 100 {
			return fmt.Errorf("recipe %q priority must be between 1 and 100", recipe.Name)
		}
		if err := validateCatalogHookRecipe(recipe); err != nil {
			return err
		}
		keyBytes, _ := json.Marshal([]string{
			recipe.LibraryGlob,
			recipe.BuildID,
			recipe.Symbol,
			recipe.Offset,
		})
		key := string(keyBytes)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("recipe %q duplicates a catalog target", recipe.Name)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateCatalogHookRecipe(catalogRecipe *CatalogRecipe) error {
	if catalogRecipe == nil || catalogRecipe.Recipe == nil {
		name := ""
		if catalogRecipe != nil {
			name = catalogRecipe.Name
		}
		return fmt.Errorf("recipe %q requires a hook recipe", name)
	}
	name := catalogRecipe.Name
	recipe := catalogRecipe.Recipe
	captureLayer, transport := hookProvenance(HookCandidate{
		Family: catalogRecipe.Family,
		Layer:  catalogRecipe.Layer,
		Role:   catalogRecipe.Role,
	})
	profile := &openssl.ApplicationProfile{
		Version: openssl.ApplicationProfileVersion,
		Name:    "catalog-validation",
		Match:   openssl.ApplicationMatch{PID: 1},
		DataHooks: []openssl.ApplicationDataHook{{
			Name:                   "catalog-hook",
			Library:                "/catalog/validation.so",
			Symbol:                 "catalog_validation",
			CaptureLayer:           captureLayer,
			Transport:              transport,
			Direction:              recipe.Direction,
			CaptureOn:              recipe.CaptureOn,
			BufferArg:              recipe.BufferArg,
			BufferOffset:           openssl.OffsetValue(recipe.BufferOffset),
			BufferIndirect:         recipe.BufferIndirect,
			LengthSource:           recipe.LengthSource,
			LengthArg:              recipe.LengthArg,
			FixedLength:            recipe.FixedLength,
			LengthOffset:           openssl.OffsetValue(recipe.LengthOffset),
			LengthSize:             recipe.LengthSize,
			LengthIndirect:         recipe.LengthIndirect,
			MaxBytes:               recipe.MaxBytes,
			ContextArg:             recipe.ContextArg,
			ContextOffset:          openssl.OffsetValue(recipe.ContextOffset),
			ContextSize:            recipe.ContextSize,
			StreamArg:              recipe.StreamArg,
			StreamOffset:           openssl.OffsetValue(recipe.StreamOffset),
			StreamSize:             recipe.StreamSize,
			StreamByteOffsetArg:    recipe.StreamByteOffsetArg,
			StreamByteOffsetOffset: openssl.OffsetValue(recipe.StreamByteOffsetOffset),
			StreamByteOffsetSize:   recipe.StreamByteOffsetSize,
			FinArg:                 recipe.FinArg,
			FinOffset:              openssl.OffsetValue(recipe.FinOffset),
			FinSize:                recipe.FinSize,
			BufferFormat:           recipe.BufferFormat,
			VectorCountArg:         recipe.VectorCountArg,
			VectorStride:           recipe.VectorStride,
			VectorBaseOffset:       recipe.VectorBaseOffset,
			VectorLengthOffset:     recipe.VectorLengthOffset,
			VectorLengthSize:       recipe.VectorLengthSize,
		}},
	}
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("recipe %q hook: %w", name, err)
	}
	return nil
}

func normalizeCatalogBuildID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimPrefix(value, "0x")
}

func (r CatalogRecipe) matchesLibrary(path string, buildID string) bool {
	if r.BuildID != "" &&
		!bytes.EqualFold([]byte(r.BuildID), []byte(normalizeCatalogBuildID(buildID))) {
		return false
	}
	if r.LibraryGlob == "" {
		return true
	}
	matched, err := filepath.Match(r.LibraryGlob, path)
	return err == nil && matched
}

func (r CatalogRecipe) symbolRecipe() symbolRecipe {
	return symbolRecipe{
		family:     r.Family,
		layer:      r.Layer,
		role:       r.Role,
		confidence: r.Confidence,
		priority:   r.Priority,
		abi:        r.ABI,
		hook:       cloneHookRecipe(r.Recipe),
		notes:      r.Notes,
	}
}
