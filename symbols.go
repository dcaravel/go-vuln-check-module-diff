package main

import (
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// symbolAccess reports whether the linker symbol required by govulncheck's
// binary extractor is present. A readable pclntab alone is insufficient.
type symbolAccess struct {
	Status string `json:"status"` // present, not_found, or unknown
	Detail string `json:"detail,omitempty"`
}

func inspectSymbolAccess(path string) symbolAccess {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		syms, err := f.Symbols()
		if errors.Is(err, elf.ErrNoSymbols) {
			return missingSymbolAccess()
		}
		if err != nil {
			return symbolAccess{Status: "unknown", Detail: "ELF linker symbols could not be read"}
		}
		for _, sym := range syms {
			if isGovulncheckSymbol(sym.Name) {
				return symbolAccess{Status: "present"}
			}
		}
		return missingSymbolAccess()
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return inspectMachOSymbolAccess(f)
	}
	if f, err := macho.OpenFat(path); err == nil {
		defer f.Close()
		for _, arch := range f.Arches {
			if inspectMachOSymbolAccess(arch.File).Status != "present" {
				return symbolAccess{Status: "unknown", Detail: "not all architectures have the linker symbols govulncheck needs"}
			}
		}
		return symbolAccess{Status: "present"}
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		for _, sym := range f.Symbols {
			if isGovulncheckSymbol(sym.Name) {
				return symbolAccess{Status: "present"}
			}
		}
		return missingSymbolAccess()
	}
	return symbolAccess{Status: "unknown", Detail: "binary format could not be inspected"}
}

func inspectMachOSymbolAccess(f *macho.File) symbolAccess {
	if f.Symtab == nil {
		return missingSymbolAccess()
	}
	for _, sym := range f.Symtab.Syms {
		if isGovulncheckSymbol(sym.Name) {
			return symbolAccess{Status: "present"}
		}
	}
	return missingSymbolAccess()
}

func isGovulncheckSymbol(name string) bool {
	name = strings.TrimPrefix(name, "_") // Mach-O prefixes external symbol names.
	return name == "go:func.*" || name == "go.func.*"
}

func missingSymbolAccess() symbolAccess {
	return symbolAccess{Status: "not_found", Detail: "linker symbols needed for package and function checks are missing"}
}

// symbolInfo describes Go function names available in the binary's pclntab.
// It does not describe the platform's ordinary symbol table or DWARF data.
type symbolInfo struct {
	Status        string `json:"status"` // present, not_found, or unknown
	FunctionCount int    `json:"function_count,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

func inspectSymbols(path string) symbolInfo {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		return inspectELF(f)
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return inspectMachO(f)
	}
	if f, err := macho.OpenFat(path); err == nil {
		defer f.Close()
		count := 0
		for _, arch := range f.Arches {
			info := inspectMachO(arch.File)
			if info.Status != "present" {
				return symbolInfo{Status: "unknown", Detail: "not all architectures contain readable Go function symbols"}
			}
			count += info.FunctionCount
		}
		return symbolInfo{Status: "present", FunctionCount: count}
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		return inspectPE(f)
	}
	return symbolInfo{Status: "unknown", Detail: "binary format could not be inspected"}
}

func inspectELF(f *elf.File) symbolInfo {
	text := f.Section(".text")
	if text == nil {
		return symbolInfo{Status: "unknown", Detail: "text section is missing"}
	}
	for _, name := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
		if section := f.Section(name); section != nil {
			data, err := section.Data()
			if err != nil {
				return symbolInfo{Status: "unknown", Detail: "Go function table could not be read"}
			}
			return decodeFunctionTable(data, text.Addr)
		}
	}
	// Some linked or stripped binaries fold the table into another section.
	for _, name := range []string{".data.rel.ro", ".rodata"} {
		if section := f.Section(name); section != nil {
			data, err := section.Data()
			if err != nil {
				continue
			}
			if info := searchFunctionTable(data, text.Addr); info.Status == "present" {
				return info
			}
		}
	}
	return symbolInfo{Status: "not_found", Detail: "no readable Go function table was found"}
}

func inspectMachO(f *macho.File) symbolInfo {
	text := f.Section("__text")
	if text == nil {
		return symbolInfo{Status: "unknown", Detail: "text section is missing"}
	}
	section := f.Section("__gopclntab")
	if section == nil {
		return symbolInfo{Status: "not_found", Detail: "no Go function table section was found"}
	}
	data, err := section.Data()
	if err != nil {
		return symbolInfo{Status: "unknown", Detail: "Go function table could not be read"}
	}
	return decodeFunctionTable(data, text.Addr)
}

func inspectPE(f *pe.File) symbolInfo {
	text := f.Section(".text")
	if text == nil {
		return symbolInfo{Status: "unknown", Detail: "text section is missing"}
	}
	var imageBase uint64
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(h.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = h.ImageBase
	default:
		return symbolInfo{Status: "unknown", Detail: "PE image base is unavailable"}
	}
	textStart := imageBase + uint64(text.VirtualAddress)
	for _, section := range f.Sections {
		if section == text {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		if info := searchFunctionTable(data, textStart); info.Status == "present" {
			return info
		}
	}
	return symbolInfo{Status: "not_found", Detail: "no readable Go function table was found"}
}

func searchFunctionTable(data []byte, textStart uint64) symbolInfo {
	for i := 0; i+16 <= len(data); i += 4 {
		if !hasPCLNMagic(data[i:]) {
			continue
		}
		if info := decodeFunctionTable(data[i:], textStart); info.Status == "present" {
			return info
		}
	}
	return symbolInfo{Status: "not_found"}
}

func hasPCLNMagic(data []byte) bool {
	if len(data) < 16 || data[4] != 0 || data[5] != 0 || (data[6] != 1 && data[6] != 2 && data[6] != 4) || (data[7] != 4 && data[7] != 8) {
		return false
	}
	magic := binary.LittleEndian.Uint32(data)
	if magic == 0xfffffffb || magic == 0xfffffffa || magic == 0xfffffff0 || magic == 0xfffffff1 {
		return true
	}
	magic = binary.BigEndian.Uint32(data)
	return magic == 0xfffffffb || magic == 0xfffffffa || magic == 0xfffffff0 || magic == 0xfffffff1
}

func decodeFunctionTable(data []byte, textStart uint64) (info symbolInfo) {
	if !hasPCLNMagic(data) {
		return symbolInfo{Status: "unknown", Detail: "Go function table has an unsupported format"}
	}
	defer func() {
		if recover() != nil {
			info = symbolInfo{Status: "unknown", Detail: "Go function table could not be decoded"}
		}
	}()
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, textStart))
	if err != nil {
		return symbolInfo{Status: "unknown", Detail: fmt.Sprintf("Go function table could not be decoded: %v", err)}
	}
	if len(table.Funcs) == 0 {
		return symbolInfo{Status: "unknown", Detail: "Go function table contains no readable functions"}
	}
	return symbolInfo{Status: "present", FunctionCount: len(table.Funcs)}
}
