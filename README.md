# PE Parser

A small parser for Windows PE files (.exe and .dll), written in C from scratch.

I built this to learn how executables are actually structured on disk, and to get
comfortable with pointers, bitwise operations, and reading binary formats by hand.
It doesn't use any Windows headers or libraries. Everything is parsed directly from
the raw bytes.

## What it does

Point it at a PE file and it reads:

- The DOS and PE signatures (MZ, PE), validating the file is really a PE
- The architecture (x86 / x64) and whether the file is an EXE or a DLL
- The section table: name, virtual size/address, and raw size/address for each section
- The import table: every DLL the file depends on

All multi-byte values are assembled from raw bytes, respecting little-endian order.
Every read is bounds-checked against the file size, so a truncated or malformed file
won't crash it or read out of bounds.

## Building

With MSVC:

cl pe-parser.c


With gcc:

gcc pe-parser.c -o pe-parser


## Usage

pe-parser.exe C:\Windows\System32\notepad.exe


Example output:

x64 architecture
Its executable file
Name: .text
Virtual Size = 267E2
...
DLL = GDI32.dll
DLL = USER32.dll
DLL = COMCTL32.dll
...


## Notes

This is a learning project, so it prints what it finds rather than exposing a clean
API.
