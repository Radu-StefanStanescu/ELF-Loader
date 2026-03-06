# ELF-Loader
Here is a **shorter, clean GitHub README** that still looks professional:

---

# Minimal Linux ELF Loader

A minimal **user-space ELF loader for Linux** capable of loading and executing **statically linked 64-bit ELF binaries**, including **static PIE executables**.

The project demonstrates how executable files are loaded by manually performing tasks normally handled by the Linux kernel.

---

## Features

* ELF header validation
* Loading `PT_LOAD` segments into memory
* Support for **static non-PIE binaries**
* Support for **static PIE executables**
* Correct memory permissions using `mprotect()`
* Manual **process stack setup** (`argc`, `argv`, `envp`, `auxv`)
* Execution transfer to the program entry point

---

## Build

Compile with GCC:

```bash
gcc -O2 -Wall loader.c -o loader
```

---

## Usage

Run the loader with a **statically linked ELF binary**:

```bash
./loader <static-elf-binary>
```

Example:

```bash
./loader ./hello_static
```

---

## Notes

* Only **64-bit static ELF binaries** are supported.
* Dynamic executables are **not supported** (no dynamic linker).

---

## License

BSD 3-Clause License.

---

If you want, I can also show you a **very common README structure used in OS / systems programming repos (MIT, Stanford, etc.)** that would make this look **even more academic and clean on GitHub.
