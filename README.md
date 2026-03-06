# ELF-Loader


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

