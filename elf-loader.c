// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <stdint.h>
#include <sys/random.h>
void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	/**
	 * TODO: ELF Header Validation
	 * Validate ELF magic bytes - "Not a valid ELF file" + exit code 3 if invalid.
	 * Validate ELF class is 64-bit (ELFCLASS64) - "Not a 64-bit ELF" + exit code 4 if invalid.
	 */
	unsigned char *elf_bytes = (unsigned char *)elf_contents;

	if (elf_bytes[0] != 0x7f || elf_bytes[1] != 'E' || elf_bytes[2] != 'L' || elf_bytes[3] != 'F') {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}
	if (elf_bytes[4] != 2) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_contents;
	Elf64_Phdr *phdr = (Elf64_Phdr *)(elf_bytes + ehdr->e_phoff);

	int is_pie = (ehdr->e_type == ET_DYN);
	size_t page_size = (size_t)getpagesize();
	uint64_t load_base = 0;

	if (!is_pie) {
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_LOAD) {
				size_t map_size = phdr[i].p_memsz;
				size_t offset = phdr[i].p_vaddr % page_size;
				size_t aligned_addr = phdr[i].p_vaddr - offset;
				size_t aligned_size = (map_size + offset + page_size - 1) & ~(page_size - 1);

				void *segment_addr = mmap((void *)aligned_addr,
							  aligned_size,
							  PROT_READ | PROT_WRITE,
							  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
							  -1, 0);
				if (segment_addr == MAP_FAILED) {
					perror("mmap segment");
					exit(1);
				}

				memcpy((void *)phdr[i].p_vaddr, elf_bytes + phdr[i].p_offset, phdr[i].p_filesz);

				if (phdr[i].p_memsz > phdr[i].p_filesz) {
					memset((void *)((uintptr_t)phdr[i].p_vaddr + phdr[i].p_filesz), 0,
					       phdr[i].p_memsz - phdr[i].p_filesz);
				}
			}
		}
	} else {
		uint64_t min_v = UINT64_MAX;
		uint64_t max_v = 0;

		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type != PT_LOAD)
				continue;
			uint64_t start = phdr[i].p_vaddr;
			uint64_t end = phdr[i].p_vaddr + phdr[i].p_memsz;

			if (start < min_v)
				min_v = start;
			if (end > max_v)
				max_v = end;
		}

		uint64_t min_al = min_v & ~((uint64_t)page_size - 1);
		uint64_t max_al = (max_v + page_size - 1) & ~((uint64_t)page_size - 1);
		size_t span = (size_t)(max_al - min_al);

		void *reserve = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (reserve == MAP_FAILED) {
			perror("mmap reserve");
			exit(1);
		}
		load_base = (uint64_t)(uintptr_t)reserve - min_al;

		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type != PT_LOAD)
				continue;
			uint64_t vaddr = phdr[i].p_vaddr;
			size_t off_in_pg = (size_t)(vaddr & (page_size - 1));
			uint64_t seg_al_start = vaddr - off_in_pg;
			size_t seg_map_size = (size_t)((phdr[i].p_memsz + off_in_pg + page_size - 1) &
						       ~((uint64_t)page_size - 1));

			void *seg = mmap((void *)(uintptr_t)(load_base + seg_al_start),
					 seg_map_size,
					 PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
					 -1, 0);
			if (seg == MAP_FAILED) {
				perror("mmap pie segment");
				exit(1);
			}

			memcpy((void *)(uintptr_t)(load_base + vaddr),
			       elf_bytes + phdr[i].p_offset,
			       (size_t)phdr[i].p_filesz);

			if (phdr[i].p_memsz > phdr[i].p_filesz) {
				memset((void *)(uintptr_t)(load_base + vaddr + phdr[i].p_filesz), 0,
				       (size_t)(phdr[i].p_memsz - phdr[i].p_filesz));
			}
		}
	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			size_t map_size = phdr[i].p_memsz;
			size_t offset = phdr[i].p_vaddr % page_size;
			size_t aligned_addr = phdr[i].p_vaddr - offset;
			size_t aligned_size = (map_size + offset + page_size - 1) & ~(page_size - 1);

			int prot = 0;

			if (phdr[i].p_flags & PF_R)
				prot |= PROT_READ;
			if (phdr[i].p_flags & PF_W)
				prot |= PROT_WRITE;
			if (phdr[i].p_flags & PF_X)
				prot |= PROT_EXEC;

			void *addr = is_pie ? (void *)(uintptr_t)(load_base + aligned_addr) : (void *)(uintptr_t)aligned_addr;

			if (mprotect(addr, aligned_size, prot) == -1) {
				perror("mprotect");
				exit(1);
			}
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *sp = NULL;
	size_t stack_size = 8 * 1024 * 1024;
	uint8_t *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

	if (stack == MAP_FAILED) {
		perror("mmap stack");
		exit(1);
	}
	uint8_t *top = stack + stack_size;
	int envc = 0;

	while (envp[envc])
		envc++;
	char **argv_ptrs = malloc(sizeof(char *) * (size_t)argc);
	char **envp_ptrs = malloc(sizeof(char *) * (size_t)envc);

	if (!argv_ptrs || !envp_ptrs) {
		perror("malloc");
		exit(1);
	}
	uint8_t *sp_bytes = top;

	sp_bytes -= 16;
	uint8_t *at_random_ptr = sp_bytes;
	ssize_t gr = getrandom(at_random_ptr, 16, 0);

	if (gr != 16) {
		int ur = open("/dev/urandom", O_RDONLY);

		if (ur >= 0) {
			ssize_t r = read(ur, at_random_ptr, 16);
			(void)r;
			close(ur);
		}
	}

	for (int i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]) + 1;

		sp_bytes -= len;
		memcpy(sp_bytes, argv[i], len);
		argv_ptrs[i] = (char *)sp_bytes;
	}
	for (int i = 0; i < envc; i++) {
		size_t len = strlen(envp[i]) + 1;

		sp_bytes -= len;
		memcpy(sp_bytes, envp[i], len);
		envp_ptrs[i] = (char *)sp_bytes;
	}
	uintptr_t aligned = ((uintptr_t)sp_bytes) & ~((uintptr_t)15);

	sp_bytes = (uint8_t *)aligned;
	uint64_t at_phdr_val = 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_PHDR) {
			at_phdr_val = phdr[i].p_vaddr;
			break;
		}
	}
	if (at_phdr_val == 0) {
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type == PT_LOAD) {
				uint64_t fstart = phdr[i].p_offset;
				uint64_t fend   = phdr[i].p_offset + phdr[i].p_filesz;

				if ((uint64_t)ehdr->e_phoff >= fstart && (uint64_t)ehdr->e_phoff < fend) {
					at_phdr_val = phdr[i].p_vaddr + ((uint64_t)ehdr->e_phoff - fstart);
					break;
				}
			}
		}
	}
	if (at_phdr_val == 0) {
		fprintf(stderr, "Failed to compute AT_PHDR\n");
		exit(1);
	}
	if (is_pie)
		at_phdr_val = load_base + at_phdr_val;
	struct { uint64_t k, v; } aux[16];
	int ax = 0;

	aux[ax++] = (typeof(aux[0])){ AT_PHDR,  at_phdr_val };
	aux[ax++] = (typeof(aux[0])){ AT_PHENT, sizeof(Elf64_Phdr) };
	aux[ax++] = (typeof(aux[0])){ AT_PHNUM, ehdr->e_phnum };
	aux[ax++] = (typeof(aux[0])){ AT_PAGESZ, (uint64_t)getpagesize() };
	aux[ax++] = (typeof(aux[0])){ AT_ENTRY, (uint64_t)(is_pie ? (load_base + ehdr->e_entry) : ehdr->e_entry) };
	aux[ax++] = (typeof(aux[0])){ AT_BASE,  0 };
	aux[ax++] = (typeof(aux[0])){ AT_UID,   (uint64_t)getuid() };
	aux[ax++] = (typeof(aux[0])){ AT_EUID,  (uint64_t)geteuid() };
	aux[ax++] = (typeof(aux[0])){ AT_GID,   (uint64_t)getgid() };
	aux[ax++] = (typeof(aux[0])){ AT_EGID,  (uint64_t)getegid() };
	aux[ax++] = (typeof(aux[0])){ AT_RANDOM, (uint64_t)(uintptr_t)at_random_ptr };
	aux[ax++] = (typeof(aux[0])){ AT_NULL,  0 };
	size_t total_slots = 1 + (size_t)argc + 1 + (size_t)envc + 1 + (size_t)(2 * ax);
	uint64_t *sp64 = (uint64_t *)(sp_bytes);

	sp64 -= total_slots;
	uint64_t *p = sp64;
	*p++ = (uint64_t)argc;
	for (int i = 0; i < argc; i++)
		*p++ = (uint64_t)(uintptr_t)argv_ptrs[i];
	*p++ = 0;
	for (int i = 0; i < envc; i++)
		*p++ = (uint64_t)(uintptr_t)envp_ptrs[i];
	*p++ = 0;
	for (int i = 0; i < ax; i++) {
		*p++ = aux[i].k;
		*p++ = aux[i].v;
	}
	sp = (void *)sp64;

	free(argv_ptrs);
	free(envp_ptrs);
	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	typedef void (*entry_t)(void);
	entry_t entry = (entry_t)(uintptr_t)(is_pie ? (load_base + ehdr->e_entry) : ehdr->e_entry);



	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
