#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <elf.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <mhash.h>

//TODO auto determine these
#define ElfN_Ehdr Elf64_Ehdr
#define ElfN_Shdr Elf64_Shdr
#define ElfN_Sym Elf64_Sym
#define ElfN_Rel Elf64_Rel
#define ElfN_Rela Elf64_Rela
#define ELFN_ST_TYPE(val) ELF64_ST_TYPE(val)

//TODO use getpagesize() ?
#define PAGE_SIZE 4096

typedef struct functioninfo
{
	unsigned char digest[16];
	char *name;
	void *address;
	size_t size;
	struct functioninfo *next;
} functioninfo_t;

bool patchedPages[512] = {false};
static uint8_t patchBuff[PAGE_SIZE];

functioninfo_t *knownFunctions = NULL;

static void patchFunction(uint8_t *func, uint8_t *newFunc)
{
	uint8_t *aligned = (uint8_t *)((uint64_t)func & ~0xFFF);
	if(patchedPages[(uintptr_t)aligned / 4096])
	{
		memcpy(patchBuff, aligned, PAGE_SIZE);

		assert(mmap(aligned, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == aligned);

		memcpy(aligned, patchBuff, PAGE_SIZE);

		patchedPages[(uintptr_t)aligned / 4096] = true;
	}

	func[0] = 0xE9; //jmp
	*(uint32_t *)(func + 1) = newFunc - func - 5;
}

//fd must be at the start of the section 'rel' is in
static void retrieveFunction(ElfN_Shdr *sec, ElfN_Sym *sym, FILE *fd,
	char *names, void (*handler)(functioninfo_t *, FILE *))
{
	MHASH td;
	td = mhash_init(MHASH_MD5);
	assert(td != MHASH_FAILED);

	long pos = ftell(fd);
	fseek(fd, sec->sh_offset + sym->st_value, SEEK_SET);

	char buff[128];
	uint32_t size = sym->st_size;
	while(size > 0)
	{
		int curr = size % 129;
		assert(fread(buff, 1, curr, fd) == curr);
		mhash(td, buff, curr);

		if(size < 256)
			size = 0;
		else
			size -= 256;
	}

	functioninfo_t info;
	mhash_deinit(td, info.digest);
	info.name = names + sym->st_name;
	info.address = (void *)sym->st_value;
	info.size = sym->st_size;
	info.next = NULL;

	fseek(fd, sec->sh_offset + sym->st_value, SEEK_SET);
	handler(&info, fd);

	fseek(fd, pos, SEEK_SET);
}

static void retrieveFunctions(char *file, void (*handler)(functioninfo_t *, FILE *))
{
	FILE *fd = fopen(file, "r");
	assert(fd != NULL);

	uint16_t shCount;
	uintptr_t shOffset;

	{
		ElfN_Ehdr header;
		fread(&header, 1, sizeof(ElfN_Ehdr), fd);
		shCount = header.e_shnum;
		shOffset = header.e_shoff;

		fseek(fd, shOffset, SEEK_SET);
	}

	while(shCount > 0)
	{
		ElfN_Shdr section;
		assert(fread(&section, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

		if(section.sh_type == SHT_SYMTAB)
		{
			char *names;
			long sectionPos = ftell(fd);

			{
				ElfN_Shdr strtab;
				fseek(fd, shOffset + section.sh_link * sizeof(ElfN_Shdr), SEEK_SET);
				fread(&strtab, 1, sizeof(ElfN_Shdr), fd);

				names = malloc(strtab.sh_size);
				fseek(fd, strtab.sh_offset, SEEK_SET);
				fread(names, 1, strtab.sh_size, fd);

				fseek(fd, section.sh_offset, SEEK_SET);
			}

			uint16_t count = section.sh_size;
			while(count > 0)
			{
				ElfN_Sym sym;
				fread(&sym, 1, sizeof(ElfN_Sym), fd);

				if(sym.st_name == 0)
					; //ignore
				else if(ELFN_ST_TYPE(sym.st_info) == STT_FUNC)
					retrieveFunction(&section, &sym, fd, names, handler);
				//TODO inplement STT_OBJECT

				count--;
			}

			free(names);
			fseek(fd, sectionPos, SEEK_SET);
		}

		shCount--;
	}
}

static void initialHandler(functioninfo_t *func, FILE *fd)
{
	functioninfo_t *info = malloc(sizeof(functioninfo_t));
	memcpy(info, func, sizeof(functioninfo_t));

	info->name = strdup(info->name);
	info->next = knownFunctions;
	knownFunctions = info;
}

static void compareHandler(functioninfo_t *func, FILE *fd)
{
	functioninfo_t *curr = knownFunctions;
	while(curr != NULL)
	{
		if(strcmp(curr->name, func->name) == 0)
		{
			if(memcmp(curr->digest, func->digest, 16) != 0)
			{
				size_t size = (func->size & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
				uint8_t *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
									MAP_32BIT | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				assert(ptr != NULL);

				fread(ptr, 1, size, fd);
				//TODO link new function

				//for now we use dlsym later we should parse the .symtab section of the
				//executable ourselves to ensure we also capture local functions
				patchFunction(dlsym(NULL, curr->name), ptr);
				memcpy(curr->digest, func->digest, 16);
			}

			return;
		}

		curr = curr->next;
	}
}

void hotswap_init()
{
	char *executable = getenv("HOTSWAP_EXECUTABLE");
	retrieveFunctions(executable, initialHandler);

	//TODO watch files in dirname(executable) on change call
	//retrieveFunctions(<changed file>, compareHandler);
}

//for testing
int main(int argc, char **argv)
{
	if(argc != 2)
	{
		printf("Usage: %s <file>\n", argv[0]);
		return 1;
	}

	retrieveFunctions(argv[1], initialHandler);

	printf("Found functions:\n");
	functioninfo_t *curr = knownFunctions;
	while(curr != NULL)
	{
		printf("    %16lX | %s\n", (uint64_t)curr->address, curr->name);
		curr = curr->next;
	}

	return 0;
}
