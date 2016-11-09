#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <elf.h>
#include <dlfcn.h>
#include <pthread.h>
#include <mhash.h>

#include <libgen.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/inotify.h>

//TODO auto determine these
#define ElfN_Ehdr Elf64_Ehdr
#define ElfN_Shdr Elf64_Shdr
#define ElfN_Sym Elf64_Sym
#define ElfN_Rel Elf64_Rel
#define ElfN_Rela Elf64_Rela
#define ELFN_ST_TYPE(val) ELF64_ST_TYPE(val)
#define ELFN_R_TYPE(val) ELF64_R_TYPE(val)

//TODO use getpagesize() ?
#define PAGE_SIZE 4096

//TODO is there a header file that already defines these?
#define R_X86_64_64 1
#define R_X86_64_PC32 2
#define R_X86_64_32 10
#define R_X86_64_32S 11

typedef struct symbolinfo
{
	unsigned char digest[16];
	char *name;
	void *address;
	size_t size;
	struct symbolinfo *next;
} symbolinfo_t;

typedef struct relinfo
{
	uintptr_t address;
	uint8_t type; //see System V amd64 ABI (page 70)
	uint8_t size : 4;
	uint8_t isRelative : 1;
	struct relinfo *next;
} relinfo_t;

bool patchedPages[512] = {false};
static uint8_t patchBuff[PAGE_SIZE];

symbolinfo_t *knownSymbols = NULL;
relinfo_t *knownRels = NULL;

static void patchFunction(uint8_t *func, uint8_t *newFunc)
{
	uint8_t *aligned = (uint8_t *)((uint64_t)func & ~0xFFF);
	if(!patchedPages[(uintptr_t)aligned / 4096])
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

static void retrieveSymbol(uintptr_t shOffset, ElfN_Sym *sym, FILE *fd,
	char *names, void (*handler)(symbolinfo_t *, FILE *))
{
	MHASH td;
	td = mhash_init(MHASH_MD5);
	assert(td != MHASH_FAILED);

	long oldPos = ftell(fd);
	long codePos;

	{
		fseek(fd, shOffset + sym->st_shndx * sizeof(ElfN_Shdr), SEEK_SET);

		ElfN_Shdr codeSec;
		assert(fread(&codeSec, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

		codePos = sym->st_value - codeSec.sh_addr + codeSec.sh_offset;
	}

	fseek(fd, codePos, SEEK_SET);

	uint8_t *buff = malloc(sym->st_size);
	assert(fread(buff, 1, sym->st_size, fd) == sym->st_size);

	relinfo_t *curr = knownRels;
	while(curr != NULL)
	{
		if(curr->address > sym->st_value
			&& curr->address < sym->st_value + sym->st_size)
		{
			switch(curr->size)
			{
				case 1:
					*(uint8_t *)(curr->address - sym->st_value + buff) = 0;
					break;
				case 2:
					*(uint16_t *)(curr->address - sym->st_value + buff) = 0;
					break;
				case 4:
					*(uint32_t *)(curr->address - sym->st_value + buff) = 0;
					break;
				case 8:
					*(uint64_t *)(curr->address - sym->st_value + buff) = 0;
					break;
			}
		}
		curr = curr->next;
	}

	mhash(td, buff, sym->st_size);

	symbolinfo_t info;
	mhash_deinit(td, info.digest);
	info.name = names + sym->st_name;
	info.address = (void *)sym->st_value;
	info.size = sym->st_size;
	info.next = NULL;

	fseek(fd, codePos, SEEK_SET);
	handler(&info, fd);

	fseek(fd, oldPos, SEEK_SET);
}

static void retrieveRels(int count, bool hasAddend, FILE *fd)
{
	while(count > 0)
	{
		ElfN_Rela rel;
		int size = hasAddend ? sizeof(ElfN_Rela) : sizeof(ElfN_Rel);
		assert(fread(&rel, 1, size, fd) == size);



		relinfo_t *info = malloc(sizeof(relinfo_t));
		assert(info != NULL);
		info->type = ELFN_R_TYPE(rel.r_info);
		info->address = rel.r_offset;

		switch(info->type)
		{
			case R_X86_64_64:
				info->size = 8;
				info->isRelative = false;
				break;
			case R_X86_64_32:
			case R_X86_64_32S:
				info->size = 4;
				info->isRelative = false;
				break;
			case R_X86_64_PC32:
				info->size = 4;
				info->isRelative = true;
				break;
			default:
				//keep them but assert(0) if they appear in a function that needs to be relocated
				info->size = 0;
				info->type = (uint8_t)-1;
		}

		info->next = knownRels;
		knownRels = info;

		printf("parsed rel at %p | type %d | size %d\n", info->address, info->type, info->size);

		count--;
	}
}

static void retrieveSymbols(char *file, bool rememberRels, void (*handler)(symbolinfo_t *, FILE *))
{
	FILE *fd = fopen(file, "r");
	assert(fd != NULL);

	uint16_t count;
	uintptr_t shOffset;

	{
		ElfN_Ehdr header;
		assert(fread(&header, 1, sizeof(ElfN_Ehdr), fd) == sizeof(ElfN_Ehdr));
		count = header.e_shnum;
		shOffset = header.e_shoff;

		fseek(fd, shOffset, SEEK_SET);
	}

	ElfN_Shdr section;
	long symPos = -1;

	while(count > 0)
	{
		assert(fread(&section, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

		if(section.sh_type == SHT_SYMTAB)
		{
			symPos = ftell(fd) - sizeof(ElfN_Shdr);
		}
		else if(rememberRels && (section.sh_type == SHT_RELA || section.sh_type == SHT_REL))
		{
			int count = section.sh_size / (section.sh_type == SHT_RELA ? sizeof(ElfN_Rela) : sizeof(ElfN_Rel));
			long oldPos = ftell(fd);

			fseek(fd, section.sh_offset, SEEK_SET);
			retrieveRels(count, section.sh_type == SHT_RELA, fd);
			fseek(fd, oldPos, SEEK_SET);
		}

		count--;
	}

	char *names;

	assert(symPos >= 0);
	fseek(fd, symPos, SEEK_SET);
	assert(fread(&section, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

	{
		ElfN_Shdr strtab;
		fseek(fd, shOffset + section.sh_link * sizeof(ElfN_Shdr), SEEK_SET);
		assert(fread(&strtab, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

		names = malloc(strtab.sh_size);
		fseek(fd, strtab.sh_offset, SEEK_SET);
		assert(fread(names, 1, strtab.sh_size, fd) == strtab.sh_size);
	}

	fseek(fd, section.sh_offset, SEEK_SET);
	count = section.sh_size / sizeof(ElfN_Sym);
	while(count > 0)
	{
		ElfN_Sym sym;
		assert(fread(&sym, 1, sizeof(ElfN_Sym), fd) == sizeof(ElfN_Sym));

		int type = ELFN_ST_TYPE(sym.st_info);
		if(sym.st_name != 0 && sym.st_size != 0 && (type == STT_FUNC || type == STT_OBJECT))
			retrieveSymbol(shOffset, &sym, fd, names, handler);

		count--;
	}

	free(names);
	fclose(fd);
}

static void initialHandler(symbolinfo_t *sym, FILE *fd)
{
	symbolinfo_t *info = malloc(sizeof(symbolinfo_t));
	assert(info != NULL);

	memcpy(info->digest, sym->digest, 16);
	info->name = strdup(sym->name);
	info->address = sym->address;;
	info->size = sym->size;
	info->next = knownSymbols;
	knownSymbols = info;
}

static void compareHandler(symbolinfo_t *sym, FILE *fd)
{
	symbolinfo_t *curr = knownSymbols;
	while(curr != NULL)
	{
		if(strcmp(curr->name, sym->name) == 0)
		{
			if(memcmp(curr->digest, sym->digest, 16) != 0)
			{
				assert(curr->address != NULL);

				size_t size = (sym->size & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
				uint8_t *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
									MAP_32BIT | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				assert(ptr != NULL);

				assert(fread(ptr, 1, sym->size, fd) == sym->size);
				//TODO link new function

				patchFunction(curr->address, ptr);
				memcpy(curr->digest, sym->digest, 16);
			}

			return;
		}

		curr = curr->next;
	}
}

void *hotswap_worker(char *path)
{
	assert(dirname(path) == path); //TODO - watching only the file doesnt work?
	int notify = inotify_init();
	int watch = inotify_add_watch(notify, path, IN_CLOSE_WRITE);

	struct inotify_event *event = malloc(sizeof(struct inotify_event) + NAME_MAX + 1);
	assert(event != NULL);

	int pathLen = strlen(path);
	char *fileName = path + pathLen + 1;
	path[pathLen] = '/';

	while(true)
	{
		read(notify, event, sizeof(struct inotify_event) + NAME_MAX + 1);
		assert(event->wd == watch);
		assert(event->mask == IN_CLOSE_WRITE);

		if(event->len > 0 && strcmp(event->name, fileName) == 0)
			retrieveSymbols(path, false, compareHandler);
	}

	return NULL; //doh
}

extern void hotswap_init() __attribute__((constructor));
void hotswap_init()
{
	char *path = malloc(PATH_MAX);
	assert(path != 0);
	assert(readlink("/proc/self/exe", path, PATH_MAX) != -1);

	retrieveSymbols(path, true, initialHandler);

	pthread_t worker;
	pthread_create(&worker, NULL, (void *)hotswap_worker, path);
	pthread_detach(worker);
}
