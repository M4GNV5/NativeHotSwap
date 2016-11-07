#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

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

//TODO use getpagesize() ?
#define PAGE_SIZE 4096

typedef struct functioninfo
{
	unsigned char digest[16];
	char *name;
	void *address;
	size_t size;
	struct functioninfo *next;
} symbolinfo_t;

bool patchedPages[512] = {false};
static uint8_t patchBuff[PAGE_SIZE];

symbolinfo_t *knownSymbols = NULL;

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

static void retrieveFunction(uintptr_t shOffset, ElfN_Sym *sym, FILE *fd,
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

static void retrieveObject(uintptr_t shOffset, ElfN_Sym *sym, FILE *fd,
	char *names, void (*handler)(symbolinfo_t *, FILE *))
{
	long oldPos = ftell(fd);
	long valPos;

	{
		fseek(fd, shOffset + sym->st_shndx * sizeof(ElfN_Shdr), SEEK_SET);

		ElfN_Shdr valInitSec;
		assert(fread(&valInitSec, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

		valPos = sym->st_value - valInitSec.sh_addr + valInitSec.sh_offset;
	}

	symbolinfo_t info;
	memset(info.digest, 0, 16);
	info.name = names + sym->st_name;
	info.address = (void *)sym->st_value;
	info.size = sym->st_size;
	info.next = NULL;

	fseek(fd, valPos, SEEK_SET);
	handler(&info, fd);

	fseek(fd, oldPos, SEEK_SET);
}

static void retrieveSymbols(char *file, void (*handler)(symbolinfo_t *, FILE *))
{
	FILE *fd = fopen(file, "r");
	assert(fd != NULL);

	uint16_t shCount;
	uintptr_t shOffset;

	{
		ElfN_Ehdr header;
		assert(fread(&header, 1, sizeof(ElfN_Ehdr), fd) == sizeof(ElfN_Ehdr));
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
				assert(fread(&strtab, 1, sizeof(ElfN_Shdr), fd) == sizeof(ElfN_Shdr));

				names = malloc(strtab.sh_size);
				fseek(fd, strtab.sh_offset, SEEK_SET);
				assert(fread(names, 1, strtab.sh_size, fd) == strtab.sh_size);

				fseek(fd, section.sh_offset, SEEK_SET);
			}

			uint16_t count = section.sh_size / sizeof(ElfN_Sym);
			while(count > 0)
			{
				ElfN_Sym sym;
				assert(fread(&sym, 1, sizeof(ElfN_Sym), fd) == sizeof(ElfN_Sym));

				if(sym.st_name == 0 || sym.st_size == 0)
					; //ignore
				else if(ELFN_ST_TYPE(sym.st_info) == STT_FUNC)
					retrieveFunction(shOffset, &sym, fd, names, handler);
				else if(ELFN_ST_TYPE(sym.st_info) == STT_OBJECT)
					retrieveObject(shOffset, &sym, fd, names, handler);

				count--;
			}

			free(names);
			fseek(fd, sectionPos, SEEK_SET);
		}

		shCount--;
	}
}

static void initialHandler(symbolinfo_t *sym, FILE *fd)
{
	symbolinfo_t *info = malloc(sizeof(symbolinfo_t));
	assert(info != NULL);

	memcpy(info->digest, sym->digest, 16);
	info->name = strdup(sym->name);
	info->address = NULL;
	info->size = sym->size;
	info->next = knownSymbols;
	knownSymbols = info;
}

static void executableHandler(symbolinfo_t *sym, FILE *fd)
{
	symbolinfo_t *curr = knownSymbols;
	while(curr != NULL)
	{
		if(strcmp(curr->name, sym->name) == 0)
		{
			curr->address = sym->address;
			return;
		}
		curr = curr->next;
	}
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
	int pathLen = strlen(path);
	int notify = inotify_init();
	int watch = inotify_add_watch(notify, path, IN_CLOSE_WRITE);
	struct inotify_event *event = malloc(sizeof(struct inotify_event) + NAME_MAX + 1);
	assert(event != NULL);

	while(true)
	{
		read(notify, event, sizeof(struct inotify_event) + NAME_MAX + 1);
		assert(event->wd == watch);
		assert(event->mask == IN_CLOSE_WRITE);

		if(event->len > 0 && strcmp(event->name + strlen(event->name) - 2, ".o") == 0)
		{
			path[pathLen] = '/';
			strcpy(path + pathLen + 1, event->name);
			retrieveSymbols(path, compareHandler);
		}
	}

	return NULL; //doh
}

extern void hotswap_init() __attribute__((constructor));
void hotswap_init()
{
	char *executable = getenv("HOTSWAP_EXECUTABLE");
	assert(executable != NULL);

	DIR *dp;
	struct dirent *curr;

	char *path = malloc(strlen(executable) + 256);
	assert(path != NULL);
	strcpy(path, executable);
	strcpy(path, dirname(path));
	int pathLen = strlen(path);

	dp = opendir(path);
	assert(dp != NULL);

	while(curr = readdir(dp))
	{
		if(curr->d_type == DT_REG && strcmp(curr->d_name + strlen(curr->d_name) - 2, ".o") == 0)
		{
			path[pathLen] = '/';
			strcpy(path + pathLen + 1, curr->d_name);
			retrieveSymbols(path, initialHandler);
		}
	}

	closedir(dp);
	path[pathLen] = 0;

	retrieveSymbols(executable, executableHandler);

	pthread_t worker;
	pthread_create(&worker, NULL, (void *)hotswap_worker, path);
	pthread_detach(worker);
}
