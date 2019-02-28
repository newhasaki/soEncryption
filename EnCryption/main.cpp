#include<stdio.h>
#include<stdlib.h>
#include<sys\stat.h>
#include"elf.h"
#include<vector>
using namespace std;

#define TEST_BIT0(addr)		(addr & 1)

typedef struct {
	size_t code_offset;
	size_t code_size;
}funInfo;

void entryCode(size_t code_base, size_t code_size);
int writeNewFile(char* path,char* buf,long file_size);
char* replaceStr(char* str, char* src_substr, char* dst_substr);
size_t ELFHash(char *key);

int main(int argc,char** argv)
{	
	char* target_funname = "Java_com_hask_pc_soencryption_MainActivity_stringFromJNI";
	FILE* fp = fopen("libnative-lib.so","rb");

	struct stat statbuf;
	stat("libnative-lib.so", &statbuf);
	long size = statbuf.st_size;
	
	char* buf = (char*)malloc(size);
	fread(buf, size , 1, fp);
	fclose(fp);

	Elf32_Ehdr* elf_hdr = (Elf32_Ehdr*)buf;

	//节头数组在文件中的偏移
	Elf32_Off shoff = elf_hdr->e_shoff;
	//节头数量
	Elf32_Half shnum = elf_hdr->e_shnum;
	
	Elf32_Shdr* shdr = (Elf32_Shdr*)((size_t)buf + shoff);
	Elf32_Off dyn_off = 0;
	Elf32_Word dyn_size = 0;
	//遍历节区，查找类型为DYNSYM的节区的偏移
	for (size_t i = 0; i < shnum; ++i) {
		if (SHT_DYNSYM == shdr[i].sh_type) {
			dyn_off = shdr[i].sh_offset;
			dyn_size = shdr[i].sh_size;
			break;
		}
	}
	
	//遍历节区，查找类型为DYNSTR的节区的偏移
	Elf32_Word strtab_off = 0;
	for (size_t i = 0; i < shnum; ++i) {
		if (SHT_STRTAB == shdr[i].sh_type) {
			strtab_off = shdr[i].sh_offset;
			break;
		}
	}

	Elf32_Word hashtab_off = 0;
	for (size_t i = 0; i < shnum; ++i) {
		if (SHT_HASH == shdr[i].sh_type) {
			hashtab_off = shdr[i].sh_offset;
			break;
		}
	}


	char* str = (char*)(strtab_off + (size_t)buf);


	//得到动态链接结构体数组
	Elf32_Sym* dyn_sym = (Elf32_Sym*)((size_t)buf + dyn_off);

	Elf32_Word dyn_sym_num = dyn_size / 16;

	funInfo fun_info;

	Elf32_Word* bucketchain = (Elf32_Word*)(hashtab_off + (size_t)buf);
	Elf32_Word nbucket = bucketchain[0];
	Elf32_Word nchain = bucketchain[1];

	Elf32_Word* bucket = (Elf32_Word*)&bucketchain[2];
	Elf32_Word* chain = (Elf32_Word*)&bucketchain[2 + nbucket];

	size_t eflag = ELFHash(target_funname);
	size_t mod = eflag%nbucket;

	for (size_t i = bucket[mod]; i != 0; i = chain[i]) {
		if (!strcmp(dyn_sym[i].st_name + str, target_funname)) {
			size_t code_revision = dyn_sym[i].st_value;
			if (TEST_BIT0(dyn_sym[i].st_value)) {
				code_revision--;
			}
			fun_info.code_offset = code_revision;
			fun_info.code_size = dyn_sym[i].st_size;
			break;
		}
	}
	//加密
	entryCode(fun_info.code_offset + (size_t)buf, fun_info.code_size);
	writeNewFile("newlibnative-lib.so", buf, size);

	free(buf);
	buf = NULL;
	return 0;
}


void entryCode(size_t code_base, size_t code_size) {
	for (size_t i = 0; i < code_size; ++i) {
		((char*)code_base)[i] = ((char*)code_base)[i] ^ 0xA;
	}
}

int writeNewFile(char* path, char* buf, long file_size){
	FILE* fp = fopen(path, "wb+");
	size_t size = fwrite(buf,file_size,1,fp);
	fclose(fp);
	return 1;
}


void freeStr(char*p) {
	free(p);
	p = nullptr;
}

size_t ELFHash(char *key)
{
	size_t hash = 0;
	size_t g = 0;

	while (*key)
	{
		hash = (hash << 4) + (*key++);
		g = hash & 0xf0000000L;
		if (g)
		{
			hash ^= (g >> 24);
			hash &= ~g;
		}
	}
	return hash;

}