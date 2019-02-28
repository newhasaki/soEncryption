#include <jni.h>
#include <string>
#include <elf.h>
#include <sys/unistd.h>
#include <sys/mman.h>

typedef struct {
    size_t code_offset;
    size_t size;
}funInfo;

unsigned long get_lib_addr(char* libname) __attribute__((visibility("hidden"))); //符号隐藏
static  unsigned int ELFHash(char *key); //,也可以直接声明为static隐藏符号
static void deCode();

extern "C" JNIEXPORT jstring JNICALL
Java_com_hask_pc_soencryption_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

JNIEXPORT jint  JNICALL JNI_OnLoad(JavaVM* vm, void* reserved){
    deCode();

    return JNI_VERSION_1_6;
}

static  unsigned int ELFHash(char *key)
{
    unsigned int hash = 0;
    unsigned int g = 0;

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

static funInfo getFunInfo(unsigned long addr, char* name){
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)addr;
    Elf32_Phdr* phdr = (Elf32_Phdr*)(ehdr->e_phoff + addr);
    Elf32_Dyn* dyn;
    for(size_t i = 0;i<ehdr->e_phnum;++i){
        if(PT_DYNAMIC == phdr->p_type){
            dyn = (Elf32_Dyn*)(phdr->p_vaddr + addr);
            break;
        }
        phdr++;
    }


    size_t dyncount = phdr->p_memsz/ sizeof(Elf32_Dyn);
    size_t hashoff = 0;
    size_t symtaboff = 0;
    size_t strtaboff = 0;

    for(size_t i = 0;i<dyncount;++i){
        if(DT_HASH == dyn->d_tag){
            hashoff = dyn->d_un.d_ptr;
        }else if(DT_SYMTAB == dyn->d_tag){
            symtaboff = dyn->d_un.d_ptr;
        }else if(DT_STRTAB == dyn->d_tag){
            strtaboff = dyn->d_un.d_ptr;
        }
        dyn++;
    }

    unsigned long eflag = ELFHash(name);
    Elf32_Word* bucketchain = (Elf32_Word*)(hashoff + addr);
    Elf32_Word bucket_count =  bucketchain[0];
    Elf32_Word chain_count = bucketchain[1];
    Elf32_Word* bucket = &bucketchain[2];
    Elf32_Word* chain = &bucketchain[2 + bucket_count];


    Elf32_Sym* sym = (Elf32_Sym*)(symtaboff+ addr);
    char* str = (char*)(strtaboff + addr);

    funInfo fun_info;
    size_t mod = eflag%bucket_count;
    for(size_t i = bucket[mod];i!=0;i = chain[i]){
        char* findstr = (char*)(str + sym[i].st_name);
        if(!strcmp(findstr,name)){
            size_t code_revision = sym[i].st_value;
            if(code_revision&0x00000001){
                code_revision--;
            }
            fun_info.code_offset = code_revision;
            fun_info.size = sym[i].st_size;
            break;
        }
    }
    return fun_info;
}

static void deCode(){
    unsigned long libBase= get_lib_addr("libnative-lib");
    funInfo fun_info = getFunInfo(libBase,"Java_com_hask_pc_soencryption_MainActivity_stringFromJNI");

    size_t pagesize = (fun_info.code_offset/PAGE_SIZE + 1)*PAGE_SIZE;
    mprotect((void*)libBase, pagesize, PROT_EXEC|PROT_READ|PROT_WRITE);
    for(size_t i = 0;i < fun_info.size;++i){
        ((char*)(fun_info.code_offset + libBase))[i]^=0xA;
    }
    mprotect((void*)libBase,pagesize,PROT_EXEC|PROT_READ);
}

unsigned long get_lib_addr(char* libname){
    char buf[4096];
    char *temp;
    unsigned long ret;
    //获取pid
    int pd = getpid();
    //生成进程maps路径
    sprintf(buf,"/proc/%d/maps",pd);
    //打开maps文件
    FILE* fp = fopen(buf,"r");
    if(fp==NULL){
        puts("open fail");
        fclose(fp);
        return -1;
    }
    //按行读取
    while (fgets(buf, sizeof(buf),fp)){
        //根据目标函数名找到对应库信息
        if(strstr(buf,libname)){
            //字符串切割，返回库函数基地址
            temp = strtok(buf, "-");
            //将字符串转为无符号整数
            ret = strtoul(temp, NULL, 16);
            break;
        }
    }
    fclose(fp);
    return ret;
}