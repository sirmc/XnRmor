#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <map>
#include <assert.h>

#define ERR -1

GElf_Shdr injectSec_shdr,dyninstSec_shdr;                 /* Section Header */

uint64_t offset_to_addr(uint32_t offset, GElf_Shdr *sec)
{
	return sec->sh_addr + offset;
}

uint32_t addr_to_offset(uint64_t addr, GElf_Shdr *sec)
{
	if ((addr > (sec->sh_addr + sec->sh_size))||(addr < sec->sh_addr)){
		printf("Asking %lx from sec %lx-%lx at offset %lx\n",
				addr, sec->sh_addr, sec->sh_addr + sec->sh_size, sec->sh_offset);
		return (uint32_t)(-1);
	}
	return addr - sec->sh_addr + sec->sh_offset;
}


class CCallSite;
class CFunction;
std::map<uint64_t,CCallSite*> callsite_map;
std::map<uint64_t, CFunction*> function_map;

class CCallSite{
	public:
		uint64_t addr;
		uint64_t target;
		uint32_t push_size;
		uint32_t call_size;
		bool inlined;
		bool processed;
	public:
		CCallSite(uint64_t addr, uint32_t push_size, uint32_t call_size)
		{
			this->addr = addr;
			this->push_size = push_size;
			this->call_size = call_size;
			this->inlined = false;
			this->processed = false;
			this->target = 0;
		};
		virtual ~CCallSite() {};
		void setInline(bool inlined) {this->inlined = inlined;};
		void setTarget(uint64_t tar) {this->target = tar;};
};

class CFunction{
	public:
		uint8_t *content;
		uint32_t size;
		uint64_t addr;
		uint64_t callsite_list[1000];
		uint32_t nr_callsite;
		bool disable;
	public:
		CFunction(uint64_t addr, uint32_t size)
		{
			this->addr = addr;
			this->size = size;
			this->nr_callsite = 0;
			this->content = NULL;
			this->disable = false;
		};
		void AddCallSite(uint64_t callsite) { callsite_list[nr_callsite] = callsite; nr_callsite++;};
		void setContent(uint8_t* ctxt) {this->content = ctxt;};
		uint32_t patch(int fd, uint32_t curr_offset, uint64_t ret_addr)
		{
			char sub_esp[4] = {0x48,0x83,0xEC,0x08};
			char add_esp[4] = {0x48,0x83,0xC4,0x08};
			char jmp_back[5] = {0xe9,0x00,0x00,0x00,0x00};
			uint8_t plt_call_payload[10];
			uint8_t payload[256];
			int32_t ret_operand,jmp_operand;
			int32_t *plt_operand;
			uint32_t i, offset, jmp_offset;
			uint32_t plt_locate; //plt here means dyninst PLT handler
			uint64_t jmp_target, callsite_addr;
			CFunction *cfunc;
			CCallSite *callsite;


			//1. patch itself into place
			lseek(fd, curr_offset + injectSec_shdr.sh_offset, SEEK_SET);
			write(fd,sub_esp,4);
			write(fd,this->content,this->size);
			write(fd,add_esp,4);
			ret_operand = ret_addr - offset_to_addr(curr_offset + 13 + this->size,&injectSec_shdr);
			memcpy((void*)(jmp_back+1),&ret_operand,4);
			write(fd,jmp_back,5);
			//2. Base on inlined address, adjust the plt call to lib
			for (i=0;i<nr_callsite;i++){
				callsite = callsite_map[this->callsite_list[i]];
				plt_locate = callsite->addr - this->addr + curr_offset + 4 - callsite->call_size;
				lseek(fd, plt_locate + injectSec_shdr.sh_offset, SEEK_SET);
				read(fd, plt_call_payload, callsite->call_size);
				assert(plt_call_payload[0] == 0xff);
				assert(plt_call_payload[1] == 0x15);
				plt_operand = (int32_t*)(&plt_call_payload[2]);
				printf("At callsite %lx, target offset is %lx, target : %lx\n",
						callsite->addr-callsite->call_size, *plt_operand,
						callsite->addr + *plt_operand);
				callsite_addr = callsite->addr - this->addr + offset_to_addr(curr_offset+4,&injectSec_shdr);
				(*plt_operand) = (callsite->addr + *plt_operand) - callsite_addr;
				lseek(fd, plt_locate + injectSec_shdr.sh_offset, SEEK_SET);
				write(fd, plt_call_payload, callsite->call_size);
			}
			//3. For all callsite which need to be inlined, inline them.
			offset = curr_offset + 13 + this->size;
			for (i=0;i<nr_callsite;i++){
				callsite = callsite_map[this->callsite_list[i]];
				if ((callsite->inlined)&&(!callsite->processed)){
					if (!function_map[callsite->target]->disable){
						callsite->processed = true;
						callsite_addr = (callsite->addr - this->addr) + 4 + offset_to_addr(curr_offset,&injectSec_shdr);
						jmp_target = offset_to_addr(offset,&injectSec_shdr);
						jmp_operand = jmp_target - (callsite_addr - callsite->push_size - callsite->call_size + 5);
						jmp_offset = addr_to_offset(callsite_addr - callsite->push_size - callsite->call_size ,&injectSec_shdr);
						if (jmp_offset==(uint32_t)(-1)){
							printf("Alert jmp_offset not found, callsite : %lx\n",callsite_addr);
							callsite->processed = false;
							continue;
						}
						lseek(fd, jmp_offset,SEEK_SET);
						memset(payload,0x90,callsite->push_size + callsite->call_size + 5);
						payload[0] = 0xe9;
						memcpy((void*)(payload+1),(void*)(&jmp_operand),4);
						write(fd, payload, callsite->push_size + callsite->call_size + 5);
						//inlined the target function
						cfunc = function_map[callsite->target];
						assert(cfunc->content!=NULL);
						offset = cfunc->patch(fd,offset,callsite_addr + 5);
						callsite->processed = false;
					}
				}
			}
			printf("=====================New offset %lx ===================\n",offset);
			return offset;
		};
};

int patch(int fd)
{
	std::map<uint64_t,CCallSite*>::iterator iter;
	CCallSite *callsite;
	CFunction *cfunc;
	uint32_t offset, jmp_offset;
	uint64_t jmp_target;
	int32_t jmp_operand;
	uint8_t payload[256];

	offset = 0;
	
	for (iter = callsite_map.begin();iter!=callsite_map.end();iter++)
	{
		callsite = iter->second;
		if (callsite->inlined){
			if (!function_map[callsite->target]->disable){
				callsite->processed = true;
				//first adjust the call instruction into jmp.
				jmp_target = offset_to_addr(offset,&injectSec_shdr);
				jmp_operand = jmp_target - (callsite->addr - callsite->push_size - callsite->call_size + 5);
				jmp_offset = addr_to_offset(callsite->addr - callsite->push_size - callsite->call_size ,&dyninstSec_shdr);
				if (jmp_offset==(uint32_t)(-1)){
					callsite->processed = false;
					continue;
				}
				lseek(fd, jmp_offset,SEEK_SET);
				memset(payload,0x90,callsite->push_size + callsite->call_size + 5);
				payload[0] = 0xe9;
				memcpy((void*)(payload+1),(void*)(&jmp_operand),4);
				write(fd, payload, callsite->push_size + callsite->call_size + 5);
				//inlined the target function
				cfunc = function_map[callsite->target];
				assert(cfunc->content!=NULL);
				offset = cfunc->patch(fd,offset,callsite->addr + 5);
				callsite->processed = false;
			}
		}

	}
	return 0;
}

void setContent(uint64_t sec_start, uint64_t sec_size, uint64_t sec_offset, int fd)
{
	std::map<uint64_t, CFunction*>::iterator iter;
	CFunction* cfunc;
	uint8_t *payload;

	for (iter = function_map.begin(); iter!=function_map.end(); iter++)
	{
		cfunc = iter->second;
		if ((cfunc->addr >= sec_start)&&(cfunc->addr < sec_start + sec_size)){
			payload = (uint8_t*)malloc(cfunc->size);
			lseek(fd,sec_offset + (cfunc->addr - sec_start),SEEK_SET);
			read(fd, (void*)payload,cfunc->size);
			cfunc->setContent(payload);
			while ((payload[cfunc->size-1] == 0x0)&&(cfunc->size>1)) cfunc->size -=1;
			if (cfunc->size < 1){
				printf("%lx\n",cfunc->addr);
				cfunc->disable = true;
			}
			if (payload[cfunc->size-1] != 0xc3){
				printf("Alert Func %lx not end by retn\n",cfunc->addr);
				cfunc->disable = true;
			}
			else if (payload[cfunc->size-2] == 0xf3){
				printf("Alert Func %lx end via rep retn\n",cfunc->addr);
				cfunc->disable = true;
			}
			payload[cfunc->size-1] = 0x90; //nop the ret instruction
		}
	}
}

void read_callsite_info()
{
	FILE* pfile;
	char buf[256];
	uint64_t addr, func_addr;
	int push_size,call_size,size;
	CCallSite *callsite;
	CFunction *cfunc;
	std::map<uint64_t,CCallSite*>::iterator iter;

	pfile = fopen("./callsite.all","r");
	while (fgets(buf,255,pfile))
	{
		sscanf(buf,"%lx,push_size=%d,call_size=%d\n",&addr, &push_size,&call_size);
		callsite = new CCallSite(addr,push_size,call_size);
		callsite_map[addr] = callsite;
	}
	fclose(pfile);

	pfile = fopen("./callsite.inline","r");
	while (fgets(buf,255,pfile))
	{
		sscanf(buf,"%lx-->%lx,%d\n",&addr, &func_addr ,&size);
		cfunc = new CFunction(func_addr,size);
		if (size > 10*4096){
			printf("Too big function : %lx\n",func_addr);
			cfunc->disable = true;
		};
		//if (callsite_map.find(addr) == callsite_map.end())
		//	continue;
		printf("Handling buf : %s, cfunc : %p, callsite : %lx\n",buf, cfunc,addr);
		callsite_map[addr]->setInline(true);
		callsite_map[addr]->setTarget(func_addr);
		function_map[func_addr] = cfunc;
		for (iter=callsite_map.begin();iter!=callsite_map.end();iter++){
			callsite = iter->second;
			if ((callsite->addr >= cfunc->addr)and(callsite->addr < cfunc->addr+cfunc->size))
				cfunc->AddCallSite(callsite->addr);
		}
		printf("Done\n");
	}
	fclose(pfile);
}

int main(int argc, char** argv)
{
	int fd; 		// File Descriptor
	char *base_ptr;		// ptr to our object in memory
	char *file = argv[1];	// filename
	struct stat elf_stats;	// fstat struct
	GElf_Shdr shdr;                 /* Section Header */
	Elf_Scn *scn;                   /* Section Descriptor */
	Elf64_Ehdr *elf_header;		/* ELF header */
	Elf *elf;                       /* Our Elf pointer for libelf */

	if (argc !=2)
	{
		printf("Usage : %s file-name\n",argv[0]);
		return ERR;
	}

	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		printf("Error on libelf initialization\n");
		return ERR;
	}
	
	read_callsite_info();

	if((fd = open(file, O_RDWR)) == ERR)
	{
		printf("couldnt open %s\n", file);
		return ERR;
	}

	if((fstat(fd, &elf_stats)))
	{
		printf("could not fstat %s\n", file);
		close(fd);
		return ERR;
	}

	if((base_ptr = (char *) malloc(elf_stats.st_size)) == NULL)
	{
		printf("could not malloc\n");
		close(fd);
		return ERR;
	}

	if((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size)
	{
		printf("could not read %s\n", file);
		free(base_ptr);
		close(fd);
		return ERR;
	}
	elf_header = (Elf64_Ehdr *) base_ptr;	// point elf_header at our object in memory
	elf = elf_begin(fd, ELF_C_READ, NULL);	// Initialize 'elf' pointer to our file descriptor
	if (!elf)
		printf("Fail to begin\n");
	scn = NULL;
	while((scn = elf_nextscn(elf, scn)) != NULL)
	{
		gelf_getshdr(scn, &shdr);
		setContent(shdr.sh_addr,shdr.sh_size,shdr.sh_offset,fd);
		if (strcmp(elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name),".dyninstInst")==0){
			dyninstSec_shdr = shdr;

		}
		if (strcmp(elf_strptr(elf, elf_header->e_shstrndx, shdr.sh_name),"inject")==0){
			injectSec_shdr = shdr;
		}
	}
//	dump_func();
	patch(fd);
	close(fd);
	return 0;
}
