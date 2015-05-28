#include <stdio.h>

//dyninst header
#include "BPatch.h"
#include "BPatch_addressSpace.h" 
#include "BPatch_process.h" 
#include "BPatch_binaryEdit.h" 
#include "BPatch_function.h"
#include "BPatch_point.h"
#include "BPatch_flowGraph.h"
#include "BPatch_object.h"

#include "PatchCommon.h"
#include "PatchMgr.h"
#include "PatchModifier.h"

#include "Symtab.h"

//dynamorio header
#include "Register.h"
#include "dr_api.h"
#include <dr_defines.h>

//std header
#include <vector>
#include <set>

//Code Armor header
#include "CACustomSnippet.h"
#include "ca_defines.h"
#include "CADecoder.h"
#include "CADecoderDynamoRIO.h"


using namespace std;
using namespace Dyninst;
using namespace Dyninst::PatchAPI;
using namespace Dyninst::InstructionAPI;
using namespace Dyninst::SymtabAPI;

BPatch *bpatch = NULL;
BPatch_addressSpace *mainApp = NULL;
BPatch_image *mainImg = NULL;
PatchMgr::Ptr mainMgr;
CADecoder *mainDecoder;
BPatch_object *libArmorConvert = NULL;

BPatch_function* initFunc;

unsigned long counter = 0;
bool SHARED_LIB = false;
std::string binary;

//Our plt search is mod based, however, for dyninst,
//each source code file is a mod, so we have the flag here
//For a stripped binary, it only have one mod, this is not nessrary
bool PLT_INJECT_FLAG = false;
uint8_t pop_r10[2] = {0x41,0x5a};
uint8_t jmp_r10[3] = {0x41,0xff,0xe2};
uint8_t call_r10[3] = {0x41,0xff,0xd2};
uint8_t mov_offset_r11[10] = {0x49,0xbb,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
uint8_t add_r11_to_r10[3] = {0x4d,0x01,0xda};

uint8_t copy_trampline(void* ptr)
{
	memcpy(ptr,(void*)pop_r10,2);
	memcpy((void*)((uint64_t)ptr+2),(void*)mov_offset_r11,10);
	memcpy((void*)((uint64_t)ptr+12),(void*)add_r11_to_r10,3);
	memcpy((void*)((uint64_t)ptr+15),(void*)jmp_r10,3);
	return 18;
}

bool overwriteInstruction(PatchBlock *block, uint64_t addr, uint8_t* val, size_t nbytes)
{
	ParseAPI::Block *b = block->block();
	ParseAPI::SymtabCodeRegion *r = dynamic_cast<ParseAPI::SymtabCodeRegion*>(b->region());
	if (r == NULL) return false;
	Offset region_off = (Offset)r->getPtrToInstruction(addr) - (Offset)r->symRegion()->getPtrToRawData();
	bool success;
	success = r->symRegion()->patchData(region_off++, (void*)val, nbytes);
	return success;
}

void instrumentInstruction(void* addr, unsigned char *bytes, size_t nbytes,
        PatchFunction *func, PatchBlock *block)
{
	CACustomSnippet::Ptr pSnippet;
	uint8_t depie_raw_byte[MAX_RAW_INSN_SIZE];
	size_t depie_nbytes;
	uint8_t nop_payload[MAX_RAW_INSN_SIZE];

	Point* point = mainMgr->findPoint(Location::InstructionInstance(func, block, (Address)addr),Point::PreInsn, true);
    assert(point != NULL);
	depie_nbytes = mainDecoder->depie(depie_raw_byte);
	pSnippet = CACustomSnippet::create(new CACustomSnippet(depie_raw_byte,depie_nbytes));
	point->pushBack(pSnippet);

	memset(nop_payload,0x90,nbytes);
	overwriteInstruction(block,(uint64_t)addr, nop_payload, nbytes);
}

void instrumentCallIns(void* addr, unsigned char *bytes, size_t nbytes, PatchFunction *func, PatchBlock *block, bool indirect)
{
	/* 
	   !!!!! This is a modified version, now it only take the indirect call as target 
	   For direct call, it is very hard to convince dyninst remove the call edge,
	   so if needed, need to manully push the (ret address + 5) to jump over the orignal call instruction, and indirect jmp
	*/

	CACustomSnippet::Ptr pSnippet,callSnippet;
	uint8_t call_raw_byte[MAX_RAW_INSN_SIZE];
	uint8_t nop_payload[MAX_RAW_INSN_SIZE];
	size_t call_nbytes;

	Point* point = mainMgr->findPoint(Location::InstructionInstance(func, block, (Address)addr),Point::PreInsn, true);
    assert(point != NULL);

	if (!indirect) return;

	//prepare the snippet: push regs, push target
	call_nbytes = mainDecoder->CallToPush(call_raw_byte);
	//now pop target to r10 and call r10
	memcpy((void*)(&call_raw_byte[call_nbytes]),(void*)pop_r10,2);
	call_nbytes += 2;
	memcpy((void*)(&call_raw_byte[call_nbytes]),(void*)call_r10,3);
	call_nbytes += 3;
	
	pSnippet = CACustomSnippet::create(new CACustomSnippet(call_raw_byte,call_nbytes));
	point->pushBack(pSnippet);

	memset(nop_payload,0x90,nbytes);
	overwriteInstruction(block,(uint64_t)addr, nop_payload, nbytes);
	return;
}

void instrumentIndirectJmpIns(void* addr, unsigned char *bytes, size_t nbytes,
        PatchFunction *func, PatchBlock *block)
{
	static uint8_t add_rsp[7] = {0x48,0x81,0xc4,0x08,0x10,0x00,0x00}; 
	//unlike call instrumentation where r10,r11 are free to use, here r10 may be context sensitive.
	//We use stack to store the target. If want more safe, use %gs, or %fs(TLS) to store target
	//But in XnR project, we are not aimming for hiding code pointer
	static uint8_t jmp_rsp_mem[7] = {0xff,0xa4,0x24,0xf8,0xef,0xff,0xff};
	CACustomSnippet::Ptr pSnippet;
	uint8_t jmp_raw_byte[MAX_RAW_INSN_SIZE];
	size_t jmp_nbytes;
	BPatch_snippet *jmphandler;
	BPatch_Vector<BPatch_snippet*> emptyArgs;

	Point* point = mainMgr->findPoint(Location::InstructionInstance(func, block, (Address)addr),Point::PreInsn, true);
    assert(point != NULL);
	jmp_nbytes = mainDecoder->JmpToPush(jmp_raw_byte,false);
	memcpy((void*)(&jmp_raw_byte[jmp_nbytes]),(void*)add_rsp,7);
	jmp_nbytes += 7;
	memcpy((void*)(&jmp_raw_byte[jmp_nbytes]),(void*)jmp_rsp_mem,7);
	jmp_nbytes += 7;

	pSnippet = CACustomSnippet::create(new CACustomSnippet(jmp_raw_byte,jmp_nbytes));
	point->pushBack(pSnippet);
	
	//we do not nop the orignal indirect jmp, since no one should reach that point.
	return;
}

void instrumentBasicBlock(BPatch_function * function, BPatch_basicBlock *block)
{
    Instruction::Ptr iptr;
    void *addr;
    unsigned char bytes[MAX_RAW_INSN_SIZE];
    size_t nbytes, i;

    // iterate backwards (PatchAPI restriction)
    PatchBlock::Insns insns;
    PatchAPI::convert(block)->getInsns(insns);
    PatchBlock::Insns::reverse_iterator j;
    for (j = insns.rbegin(); j != insns.rend(); j++) {

        // get instruction bytes
        addr = (void*)((*j).first);
        iptr = (*j).second;
        nbytes = iptr->size();
        assert(nbytes <= MAX_RAW_INSN_SIZE);
        for (i=0; i<nbytes; i++) {
            bytes[i] = iptr->rawByte(i);
        }
        bytes[nbytes] = '\0';

        // apply filter
		mainDecoder->decode((uint64_t)addr,iptr);

		if (mainDecoder->isCall()&&mainDecoder->isCall_indirect())
		{
			instrumentCallIns(addr, bytes, nbytes,
					PatchAPI::convert(function), PatchAPI::convert(block),mainDecoder->isCall_indirect());
		}
		else if (mainDecoder->isIndirectJmp())
		{
			instrumentIndirectJmpIns(addr, bytes, nbytes,
					PatchAPI::convert(function), PatchAPI::convert(block));
		}
		else if (mainDecoder->needDepie())
		{
			instrumentInstruction(addr, bytes, nbytes,
					PatchAPI::convert(function), PatchAPI::convert(block));
		}
    }
}


void instrumentFunction(BPatch_function *function)
{
    std::set<BPatch_basicBlock*> blocks;
    std::set<BPatch_basicBlock*>::reverse_iterator b;
    BPatch_flowGraph *cfg = function->getCFG();
    cfg->getAllBasicBlocks(blocks);
    for (b = blocks.rbegin(); b != blocks.rend(); b++) {
        instrumentBasicBlock(function, *b);
    }
}

/*
  NOTE: when debug, try to turn it off. GDB not support the modification of plt table
  TODO: more friendly GDB interface.
  Instead of put everythin into the new plt table, should reserve the push/jmp instruction in orignal place
  The first indirect jmp need to redirect to the new table. 
  So if the first time plt invoked:
  plt_invoke->orig_plt_entry->new_plt_entry->indirect jmp to GOT table target->old_plt_entry push->old resolver->new resolver
  After that:
  plt_invoke->orig_plt_entry->new_plt_entry->GOT taget
*/
void instrumentPLTSection(BPatch_module* mod)
{
	BPatch_object* obj;
	SymtabAPI::Symtab *symObj;
	SymtabAPI::Region *pltReg;
	uint8_t *orig_plt,*new_plt;
	void *orig_addr,*new_addr;
	uint64_t orig_offset,new_offset,plt_size,depie_nbytes;
	uint32_t direct_offset;
	std::map<uint64_t,uint64_t> addr_map;
	uint8_t jmp_to_resolver[5] = {0xe9,0x00,0x00,0x00,0x00};

	if (PLT_INJECT_FLAG)
		return;
	
	//Get orignal plt 
	obj = mod->getObject();
	symObj = SymtabAPI::convert(obj);
	if (!symObj->findRegion(pltReg, std::string(".plt")))
		return;
	
	plt_size = pltReg->getMemSize();
	orig_plt = (uint8_t*)malloc(pltReg->getMemSize());
	memcpy(orig_plt,pltReg->getPtrToRawData(),pltReg->getMemSize());
	orig_addr = (void*)pltReg->getMemOffset();

	/*
	   A bit hacky, assumption here is each plt entry is 0x10 length, and
	   the first one is the resolver of plt. 
	   Steps:
	   1. Allocate buffer for relocated plt
	   2. Go entry by entry in plt to construct the new plt
	   3. Inject the relocated plt into rewrite binary
	   4. Redirect the orignal plt entry to the new one. 
	*/
	//Just preallocate a four page buffer, should be enough to contain the PLT
	new_plt = (uint8_t*)malloc(0x4000);
	
	orig_offset = 0;
	new_offset = 0;
	addr_map[orig_offset] = new_offset;
	//convert pushq in resolver
	mainDecoder->decode((uint64_t)orig_addr + orig_offset,(uint8_t*)((uint64_t)orig_plt+orig_offset),6);
	depie_nbytes = mainDecoder->depie((uint8_t*)((uint64_t)new_plt+new_offset));
	orig_offset += 6;
	new_offset += depie_nbytes;
	//convert jmpq in resolver
	mainDecoder->decode((uint64_t)orig_addr + orig_offset,(uint8_t*)((uint64_t)orig_plt+orig_offset),6);
	depie_nbytes = mainDecoder->JmpToPush((uint8_t*)((uint64_t)new_plt+new_offset),true);
	orig_offset += 6;
	new_offset += depie_nbytes;
	new_offset += copy_trampline((void*)((uint64_t)new_plt+new_offset));
	//copy the rest
	memcpy((void*)((uint64_t)new_plt+new_offset),(void*)((uint64_t)orig_plt+orig_offset),4);
	orig_offset += 4;
	new_offset += 4;
	
	//handle entry by entry
	while (orig_offset < pltReg->getMemSize()){
		addr_map[orig_offset] = new_offset;
		mainDecoder->decode((uint64_t)orig_addr + orig_offset,(uint8_t*)((uint64_t)orig_plt+orig_offset),6);
		depie_nbytes = mainDecoder->JmpToPush((uint8_t*)((uint64_t)new_plt+new_offset),true);
		orig_offset += 6;
		new_offset += depie_nbytes;
		new_offset += copy_trampline((void*)((uint64_t)new_plt+new_offset));
		
		//copy the push
		//The orignal address store in GOT is the push address. So add a jmp here for lazy resloving
		addr_map[orig_offset] = new_offset; 
		memcpy((void*)((uint64_t)new_plt+new_offset),(void*)((uint64_t)orig_plt+orig_offset),5);
		orig_offset += 5;
		
		new_offset += 5;
		//adjust the direct jmp (negative jmp use the binary complement)
		direct_offset = (uint32_t)(0x100000000 - new_offset - 5);
		memcpy((void*)(&jmp_to_resolver[1]),(void*)(&direct_offset),4);
		memcpy((void*)((uint64_t)new_plt+new_offset),(void*)(jmp_to_resolver),5);
		orig_offset += 5;
		new_offset += 5;
	}

	//Inject code to binary
	new_addr = ((BPatch_binaryEdit*)mainApp)->injectCode(new_offset, new_plt);
	fprintf(stderr,"New PLT table address : %p\n",new_addr);
	free(new_plt);

	//Patch the orignal plt table to redirect to the new plt table
	memset((void*)((uint64_t)orig_plt),0x90,plt_size);
	for (std::map<uint64_t,uint64_t>::iterator iter=addr_map.begin(); iter!=addr_map.end(); ++iter)
	{
		orig_offset = iter->first;
		new_offset = iter->second;
		direct_offset = (uint32_t)(new_offset+(uint64_t)new_addr - orig_offset - (uint64_t)orig_addr - 5);
		*(uint8_t*)(orig_plt+orig_offset) = 0xe9;
		memcpy((void*)((uint64_t)orig_plt+orig_offset+1),(void*)(&direct_offset),4);
	}
	pltReg->patchData(0,orig_plt,plt_size);
	free(orig_plt);

	PLT_INJECT_FLAG = true;
	return;
}

void instrumentModule(BPatch_module *module)
{
	char funcname[BUFFER_STRING_LEN];

	instrumentPLTSection(module);
	std::vector<BPatch_function *>* functions;
	functions = module->getProcedures();

	for (unsigned i = 0; i < functions->size(); i++) {
		BPatch_function *function = functions->at(i);
		function->getName(funcname, BUFFER_STRING_LEN);
		instrumentFunction(function);
	}
}

BPatch_function* getMutateeFunction(const char *name) {                                   
	BPatch_Vector<BPatch_function *> funcs;
	mainImg->findFunction(name, funcs, true, true, true);
	if (funcs.size() != 1)
		return NULL;
	return funcs.at(0); 
}                                                                                         

BPatch_function* getAnalysisFunction(const char *name) {
	return getMutateeFunction(name);                                                      
}


void instrumentApplication()
{
	std::vector<BPatch_module *>* modules;
	std::vector<BPatch_module *>::iterator m;
	BPatch_Vector<BPatch_point*> *entryMainPoints;
	BPatch_snippet *initCall;
	BPatch_Vector<BPatch_snippet*> emptyArgs;
	char mod_name[256];

	initFunc = getAnalysisFunction("_INST_init");
	//TODO should be replace to _start. Can achive this via symtab API. 
	//In our case, main also work, since the init function is lazily invoked, i.e., the first call/indirect jmp is the
	//triger to load init function, and the modified loader will init %gs for us. 
	//But still this is not clean
	if (getMutateeFunction("main")!=NULL){
		entryMainPoints = getMutateeFunction("main")->findPoint(BPatch_entry);
		initCall = new BPatch_funcCallExpr(*initFunc, emptyArgs);
		mainApp->insertSnippet(*initCall, *entryMainPoints, BPatch_callBefore);
	}

	modules = mainImg->getModules();
	for (m = modules->begin(); m!=modules->end(); m++){
		(*m)->getName(mod_name,256);
		fprintf(stderr,"<CODEARMOR> Load module : %s\n",mod_name);
		if (!(*m)->isSharedLib()){
			instrumentModule(*m);
		}
		else if (SHARED_LIB){
			if (binary.find(mod_name)!=std::string::npos)
				instrumentModule(*m);
		}
	}
}

int main(int argc, char** argv)
{
	BPatch_addressSpace *app;
	int is_bin_edit = !getenv("RT_EDIT");

	if (argc < 2) {
		fprintf(stderr, "Usage: %s proc_filename [args]\n",argv[0]);
			return 1;
	}

	binary = argv[1];

	bpatch = new BPatch;
	printf("Start editing %s\n",binary.c_str());
	if (is_bin_edit) {
		app = bpatch->openBinary(binary.c_str(), true);
	}
	else{
		app = bpatch->processCreate(binary.c_str(), (const char**)(argv+1));
	}
	assert(app);

	//config
	bpatch->setTrampRecursive(true);
	bpatch->setForceInstrumentation(true);
	bpatch->setSaveFPR(false);
	bpatch->setInstrStackFrames(false);
	bpatch->setLivenessAnalysis(true);
	bpatch->setTypeChecking(false);
	bpatch->setMergeTramp(true);

	mainApp = app;
	mainImg = mainApp->getImage();
	mainMgr = PatchAPI::convert(mainApp);
	libArmorConvert = ((BPatch_binaryEdit*)app)->loadLibrary("libarmorconvert.so");
	if (libArmorConvert == NULL){
		printf("ERROR : Unable to open libarmorconvert.so\n");
		exit(EXIT_FAILURE);
	}
	mainDecoder = new CADecoderDynamoRIO();

	instrumentApplication();
	
	if (is_bin_edit){
		binary += ".rewrite";
		printf("Writeing new binary to %s \n", binary.c_str());
		((BPatch_binaryEdit*)app)->writeFile(binary.c_str());
	}
	else{
		printf("Resuming process ...\n");
		((BPatch_process*)app)->continueExecution();
		while (!((BPatch_process*)app)->isTerminated()){
			bpatch->waitForStatusChange();
		}
	}
	printf("Done.\n");
	return(EXIT_SUCCESS);
}
