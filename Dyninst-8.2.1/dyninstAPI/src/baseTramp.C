/*
 * See the dyninst/COPYRIGHT file for copyright information.
 * 
 * We provide the Paradyn Tools (below described as "Paradyn")
 * on an AS IS basis, and do not warrant its validity or performance.
 * We reserve the right to update, modify, or discontinue this
 * software at any time.  We shall have no obligation to supply such
 * updates or modifications or any other form of support to you.
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

// $Id: baseTramp.C,v 1.68 2008/09/03 06:08:44 jaw Exp $

#include "dyninstAPI/src/baseTramp.h"
#include "dyninstAPI/src/instP.h"
#include "dyninstAPI/src/addressSpace.h"
#include "dyninstAPI/src/dynThread.h"
#include "dyninstAPI/src/binaryEdit.h"
#include "dyninstAPI/src/registerSpace.h"
#include "dyninstAPI/src/ast.h"
#include "dyninstAPI/h/BPatch.h"
#include "debug.h"
#include "mapped_object.h"
#include "dyninstAPI/src/instPoint.h"
#include "Point.h"

using namespace Dyninst;
using namespace PatchAPI;

// Normal constructor
baseTramp::baseTramp() :
   point_(NULL),
   as_(NULL),
   funcJumpState_(cfj_unset),
   needsStackFrame_(false),
   threaded_(false),
   optimizationInfo_(false),
   savedFPRs(false),
   createdFrame(false),
   savedOrigAddr(false),
   createdLocalSpace(false),
   alignedStack(false),
   savedFlags(false),
   optimizedSavedRegs(false),
   suppressGuards(false),
   suppressThreads(false),
   spilledRegisters(false),
   stackHeight(0),
   skippedRedZone(false),
   wasFullFPRSave(false)
{
}

baseTramp::~baseTramp()
{
   //TODO: implement me
}

baseTramp *baseTramp::create(instPoint *p) {
   baseTramp *bt = new baseTramp();
   bt->point_ = p;
   return bt;
}

baseTramp *baseTramp::createForIRPC(AddressSpace *as) {
    // We use baseTramps to generate save and restore code for iRPCs
    // iRPCs don't have a corresponding instPoint so the AddressSpace
    // needs to be specified
    baseTramp *bt = new baseTramp();
    bt->as_ = as;
    return bt;
}

baseTramp *baseTramp::fork(baseTramp *parent, AddressSpace *child) {
   if (parent->point()) {
      instPoint *childPoint = instPoint::fork(parent->point(), child);
      baseTramp *newBT = childPoint->tramp();
      return newBT;
   }
   else {
      // bugger...
      assert(0 && "Illegal call to baseTramp::fork!");
      return NULL;
   }
}

void baseTramp::initializeFlags() {
   needsStackFrame_ = false;
   threaded_ = false;
   optimizationInfo_ = false;
   savedFPRs = false;
   createdFrame = false;
   savedOrigAddr = false;
   createdLocalSpace = false;
   alignedStack = false;
   savedFlags = false;
   optimizedSavedRegs = false;
   suppressGuards = false;
   suppressThreads = false;
   spilledRegisters = false;
   stackHeight = 0;
   skippedRedZone = false;
}

bool baseTramp::shouldRegenBaseTramp(registerSpace *rs)
{
#if !defined(cap_tramp_liveness)
   return false;
#endif

   int saved_unneeded = 0;
   unsigned actually_saved = 0;
   int needed_saved = 0;
   
   regalloc_printf("BT: checking for unneeded saved registers (in %p)\n", this);

   if (spilledRegisters && !createdLocalSpace)
      return true;

   pdvector<registerSlot *> &regs = rs->trampRegs();
   for (unsigned i = 0; i < regs.size(); i++) {
      registerSlot *reg = regs[i];
      regalloc_printf("[%s:%u] - checking reg (index %d, number %d, encoding %d)\n", __FILE__, 
		      __LINE__, i, reg->number, reg->encoding());

      if (reg->spilledState != registerSlot::unspilled) {
         regalloc_printf("[%s:%u] - reg %d saved\n", __FILE__, 
                         __LINE__, reg->number);
         actually_saved++;
      }
      if (definedRegs[reg->encoding()]) {
         regalloc_printf("[%s:%u] - reg %d used\n", __FILE__, 
                         __LINE__, reg->number);
         needed_saved++;
      }

      if ((reg->spilledState != registerSlot::unspilled) &&
          (!definedRegs[reg->encoding()]) &&
          (!reg->offLimits))
      {
         saved_unneeded++;
         regalloc_printf("[%s:%u] - baseTramp saved unneeded register %d, "
                         "suggesting regen (%d, %d, %d)\n", __FILE__, __LINE__, reg->number,
                         reg->spilledState,
                         (definedRegs[reg->encoding()] ? 1 : 0),
                         reg->offLimits);
      }
      if (!reg->liveState == registerSlot::spilled &&
          definedRegs[reg->encoding()])
      {
         regalloc_printf("[%s:%u] - Decided not to save a defined register %d. "
                         "App liveness?\n",  __FILE__, __LINE__, reg->number);         
      }
   }
   regalloc_printf("[%s:%u] - Should regen found %d unneeded saves\n",
                   __FILE__, __LINE__, saved_unneeded);
#if defined(arch_x86_64) || defined(arch_x86)
   if (proc()->getAddressWidth() == 4)
   {
      //No regen if we did a pusha and saved more regs than the 
      // X86_REGS_SAVE_LIMIT recommended limit.
      if (actually_saved == regs.size() &&
          needed_saved > X86_REGS_SAVE_LIMIT) {
         return false;
      }
   }
#endif
   return (saved_unneeded != 0);
}

bool baseTramp::generateCode(codeGen &gen,
                             Address baseInMutatee) {
   inst_printf("baseTramp %p ::generateCode(%p, 0x%x, %d)\n",
               this, gen.start_ptr(), baseInMutatee, gen.used());
   initializeFlags();

   doOptimizations();
    
   if (point_ &&
       point_->empty()) return true;

   gen.setPCRelUseCount(0);
   gen.setBT(this);
   if (instP()) {
      //iRPCs already have this set
      gen.setPoint(instP());
      gen.setRegisterSpace(registerSpace::actualRegSpace(instP()));
   }
   int count = 0;

   for (;;) {
      regalloc_printf("[%s:%u] - Beginning baseTramp generate iteration # %d\n",
                      __FILE__, __LINE__, ++count);
      codeBufIndex_t start = gen.getIndex();

      unsigned int num_patches = gen.allPatches().size();

      gen.beginTrackRegDefs();
      gen.rs()->initRealRegSpace();
      bool result = generateCodeInlined(gen, baseInMutatee);
      if (!result)
         return false;
      gen.endTrackRegDefs();

      definedRegs = gen.getRegsDefined();
      optimizationInfo_ = true;
      if (spilledRegisters) {
         spilledRegisters = gen.rs()->spilledAnything();
      }

      if (!shouldRegenBaseTramp(gen.rs())) {
         break;
      }
	  
      gen.setPCRelUseCount(gen.rs()->pc_rel_use_count);
       
      gen.setIndex(start);
      while (gen.allPatches().size() > num_patches) {
         gen.allPatches().pop_back();
      }
   }

   if( dyn_debug_disassemble ) {
       fprintf(stderr, "%s", gen.format().c_str());
   }

   gen.setBT(NULL);

   return true;
}


#include "BPatch.h"
#include "BPatch_collections.h"

bool baseTramp::generateCodeInlined(codeGen &gen,
                                    Address) {
   // We're generating something like so:
   //
   // <Save state>
   // <If>
   //    <compare>
   //      <load>
   //        <add>
   //          <tramp guard addr>
   //          <multiply>
   //            <thread index>
   //            <sizeof (int)>
   //      <0>
   //    <sequence>
   //      <store>
   //        <... tramp guard addr>
   //        <1>
   //      <mini tramp sequence>
   //      <store>
   //        <... tramp guard addr>
   //        <0>
   // <Cost section>
   // <Load state>

   // Break it down...
   // <Save state>
   //   -- TODO: an AST for saves that knows how many registers
   //      we're using...

   // Now we start building up the ASTs to generate. Let's get the
   // pieces.

   // Specialize for the instPoint...
	
   gen.setRegisterSpace(registerSpace::actualRegSpace(instP()));

   pdvector<AstNodePtr> miniTramps;

   if (point_) {
      for (instPoint::instance_iter iter = point_->begin(); 
           iter != point_->end(); ++iter) {
         AstNodePtr ast = DCAST_AST((*iter)->snippet());
         if (ast) 
            miniTramps.push_back(ast);
         else
            miniTramps.push_back(AstNode::snippetNode((*iter)->snippet()));
      }
   }
   else {
      miniTramps.push_back(ast_);
   }

   AstNodePtr minis = AstNode::sequenceNode(miniTramps);

   // Let's build the tramp guard addr (if we want it)
   AstNodePtr threadIndex;
   AstNodePtr trampGuardAddr;
	
   if (guarded() &&
       minis->containsFuncCall() &&
       (proc()->trampGuardAST() != AstNodePtr())) {
      // If we don't have a function call, then we don't
      // need the guard....

      // Now, the guard flag. 
      // If we're multithreaded, we need to index off
      // the base address.

      if (!threaded()) {
         // ...
      }
      else if (gen.thread()) {
         // Constant override...
         threadIndex = AstNode::operandNode(AstNode::Constant,
                                            (void *)(long)gen.thread()->getIndex());
      }
      else {
         // TODO: we can get clever with this, and have the generation of
         // the thread index depend on whether gen has a thread defined...
         // For that, we'd need an AST thread index node. Just something
         // to think about. Maybe a child of funcNode?
         threadIndex = AstNode::threadIndexNode();
      }
        
      if (threadIndex) {
         trampGuardAddr = AstNode::operandNode(AstNode::DataIndir,
                                               AstNode::operatorNode(plusOp,
                                                                     AstNode::operatorNode(timesOp,
      
                                                                                           AstNode::operandNode(AstNode::Constant, 
                                                                                                                (void *)sizeof(unsigned))),
                                                                     proc()->trampGuardAST()));

         /* At the moment, we can't directly specify the fact
            that we're loading 4 bytes instead of a normal
            (address-width) word. */
         trampGuardAddr->setType( BPatch::getBPatch()->builtInTypes->findBuiltInType( "unsigned int" ) );
      }
      else {
         trampGuardAddr = AstNode::operandNode(AstNode::DataIndir,
                                               proc()->trampGuardAST());
         trampGuardAddr->setType( BPatch::getBPatch()->builtInTypes->findBuiltInType( "unsigned int" ) );
      }
   }


   AstNodePtr baseTrampSequence;
   pdvector<AstNodePtr > baseTrampElements;
   
   //CHEN comment, the guarded() seems to check if need to set the trampguard to detect recursive tramp
   //However for our own insturmentation, we do not want any trampoline code which allocate stack or save
   //the recursive tramp flag, so in our case, we only want the "minis" be generated
   if (minis->isDIY())
	   trampGuardAddr = AstNodePtr();

   if (trampGuardAddr) {
      // First, set it to 0
      baseTrampElements.push_back(AstNode::operatorNode(storeOp, 
                                                        trampGuardAddr,
                                                        AstNode::operandNode(AstNode::Constant,
                                                                             (void *)0)));
   }
    
   // Run the minitramps
   baseTrampElements.push_back(minis);
    
   if (trampGuardAddr) {
      // And set the tramp guard flag to 1
      baseTrampElements.push_back(AstNode::operatorNode(storeOp,
                                                        trampGuardAddr,
                                                        AstNode::operandNode(AstNode::Constant,
                                                                             (void *)1)));
   }

   baseTrampSequence = AstNode::sequenceNode(baseTrampElements);

   AstNodePtr baseTrampAST;

   // If trampAddr is non-NULL, then we wrap this with an IF. If not, 
   // we just run the minitramps.
   if (trampGuardAddr == NULL) {
      baseTrampAST = baseTrampSequence;
      baseTrampSequence.reset();
   }
   else {
      // Oh, boy. 
      // Short form of the above
      baseTrampAST = AstNode::operatorNode(ifOp,
                                           trampGuardAddr,
                                           baseTrampSequence);
   }



   // Sets up state in the codeGen object (and gen.rs())
   // that is later used when saving and restoring. This
   // MUST HAPPEN BEFORE THE SAVES, and state should not
   // be reset until AFTER THE RESTORES.
   bool retval = baseTrampAST->initRegisters(gen);
   if (!baseTrampAST->isDIY()) generateSaves(gen, gen.rs());

   if (!baseTrampAST->generateCode(gen, false)) {
      fprintf(stderr, "Gripe: base tramp creation failed\n");
      retval = false;
   }

   if (!baseTrampAST->isDIY()) generateRestores(gen, gen.rs());

   // And now to clean up after us
   //if (minis) delete minis;
   //if (trampGuardAddr) delete trampGuardAddr;
   //if (baseTrampSequence) delete baseTrampSequence;
   //if (baseTramp) delete baseTramp;

   return retval;
}

AddressSpace *baseTramp::proc() const { 
   if (point_)
      return point_->proc();
   if (as_)
       return as_;
   return NULL;
}

bool baseTramp::checkForFuncCalls()
{
   if (ast_)
      return ast_->containsFuncCall();
   if (point_) {
     /*
      for (instPoint::iterator iter = point_->begin(); 
           iter != point_->end(); ++iter) {
         if ((*iter)->ast()->containsFuncCall()) return true;
      }
*/
      for (instPoint::instance_iter iter = point_->begin(); 
           iter != point_->end(); ++iter) {
         AstNodePtr ast = DCAST_AST((*iter)->snippet());
         if (!ast) continue;
         if (ast->containsFuncCall()) return true;
      }
   }
   return false;
}

bool baseTramp::doOptimizations() 
{
   bool hasFuncCall = false;
   bool usesReg = false;

   if (BPatch::bpatch->getInstrStackFrames()) {
      usesReg = true;
   }

   hasFuncCall = false;
   /*
   for (instPoint::iterator iter = point_->begin(); 
        iter != point_->end(); ++iter) {
      if ((*iter)->ast()->containsFuncCall()) {
         hasFuncCall = true;
         break;
      }
   }
   */
   for (instPoint::instance_iter iter = point_->begin(); 
        iter != point_->end(); ++iter) {
      AstNodePtr ast = DCAST_AST((*iter)->snippet());
      if (!ast) continue;
      if (ast->containsFuncCall()) {
         hasFuncCall = true;
         break;
      }
   }

   needsStackFrame_ = usesReg;
   
   if (!hasFuncCall) {
      suppressThreads = true;
      suppressGuards = true;
      return true;
   }

   return false;
}

bool baseTramp::threaded() const {
   if (!proc()->multithread_ready())
      return false;
   return true;
}

int baseTramp::numDefinedRegs()
{
   int count = 0;
   if (!optimizationInfo_)
      return -1;
   registerSpace *rs = registerSpace::getRegisterSpace(proc()->getAddressWidth());
   pdvector<registerSlot *> &regs = rs->trampRegs();
   for (unsigned i=0; i<regs.size(); i++) {
      registerSlot *reg = regs[i];
      if (definedRegs[reg->encoding()]) {
         count++;
      }
   }
   return count;
}

int baseTramp::funcJumpSlotSize()
{
   return 0;
}

bool baseTramp::makesCall() {
   // multithread index..
   if (threaded() && guarded()) return true;

   if (checkForFuncCalls()) return true;

   return false;
}

bool baseTramp::saveFPRs() {
   // Assume FPRs dead at function entry/exit/call, 
   // live at anything else. 
   if (!point_) {
      return true;
   }

   switch (point()->type()) {
      case instPoint::FuncEntry:
      case instPoint::FuncExit:
      case instPoint::PreCall:
      case instPoint::PostCall:
         return false;
      default:
         return true;
   }
}

bool baseTramp::guarded() const {
   if (suppressGuards) return false;
   if (!point_) return false; // iRPCs never guarded

   bool guarded = false;
   bool recursive = false;

   // See if any of our miniTramps are guarded
   /*
   for (instPoint::iterator iter = point_->begin(); 
        iter != point_->end(); ++iter) {
      if ((*iter)->recursive())
         recursive = true;
      else
         guarded = true;
   }
   */
   for (instPoint::instance_iter iter = point_->begin(); 
        iter != point_->end(); ++iter) {
      if ((*iter)->recursiveGuardEnabled()) {
         guarded = true;
      }
      else {
         recursive = true;
      }
   }

   if (recursive && guarded) {
      cerr << "Warning: mix of recursive and guarded snippets @ " << point_
           << ", picking guarded" << endl;
      return true;
   }
   if (guarded) return true;
   return false;
}
