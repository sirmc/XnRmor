   .file    "RTthread-powerpc-asm.S"
   .machine "push"      
#if defined(arch_64bit)
   .machine "ppc64"       
#else
   .machine "ppc"       
#endif


   .section ".text"
   .align   2
# /* ---------------------------------- */
# /* unsigned DYNINSTthreadIndexFAST(); */
# /* ---------------------------------- */
#if defined(arch_64bit)
   .globl   DYNINSTthreadIndexFAST
   .section ".opd", "aw"
   .align   3
DYNINSTthreadIndexFAST:
   .quad    .DYNINSTthreadIndexFAST, .TOC.@tocbase, 0
   .size    DYNINSTthreadIndexFAST, 24

   .previous
   .globl   .DYNINSTthreadIndexFAST
   .type    .DYNINSTthreadIndexFAST, @function
.DYNINSTthreadIndexFAST:
#else
   .globl   DYNINSTthreadIndexFAST
   .type    DYNINSTthreadIndexFAST, @function
DYNINSTthreadIndexFAST:
#endif

   mr       3,12    # function return value = r3 = r12
   blr              # branch via link register (function return)

#if defined(arch_64bit)
   .size    .DYNINSTthreadIndexFAST, . - .DYNINSTthreadIndexFAST
#else
   .size    DYNINSTthreadIndexFAST, . - DYNINSTthreadIndexFAST
#endif


   .section ".text"
   .align   2
# /* ------------------------------------------- */
# /* int atomic_set(volatile int *int_ptr);      */
# /*                                             */
# /* The only possible values at the given       */
# /* memory location are 0 and 1.  Attempt to    */
# /* atomically update the value from 0 to 1.    */
# /* Return 1 if such an atomic update occurred; */
# /* return 0 otherwise.                         */
# /* ------------------------------------------- */
#if defined(arch_64bit)
   .globl   atomic_set
   .section ".opd", "aw"
   .align   3
atomic_set:
   .quad    .atomic_set, .TOC.@tocbase, 0
   .size    atomic_set, 24

   .previous
   .globl   .atomic_set
   .type    .atomic_set, @function
.atomic_set:
#else
   .globl   atomic_set
   .type    atomic_set, @function
atomic_set:
#endif
   addi     4,0,1               # r4 = 1
                                # Attempt atomic memory swap
   lwarx    5,0,3               #   r5 = *int_ptr (load reserve indexed)
   stwcx.   4,0,3               #   *int_ptr = 1  (store conditional indexed)
   bne-     atomic_set_return_0 # if atomic swap failed, return 0

   cmpw     5,4                 # if original value was already 1,
   beq-     atomic_set_return_0 #   return 0 because no value update occurred

   addi     3,0,1               # function return value = r3 = 1
   blr                          # branch via link register (function return)

atomic_set_return_0:
   addi     3,0,0               # function return value = r3 = 0
   blr                          # branch via link register (function return)

#if defined(arch_64bit)
   .size    .atomic_set, . - .atomic_set
#else
   .size    atomic_set, . - atomic_set
#endif

   .machine "pop"
