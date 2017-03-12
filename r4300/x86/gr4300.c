/**
 * Mupen64 - gr4300.c
 * Copyright (C) 2002 Hacktarux
 *
 * Mupen64 homepage: http://mupen64.emulation64.com
 * email address: hacktarux@yahoo.fr
 * 
 * If you want to contribute to the project please contact
 * me first (maybe someone is already making what you are
 * planning to do).
 *
 *
 * This program is free software; you can redistribute it and/
 * or modify it under the terms of the GNU General Public Li-
 * cence as published by the Free Software Foundation; either
 * version 2 of the Licence, or any later version.
 *
 * This program is distributed in the hope that it will be use-
 * ful, but WITHOUT ANY WARRANTY; without even the implied war-
 * ranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public Licence for more details.
 *
 * You should have received a copy of the GNU General Public
 * Licence along with this program; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
**/
#if defined(HAVE_RECOMPILER)

#include "assemble.h"
#include "../r4300.h"
#include "../macros.h"
#include "../../memory/memory.h"
#include "../interupt.h"
#include "../ops.h"
#include "../recomph.h"
#include "regcache.h"
#include "../exception.h"
#include "interpret.h"

extern u32 op;
extern u32 src;

precomp_instr fake_instr;
static int eax, ebx, ecx, edx, esp, ebp, esi, edi;

int branch_taken;

void gennotcompiled()
{
   free_all_registers();
   simplify_access();
   
   if (dst->addr == 0xa4000040)
     {
	sub_reg32_imm32(ESP, 0xC);
	mov_m32_reg32((u32*)(&return_address), ESP);
	sub_m32_imm32((u32*)(&return_address), 4);
     }
   mov_m32_imm32((u32*)(&PC), (u32)(dst));
   mov_reg32_imm32(EAX, (u32)NOTCOMPILED);
   call_reg32(EAX);
}

void genlink_subblock()
{
   free_all_registers();
   jmp(dst->addr+4);
}

void gendebug()
{
/* free_all_registers(); */
   mov_m32_reg32((u32*)&eax, EAX);
   mov_m32_reg32((u32*)&ebx, EBX);
   mov_m32_reg32((u32*)&ecx, ECX);
   mov_m32_reg32((u32*)&edx, EDX);
   mov_m32_reg32((u32*)&esp, ESP);
   mov_m32_reg32((u32*)&ebp, EBP);
   mov_m32_reg32((u32*)&esi, ESI);
   mov_m32_reg32((u32*)&edi, EDI);
   
   mov_m32_imm32((u32*)(&PC), (u32)(dst));
   mov_m32_imm32((u32*)(&op), (u32)(src));
   mov_reg32_imm32(EAX, (u32)debug);
   call_reg32(EAX);
   
   mov_reg32_m32(EAX, (u32*)&eax);
   mov_reg32_m32(EBX, (u32*)&ebx);
   mov_reg32_m32(ECX, (u32*)&ecx);
   mov_reg32_m32(EDX, (u32*)&edx);
   mov_reg32_m32(ESP, (u32*)&esp);
   mov_reg32_m32(EBP, (u32*)&ebp);
   mov_reg32_m32(ESI, (u32*)&esi);
   mov_reg32_m32(EDI, (u32*)&edi);
}

void gencallinterp(u32 addr, int jump)
{
   free_all_registers();
   simplify_access();
   if (jump)
     mov_m32_imm32((u32*)(&dyna_interp), 1);
   mov_m32_imm32((u32*)(&PC), (u32)(dst));
   mov_reg32_imm32(EAX, addr);
   call_reg32(EAX);
   if (jump)
     {
	mov_m32_imm32((u32*)(&dyna_interp), 0);
	mov_reg32_imm32(EAX, (u32)dyna_jump);
	call_reg32(EAX);
     }
}

void genupdate_count(u32 addr)
{
#ifndef COMPARE_CORE
#ifndef DBG
   mov_reg32_imm32(EAX, addr);
   sub_reg32_m32(EAX, (u32*)(&last_addr));
   shr_reg32_imm8(EAX, 1);
   add_m32_reg32((u32*)(&Count), EAX);
#else
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)update_count);
   call_reg32(EAX);
#endif
#else
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)update_count);
   call_reg32(EAX);
#endif
}

void gendelayslot()
{
   mov_m32_imm32((void*)(&delay_slot), 1);
   recompile_opcode();
   
   free_all_registers();
   genupdate_count(dst->addr+4);
   
   mov_m32_imm32((void*)(&delay_slot), 0);
}

void genni()
{
#ifdef EMU64_DEBUG
   gencallinterp((u32)NI, 0);
#endif
}

void genreserved()
{
#ifdef EMU64_DEBUG
   gencallinterp((u32)RESERVED, 0);
#endif
}

void genfin_block()
{
   gencallinterp((u32)FIN_BLOCK, 0);
}

void gencheck_interupt(u32 instr_structure)
{
   mov_eax_memoffs32((void*)(&next_interupt));
   cmp_reg32_m32(EAX, (void*)&Count);
   ja_rj(17);
   mov_m32_imm32((u32*)(&PC), instr_structure); /* 10 */
   mov_reg32_imm32(EAX, (u32)gen_interupt); /* 5 */
   call_reg32(EAX); /* 2 */
}

void gencheck_interupt_out(u32 addr)
{
   mov_eax_memoffs32((void*)(&next_interupt));
   cmp_reg32_m32(EAX, (void*)&Count);
   ja_rj(27);
   mov_m32_imm32((u32*)(&fake_instr.addr), addr);
   mov_m32_imm32((u32*)(&PC), (u32)(&fake_instr));
   mov_reg32_imm32(EAX, (u32)gen_interupt);
   call_reg32(EAX);
}

void gencheck_interupt_reg() /* addr is in EAX */
{
   mov_reg32_m32(EBX, (void*)&next_interupt);
   cmp_reg32_m32(EBX, (void*)&Count);
   ja_rj(22);
   mov_memoffs32_eax((u32*)(&fake_instr.addr)); /* 5 */
   mov_m32_imm32((u32*)(&PC), (u32)(&fake_instr)); /* 10 */
   mov_reg32_imm32(EAX, (u32)gen_interupt); /* 5 */
   call_reg32(EAX); /* 2 */
}

void gennop()
{
}

void genj()
{
#ifdef INTERPRET_J
   gencallinterp((u32)J, 1);
#else
   u32 naddr;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)J, 1);
	return;
     }
   
   gendelayslot();
   naddr = ((dst-1)->f.j.inst_index<<2) | (dst->addr & 0xF0000000);
   
   mov_m32_imm32((void*)(&last_addr), naddr);
   gencheck_interupt((u32)&actual->block[(naddr-actual->start)/4]);
   jmp(naddr);
#endif
}

void genj_out()
{
#ifdef INTERPRET_J_OUT
   gencallinterp((u32)J_OUT, 1);
#else
   u32 naddr;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)J_OUT, 1);
	return;
     }
   
   gendelayslot();
   naddr = ((dst-1)->f.j.inst_index<<2) | (dst->addr & 0xF0000000);
   
   mov_m32_imm32((void*)(&last_addr), naddr);
   gencheck_interupt_out(naddr);
   mov_m32_imm32(&jump_to_address, naddr);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
#endif
}

void genj_idle()
{
#ifdef INTERPRET_J_IDLE
   gencallinterp((u32)J_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)J_IDLE, 1);
	return;
     }
   
   mov_eax_memoffs32((u32 *)(&next_interupt));
   sub_reg32_m32(EAX, (u32 *)(&Count));
   cmp_reg32_imm8(EAX, 3);
   jbe_rj(11);
   
   and_eax_imm32(0xFFFFFFFC);
   add_m32_reg32((u32 *)(&Count), EAX);
  
   genj();
#endif
}

void genjal()
{
#ifdef INTERPRET_JAL
   gencallinterp((u32)JAL, 1);
#else
   u32 naddr;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)JAL, 1);
	return;
     }
   
   gendelayslot();
   
   mov_m32_imm32((u32 *)(reg + 31), dst->addr + 4);
   if (((dst->addr + 4) & 0x80000000))
     mov_m32_imm32((u32 *)(&reg[31])+1, 0xFFFFFFFF);
   else
     mov_m32_imm32((u32 *)(&reg[31])+1, 0);
   
   naddr = ((dst-1)->f.j.inst_index<<2) | (dst->addr & 0xF0000000);
   
   mov_m32_imm32((void*)(&last_addr), naddr);
   gencheck_interupt((u32)&actual->block[(naddr-actual->start)/4]);
   jmp(naddr);
#endif
}

void genjal_out()
{
#ifdef INTERPRET_JAL_OUT
   gencallinterp((u32)JAL_OUT, 1);
#else
   u32 naddr;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)JAL_OUT, 1);
	return;
     }
   
   gendelayslot();
   
   mov_m32_imm32((u32 *)(reg + 31), dst->addr + 4);
   if (((dst->addr + 4) & 0x80000000))
     mov_m32_imm32((u32 *)(&reg[31])+1, 0xFFFFFFFF);
   else
     mov_m32_imm32((u32 *)(&reg[31])+1, 0);
   
   naddr = ((dst-1)->f.j.inst_index<<2) | (dst->addr & 0xF0000000);
   
   mov_m32_imm32((void*)(&last_addr), naddr);
   gencheck_interupt_out(naddr);
   mov_m32_imm32(&jump_to_address, naddr);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
#endif
}

void genjal_idle()
{
#ifdef INTERPRET_JAL_IDLE
   gencallinterp((u32)JAL_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)JAL_IDLE, 1);
	return;
     }
   
   mov_eax_memoffs32((u32 *)(&next_interupt));
   sub_reg32_m32(EAX, (u32 *)(&Count));
   cmp_reg32_imm8(EAX, 3);
   jbe_rj(11);
   
   and_eax_imm32(0xFFFFFFFC);
   add_m32_reg32((u32 *)(&Count), EAX);
  
   genjal();
#endif
}

void genbeq_test()
{
   int rs_64bit = is64((u32 *)dst->f.i.rs);
   int rt_64bit = is64((u32 *)dst->f.i.rt);
   
   if (!rs_64bit && !rt_64bit)
     {
	int rs = allocate_register((u32 *)dst->f.i.rs);
	int rt = allocate_register((u32 *)dst->f.i.rt);
	
	cmp_reg32_reg32(rs, rt);
	jne_rj(12);
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else if (rs_64bit == -1)
     {
	int rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	int rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	
	cmp_reg32_m32(rt1, (u32 *)dst->f.i.rs);
	jne_rj(20);
	cmp_reg32_m32(rt2, ((u32 *)dst->f.i.rs)+1); /* 6 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else if (rt_64bit == -1)
     {
	int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	
	cmp_reg32_m32(rs1, (u32 *)dst->f.i.rt);
	jne_rj(20);
	cmp_reg32_m32(rs2, ((u32 *)dst->f.i.rt) + 1); /* 6 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else
     {
	int rs1, rs2, rt1, rt2;
	if (!rs_64bit)
	  {
	     rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	     rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	     rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	     rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	  }
	else
	  {
	     rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	     rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	     rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	     rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	  }
	cmp_reg32_reg32(rs1, rt1);
	jne_rj(16);
	cmp_reg32_reg32(rs2, rt2); /* 2 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
}

void gentest()
{
   u32 temp, temp2;
   
   cmp_m32_imm32((u32 *)(&branch_taken), 0);
   je_near_rj(0);
   temp = code_length;
   mov_m32_imm32((void*)(&last_addr), dst->addr + (dst-1)->f.i.immediate*4);
   gencheck_interupt((u32)(dst + (dst-1)->f.i.immediate));
   jmp(dst->addr + (dst-1)->f.i.immediate*4);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   mov_m32_imm32((void*)(&last_addr), dst->addr + 4);
   gencheck_interupt((u32)(dst + 1));
   jmp(dst->addr + 4);
}

void genbeq()
{
#ifdef INTERPRET_BEQ
   gencallinterp((u32)BEQ, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQ, 1);
	return;
     }
   
   genbeq_test();
   gendelayslot();
   gentest();
#endif
}

void gentest_out()
{
   u32 temp, temp2;
   
   cmp_m32_imm32((u32 *)(&branch_taken), 0);
   je_near_rj(0);
   temp = code_length;
   mov_m32_imm32((void*)(&last_addr), dst->addr + (dst-1)->f.i.immediate*4);
   gencheck_interupt_out(dst->addr + (dst-1)->f.i.immediate*4);
   mov_m32_imm32(&jump_to_address, dst->addr + (dst-1)->f.i.immediate*4);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   mov_m32_imm32((void*)(&last_addr), dst->addr + 4);
   gencheck_interupt((u32)(dst + 1));
   jmp(dst->addr + 4);
}

void genbeq_out()
{
#ifdef INTERPRET_BEQ_OUT
   gencallinterp((u32)BEQ_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQ_OUT, 1);
	return;
     }
   
   genbeq_test();
   gendelayslot();
   gentest_out();
#endif
}

void gentest_idle()
{
   u32 temp, temp2;
   int reg;
   
   reg = lru_register();
   free_register(reg);
   
   cmp_m32_imm32((u32 *)(&branch_taken), 0);
   je_near_rj(0);
   temp = code_length;
   
   mov_reg32_m32(reg, (u32 *)(&next_interupt));
   sub_reg32_m32(reg, (u32 *)(&Count));
   cmp_reg32_imm8(reg, 3);
   jbe_rj(12);
   
   and_reg32_imm32(reg, 0xFFFFFFFC); /* 6 */
   add_m32_reg32((u32 *)(&Count), reg); /* 6 */
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
}

void genbeq_idle()
{
#ifdef INTERPRET_BEQ_IDLE
   gencallinterp((u32)BEQ_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQ_IDLE, 1);
	return;
     }
   
   genbeq_test();
   gentest_idle();
   genbeq();
#endif
}

void genbne_test()
{
   int rs_64bit = is64((u32 *)dst->f.i.rs);
   int rt_64bit = is64((u32 *)dst->f.i.rt);
   
   if (!rs_64bit && !rt_64bit)
     {
	int rs = allocate_register((u32 *)dst->f.i.rs);
	int rt = allocate_register((u32 *)dst->f.i.rt);
	
	cmp_reg32_reg32(rs, rt);
	je_rj(12);
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else if (rs_64bit == -1)
     {
	int rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	int rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	
	cmp_reg32_m32(rt1, (u32 *)dst->f.i.rs);
	jne_rj(20);
	cmp_reg32_m32(rt2, ((u32 *)dst->f.i.rs)+1); /* 6 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
   else if (rt_64bit == -1)
     {
	int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	
	cmp_reg32_m32(rs1, (u32 *)dst->f.i.rt);
	jne_rj(20);
	cmp_reg32_m32(rs2, ((u32 *)dst->f.i.rt)+1); /* 6 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
   else
     {
	int rs1, rs2, rt1, rt2;
	if (!rs_64bit)
	  {
	     rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	     rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	     rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	     rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	  }
	else
	  {
	     rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	     rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	     rt1 = allocate_64_register1((u32 *)dst->f.i.rt);
	     rt2 = allocate_64_register2((u32 *)dst->f.i.rt);
	  }
	cmp_reg32_reg32(rs1, rt1);
	jne_rj(16);
	cmp_reg32_reg32(rs2, rt2); /* 2 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
}

void genbne()
{
#ifdef INTERPRET_BNE
   gencallinterp((u32)BNE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNE, 1);
	return;
     }
   
   genbne_test();
   gendelayslot();
   gentest();
#endif
}

void genbne_out()
{
#ifdef INTERPRET_BNE_OUT
   gencallinterp((u32)BNE_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNE_OUT, 1);
	return;
     }
   
   genbne_test();
   gendelayslot();
   gentest_out();
#endif
}

void genbne_idle()
{
#ifdef INTERPRET_BNE_IDLE
   gencallinterp((u32)BNE_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNE_IDLE, 1);
	return;
     }
   
   genbne_test();
   gentest_idle();
   genbne();
#endif
}

void genblez_test()
{
   int rs_64bit = is64((u32 *)dst->f.i.rs);
   
   if (!rs_64bit)
     {
	int rs = allocate_register((u32 *)dst->f.i.rs);
	
	cmp_reg32_imm32(rs, 0);
	jg_rj(12);
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else if (rs_64bit == -1)
     {
	cmp_m32_imm32(((u32 *)dst->f.i.rs)+1, 0);
	jg_rj(14);
	jne_rj(24); /* 2 */
	cmp_m32_imm32((u32 *)dst->f.i.rs, 0); /* 10 */
	je_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
   else
     {
	int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	
	cmp_reg32_imm32(rs2, 0);
	jg_rj(10);
	jne_rj(20); /* 2 */
	cmp_reg32_imm32(rs1, 0); /* 6 */
	je_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
}

void genblez()
{
#ifdef INTERPRET_BLEZ
   gencallinterp((u32)BLEZ, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZ, 1);
	return;
     }
   
   genblez_test();
   gendelayslot();
   gentest();
#endif
}

void genblez_out()
{
#ifdef INTERPRET_BLEZ_OUT
   gencallinterp((u32)BLEZ_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZ_OUT, 1);
	return;
     }
   
   genblez_test();
   gendelayslot();
   gentest_out();
#endif
}

void genblez_idle()
{
#ifdef INTERPRET_BLEZ_IDLE
   gencallinterp((u32)BLEZ_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZ_IDLE, 1);
	return;
     }
   
   genblez_test();
   gentest_idle();
   genblez();
#endif
}

void genbgtz_test()
{
   int rs_64bit = is64((u32 *)dst->f.i.rs);
   
   if (!rs_64bit)
     {
	int rs = allocate_register((u32 *)dst->f.i.rs);
	
	cmp_reg32_imm32(rs, 0);
	jle_rj(12);
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
     }
   else if (rs_64bit == -1)
     {
	cmp_m32_imm32(((u32 *)dst->f.i.rs)+1, 0);
	jl_rj(14);
	jne_rj(24); /* 2 */
	cmp_m32_imm32((u32 *)dst->f.i.rs, 0); /* 10 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
   else
     {
	int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
	int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
	
	cmp_reg32_imm32(rs2, 0);
	jl_rj(10);
	jne_rj(20); /* 2 */
	cmp_reg32_imm32(rs1, 0); /* 6 */
	jne_rj(12); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 0); /* 10 */
	jmp_imm_short(10); /* 2 */
	mov_m32_imm32((u32 *)(&branch_taken), 1); /* 10 */
     }
}

void genbgtz()
{
#ifdef INTERPRET_BGTZ
   gencallinterp((u32)BGTZ, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZ, 1);
	return;
     }
   
   genbgtz_test();
   gendelayslot();
   gentest();
#endif
}

void genbgtz_out()
{
#ifdef INTERPRET_BGTZ_OUT
   gencallinterp((u32)BGTZ_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZ_OUT, 1);
	return;
     }
   
   genbgtz_test();
   gendelayslot();
   gentest_out();
#endif
}

void genbgtz_idle()
{
#ifdef INTERPRET_BGTZ_IDLE
   gencallinterp((u32)BGTZ_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZ_IDLE, 1);
	return;
     }
   
   genbgtz_test();
   gentest_idle();
   genbgtz();
#endif
}

void genaddi()
{
#ifdef INTERPRET_ADDI
   gencallinterp((u32)ADDI, 0);
#else
   int rs = allocate_register((u32 *)dst->f.i.rs);
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt, rs);
   add_reg32_imm32(rt,(s32)dst->f.i.immediate);
#endif
}

void genaddiu()
{
#ifdef INTERPRET_ADDIU
   gencallinterp((u32)ADDIU, 0);
#else
   int rs = allocate_register((u32 *)dst->f.i.rs);
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt, rs);
   add_reg32_imm32(rt,(s32)dst->f.i.immediate);
#endif
}

void genslti()
{
#ifdef INTERPRET_SLTI
   gencallinterp((u32)SLTI, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   s64 imm = (s64)dst->f.i.immediate;
   
   cmp_reg32_imm32(rs2, (u32)(imm >> 32));
   jl_rj(17);
   jne_rj(8); /* 2 */
   cmp_reg32_imm32(rs1, (u32)imm); /* 6 */
   jl_rj(7); /* 2 */
   mov_reg32_imm32(rt, 0); /* 5 */
   jmp_imm_short(5); /* 2 */
   mov_reg32_imm32(rt, 1); /* 5 */
#endif
}

void gensltiu()
{
#ifdef INTERPRET_SLTIU
   gencallinterp((u32)SLTIU, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   s64 imm = (s64)dst->f.i.immediate;
   
   cmp_reg32_imm32(rs2, (u32)(imm >> 32));
   jb_rj(17);
   jne_rj(8); /* 2 */
   cmp_reg32_imm32(rs1, (u32)imm); /* 6 */
   jb_rj(7); /* 2 */
   mov_reg32_imm32(rt, 0); /* 5 */
   jmp_imm_short(5); /* 2 */
   mov_reg32_imm32(rt, 1); /* 5 */
#endif
}

void genandi()
{
#ifdef INTERPRET_ANDI
   gencallinterp((u32)ANDI, 0);
#else
   int rs = allocate_register((u32 *)dst->f.i.rs);
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt, rs);
   and_reg32_imm32(rt, (unsigned short)dst->f.i.immediate);
#endif
}

void genori()
{
#ifdef INTERPRET_ORI
   gencallinterp((u32)ORI, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt1 = allocate_64_register1_w((u32 *)dst->f.i.rt);
   int rt2 = allocate_64_register2_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt1, rs1);
   mov_reg32_reg32(rt2, rs2);
   or_reg32_imm32(rt1, (unsigned short)dst->f.i.immediate);
#endif
}

void genxori()
{
#ifdef INTERPRET_XORI
   gencallinterp((u32)XORI, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt1 = allocate_64_register1_w((u32 *)dst->f.i.rt);
   int rt2 = allocate_64_register2_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt1, rs1);
   mov_reg32_reg32(rt2, rs2);
   xor_reg32_imm32(rt1, (unsigned short)dst->f.i.immediate);
#endif
}

void genlui()
{
#ifdef INTERPRET_LUI
   gencallinterp((u32)LUI, 0);
#else
   int rt = allocate_register_w((u32 *)dst->f.i.rt);
   
   mov_reg32_imm32(rt, (u32)dst->f.i.immediate << 16);
#endif
}

void gentestl()
{
   u32 temp, temp2;
   
   cmp_m32_imm32((u32 *)(&branch_taken), 0);
   je_near_rj(0);
   temp = code_length;
   gendelayslot();
   mov_m32_imm32((void*)(&last_addr), dst->addr + (dst-1)->f.i.immediate*4);
   gencheck_interupt((u32)(dst + (dst-1)->f.i.immediate));
   jmp(dst->addr + (dst-1)->f.i.immediate*4);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   genupdate_count(dst->addr-4);
   mov_m32_imm32((void*)(&last_addr), dst->addr + 4);
   gencheck_interupt((u32)(dst + 1));
   jmp(dst->addr + 4);
}

void genbeql()
{
#ifdef INTERPRET_BEQL
   gencallinterp((u32)BEQL, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQL, 1);
	return;
     }
   
   genbeq_test();
   free_all_registers();
   gentestl();
#endif
}

void gentestl_out()
{
   u32 temp, temp2;
   
   cmp_m32_imm32((u32 *)(&branch_taken), 0);
   je_near_rj(0);
   temp = code_length;
   gendelayslot();
   mov_m32_imm32((void*)(&last_addr), dst->addr + (dst-1)->f.i.immediate*4);
   gencheck_interupt_out(dst->addr + (dst-1)->f.i.immediate*4);
   mov_m32_imm32(&jump_to_address, dst->addr + (dst-1)->f.i.immediate*4);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   genupdate_count(dst->addr-4);
   mov_m32_imm32((void*)(&last_addr), dst->addr + 4);
   gencheck_interupt((u32)(dst + 1));
   jmp(dst->addr + 4);
}

void genbeql_out()
{
#ifdef INTERPRET_BEQL_OUT
   gencallinterp((u32)BEQL_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQL_OUT, 1);
	return;
     }
   
   genbeq_test();
   free_all_registers();
   gentestl_out();
#endif
}

void genbeql_idle()
{
#ifdef INTERPRET_BEQL_IDLE
   gencallinterp((u32)BEQL_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BEQL_IDLE, 1);
	return;
     }
   
   genbeq_test();
   gentest_idle();
   genbeql();
#endif
}

void genbnel()
{
#ifdef INTERPRET_BNEL
   gencallinterp((u32)BNEL, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNEL, 1);
	return;
     }
   
   genbne_test();
   free_all_registers();
   gentestl();
#endif
}

void genbnel_out()
{
#ifdef INTERPRET_BNEL_OUT
   gencallinterp((u32)BNEL_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNEL_OUT, 1);
	return;
     }
   
   genbne_test();
   free_all_registers();
   gentestl_out();
#endif
}

void genbnel_idle()
{
#ifdef INTERPRET_BNEL_IDLE
   gencallinterp((u32)BNEL_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BNEL_IDLE, 1);
	return;
     }
   
   genbne_test();
   gentest_idle();
   genbnel();
#endif
}

void genblezl()
{
#ifdef INTERPRET_BLEZL
   gencallinterp((u32)BLEZL, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZL, 1);
	return;
     }
   
   genblez_test();
   free_all_registers();
   gentestl();
#endif
}

void genblezl_out()
{
#ifdef INTERPRET_BLEZL_OUT
   gencallinterp((u32)BLEZL_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZL_OUT, 1);
	return;
     }
   
   genblez_test();
   free_all_registers();
   gentestl_out();
#endif
}

void genblezl_idle()
{
#ifdef INTERPRET_BLEZL_IDLE
   gencallinterp((u32)BLEZL_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BLEZL_IDLE, 1);
	return;
     }
   
   genblez_test();
   gentest_idle();
   genblezl();
#endif
}

void genbgtzl()
{
#ifdef INTERPRET_BGTZL
   gencallinterp((u32)BGTZL, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZL, 1);
	return;
     }
   
   genbgtz_test();
   free_all_registers();
   gentestl();
#endif
}

void genbgtzl_out()
{
#ifdef INTERPRET_BGTZL_OUT
   gencallinterp((u32)BGTZL_OUT, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZL_OUT, 1);
	return;
     }
   
   genbgtz_test();
   free_all_registers();
   gentestl_out();
#endif
}

void genbgtzl_idle()
{
#ifdef INTERPRET_BGTZL_IDLE
   gencallinterp((u32)BGTZL_IDLE, 1);
#else
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)BGTZL_IDLE, 1);
	return;
     }
   
   genbgtz_test();
   gentest_idle();
   genbgtzl();
#endif
}

void gendaddi()
{
#ifdef INTERPRET_DADDI
   gencallinterp((u32)DADDI, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt1 = allocate_64_register1_w((u32 *)dst->f.i.rt);
   int rt2 = allocate_64_register2_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt1, rs1);
   mov_reg32_reg32(rt2, rs2);
   add_reg32_imm32(rt1, dst->f.i.immediate);
   adc_reg32_imm32(rt2, (int)dst->f.i.immediate>>31);
#endif
}

void gendaddiu()
{
#ifdef INTERPRET_DADDIU
   gencallinterp((u32)DADDIU, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.i.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.i.rs);
   int rt1 = allocate_64_register1_w((u32 *)dst->f.i.rt);
   int rt2 = allocate_64_register2_w((u32 *)dst->f.i.rt);
   
   mov_reg32_reg32(rt1, rs1);
   mov_reg32_reg32(rt2, rs2);
   add_reg32_imm32(rt1, dst->f.i.immediate);
   adc_reg32_imm32(rt2, (int)dst->f.i.immediate>>31);
#endif
}

void genldl()
{
   gencallinterp((u32)LDL, 0);
}

void genldr()
{
   gencallinterp((u32)LDR, 0);
}

void genlb()
{
#ifdef INTERPRET_LB
   gencallinterp((u32)LB, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemb);
	cmp_reg32_imm32(EAX, (u32)read_rdramb);
     }
   je_rj(47);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemb); /* 7 */
   call_reg32(EBX); /* 2 */
   movsx_reg32_m8(EAX, (unsigned char *)dst->f.i.rt); /* 7 */
   jmp_imm_short(16); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 3); /* 3 */
   movsx_reg32_8preg32pimm32(EAX, EBX, (u32)rdram); /* 7 */
   
   set_register_state(EAX, (u32*)dst->f.i.rt, 1);
#endif
}

void genlh()
{
#ifdef INTERPRET_LH
   gencallinterp((u32)LH, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemh);
	cmp_reg32_imm32(EAX, (u32)read_rdramh);
     }
   je_rj(47);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemh); /* 7 */
   call_reg32(EBX); /* 2 */
   movsx_reg32_m16(EAX, (unsigned short *)dst->f.i.rt); /* 7 */
   jmp_imm_short(16); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 2); /* 3 */
   movsx_reg32_16preg32pimm32(EAX, EBX, (u32)rdram); /* 7 */
   
   set_register_state(EAX, (u32*)dst->f.i.rt, 1);
#endif
}

void genlwl()
{
   gencallinterp((u32)LWL, 0);
}

void genlw()
{
#ifdef INTERPRET_LW
   gencallinterp((u32)LW, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmem);
	cmp_reg32_imm32(EAX, (u32)read_rdram);
     }
   je_rj(45);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmem); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(dst->f.i.rt)); /* 5 */
   jmp_imm_short(12); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_reg32_preg32pimm32(EAX, EBX, (u32)rdram); /* 6 */
   
   set_register_state(EAX, (u32*)dst->f.i.rt, 1);
#endif
}

void genlbu()
{
#ifdef INTERPRET_LBU
   gencallinterp((u32)LBU, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemb);
	cmp_reg32_imm32(EAX, (u32)read_rdramb);
     }
   je_rj(46);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemb); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_reg32_m32(EAX, (u32 *)dst->f.i.rt); /* 6 */
   jmp_imm_short(15); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 3); /* 3 */
   mov_reg32_preg32pimm32(EAX, EBX, (u32)rdram); /* 6 */
   
   and_eax_imm32(0xFF);
   
   set_register_state(EAX, (u32*)dst->f.i.rt, 1);
#endif
}

void genlhu()
{
#ifdef INTERPRET_LHU
   gencallinterp((u32)LHU, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemh);
	cmp_reg32_imm32(EAX, (u32)read_rdramh);
     }
   je_rj(46);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemh); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_reg32_m32(EAX, (u32 *)dst->f.i.rt); /* 6 */
   jmp_imm_short(15); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 2); /* 3 */
   mov_reg32_preg32pimm32(EAX, EBX, (u32)rdram); /* 6 */
   
   and_eax_imm32(0xFFFF);
   
   set_register_state(EAX, (u32*)dst->f.i.rt, 1);
#endif
}

void genlwr()
{
   gencallinterp((u32)LWR, 0);
}

void genlwu()
{
#ifdef INTERPRET_LWU
   gencallinterp((u32)LWU, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmem);
	cmp_reg32_imm32(EAX, (u32)read_rdram);
     }
   je_rj(45);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmem); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(dst->f.i.rt)); /* 5 */
   jmp_imm_short(12); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_reg32_preg32pimm32(EAX, EBX, (u32)rdram); /* 6 */
   
   xor_reg32_reg32(EBX, EBX);
   
   set_64_register_state(EAX, EBX, (u32*)dst->f.i.rt, 1);
#endif
}

void gensb()
{
#ifdef INTERPRET_SB
   gencallinterp((u32)SB, 0);
#else
   free_all_registers();
   simplify_access();
   mov_reg8_m8(CL, (unsigned char *)dst->f.i.rt);
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writememb);
	cmp_reg32_imm32(EAX, (u32)write_rdramb);
     }
   je_rj(41);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m8_reg8((unsigned char *)(&byte), CL); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writememb); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(17); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 3); /* 3 */
   mov_preg32pimm32_reg8(EBX, (u32)rdram, CL); /* 6 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void gensh()
{
#ifdef INTERPRET_SH
   gencallinterp((u32)SH, 0);
#else
   free_all_registers();
   simplify_access();
   mov_reg16_m16(CX, (unsigned short *)dst->f.i.rt);
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writememh);
	cmp_reg32_imm32(EAX, (u32)write_rdramh);
     }
   je_rj(42);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m16_reg16((unsigned short *)(&hword), CX); /* 7 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writememh); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(18); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   xor_reg8_imm8(BL, 2); /* 3 */
   mov_preg32pimm32_reg16(EBX, (u32)rdram, CX); /* 7 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void genswl()
{
   gencallinterp((u32)SWL, 0);
}

void gensw()
{
#ifdef INTERPRET_SW
   gencallinterp((u32)SW, 0);
#else
   free_all_registers();
   simplify_access();
   mov_reg32_m32(ECX, (u32 *)dst->f.i.rt);
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writemem);
	cmp_reg32_imm32(EAX, (u32)write_rdram);
     }
   je_rj(41);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_reg32((u32 *)(&word), ECX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writemem); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(14); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_preg32pimm32_reg32(EBX, (u32)rdram, ECX); /* 6 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void gensdl()
{
   gencallinterp((u32)SDL, 0);
}

void gensdr()
{
   gencallinterp((u32)SDR, 0);
}

void genswr()
{
   gencallinterp((u32)SWR, 0);
}

void gencheck_cop1_unusable()
{
   u32 temp, temp2;
   free_all_registers();
   simplify_access();
   test_m32_imm32((u32*)&Status, 0x20000000);
   jne_rj(0);
   temp = code_length;
   
   gencallinterp((u32)check_cop1_unusable, 0);
   
   temp2 = code_length;
   code_length = temp - 1;
   put8(temp2 - temp);
   code_length = temp2;
}

void genlwc1()
{
#ifdef INTERPRET_LWC1
   gencallinterp((u32)LWC1, 0);
#else
   gencheck_cop1_unusable();
   
   mov_eax_memoffs32((u32 *)(&reg[dst->f.lf.base]));
   add_eax_imm32((s32)dst->f.lf.offset);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmem);
	cmp_reg32_imm32(EAX, (u32)read_rdram);
     }
   je_rj(42);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_reg32_m32(EDX, (u32*)(&reg_cop1_simple[dst->f.lf.ft])); /* 6 */
   mov_m32_reg32((u32 *)(&rdword), EDX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmem); /* 7 */
   call_reg32(EBX); /* 2 */
   jmp_imm_short(20); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_reg32_preg32pimm32(EAX, EBX, (u32)rdram); /* 6 */
   mov_reg32_m32(EBX, (u32*)(&reg_cop1_simple[dst->f.lf.ft])); /* 6 */
   mov_preg32_reg32(EBX, EAX); /* 2 */
#endif
}

void genldc1()
{
#ifdef INTERPRET_LDC1
   gencallinterp((u32)LDC1, 0);
#else
   gencheck_cop1_unusable();
   
   mov_eax_memoffs32((u32 *)(&reg[dst->f.lf.base]));
   add_eax_imm32((s32)dst->f.lf.offset);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemd);
	cmp_reg32_imm32(EAX, (u32)read_rdramd);
     }
   je_rj(42);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_reg32_m32(EDX, (u32*)(&reg_cop1_double[dst->f.lf.ft])); /* 6 */
   mov_m32_reg32((u32 *)(&rdword), EDX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemd); /* 7 */
   call_reg32(EBX); /* 2 */
   jmp_imm_short(32); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_reg32_preg32pimm32(EAX, EBX, ((u32)rdram)+4); /* 6 */
   mov_reg32_preg32pimm32(ECX, EBX, ((u32)rdram)); /* 6 */
   mov_reg32_m32(EBX, (u32*)(&reg_cop1_double[dst->f.lf.ft])); /* 6 */
   mov_preg32_reg32(EBX, EAX); /* 2 */
   mov_preg32pimm32_reg32(EBX, 4, ECX); /* 6 */
#endif
}

void gencache()
{
}

void genld()
{
#ifdef INTERPRET_LD
   gencallinterp((u32)LD, 0);
#else
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)readmemd);
	cmp_reg32_imm32(EAX, (u32)read_rdramd);
     }
   je_rj(51);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_imm32((u32 *)(&rdword), (u32)dst->f.i.rt); /* 10 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)readmemd); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(dst->f.i.rt)); /* 5 */
   mov_reg32_m32(ECX, (u32 *)(dst->f.i.rt)+1); /* 6 */
   jmp_imm_short(18); /* 2 */
   
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_reg32_preg32pimm32(EAX, EBX, ((u32)rdram)+4); /* 6 */
   mov_reg32_preg32pimm32(ECX, EBX, ((u32)rdram)); /* 6 */
   
   set_64_register_state(EAX, ECX, (u32*)dst->f.i.rt, 1);
#endif
}

void genswc1()
{
#ifdef INTERPRET_SWC1
   gencallinterp((u32)SWC1, 0);
#else
   gencheck_cop1_unusable();
   
   mov_reg32_m32(EDX, (u32*)(&reg_cop1_simple[dst->f.lf.ft]));
   mov_reg32_preg32(ECX, EDX);
   mov_eax_memoffs32((u32 *)(&reg[dst->f.lf.base]));
   add_eax_imm32((s32)dst->f.lf.offset);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writemem);
	cmp_reg32_imm32(EAX, (u32)write_rdram);
     }
   je_rj(41);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_reg32((u32 *)(&word), ECX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writemem); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(14); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_preg32pimm32_reg32(EBX, (u32)rdram, ECX); /* 6 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void gensdc1()
{
#ifdef INTERPRET_SDC1
   gencallinterp((u32)SDC1, 0);
#else
   gencheck_cop1_unusable();
   
   mov_reg32_m32(ESI, (u32*)(&reg_cop1_double[dst->f.lf.ft]));
   mov_reg32_preg32(ECX, ESI);
   mov_reg32_preg32pimm32(EDX, ESI, 4);
   mov_eax_memoffs32((u32 *)(&reg[dst->f.lf.base]));
   add_eax_imm32((s32)dst->f.lf.offset);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writememd);
	cmp_reg32_imm32(EAX, (u32)write_rdramd);
     }
   je_rj(47);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_reg32((u32 *)(&dword), ECX); /* 6 */
   mov_m32_reg32((u32 *)(&dword)+1, EDX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writememd); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(20); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_preg32pimm32_reg32(EBX, ((u32)rdram)+4, ECX); /* 6 */
   mov_preg32pimm32_reg32(EBX, ((u32)rdram)+0, EDX); /* 6 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void gensd()
{
#ifdef INTERPRET_SD
   gencallinterp((u32)SD, 0);
#else
   free_all_registers();
   simplify_access();
   
   mov_reg32_m32(ECX, (u32 *)dst->f.i.rt);
   mov_reg32_m32(EDX, ((u32 *)dst->f.i.rt)+1);
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   add_eax_imm32((s32)dst->f.i.immediate);
   mov_reg32_reg32(EBX, EAX);
   if(fast_memory)
     {
	and_eax_imm32(0xDF800000);
	cmp_eax_imm32(0x80000000);
     }
   else
     {
	shr_reg32_imm8(EAX, 16);
	mov_reg32_preg32x4pimm32(EAX, EAX, (u32)writememd);
	cmp_reg32_imm32(EAX, (u32)write_rdramd);
     }
   je_rj(47);
   
   mov_m32_imm32((void *)(&PC), (u32)(dst+1)); /* 10 */
   mov_m32_reg32((u32 *)(&address), EBX); /* 6 */
   mov_m32_reg32((u32 *)(&dword), ECX); /* 6 */
   mov_m32_reg32((u32 *)(&dword)+1, EDX); /* 6 */
   shr_reg32_imm8(EBX, 16); /* 3 */
   mov_reg32_preg32x4pimm32(EBX, EBX, (u32)writememd); /* 7 */
   call_reg32(EBX); /* 2 */
   mov_eax_memoffs32((u32 *)(&address)); /* 5 */
   jmp_imm_short(20); /* 2 */
   
   mov_reg32_reg32(EAX, EBX); /* 2 */
   and_reg32_imm32(EBX, 0x7FFFFF); /* 6 */
   mov_preg32pimm32_reg32(EBX, ((u32)rdram)+4, ECX); /* 6 */
   mov_preg32pimm32_reg32(EBX, ((u32)rdram)+0, EDX); /* 6 */
   
   mov_reg32_reg32(EBX, EAX);
   shr_reg32_imm8(EBX, 12);
   cmp_preg32pimm32_imm8(EBX, (u32)invalid_code, 0);
   jne_rj(54);
   mov_reg32_reg32(ECX, EBX); /* 2 */
   shl_reg32_imm8(EBX, 2); /* 3 */
   mov_reg32_preg32pimm32(EBX, EBX, (u32)blocks); /* 6 */
   mov_reg32_preg32pimm32(EBX, EBX, (int)&actual->block - (int)actual); /* 6 */
   and_eax_imm32(0xFFF); /* 5 */
   shr_reg32_imm8(EAX, 2); /* 3 */
   mov_reg32_imm32(EDX, sizeof(precomp_instr)); /* 5 */
   mul_reg32(EDX); /* 2 */
   mov_reg32_preg32preg32pimm32(EAX, EAX, EBX, (int)&dst->ops - (int)dst); /* 7 */
   cmp_reg32_imm32(EAX, (u32)NOTCOMPILED); /* 6 */
   je_rj(7); /* 2 */
   mov_preg32pimm32_imm8(ECX, (u32)invalid_code, 1); /* 7 */
#endif
}

void genll()
{
   gencallinterp((u32)LL, 0);
}

void gensc()
{
   gencallinterp((u32)SC, 0);
}

#endif
