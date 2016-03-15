/**
 * Mupen64 - gspecial.c
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

#include <stdio.h>
#include "../recomph.h"
#include "../recomp.h"
#include "assemble.h"
#include "../r4300.h"
#include "../ops.h"
#include "../macros.h"
#include "../exception.h"
#include "interpret.h"

void gensll()
{
#ifdef INTERPRET_SLL
   gencallinterp((u32)SLL, 0);
#else
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd, rt);
   shl_reg32_imm8(rd, dst->f.r.sa);
#endif
}

void gensrl()
{
#ifdef INTERPRET_SRL
   gencallinterp((u32)SRL, 0);
#else
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd, rt);
   shr_reg32_imm8(rd, dst->f.r.sa);
#endif
}

void gensra()
{
#ifdef INTERPRET_SRA
   gencallinterp((u32)SRA, 0);
#else
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd, rt);
   sar_reg32_imm8(rd, dst->f.r.sa);
#endif
}

void gensllv()
{
#ifdef INTERPRET_SLLV
   gencallinterp((u32)SLLV, 0);
#else
   int rt, rd;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt = allocate_register((u32 *)dst->f.r.rt);
   rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rd != ECX)
     {
	mov_reg32_reg32(rd, rt);
	shl_reg32_cl(rd);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rt);
	shl_reg32_cl(temp);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void gensrlv()
{
#ifdef INTERPRET_SRLV
   gencallinterp((u32)SRLV, 0);
#else
   int rt, rd;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt = allocate_register((u32 *)dst->f.r.rt);
   rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rd != ECX)
     {
	mov_reg32_reg32(rd, rt);
	shr_reg32_cl(rd);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rt);
	shr_reg32_cl(temp);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void gensrav()
{
#ifdef INTERPRET_SRAV
   gencallinterp((u32)SRAV, 0);
#else
   int rt, rd;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt = allocate_register((u32 *)dst->f.r.rt);
   rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rd != ECX)
     {
	mov_reg32_reg32(rd, rt);
	sar_reg32_cl(rd);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rt);
	sar_reg32_cl(temp);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void genjr()
{
#ifdef INTERPRET_JR
   gencallinterp((u32)JR, 1);
#else
   static u32 precomp_instr_size = sizeof(precomp_instr);
   u32 diff = 
     (u32)(&dst->local_addr) - (u32)(dst);
   u32 diff_need = 
     (u32)(&dst->reg_cache_infos.need_map) - (u32)(dst);
   u32 diff_wrap = 
     (u32)(&dst->reg_cache_infos.jump_wrapper) - (u32)(dst);
   u32 temp, temp2;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)JR, 1);
	return;
     }
   
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.i.rs);
   mov_memoffs32_eax((u32 *)&local_rs);
   
   gendelayslot();
   
   mov_eax_memoffs32((u32 *)&local_rs);
   mov_memoffs32_eax((u32 *)&last_addr);
   
   gencheck_interupt_reg();
   
   mov_eax_memoffs32((u32 *)&local_rs);
   mov_reg32_reg32(EBX, EAX);
   and_eax_imm32(0xFFFFF000);
   cmp_eax_imm32(dst_block->start & 0xFFFFF000);
   je_near_rj(0);
   temp = code_length;
   
   mov_m32_reg32(&jump_to_address, EBX);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   
   mov_reg32_reg32(EAX, EBX);
   sub_eax_imm32(dst_block->start);
   shr_reg32_imm8(EAX, 2);
   mul_m32((u32 *)(&precomp_instr_size));
   
   mov_reg32_preg32pimm32(EBX, EAX, (u32)(dst_block->block)+diff_need);
   cmp_reg32_imm32(EBX, 1);
   jne_rj(7);
   
   add_eax_imm32((u32)(dst_block->block)+diff_wrap); /* 5 */
   jmp_reg32(EAX); /* 2 */
   
   mov_reg32_preg32pimm32(EAX, EAX, (u32)(dst_block->block)+diff);
   add_reg32_m32(EAX, (u32 *)(&dst_block->code));
   
   jmp_reg32(EAX);
#endif
}

void genjalr()
{
#ifdef INTERPRET_JALR
   gencallinterp((u32)JALR, 0);
#else
   static u32 precomp_instr_size = sizeof(precomp_instr);
   u32 diff = 
     (u32)(&dst->local_addr) - (u32)(dst);
   u32 diff_need = 
     (u32)(&dst->reg_cache_infos.need_map) - (u32)(dst);
   u32 diff_wrap = 
     (u32)(&dst->reg_cache_infos.jump_wrapper) - (u32)(dst);
   u32 temp, temp2;
   
   if (((dst->addr & 0xFFF) == 0xFFC && 
       (dst->addr < 0x80000000 || dst->addr >= 0xC0000000))||no_compiled_jump)
     {
	gencallinterp((u32)JALR, 1);
	return;
     }
   
   free_all_registers();
   simplify_access();
   mov_eax_memoffs32((u32 *)dst->f.r.rs);
   mov_memoffs32_eax((u32 *)&local_rs);
   
   gendelayslot();
   
   mov_m32_imm32((u32 *)(dst-1)->f.r.rd, dst->addr+4);
   if ((dst->addr+4) & 0x80000000)
     mov_m32_imm32(((u32 *)(dst-1)->f.r.rd)+1, 0xFFFFFFFF);
   else
     mov_m32_imm32(((u32 *)(dst-1)->f.r.rd)+1, 0);
   
   mov_eax_memoffs32((u32 *)&local_rs);
   mov_memoffs32_eax((u32 *)&last_addr);
   
   gencheck_interupt_reg();
   
   mov_eax_memoffs32((u32 *)&local_rs);
   mov_reg32_reg32(EBX, EAX);
   and_eax_imm32(0xFFFFF000);
   cmp_eax_imm32(dst_block->start & 0xFFFFF000);
   je_near_rj(0);
   temp = code_length;
   
   mov_m32_reg32(&jump_to_address, EBX);
   mov_m32_imm32((u32*)(&PC), (u32)(dst+1));
   mov_reg32_imm32(EAX, (u32)jump_to_func);
   call_reg32(EAX);
   
   temp2 = code_length;
   code_length = temp-4;
   put32(temp2 - temp);
   code_length = temp2;
   
   mov_reg32_reg32(EAX, EBX);
   sub_eax_imm32(dst_block->start);
   shr_reg32_imm8(EAX, 2);
   mul_m32((u32 *)(&precomp_instr_size));
   
   mov_reg32_preg32pimm32(EBX, EAX, (u32)(dst_block->block)+diff_need);
   cmp_reg32_imm32(EBX, 1);
   jne_rj(7);
   
   add_eax_imm32((u32)(dst_block->block)+diff_wrap); /* 5 */
   jmp_reg32(EAX); /* 2 */
   
   mov_reg32_preg32pimm32(EAX, EAX, (u32)(dst_block->block)+diff);
   add_reg32_m32(EAX, (u32 *)(&dst_block->code));
   
   jmp_reg32(EAX);
#endif
}

void gensyscall()
{
#ifdef INTERPRET_SYSCALL
   gencallinterp((u32)SYSCALL, 0);
#else
   free_all_registers();
   simplify_access();
   mov_m32_imm32(&Cause, 8 << 2);
   gencallinterp((u32)exception_general, 0);
#endif
}

void gensync()
{
}

void genmfhi()
{
#ifdef INTERPRET_MFHI
   gencallinterp((u32)MFHI, 0);
#else
   int rd1 = allocate_64_register1_w((u32*)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32*)dst->f.r.rd);
   int hi1 = allocate_64_register1((u32*)&hi);
   int hi2 = allocate_64_register2((u32*)&hi);
   
   mov_reg32_reg32(rd1, hi1);
   mov_reg32_reg32(rd2, hi2);
#endif
}

void genmthi()
{
#ifdef INTERPRET_MTHI
   gencallinterp((u32)MTHI, 0);
#else
   int hi1 = allocate_64_register1_w((u32*)&hi);
   int hi2 = allocate_64_register2_w((u32*)&hi);
   int rs1 = allocate_64_register1((u32*)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32*)dst->f.r.rs);
   
   mov_reg32_reg32(hi1, rs1);
   mov_reg32_reg32(hi2, rs2);
#endif
}

void genmflo()
{
#ifdef INTERPRET_MFLO
   gencallinterp((u32)MFLO, 0);
#else
   int rd1 = allocate_64_register1_w((u32*)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32*)dst->f.r.rd);
   int lo1 = allocate_64_register1((u32*)&lo);
   int lo2 = allocate_64_register2((u32*)&lo);
   
   mov_reg32_reg32(rd1, lo1);
   mov_reg32_reg32(rd2, lo2);
#endif
}

void genmtlo()
{
#ifdef INTERPRET_MTLO
   gencallinterp((u32)MTLO, 0);
#else
   int lo1 = allocate_64_register1_w((u32*)&lo);
   int lo2 = allocate_64_register2_w((u32*)&lo);
   int rs1 = allocate_64_register1((u32*)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32*)dst->f.r.rs);
   
   mov_reg32_reg32(lo1, rs1);
   mov_reg32_reg32(lo2, rs2);
#endif
}

void gendsllv()
{
#ifdef INTERPRET_DSLLV
   gencallinterp((u32)DSLLV, 0);
#else
   int rt1, rt2, rd1, rd2;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rd1 != ECX && rd2 != ECX)
     {
	mov_reg32_reg32(rd1, rt1);
	mov_reg32_reg32(rd2, rt2);
	shld_reg32_reg32_cl(rd2,rd1);
	shl_reg32_cl(rd1);
	test_reg32_imm32(ECX, 0x20);
	je_rj(4);
	mov_reg32_reg32(rd2, rd1); /* 2 */
	xor_reg32_reg32(rd1, rd1); /* 2 */
     }
   else
     {
	int temp1, temp2;
	force_32(ECX);
	temp1 = lru_register();
	temp2 = lru_register_exc1(temp1);
	free_register(temp1);
	free_register(temp2);
	
	mov_reg32_reg32(temp1, rt1);
	mov_reg32_reg32(temp2, rt2);
	shld_reg32_reg32_cl(temp2, temp1);
	shl_reg32_cl(temp1);
	test_reg32_imm32(ECX, 0x20);
	je_rj(4);
	mov_reg32_reg32(temp2, temp1); /* 2 */
	xor_reg32_reg32(temp1, temp1); /* 2 */
	
	mov_reg32_reg32(rd1, temp1);
	mov_reg32_reg32(rd2, temp2);
     }
#endif
}

void gendsrlv()
{
#ifdef INTERPRET_DSRLV
   gencallinterp((u32)DSRLV, 0);
#else
   int rt1, rt2, rd1, rd2;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rd1 != ECX && rd2 != ECX)
     {
	mov_reg32_reg32(rd1, rt1);
	mov_reg32_reg32(rd2, rt2);
	shrd_reg32_reg32_cl(rd1,rd2);
	shr_reg32_cl(rd2);
	test_reg32_imm32(ECX, 0x20);
	je_rj(4);
	mov_reg32_reg32(rd1, rd2); /* 2 */
	xor_reg32_reg32(rd2, rd2); /* 2 */
     }
   else
     {
	int temp1, temp2;
	force_32(ECX);
	temp1 = lru_register();
	temp2 = lru_register_exc1(temp1);
	free_register(temp1);
	free_register(temp2);
	
	mov_reg32_reg32(temp1, rt1);
	mov_reg32_reg32(temp2, rt2);
	shrd_reg32_reg32_cl(temp1, temp2);
	shr_reg32_cl(temp2);
	test_reg32_imm32(ECX, 0x20);
	je_rj(4);
	mov_reg32_reg32(temp1, temp2); /* 2 */
	xor_reg32_reg32(temp2, temp2); /* 2 */
	
	mov_reg32_reg32(rd1, temp1);
	mov_reg32_reg32(rd2, temp2);
     }
#endif
}

void gendsrav()
{
#ifdef INTERPRET_DSRAV
   gencallinterp((u32)DSRAV, 0);
#else
   int rt1, rt2, rd1, rd2;
   allocate_register_manually(ECX, (u32 *)dst->f.r.rs);
   
   rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rd1 != ECX && rd2 != ECX)
     {
	mov_reg32_reg32(rd1, rt1);
	mov_reg32_reg32(rd2, rt2);
	shrd_reg32_reg32_cl(rd1,rd2);
	sar_reg32_cl(rd2);
	test_reg32_imm32(ECX, 0x20);
	je_rj(5);
	mov_reg32_reg32(rd1, rd2); /* 2 */
	sar_reg32_imm8(rd2, 31); /* 3 */
     }
   else
     {
	int temp1, temp2;
	force_32(ECX);
	temp1 = lru_register();
	temp2 = lru_register_exc1(temp1);
	free_register(temp1);
	free_register(temp2);
	
	mov_reg32_reg32(temp1, rt1);
	mov_reg32_reg32(temp2, rt2);
	shrd_reg32_reg32_cl(temp1, temp2);
	sar_reg32_cl(temp2);
	test_reg32_imm32(ECX, 0x20);
	je_rj(5);
	mov_reg32_reg32(temp1, temp2); /* 2 */
	sar_reg32_imm8(temp2, 31); /* 3 */
	
	mov_reg32_reg32(rd1, temp1);
	mov_reg32_reg32(rd2, temp2);
     }
#endif
}

void genmult()
{
#ifdef INTERPRET_MULT
   gencallinterp((u32)MULT, 0);
#else
   int rs, rt;
   allocate_register_manually_w(EAX, (u32 *)&lo, 0);
   allocate_register_manually_w(EDX, (u32 *)&hi, 0);
   rs = allocate_register((u32*)dst->f.r.rs);
   rt = allocate_register((u32*)dst->f.r.rt);
   mov_reg32_reg32(EAX, rs);
   imul_reg32(rt);
#endif
}

void genmultu()
{
#ifdef INTERPRET_MULTU
   gencallinterp((u32)MULTU, 0);
#else
   int rs, rt;
   allocate_register_manually_w(EAX, (u32 *)&lo, 0);
   allocate_register_manually_w(EDX, (u32 *)&hi, 0);
   rs = allocate_register((u32*)dst->f.r.rs);
   rt = allocate_register((u32*)dst->f.r.rt);
   mov_reg32_reg32(EAX, rs);
   mul_reg32(rt);
#endif
}

void gendiv()
{
#ifdef INTERPRET_DIV
   gencallinterp((u32)DIV, 0);
#else
   int rs, rt;
   allocate_register_manually_w(EAX, (u32 *)&lo, 0);
   allocate_register_manually_w(EDX, (u32 *)&hi, 0);
   rs = allocate_register((u32*)dst->f.r.rs);
   rt = allocate_register((u32*)dst->f.r.rt);
   cmp_reg32_imm32(rt, 0);
   je_rj((rs == EAX ? 0 : 2) + 1 + 2);
   mov_reg32_reg32(EAX, rs); /* 0 or 2 */
   cdq(); /* 1 */
   idiv_reg32(rt); /* 2 */
#endif
}

void gendivu()
{
#ifdef INTERPRET_DIVU
   gencallinterp((u32)DIVU, 0);
#else
   int rs, rt;
   allocate_register_manually_w(EAX, (u32 *)&lo, 0);
   allocate_register_manually_w(EDX, (u32 *)&hi, 0);
   rs = allocate_register((u32*)dst->f.r.rs);
   rt = allocate_register((u32*)dst->f.r.rt);
   cmp_reg32_imm32(rt, 0);
   je_rj((rs == EAX ? 0 : 2) + 2 + 2);
   mov_reg32_reg32(EAX, rs); /* 0 or 2 */
   xor_reg32_reg32(EDX, EDX); /* 2 */
   div_reg32(rt); /* 2 */
#endif
}

void gendmult()
{
   gencallinterp((u32)DMULT, 0);
}

void gendmultu()
{
#ifdef INTERPRET_DMULTU
   gencallinterp((u32)DMULTU, 0);
#else
   free_all_registers();
   simplify_access();
   
   mov_eax_memoffs32((u32 *)dst->f.r.rs);
   mul_m32((u32 *)dst->f.r.rt); /* EDX:EAX = temp1 */
   mov_memoffs32_eax((u32 *)(&lo));
   
   mov_reg32_reg32(EBX, EDX); /* EBX = temp1 >> 32 */
   mov_eax_memoffs32((u32 *)dst->f.r.rs);
   mul_m32((u32 *)(dst->f.r.rt)+1);
   add_reg32_reg32(EBX, EAX);
   adc_reg32_imm32(EDX, 0);
   mov_reg32_reg32(ECX, EDX); /* ECX:EBX = temp2 */
   
   mov_eax_memoffs32((u32 *)(dst->f.r.rs)+1);
   mul_m32((u32 *)dst->f.r.rt); /* EDX:EAX = temp3 */
   
   add_reg32_reg32(EBX, EAX);
   adc_reg32_imm32(ECX, 0); /* ECX:EBX = result2 */
   mov_m32_reg32((u32*)(&lo)+1, EBX);
   
   mov_reg32_reg32(ESI, EDX); /* ESI = temp3 >> 32 */
   mov_eax_memoffs32((u32 *)(dst->f.r.rs)+1);
   mul_m32((u32 *)(dst->f.r.rt)+1);
   add_reg32_reg32(EAX, ESI);
   adc_reg32_imm32(EDX, 0); /* EDX:EAX = temp4 */
   
   add_reg32_reg32(EAX, ECX);
   adc_reg32_imm32(EDX, 0); /* EDX:EAX = result3 */
   mov_memoffs32_eax((u32 *)(&hi));
   mov_m32_reg32((u32 *)(&hi)+1, EDX);
#endif
}

void genddiv()
{
   gencallinterp((u32)DDIV, 0);
}

void genddivu()
{
   gencallinterp((u32)DDIVU, 0);
}

void genadd()
{
#ifdef INTERPRET_ADD
   gencallinterp((u32)ADD, 0);
#else
   int rs = allocate_register((u32 *)dst->f.r.rs);
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rt != rd && rs != rd)
     {
	mov_reg32_reg32(rd, rs);
	add_reg32_reg32(rd, rt);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs);
	add_reg32_reg32(temp, rt);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void genaddu()
{
#ifdef INTERPRET_ADDU
   gencallinterp((u32)ADDU, 0);
#else
   int rs = allocate_register((u32 *)dst->f.r.rs);
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rt != rd && rs != rd)
     {
	mov_reg32_reg32(rd, rs);
	add_reg32_reg32(rd, rt);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs);
	add_reg32_reg32(temp, rt);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void gensub()
{
#ifdef INTERPRET_SUB
   gencallinterp((u32)SUB, 0);
#else
   int rs = allocate_register((u32 *)dst->f.r.rs);
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rt != rd && rs != rd)
     {
	mov_reg32_reg32(rd, rs);
	sub_reg32_reg32(rd, rt);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs);
	sub_reg32_reg32(temp, rt);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void gensubu()
{
#ifdef INTERPRET_SUBU
   gencallinterp((u32)SUBU, 0);
#else
   int rs = allocate_register((u32 *)dst->f.r.rs);
   int rt = allocate_register((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   if (rt != rd && rs != rd)
     {
	mov_reg32_reg32(rd, rs);
	sub_reg32_reg32(rd, rt);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs);
	sub_reg32_reg32(temp, rt);
	mov_reg32_reg32(rd, temp);
     }
#endif
}

void genand()
{
#ifdef INTERPRET_AND
   gencallinterp((u32)AND, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	and_reg32_reg32(rd1, rt1);
	and_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	and_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	and_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void genor()
{
#ifdef INTERPRET_OR
   gencallinterp((u32)OR, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	or_reg32_reg32(rd1, rt1);
	or_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	or_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	or_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void genxor()
{
#ifdef INTERPRET_XOR
   gencallinterp((u32)XOR, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	xor_reg32_reg32(rd1, rt1);
	xor_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	xor_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	xor_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void gennor()
{
#ifdef INTERPRET_NOR
   gencallinterp((u32)NOR, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	or_reg32_reg32(rd1, rt1);
	or_reg32_reg32(rd2, rt2);
	not_reg32(rd1);
	not_reg32(rd2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	or_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	or_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
	not_reg32(rd1);
	not_reg32(rd2);
     }
#endif
}

void genslt()
{
#ifdef INTERPRET_SLT
   gencallinterp((u32)SLT, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   cmp_reg32_reg32(rs2, rt2);
   jl_rj(13);
   jne_rj(4); /* 2 */
   cmp_reg32_reg32(rs1, rt1); /* 2 */
   jl_rj(7); /* 2 */
   mov_reg32_imm32(rd, 0); /* 5 */
   jmp_imm_short(5); /* 2 */
   mov_reg32_imm32(rd, 1); /* 5 */
#endif
}

void gensltu()
{
#ifdef INTERPRET_SLTU
   gencallinterp((u32)SLTU, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   cmp_reg32_reg32(rs2, rt2);
   jb_rj(13);
   jne_rj(4); /* 2 */
   cmp_reg32_reg32(rs1, rt1); /* 2 */
   jb_rj(7); /* 2 */
   mov_reg32_imm32(rd, 0); /* 5 */
   jmp_imm_short(5); /* 2 */
   mov_reg32_imm32(rd, 1); /* 5 */
#endif
}

void gendadd()
{
#ifdef INTERPRET_DADD
   gencallinterp((u32)DADD, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	add_reg32_reg32(rd1, rt1);
	adc_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	add_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	adc_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void gendaddu()
{
#ifdef INTERPRET_DADDU
   gencallinterp((u32)DADDU, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	add_reg32_reg32(rd1, rt1);
	adc_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	add_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	adc_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void gendsub()
{
#ifdef INTERPRET_DSUB
   gencallinterp((u32)DSUB, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	sub_reg32_reg32(rd1, rt1);
	sbb_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	sub_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	sbb_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void gendsubu()
{
#ifdef INTERPRET_DSUBU
   gencallinterp((u32)DSUBU, 0);
#else
   int rs1 = allocate_64_register1((u32 *)dst->f.r.rs);
   int rs2 = allocate_64_register2((u32 *)dst->f.r.rs);
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   if (rt1 != rd1 && rs1 != rd1)
     {
	mov_reg32_reg32(rd1, rs1);
	mov_reg32_reg32(rd2, rs2);
	sub_reg32_reg32(rd1, rt1);
	sbb_reg32_reg32(rd2, rt2);
     }
   else
     {
	int temp = lru_register();
	free_register(temp);
	mov_reg32_reg32(temp, rs1);
	sub_reg32_reg32(temp, rt1);
	mov_reg32_reg32(rd1, temp);
	mov_reg32_reg32(temp, rs2);
	sbb_reg32_reg32(temp, rt2);
	mov_reg32_reg32(rd2, temp);
     }
#endif
}

void genteq()
{
   gencallinterp((u32)TEQ, 0);
}

void gendsll()
{
#ifdef INTERPRET_DSLL
   gencallinterp((u32)DSLL, 0);
#else
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd1, rt1);
   mov_reg32_reg32(rd2, rt2);
   shld_reg32_reg32_imm8(rd2, rd1, dst->f.r.sa);
   shl_reg32_imm8(rd1, dst->f.r.sa);
   if (dst->f.r.sa & 0x20)
     {
	mov_reg32_reg32(rd2, rd1);
	xor_reg32_reg32(rd1, rd1);
     }
#endif
}

void gendsrl()
{
#ifdef INTERPRET_DSRL
   gencallinterp((u32)DSRL, 0);
#else
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd1, rt1);
   mov_reg32_reg32(rd2, rt2);
   shrd_reg32_reg32_imm8(rd1, rd2, dst->f.r.sa);
   shr_reg32_imm8(rd2, dst->f.r.sa);
   if (dst->f.r.sa & 0x20)
     {
	mov_reg32_reg32(rd1, rd2);
	xor_reg32_reg32(rd2, rd2);
     }
#endif
}

void gendsra()
{
#ifdef INTERPRET_DSRA
   gencallinterp((u32)DSRA, 0);
#else
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd1, rt1);
   mov_reg32_reg32(rd2, rt2);
   shrd_reg32_reg32_imm8(rd1, rd2, dst->f.r.sa);
   sar_reg32_imm8(rd2, dst->f.r.sa);
   if (dst->f.r.sa & 0x20)
     {
	mov_reg32_reg32(rd1, rd2);
	sar_reg32_imm8(rd2, 31);
     }
#endif
}

void gendsll32()
{
#ifdef INTERPRET_DSLL32
   gencallinterp((u32)DSLL32, 0);
#else
   int rt1 = allocate_64_register1((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd2, rt1);
   shl_reg32_imm8(rd2, dst->f.r.sa);
   xor_reg32_reg32(rd1, rd1);
#endif
}

void gendsrl32()
{
#ifdef INTERPRET_DSRL32
   gencallinterp((u32)DSRL32, 0);
#else
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd1 = allocate_64_register1_w((u32 *)dst->f.r.rd);
   int rd2 = allocate_64_register2_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd1, rt2);
   shr_reg32_imm8(rd1, dst->f.r.sa);
   xor_reg32_reg32(rd2, rd2);
#endif
}

void gendsra32()
{
#ifdef INTERPRET_DSRA32
   gencallinterp((u32)DSRA32, 0);
#else
   int rt2 = allocate_64_register2((u32 *)dst->f.r.rt);
   int rd = allocate_register_w((u32 *)dst->f.r.rd);
   
   mov_reg32_reg32(rd, rt2);
   sar_reg32_imm8(rd, dst->f.r.sa);
#endif
}

#endif
