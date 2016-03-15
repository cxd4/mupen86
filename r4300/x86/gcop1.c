/**
 * Mupen64 - gcop1.c
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
#include "../../memory/memory.h"
#include "../macros.h"
#include "interpret.h"

void genmfc1()
{
#ifdef INTERPRET_MFC1
   gencallinterp((u32)MFC1, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((u32*)(&reg_cop1_simple[dst->f.r.nrd]));
   mov_reg32_preg32(EBX, EAX);
   mov_m32_reg32((u32*)dst->f.r.rt, EBX);
   sar_reg32_imm8(EBX, 31);
   mov_m32_reg32(((u32*)dst->f.r.rt)+1, EBX);
#endif
}

void gendmfc1()
{
#ifdef INTERPRET_DMFC1
   gencallinterp((u32)DMFC1, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((u32*)(&reg_cop1_double[dst->f.r.nrd]));
   mov_reg32_preg32(EBX, EAX);
   mov_reg32_preg32pimm32(ECX, EAX, 4);
   mov_m32_reg32((u32*)dst->f.r.rt, EBX);
   mov_m32_reg32(((u32*)dst->f.r.rt)+1, ECX);
#endif
}

void gencfc1()
{
#ifdef INTERPRET_CFC1
   gencallinterp((u32)CFC1, 0);
#else
   gencheck_cop1_unusable();
   if(dst->f.r.nrd == 31) mov_eax_memoffs32((u32*)&FCR31);
   else mov_eax_memoffs32((u32*)&FCR0);
   mov_memoffs32_eax((u32*)dst->f.r.rt);
   sar_reg32_imm8(EAX, 31);
   mov_memoffs32_eax(((u32*)dst->f.r.rt)+1);
#endif
}

void genmtc1()
{
#ifdef INTERPRET_MTC1
   gencallinterp((u32)MTC1, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((u32*)dst->f.r.rt);
   mov_reg32_m32(EBX, (u32*)(&reg_cop1_simple[dst->f.r.nrd]));
   mov_preg32_reg32(EBX, EAX);
#endif
}

void gendmtc1()
{
#ifdef INTERPRET_DMTC1
   gencallinterp((u32)DMTC1, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((u32*)dst->f.r.rt);
   mov_reg32_m32(EBX, ((u32*)dst->f.r.rt)+1);
   mov_reg32_m32(EDX, (u32*)(&reg_cop1_double[dst->f.r.nrd]));
   mov_preg32_reg32(EDX, EAX);
   mov_preg32pimm32_reg32(EDX, 4, EBX);
#endif
}

void genctc1()
{
#ifdef INTERPRET_CTC1
   gencallinterp((u32)CTC1, 0);
#else
   gencheck_cop1_unusable();

    if (dst->f.r.nrd != 31)
       return;
   mov_eax_memoffs32((u32*)dst->f.r.rt);
   mov_memoffs32_eax((u32*)&FCR31);
   and_eax_imm32(3);

   cmp_eax_imm32(0);
   jne_rj(12);
   mov_m32_imm32((u32*)&rounding_mode, 0x33F); /* 10 */
   jmp_imm_short(48); /* 2 */

   cmp_eax_imm32(1); /* 5 */
   jne_rj(12); /* 2 */
   mov_m32_imm32((u32*)&rounding_mode, 0xF3F); /* 10 */
   jmp_imm_short(29); /* 2 */

   cmp_eax_imm32(2); /* 5 */
   jne_rj(12); /* 2 */
   mov_m32_imm32((u32*)&rounding_mode, 0xB3F); /* 10 */
   jmp_imm_short(10); /* 2 */

   mov_m32_imm32((u32*)&rounding_mode, 0x73F); /* 10 */

   fldcw_m16((u16*)&rounding_mode);
#endif
}

#endif
