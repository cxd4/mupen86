/**
 * Mupen64 - gcop1_d.c
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

#include <stdio.h>
#include "../recomph.h"
#include "assemble.h"
#include "../r4300.h"
#include "../ops.h"
#include "interpret.h"

void genadd_d()
{
#ifdef INTERPRET_ADD_D
   gencallinterp((unsigned long)ADD_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.ft]));
   fadd_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void gensub_d()
{
#ifdef INTERPRET_SUB_D
   gencallinterp((unsigned long)SUB_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.ft]));
   fsub_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void genmul_d()
{
#ifdef INTERPRET_MUL_D
   gencallinterp((unsigned long)MUL_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.ft]));
   fmul_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void gendiv_d()
{
#ifdef INTERPRET_DIV_D
   gencallinterp((unsigned long)DIV_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.ft]));
   fdiv_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void gensqrt_d()
{
#ifdef INTERPRET_SQRT_D
   gencallinterp((unsigned long)SQRT_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fsqrt();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void genabs_d()
{
#ifdef INTERPRET_ABS_D
   gencallinterp((unsigned long)ABS_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fabs_();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void genmov_d()
{
#ifdef INTERPRET_MOV_D
   gencallinterp((unsigned long)MOV_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   mov_reg32_preg32(EBX, EAX);
   mov_reg32_preg32pimm32(ECX, EAX, 4);
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   mov_preg32_reg32(EAX, EBX);
   mov_preg32pimm32_reg32(EAX, 4, ECX);
#endif
}

void genneg_d()
{
#ifdef INTERPRET_NEG_D
   gencallinterp((unsigned long)NEG_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fchs();
   mov_eax_memoffs32((unsigned long *)(&reg_cop1_double[dst->f.cf.fd]));
   fstp_preg32_qword(EAX);
#endif
}

void genround_l_d()
{
#ifdef INTERPRET_ROUND_L_D
   gencallinterp((unsigned long)ROUND_L_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&round_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fd]));
   fistp_preg32_qword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void gentrunc_l_d()
{
#ifdef INTERPRET_TRUNC_L_D
   gencallinterp((unsigned long)TRUNC_L_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&trunc_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fd]));
   fistp_preg32_qword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void genceil_l_d()
{
#ifdef INTERPRET_CEIL_L_D
   gencallinterp((unsigned long)CEIL_L_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&ceil_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fd]));
   fistp_preg32_qword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void genfloor_l_d()
{
#ifdef INTERPRET_FLOOR_L_D
   gencallinterp((unsigned long)FLOOR_L_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&floor_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fd]));
   fistp_preg32_qword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void genround_w_d()
{
#ifdef INTERPRET_ROUND_W_D
   gencallinterp((unsigned long)ROUND_W_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&round_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fistp_preg32_dword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void gentrunc_w_d()
{
#ifdef INTERPRET_TRUNC_W_D
   gencallinterp((unsigned long)TRUNC_W_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&trunc_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fistp_preg32_dword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void genceil_w_d()
{
#ifdef INTERPRET_CEIL_W_D
   gencallinterp((unsigned long)CEIL_W_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&ceil_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fistp_preg32_dword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void genfloor_w_d()
{
#ifdef INTERPRET_FLOOR_W_D
   gencallinterp((unsigned long)FLOOR_W_D, 0);
#else
   gencheck_cop1_unusable();
   fldcw_m16((unsigned short*)&floor_mode);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fistp_preg32_dword(EAX);
   fldcw_m16((unsigned short*)&rounding_mode);
#endif
}

void gencvt_s_d()
{
#ifdef INTERPRET_CVT_S_D
   gencallinterp((unsigned long)CVT_S_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fstp_preg32_dword(EAX);
#endif
}

void gencvt_w_d()
{
#ifdef INTERPRET_CVT_W_D
   gencallinterp((unsigned long)CVT_W_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_simple[dst->f.cf.fd]));
   fistp_preg32_dword(EAX);
#endif
}

void gencvt_l_d()
{
#ifdef INTERPRET_CVT_L_D
   gencallinterp((unsigned long)CVT_L_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fd]));
   fistp_preg32_qword(EAX);
#endif
}

void genc_f_d()
{
#ifdef INTERPRET_C_F_D
   gencallinterp((unsigned long)C_F_D, 0);
#else
   gencheck_cop1_unusable();
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000);
#endif
}

void genc_un_d()
{
#ifdef INTERPRET_C_UN_D
   gencallinterp((unsigned long)C_UN_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(12);
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
   jmp_imm_short(10); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
#endif
}

void genc_eq_d()
{
#ifdef INTERPRET_C_EQ_D
   gencallinterp((unsigned long)C_EQ_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jne_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ueq_d()
{
#ifdef INTERPRET_C_UEQ_D
   gencallinterp((unsigned long)C_UEQ_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   jne_rj(12);
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_olt_d()
{
#ifdef INTERPRET_C_OLT_D
   gencallinterp((unsigned long)C_OLT_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jae_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ult_d()
{
#ifdef INTERPRET_C_ULT_D
   gencallinterp((unsigned long)C_ULT_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   jae_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ole_d()
{
#ifdef INTERPRET_C_OLE_D
   gencallinterp((unsigned long)C_OLE_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   ja_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ule_d()
{
#ifdef INTERPRET_C_ULE_D
   gencallinterp((unsigned long)C_ULE_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fucomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   ja_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_sf_d()
{
#ifdef INTERPRET_C_SF_D
   gencallinterp((unsigned long)C_SF_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000);
#endif
}

void genc_ngle_d()
{
#ifdef INTERPRET_C_NGLE_D
   gencallinterp((unsigned long)C_NGLE_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(12);
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
   jmp_imm_short(10); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
#endif
}

void genc_seq_d()
{
#ifdef INTERPRET_C_SEQ_D
   gencallinterp((unsigned long)C_SEQ_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jne_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ngl_d()
{
#ifdef INTERPRET_C_NGL_D
   gencallinterp((unsigned long)C_NGL_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   jne_rj(12);
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_lt_d()
{
#ifdef INTERPRET_C_LT_D
   gencallinterp((unsigned long)C_LT_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jae_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_nge_d()
{
#ifdef INTERPRET_C_NGE_D
   gencallinterp((unsigned long)C_NGE_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   jae_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_le_d()
{
#ifdef INTERPRET_C_LE_D
   gencallinterp((unsigned long)C_LE_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   ja_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}

void genc_ngt_d()
{
#ifdef INTERPRET_C_NGT_D
   gencallinterp((unsigned long)C_NGT_D, 0);
#else
   gencheck_cop1_unusable();
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.ft]));
   fld_preg32_qword(EAX);
   mov_eax_memoffs32((unsigned long*)(&reg_cop1_double[dst->f.cf.fs]));
   fld_preg32_qword(EAX);
   fcomip_fpreg(1);
   ffree_fpreg(0);
   jp_rj(14);
   ja_rj(12); // 2
   or_m32_imm32((unsigned long*)&FCR31, 0x800000); // 10
   jmp_imm_short(10); // 2
   and_m32_imm32((unsigned long*)&FCR31, ~0x800000); // 10
#endif
}
