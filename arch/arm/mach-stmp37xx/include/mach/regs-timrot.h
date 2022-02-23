/*
 * stmp37xx: TIMROT register definitions
 *
 * Copyright (c) 2008 Freescale Semiconductor
 * Copyright 2008 Embedded Alley Solutions, Inc All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#ifndef _MACH_REGS_TIMROT
#define _MACH_REGS_TIMROT

#define REGS_TIMROT_BASE	(STMP3XXX_REGS_BASE + 0x68000)

#define HW_TIMROT_ROTCTRL	0x0
#define BM_TIMROT_ROTCTRL_CLKGATE	0x40000000
#define BM_TIMROT_ROTCTRL_SFTRST	0x80000000

#define HW_TIMROT_TIMCTRL0	(0x20 + 0 * 0x20)
#define HW_TIMROT_TIMCTRL1	(0x20 + 1 * 0x20)
#define HW_TIMROT_TIMCTRL2	(0x20 + 2 * 0x20)

#define HW_TIMROT_TIMCTRLn	0x20
#define BM_TIMROT_TIMCTRLn_SELECT	0x0000000F
#define BP_TIMROT_TIMCTRLn_SELECT	0
#define BM_TIMROT_TIMCTRLn_PRESCALE	0x00000030
#define BP_TIMROT_TIMCTRLn_PRESCALE	4
#define BM_TIMROT_TIMCTRLn_RELOAD	0x00000040
#define BM_TIMROT_TIMCTRLn_UPDATE	0x00000080
#define BM_TIMROT_TIMCTRLn_IRQ_EN	0x00004000
#define BM_TIMROT_TIMCTRLn_IRQ	0x00008000

#define HW_TIMROT_TIMCOUNT0	(0x30 + 0 * 0x20)
#define HW_TIMROT_TIMCOUNT1	(0x30 + 1 * 0x20)
#define HW_TIMROT_TIMCOUNT2	(0x30 + 2 * 0x20)

#define HW_TIMROT_TIMCOUNTn	0x30
#endif
