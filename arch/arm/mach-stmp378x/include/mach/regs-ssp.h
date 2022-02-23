/*
 * stmp378x: SSP register definitions
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
#define REGS_SSP1_BASE	(STMP3XXX_REGS_BASE + 0x10000)
#define REGS_SSP1_PHYS	0x80010000
#define REGS_SSP2_BASE	(STMP3XXX_REGS_BASE + 0x34000)
#define REGS_SSP2_PHYS	0x80034000
#define REGS_SSP_SIZE	0x2000

#define HW_SSP_CTRL0		0x0
#define BM_SSP_CTRL0_XFER_COUNT	0x0000FFFF
#define BP_SSP_CTRL0_XFER_COUNT	0
#define BM_SSP_CTRL0_ENABLE	0x00010000
#define BM_SSP_CTRL0_GET_RESP	0x00020000
#define BM_SSP_CTRL0_LONG_RESP	0x00080000
#define BM_SSP_CTRL0_WAIT_FOR_CMD	0x00100000
#define BM_SSP_CTRL0_WAIT_FOR_IRQ	0x00200000
#define BM_SSP_CTRL0_BUS_WIDTH	0x00C00000
#define BP_SSP_CTRL0_BUS_WIDTH	22
#define BM_SSP_CTRL0_DATA_XFER	0x01000000
#define BM_SSP_CTRL0_READ	0x02000000
#define BM_SSP_CTRL0_IGNORE_CRC	0x04000000
#define BM_SSP_CTRL0_LOCK_CS	0x08000000
#define BM_SSP_CTRL0_RUN	0x20000000
#define BM_SSP_CTRL0_CLKGATE	0x40000000
#define BM_SSP_CTRL0_SFTRST	0x80000000

#define HW_SSP_CMD0		0x10
#define BM_SSP_CMD0_CMD		0x000000FF
#define BP_SSP_CMD0_CMD		0
#define BM_SSP_CMD0_BLOCK_COUNT	0x0000FF00
#define BP_SSP_CMD0_BLOCK_COUNT	8
#define BM_SSP_CMD0_BLOCK_SIZE	0x000F0000
#define BP_SSP_CMD0_BLOCK_SIZE	16
#define BM_SSP_CMD0_APPEND_8CYC	0x00100000
#define BM_SSP_CMD1_CMD_ARG	0xFFFFFFFF
#define BP_SSP_CMD1_CMD_ARG	0

#define HW_SSP_TIMING		0x50
#define BM_SSP_TIMING_CLOCK_RATE	0x000000FF
#define BP_SSP_TIMING_CLOCK_RATE	0
#define BM_SSP_TIMING_CLOCK_DIVIDE	0x0000FF00
#define BP_SSP_TIMING_CLOCK_DIVIDE	8
#define BM_SSP_TIMING_TIMEOUT	0xFFFF0000
#define BP_SSP_TIMING_TIMEOUT	16

#define HW_SSP_CTRL1		0x60
#define BM_SSP_CTRL1_SSP_MODE	0x0000000F
#define BP_SSP_CTRL1_SSP_MODE	0
#define BM_SSP_CTRL1_WORD_LENGTH	0x000000F0
#define BP_SSP_CTRL1_WORD_LENGTH	4
#define BM_SSP_CTRL1_POLARITY	0x00000200
#define BM_SSP_CTRL1_PHASE	0x00000400
#define BM_SSP_CTRL1_DMA_ENABLE	0x00002000
#define BM_SSP_CTRL1_FIFO_OVERRUN_IRQ	0x00008000
#define BM_SSP_CTRL1_RECV_TIMEOUT_IRQ_EN	0x00010000
#define BM_SSP_CTRL1_RECV_TIMEOUT_IRQ	0x00020000
#define BM_SSP_CTRL1_FIFO_UNDERRUN_IRQ	0x00200000
#define BM_SSP_CTRL1_DATA_CRC_IRQ_EN	0x00400000
#define BM_SSP_CTRL1_DATA_CRC_IRQ	0x00800000
#define BM_SSP_CTRL1_DATA_TIMEOUT_IRQ_EN	0x01000000
#define BM_SSP_CTRL1_DATA_TIMEOUT_IRQ	0x02000000
#define BM_SSP_CTRL1_RESP_TIMEOUT_IRQ_EN	0x04000000
#define BM_SSP_CTRL1_RESP_TIMEOUT_IRQ	0x08000000
#define BM_SSP_CTRL1_RESP_ERR_IRQ_EN	0x10000000
#define BM_SSP_CTRL1_RESP_ERR_IRQ	0x20000000
#define BM_SSP_CTRL1_SDIO_IRQ	0x80000000

#define HW_SSP_DATA		0x70

#define HW_SSP_SDRESP0		0x80

#define HW_SSP_SDRESP1		0x90

#define HW_SSP_SDRESP2		0xA0

#define HW_SSP_SDRESP3		0xB0

#define HW_SSP_STATUS		0xC0
#define BM_SSP_STATUS_FIFO_EMPTY	0x00000020
#define BM_SSP_STATUS_TIMEOUT	0x00001000
#define BM_SSP_STATUS_RESP_TIMEOUT	0x00004000
#define BM_SSP_STATUS_RESP_ERR	0x00008000
#define BM_SSP_STATUS_RESP_CRC_ERR	0x00010000
#define BM_SSP_STATUS_CARD_DETECT	0x10000000
