/*  *********************************************************************
    *  BCM1280/BCM1480 Board Support Package
    *
    *  L2 Cache constants and macros		File: bcm1480_l2c.h
    *
    *  This module contains constants useful for manipulating the
    *  level 2 cache.
    *
    *  BCM1400 specification level:  1280-UM100-D2 (11/14/03)
    *
    *********************************************************************
    *
    *  Copyright 2000,2001,2002,2003
    *  Broadcom Corporation. All rights reserved.
    *
    *  This program is free software; you can redistribute it and/or
    *  modify it under the terms of the GNU General Public License as
    *  published by the Free Software Foundation; either version 2 of
    *  the License, or (at your option) any later version.
    *
    *  This program is distributed in the hope that it will be useful,
    *  but WITHOUT ANY WARRANTY; without even the implied warranty of
    *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    *  GNU General Public License for more details.
    *
    *  You should have received a copy of the GNU General Public License
    *  along with this program; if not, write to the Free Software
    *  Foundation, Inc., 59 Temple Place, Suite 330, Boston,
    *  MA 02111-1307 USA
    ********************************************************************* */


#ifndef _BCM1480_L2C_H
#define _BCM1480_L2C_H

#include "sb1250_defs.h"

/*
 * Format of level 2 cache management address (Table 55)
 */

#define S_BCM1480_L2C_MGMT_INDEX            5
#define M_BCM1480_L2C_MGMT_INDEX            _SB_MAKEMASK(12, S_BCM1480_L2C_MGMT_INDEX)
#define V_BCM1480_L2C_MGMT_INDEX(x)         _SB_MAKEVALUE(x, S_BCM1480_L2C_MGMT_INDEX)
#define G_BCM1480_L2C_MGMT_INDEX(x)         _SB_GETVALUE(x, S_BCM1480_L2C_MGMT_INDEX, M_BCM1480_L2C_MGMT_INDEX)

#define S_BCM1480_L2C_MGMT_WAY              17
#define M_BCM1480_L2C_MGMT_WAY              _SB_MAKEMASK(3, S_BCM1480_L2C_MGMT_WAY)
#define V_BCM1480_L2C_MGMT_WAY(x)           _SB_MAKEVALUE(x, S_BCM1480_L2C_MGMT_WAY)
#define G_BCM1480_L2C_MGMT_WAY(x)           _SB_GETVALUE(x, S_BCM1480_L2C_MGMT_WAY, M_BCM1480_L2C_MGMT_WAY)

#define M_BCM1480_L2C_MGMT_DIRTY            _SB_MAKEMASK1(20)
#define M_BCM1480_L2C_MGMT_VALID            _SB_MAKEMASK1(21)

#define S_BCM1480_L2C_MGMT_ECC_DIAG         22
#define M_BCM1480_L2C_MGMT_ECC_DIAG         _SB_MAKEMASK(2, S_BCM1480_L2C_MGMT_ECC_DIAG)
#define V_BCM1480_L2C_MGMT_ECC_DIAG(x)      _SB_MAKEVALUE(x, S_BCM1480_L2C_MGMT_ECC_DIAG)
#define G_BCM1480_L2C_MGMT_ECC_DIAG(x)      _SB_GETVALUE(x, S_BCM1480_L2C_MGMT_ECC_DIAG, M_BCM1480_L2C_MGMT_ECC_DIAG)

#define A_BCM1480_L2C_MGMT_TAG_BASE         0x00D0000000

#define BCM1480_L2C_ENTRIES_PER_WAY         4096
#define BCM1480_L2C_NUM_WAYS                8


/*
 * Level 2 Cache Tag register (Table 59)
 */

#define S_BCM1480_L2C_TAG_MBZ               0
#define M_BCM1480_L2C_TAG_MBZ               _SB_MAKEMASK(5, S_BCM1480_L2C_TAG_MBZ)

#define S_BCM1480_L2C_TAG_INDEX             5
#define M_BCM1480_L2C_TAG_INDEX             _SB_MAKEMASK(12, S_BCM1480_L2C_TAG_INDEX)
#define V_BCM1480_L2C_TAG_INDEX(x)          _SB_MAKEVALUE(x, S_BCM1480_L2C_TAG_INDEX)
#define G_BCM1480_L2C_TAG_INDEX(x)          _SB_GETVALUE(x, S_BCM1480_L2C_TAG_INDEX, M_BCM1480_L2C_TAG_INDEX)

/* Note that index bit 16 is also tag bit 40 */
#define S_BCM1480_L2C_TAG_TAG               17
#define M_BCM1480_L2C_TAG_TAG               _SB_MAKEMASK(23, S_BCM1480_L2C_TAG_TAG)
#define V_BCM1480_L2C_TAG_TAG(x)            _SB_MAKEVALUE(x, S_BCM1480_L2C_TAG_TAG)
#define G_BCM1480_L2C_TAG_TAG(x)            _SB_GETVALUE(x, S_BCM1480_L2C_TAG_TAG, M_BCM1480_L2C_TAG_TAG)

#define S_BCM1480_L2C_TAG_ECC               40
#define M_BCM1480_L2C_TAG_ECC               _SB_MAKEMASK(6, S_BCM1480_L2C_TAG_ECC)
#define V_BCM1480_L2C_TAG_ECC(x)            _SB_MAKEVALUE(x, S_BCM1480_L2C_TAG_ECC)
#define G_BCM1480_L2C_TAG_ECC(x)            _SB_GETVALUE(x, S_BCM1480_L2C_TAG_ECC, M_BCM1480_L2C_TAG_ECC)

#define S_BCM1480_L2C_TAG_WAY               46
#define M_BCM1480_L2C_TAG_WAY               _SB_MAKEMASK(3, S_BCM1480_L2C_TAG_WAY)
#define V_BCM1480_L2C_TAG_WAY(x)            _SB_MAKEVALUE(x, S_BCM1480_L2C_TAG_WAY)
#define G_BCM1480_L2C_TAG_WAY(x)            _SB_GETVALUE(x, S_BCM1480_L2C_TAG_WAY, M_BCM1480_L2C_TAG_WAY)

#define M_BCM1480_L2C_TAG_DIRTY             _SB_MAKEMASK1(49)
#define M_BCM1480_L2C_TAG_VALID             _SB_MAKEMASK1(50)

#define S_BCM1480_L2C_DATA_ECC              51
#define M_BCM1480_L2C_DATA_ECC              _SB_MAKEMASK(10, S_BCM1480_L2C_DATA_ECC)
#define V_BCM1480_L2C_DATA_ECC(x)           _SB_MAKEVALUE(x, S_BCM1480_L2C_DATA_ECC)
#define G_BCM1480_L2C_DATA_ECC(x)           _SB_GETVALUE(x, S_BCM1480_L2C_DATA_ECC, M_BCM1480_L2C_DATA_ECC)


/*
 * L2 Misc0 Value Register (Table 60)
 */

#define S_BCM1480_L2C_MISC0_WAY_REMOTE      0
#define M_BCM1480_L2C_MISC0_WAY_REMOTE      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC0_WAY_REMOTE)
#define G_BCM1480_L2C_MISC0_WAY_REMOTE(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC0_WAY_REMOTE, M_BCM1480_L2C_MISC0_WAY_REMOTE)

#define S_BCM1480_L2C_MISC0_WAY_LOCAL       8
#define M_BCM1480_L2C_MISC0_WAY_LOCAL       _SB_MAKEMASK(8, S_BCM1480_L2C_MISC0_WAY_LOCAL)
#define G_BCM1480_L2C_MISC0_WAY_LOCAL(x)    _SB_GETVALUE(x, S_BCM1480_L2C_MISC0_WAY_LOCAL, M_BCM1480_L2C_MISC0_WAY_LOCAL)

#define S_BCM1480_L2C_MISC0_WAY_ENABLE      16
#define M_BCM1480_L2C_MISC0_WAY_ENABLE      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC0_WAY_ENABLE)
#define G_BCM1480_L2C_MISC0_WAY_ENABLE(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC0_WAY_ENABLE, M_BCM1480_L2C_MISC0_WAY_ENABLE)

#define S_BCM1480_L2C_MISC0_CACHE_DISABLE   24
#define M_BCM1480_L2C_MISC0_CACHE_DISABLE   _SB_MAKEMASK(2, S_BCM1480_L2C_MISC0_CACHE_DISABLE)
#define G_BCM1480_L2C_MISC0_CACHE_DISABLE(x) _SB_GETVALUE(x, S_BCM1480_L2C_MISC0_CACHE_DISABLE, M_BCM1480_L2C_MISC0_CACHE_DISABLE)

#define S_BCM1480_L2C_MISC0_CACHE_QUAD      26
#define M_BCM1480_L2C_MISC0_CACHE_QUAD      _SB_MAKEMASK(2, S_BCM1480_L2C_MISC0_CACHE_QUAD)
#define G_BCM1480_L2C_MISC0_CACHE_QUAD(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC0_CACHE_QUAD, M_BCM1480_L2C_MISC0_CACHE_QUAD)

#define S_BCM1480_L2C_MISC0_MC_PRIORITY      30
#define M_BCM1480_L2C_MISC0_MC_PRIORITY      _SB_MAKEMASK1(S_BCM1480_L2C_MISC0_MC_PRIORITY)

#define S_BCM1480_L2C_MISC0_ECC_CLEANUP      31
#define M_BCM1480_L2C_MISC0_ECC_CLEANUP      _SB_MAKEMASK1(S_BCM1480_L2C_MISC0_ECC_CLEANUP)


/*
 * L2 Misc1 Value Register (Table 60)
 */

#define S_BCM1480_L2C_MISC1_WAY_AGENT_0      0
#define M_BCM1480_L2C_MISC1_WAY_AGENT_0      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC1_WAY_AGENT_0)
#define G_BCM1480_L2C_MISC1_WAY_AGENT_0(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC1_WAY_AGENT_0, M_BCM1480_L2C_MISC1_WAY_AGENT_0)

#define S_BCM1480_L2C_MISC1_WAY_AGENT_1      8
#define M_BCM1480_L2C_MISC1_WAY_AGENT_1      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC1_WAY_AGENT_1)
#define G_BCM1480_L2C_MISC1_WAY_AGENT_1(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC1_WAY_AGENT_1, M_BCM1480_L2C_MISC1_WAY_AGENT_1)

#define S_BCM1480_L2C_MISC1_WAY_AGENT_2      16
#define M_BCM1480_L2C_MISC1_WAY_AGENT_2      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC1_WAY_AGENT_2)
#define G_BCM1480_L2C_MISC1_WAY_AGENT_2(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC1_WAY_AGENT_2, M_BCM1480_L2C_MISC1_WAY_AGENT_2)

#define S_BCM1480_L2C_MISC1_WAY_AGENT_3      24
#define M_BCM1480_L2C_MISC1_WAY_AGENT_3      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC1_WAY_AGENT_3)
#define G_BCM1480_L2C_MISC1_WAY_AGENT_3(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC1_WAY_AGENT_3, M_BCM1480_L2C_MISC1_WAY_AGENT_3)

#define S_BCM1480_L2C_MISC1_WAY_AGENT_4      32
#define M_BCM1480_L2C_MISC1_WAY_AGENT_4      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC1_WAY_AGENT_4)
#define G_BCM1480_L2C_MISC1_WAY_AGENT_4(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC1_WAY_AGENT_4, M_BCM1480_L2C_MISC1_WAY_AGENT_4)


/*
 * L2 Misc2 Value Register (Table 60)
 */

#define S_BCM1480_L2C_MISC2_WAY_AGENT_8      0
#define M_BCM1480_L2C_MISC2_WAY_AGENT_8      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC2_WAY_AGENT_8)
#define G_BCM1480_L2C_MISC2_WAY_AGENT_8(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC2_WAY_AGENT_8, M_BCM1480_L2C_MISC2_WAY_AGENT_8)

#define S_BCM1480_L2C_MISC2_WAY_AGENT_9      8
#define M_BCM1480_L2C_MISC2_WAY_AGENT_9      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC2_WAY_AGENT_9)
#define G_BCM1480_L2C_MISC2_WAY_AGENT_9(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC2_WAY_AGENT_9, M_BCM1480_L2C_MISC2_WAY_AGENT_9)

#define S_BCM1480_L2C_MISC2_WAY_AGENT_A      16
#define M_BCM1480_L2C_MISC2_WAY_AGENT_A      _SB_MAKEMASK(8, S_BCM1480_L2C_MISC2_WAY_AGENT_A)
#define G_BCM1480_L2C_MISC2_WAY_AGENT_A(x)   _SB_GETVALUE(x, S_BCM1480_L2C_MISC2_WAY_AGENT_A, M_BCM1480_L2C_MISC2_WAY_AGENT_A)


#endif /* _BCM1480_L2C_H */
