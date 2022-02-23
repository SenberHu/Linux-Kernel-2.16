/*
 * SH-X3 Prototype Setup
 *
 *  Copyright (C) 2007 - 2009  Paul Mundt
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/serial.h>
#include <linux/serial_sci.h>
#include <linux/io.h>
#include <linux/sh_timer.h>
#include <asm/mmzone.h>

static struct plat_sci_port sci_platform_data[] = {
	{
		.mapbase	= 0xffc30000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		= { 40, 41, 43, 42 },
	}, {
		.mapbase	= 0xffc40000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		= { 44, 45, 47, 46 },
	}, {
		.mapbase	= 0xffc50000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		= { 48, 49, 51, 50 },
	}, {
		.mapbase	= 0xffc60000,
		.flags		= UPF_BOOT_AUTOCONF,
		.type		= PORT_SCIF,
		.irqs		= { 52, 53, 55, 54 },
	}, {
		.flags = 0,
	}
};

static struct platform_device sci_device = {
	.name		= "sh-sci",
	.id		= -1,
	.dev		= {
		.platform_data	= sci_platform_data,
	},
};

static struct sh_timer_config tmu0_platform_data = {
	.name = "TMU0",
	.channel_offset = 0x04,
	.timer_bit = 0,
	.clk = "peripheral_clk",
	.clockevent_rating = 200,
};

static struct resource tmu0_resources[] = {
	[0] = {
		.name	= "TMU0",
		.start	= 0xffc10008,
		.end	= 0xffc10013,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 16,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu0_device = {
	.name		= "sh_tmu",
	.id		= 0,
	.dev = {
		.platform_data	= &tmu0_platform_data,
	},
	.resource	= tmu0_resources,
	.num_resources	= ARRAY_SIZE(tmu0_resources),
};

static struct sh_timer_config tmu1_platform_data = {
	.name = "TMU1",
	.channel_offset = 0x10,
	.timer_bit = 1,
	.clk = "peripheral_clk",
	.clocksource_rating = 200,
};

static struct resource tmu1_resources[] = {
	[0] = {
		.name	= "TMU1",
		.start	= 0xffc10014,
		.end	= 0xffc1001f,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 17,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu1_device = {
	.name		= "sh_tmu",
	.id		= 1,
	.dev = {
		.platform_data	= &tmu1_platform_data,
	},
	.resource	= tmu1_resources,
	.num_resources	= ARRAY_SIZE(tmu1_resources),
};

static struct sh_timer_config tmu2_platform_data = {
	.name = "TMU2",
	.channel_offset = 0x1c,
	.timer_bit = 2,
	.clk = "peripheral_clk",
};

static struct resource tmu2_resources[] = {
	[0] = {
		.name	= "TMU2",
		.start	= 0xffc10020,
		.end	= 0xffc1002f,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 18,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu2_device = {
	.name		= "sh_tmu",
	.id		= 2,
	.dev = {
		.platform_data	= &tmu2_platform_data,
	},
	.resource	= tmu2_resources,
	.num_resources	= ARRAY_SIZE(tmu2_resources),
};

static struct sh_timer_config tmu3_platform_data = {
	.name = "TMU3",
	.channel_offset = 0x04,
	.timer_bit = 0,
	.clk = "peripheral_clk",
};

static struct resource tmu3_resources[] = {
	[0] = {
		.name	= "TMU3",
		.start	= 0xffc20008,
		.end	= 0xffc20013,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 19,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu3_device = {
	.name		= "sh_tmu",
	.id		= 3,
	.dev = {
		.platform_data	= &tmu3_platform_data,
	},
	.resource	= tmu3_resources,
	.num_resources	= ARRAY_SIZE(tmu3_resources),
};

static struct sh_timer_config tmu4_platform_data = {
	.name = "TMU4",
	.channel_offset = 0x10,
	.timer_bit = 1,
	.clk = "peripheral_clk",
};

static struct resource tmu4_resources[] = {
	[0] = {
		.name	= "TMU4",
		.start	= 0xffc20014,
		.end	= 0xffc2001f,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 20,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu4_device = {
	.name		= "sh_tmu",
	.id		= 4,
	.dev = {
		.platform_data	= &tmu4_platform_data,
	},
	.resource	= tmu4_resources,
	.num_resources	= ARRAY_SIZE(tmu4_resources),
};

static struct sh_timer_config tmu5_platform_data = {
	.name = "TMU5",
	.channel_offset = 0x1c,
	.timer_bit = 2,
	.clk = "peripheral_clk",
};

static struct resource tmu5_resources[] = {
	[0] = {
		.name	= "TMU5",
		.start	= 0xffc20020,
		.end	= 0xffc2002b,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= 21,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device tmu5_device = {
	.name		= "sh_tmu",
	.id		= 5,
	.dev = {
		.platform_data	= &tmu5_platform_data,
	},
	.resource	= tmu5_resources,
	.num_resources	= ARRAY_SIZE(tmu5_resources),
};

static struct platform_device *shx3_early_devices[] __initdata = {
	&tmu0_device,
	&tmu1_device,
	&tmu2_device,
	&tmu3_device,
	&tmu4_device,
	&tmu5_device,
};

static struct platform_device *shx3_devices[] __initdata = {
	&sci_device,
};

static int __init shx3_devices_setup(void)
{
	int ret;

	ret = platform_add_devices(shx3_early_devices,
				   ARRAY_SIZE(shx3_early_devices));
	if (unlikely(ret != 0))
		return ret;

	return platform_add_devices(shx3_devices,
				    ARRAY_SIZE(shx3_devices));
}
arch_initcall(shx3_devices_setup);

void __init plat_early_device_setup(void)
{
	early_platform_add_devices(shx3_early_devices,
				   ARRAY_SIZE(shx3_early_devices));
}

enum {
	UNUSED = 0,

	/* interrupt sources */
	IRL, IRQ0, IRQ1, IRQ2, IRQ3,
	HUDII,
	TMU0, TMU1, TMU2, TMU3, TMU4, TMU5,
	PCII0, PCII1, PCII2, PCII3, PCII4,
	PCII5, PCII6, PCII7, PCII8, PCII9,
	SCIF0_ERI, SCIF0_RXI, SCIF0_BRI, SCIF0_TXI,
	SCIF1_ERI, SCIF1_RXI, SCIF1_BRI, SCIF1_TXI,
	SCIF2_ERI, SCIF2_RXI, SCIF2_BRI, SCIF2_TXI,
	SCIF3_ERI, SCIF3_RXI, SCIF3_BRI, SCIF3_TXI,
	DMAC0_DMINT0, DMAC0_DMINT1, DMAC0_DMINT2, DMAC0_DMINT3,
	DMAC0_DMINT4, DMAC0_DMINT5, DMAC0_DMAE,
	DU,
	DMAC1_DMINT6, DMAC1_DMINT7, DMAC1_DMINT8, DMAC1_DMINT9,
	DMAC1_DMINT10, DMAC1_DMINT11, DMAC1_DMAE,
	IIC, VIN0, VIN1, VCORE0, ATAPI,
	DTU0, DTU1, DTU2, DTU3,
	FE0, FE1,
	GPIO0, GPIO1, GPIO2, GPIO3,
	PAM, IRM,
	INTICI0, INTICI1, INTICI2, INTICI3,
	INTICI4, INTICI5, INTICI6, INTICI7,

	/* interrupt groups */
	PCII56789, SCIF0, SCIF1, SCIF2, SCIF3,
	DMAC0, DMAC1,
};

static struct intc_vect vectors[] __initdata = {
	INTC_VECT(HUDII, 0x3e0),
	INTC_VECT(TMU0, 0x400), INTC_VECT(TMU1, 0x420),
	INTC_VECT(TMU2, 0x440), INTC_VECT(TMU3, 0x460),
	INTC_VECT(TMU4, 0x480), INTC_VECT(TMU5, 0x4a0),
	INTC_VECT(PCII0, 0x500), INTC_VECT(PCII1, 0x520),
	INTC_VECT(PCII2, 0x540), INTC_VECT(PCII3, 0x560),
	INTC_VECT(PCII4, 0x580), INTC_VECT(PCII5, 0x5a0),
	INTC_VECT(PCII6, 0x5c0), INTC_VECT(PCII7, 0x5e0),
	INTC_VECT(PCII8, 0x600), INTC_VECT(PCII9, 0x620),
	INTC_VECT(SCIF0_ERI, 0x700), INTC_VECT(SCIF0_RXI, 0x720),
	INTC_VECT(SCIF0_BRI, 0x740), INTC_VECT(SCIF0_TXI, 0x760),
	INTC_VECT(SCIF1_ERI, 0x780), INTC_VECT(SCIF1_RXI, 0x7a0),
	INTC_VECT(SCIF1_BRI, 0x7c0), INTC_VECT(SCIF1_TXI, 0x7e0),
	INTC_VECT(SCIF2_ERI, 0x800), INTC_VECT(SCIF2_RXI, 0x820),
	INTC_VECT(SCIF2_BRI, 0x840), INTC_VECT(SCIF2_TXI, 0x860),
	INTC_VECT(SCIF3_ERI, 0x880), INTC_VECT(SCIF3_RXI, 0x8a0),
	INTC_VECT(SCIF3_BRI, 0x8c0), INTC_VECT(SCIF3_TXI, 0x8e0),
	INTC_VECT(DMAC0_DMINT0, 0x900), INTC_VECT(DMAC0_DMINT1, 0x920),
	INTC_VECT(DMAC0_DMINT2, 0x940), INTC_VECT(DMAC0_DMINT3, 0x960),
	INTC_VECT(DMAC0_DMINT4, 0x980), INTC_VECT(DMAC0_DMINT5, 0x9a0),
	INTC_VECT(DMAC0_DMAE, 0x9c0),
	INTC_VECT(DU, 0x9e0),
	INTC_VECT(DMAC1_DMINT6, 0xa00), INTC_VECT(DMAC1_DMINT7, 0xa20),
	INTC_VECT(DMAC1_DMINT8, 0xa40), INTC_VECT(DMAC1_DMINT9, 0xa60),
	INTC_VECT(DMAC1_DMINT10, 0xa80), INTC_VECT(DMAC1_DMINT11, 0xaa0),
	INTC_VECT(DMAC1_DMAE, 0xac0),
	INTC_VECT(IIC, 0xae0),
	INTC_VECT(VIN0, 0xb00), INTC_VECT(VIN1, 0xb20),
	INTC_VECT(VCORE0, 0xb00), INTC_VECT(ATAPI, 0xb60),
	INTC_VECT(DTU0, 0xc00), INTC_VECT(DTU0, 0xc20),
	INTC_VECT(DTU0, 0xc40),
	INTC_VECT(DTU1, 0xc60), INTC_VECT(DTU1, 0xc80),
	INTC_VECT(DTU1, 0xca0),
	INTC_VECT(DTU2, 0xcc0), INTC_VECT(DTU2, 0xce0),
	INTC_VECT(DTU2, 0xd00),
	INTC_VECT(DTU3, 0xd20), INTC_VECT(DTU3, 0xd40),
	INTC_VECT(DTU3, 0xd60),
	INTC_VECT(FE0, 0xe00), INTC_VECT(FE1, 0xe20),
	INTC_VECT(GPIO0, 0xe40), INTC_VECT(GPIO1, 0xe60),
	INTC_VECT(GPIO2, 0xe80), INTC_VECT(GPIO3, 0xea0),
	INTC_VECT(PAM, 0xec0), INTC_VECT(IRM, 0xee0),
	INTC_VECT(INTICI0, 0xf00), INTC_VECT(INTICI1, 0xf20),
	INTC_VECT(INTICI2, 0xf40), INTC_VECT(INTICI3, 0xf60),
	INTC_VECT(INTICI4, 0xf80), INTC_VECT(INTICI5, 0xfa0),
	INTC_VECT(INTICI6, 0xfc0), INTC_VECT(INTICI7, 0xfe0),
};

static struct intc_group groups[] __initdata = {
	INTC_GROUP(PCII56789, PCII5, PCII6, PCII7, PCII8, PCII9),
	INTC_GROUP(SCIF0, SCIF0_ERI, SCIF0_RXI, SCIF0_BRI, SCIF0_TXI),
	INTC_GROUP(SCIF1, SCIF1_ERI, SCIF1_RXI, SCIF1_BRI, SCIF1_TXI),
	INTC_GROUP(SCIF2, SCIF2_ERI, SCIF2_RXI, SCIF2_BRI, SCIF2_TXI),
	INTC_GROUP(SCIF3, SCIF3_ERI, SCIF3_RXI, SCIF3_BRI, SCIF3_TXI),
	INTC_GROUP(DMAC0, DMAC0_DMINT0, DMAC0_DMINT1, DMAC0_DMINT2,
		   DMAC0_DMINT3, DMAC0_DMINT4, DMAC0_DMINT5, DMAC0_DMAE),
	INTC_GROUP(DMAC1, DMAC1_DMINT6, DMAC1_DMINT7, DMAC1_DMINT8,
		   DMAC1_DMINT9, DMAC1_DMINT10, DMAC1_DMINT11),
};

static struct intc_mask_reg mask_registers[] __initdata = {
	{ 0xfe410030, 0xfe410050, 32, /* CnINTMSK0 / CnINTMSKCLR0 */
	  { IRQ0, IRQ1, IRQ2, IRQ3 } },
	{ 0xfe410040, 0xfe410060, 32, /* CnINTMSK1 / CnINTMSKCLR1 */
	  { IRL } },
	{ 0xfe410820, 0xfe410850, 32, /* CnINT2MSK0 / CnINT2MSKCLR0 */
	  { FE1, FE0, 0, ATAPI, VCORE0, VIN1, VIN0, IIC,
	    DU, GPIO3, GPIO2, GPIO1, GPIO0, PAM, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0, /* HUDI bits ignored */
	    0, TMU5, TMU4, TMU3, TMU2, TMU1, TMU0, 0, } },
	{ 0xfe410830, 0xfe410860, 32, /* CnINT2MSK1 / CnINT2MSKCLR1 */
	  { 0, 0, 0, 0, DTU3, DTU2, DTU1, DTU0, /* IRM bits ignored */
	    PCII9, PCII8, PCII7, PCII6, PCII5, PCII4, PCII3, PCII2,
	    PCII1, PCII0, DMAC1_DMAE, DMAC1_DMINT11,
	    DMAC1_DMINT10, DMAC1_DMINT9, DMAC1_DMINT8, DMAC1_DMINT7,
	    DMAC1_DMINT6, DMAC0_DMAE, DMAC0_DMINT5, DMAC0_DMINT4,
	    DMAC0_DMINT3, DMAC0_DMINT2, DMAC0_DMINT1, DMAC0_DMINT0 } },
	{ 0xfe410840, 0xfe410870, 32, /* CnINT2MSK2 / CnINT2MSKCLR2 */
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    SCIF3_TXI, SCIF3_BRI, SCIF3_RXI, SCIF3_ERI,
	    SCIF2_TXI, SCIF2_BRI, SCIF2_RXI, SCIF2_ERI,
	    SCIF1_TXI, SCIF1_BRI, SCIF1_RXI, SCIF1_ERI,
	    SCIF0_TXI, SCIF0_BRI, SCIF0_RXI, SCIF0_ERI } },
};

static struct intc_prio_reg prio_registers[] __initdata = {
	{ 0xfe410010, 0, 32, 4, /* INTPRI */ { IRQ0, IRQ1, IRQ2, IRQ3 } },

	{ 0xfe410800, 0, 32, 4, /* INT2PRI0 */ { 0, HUDII, TMU5, TMU4,
						 TMU3, TMU2, TMU1, TMU0 } },
	{ 0xfe410804, 0, 32, 4, /* INT2PRI1 */ { DTU3, DTU2, DTU1, DTU0,
						 SCIF3, SCIF2,
						 SCIF1, SCIF0 } },
	{ 0xfe410808, 0, 32, 4, /* INT2PRI2 */ { DMAC1, DMAC0,
						 PCII56789, PCII4,
						 PCII3, PCII2,
						 PCII1, PCII0 } },
	{ 0xfe41080c, 0, 32, 4, /* INT2PRI3 */ { FE1, FE0, ATAPI, VCORE0,
						 VIN1, VIN0, IIC, DU} },
	{ 0xfe410810, 0, 32, 4, /* INT2PRI4 */ { 0, 0, PAM, GPIO3,
						 GPIO2, GPIO1, GPIO0, IRM } },
	{ 0xfe410090, 0xfe4100a0, 32, 4, /* CnICIPRI / CnICIPRICLR */
	  { INTICI7, INTICI6, INTICI5, INTICI4,
	    INTICI3, INTICI2, INTICI1, INTICI0 }, INTC_SMP(4, 4) },
};

static DECLARE_INTC_DESC(intc_desc, "shx3", vectors, groups,
			 mask_registers, prio_registers, NULL);

/* Support for external interrupt pins in IRQ mode */
static struct intc_vect vectors_irq[] __initdata = {
	INTC_VECT(IRQ0, 0x240), INTC_VECT(IRQ1, 0x280),
	INTC_VECT(IRQ2, 0x2c0), INTC_VECT(IRQ3, 0x300),
};

static struct intc_sense_reg sense_registers[] __initdata = {
	{ 0xfe41001c, 32, 2, /* ICR1 */   { IRQ0, IRQ1, IRQ2, IRQ3 } },
};

static DECLARE_INTC_DESC(intc_desc_irq, "shx3-irq", vectors_irq, groups,
			 mask_registers, prio_registers, sense_registers);

/* External interrupt pins in IRL mode */
static struct intc_vect vectors_irl[] __initdata = {
	INTC_VECT(IRL, 0x200), INTC_VECT(IRL, 0x220),
	INTC_VECT(IRL, 0x240), INTC_VECT(IRL, 0x260),
	INTC_VECT(IRL, 0x280), INTC_VECT(IRL, 0x2a0),
	INTC_VECT(IRL, 0x2c0), INTC_VECT(IRL, 0x2e0),
	INTC_VECT(IRL, 0x300), INTC_VECT(IRL, 0x320),
	INTC_VECT(IRL, 0x340), INTC_VECT(IRL, 0x360),
	INTC_VECT(IRL, 0x380), INTC_VECT(IRL, 0x3a0),
	INTC_VECT(IRL, 0x3c0),
};

static DECLARE_INTC_DESC(intc_desc_irl, "shx3-irl", vectors_irl, groups,
			 mask_registers, prio_registers, NULL);

void __init plat_irq_setup_pins(int mode)
{
	switch (mode) {
	case IRQ_MODE_IRQ:
		register_intc_controller(&intc_desc_irq);
		break;
	case IRQ_MODE_IRL3210:
		register_intc_controller(&intc_desc_irl);
		break;
	default:
		BUG();
	}
}

void __init plat_irq_setup(void)
{
	register_intc_controller(&intc_desc);
}

void __init plat_mem_setup(void)
{
	unsigned int nid = 1;

	/* Register CPU#0 URAM space as Node 1 */
	setup_bootmem_node(nid++, 0x145f0000, 0x14610000);	/* CPU0 */

#if 0
	/* XXX: Not yet.. */
	setup_bootmem_node(nid++, 0x14df0000, 0x14e10000);	/* CPU1 */
	setup_bootmem_node(nid++, 0x155f0000, 0x15610000);	/* CPU2 */
	setup_bootmem_node(nid++, 0x15df0000, 0x15e10000);	/* CPU3 */
#endif

	setup_bootmem_node(nid++, 0x16000000, 0x16020000);	/* CSM */
}
