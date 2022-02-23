/*
 *  Copyright (c) 2000-2001 Vojtech Pavlik
 *
 *  Based on the work of:
 *	Richard Zidlicky <Richard.Zidlicky@stud.informatik.uni-erlangen.de>
 */

/*
 * Q40 PS/2 keyboard controller driver for Linux/m68k
 */

/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Should you need to contact me, the author, you can do so either by
 * e-mail - mail your message to <vojtech@ucw.cz>, or by paper mail:
 * Vojtech Pavlik, Simunkova 1594, Prague 8, 182 00 Czech Republic
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/serio.h>
#include <linux/interrupt.h>
#include <linux/err.h>
#include <linux/bitops.h>
#include <linux/platform_device.h>

#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/q40_master.h>
#include <asm/irq.h>
#include <asm/q40ints.h>

MODULE_AUTHOR("Vojtech Pavlik <vojtech@ucw.cz>");
MODULE_DESCRIPTION("Q40 PS/2 keyboard controller driver");
MODULE_LICENSE("GPL");

static DEFINE_SPINLOCK(q40kbd_lock);
static struct serio *q40kbd_port;
static struct platform_device *q40kbd_device;

//中断处理函数
static irqreturn_t q40kbd_interrupt(int irq, void *dev_id)
{
	unsigned long flags;

	spin_lock_irqsave(&q40kbd_lock, flags);

	if (Q40_IRQ_KEYB_MASK & master_inb(INTERRUPT_REG))
		serio_interrupt(q40kbd_port, master_inb(KEYCODE_REG), 0);

	//向端口	KEYBOARD_UNLOCK_REG写数据
	master_outb(-1, KEYBOARD_UNLOCK_REG);

	spin_unlock_irqrestore(&q40kbd_lock, flags);

	return IRQ_HANDLED;
}

/*
 * q40kbd_flush() flushes all data that may be in the keyboard buffers
 */

static void q40kbd_flush(void)
{
	int maxread = 100;
	unsigned long flags;

	spin_lock_irqsave(&q40kbd_lock, flags);

	while (maxread-- && (Q40_IRQ_KEYB_MASK & master_inb(INTERRUPT_REG)))
		master_inb(KEYCODE_REG);

	spin_unlock_irqrestore(&q40kbd_lock, flags);
}

/*
 * q40kbd_open() is called when a port is open by the higher layer.
 * It allocates the interrupt and enables in in the chip.
 */

static int q40kbd_open(struct serio *port)
{
	q40kbd_flush();

	if (request_irq(Q40_IRQ_KEYBOARD, q40kbd_interrupt, 0, "q40kbd", NULL)) {
		printk(KERN_ERR "q40kbd.c: Can't get irq %d.\n", Q40_IRQ_KEYBOARD);
		return -EBUSY;
	}

	/* off we go */
	master_outb(-1, KEYBOARD_UNLOCK_REG);
	master_outb(1, KEY_IRQ_ENABLE_REG);

	return 0;
}

static void q40kbd_close(struct serio *port)
{
	master_outb(0, KEY_IRQ_ENABLE_REG);
	master_outb(-1, KEYBOARD_UNLOCK_REG);
	free_irq(Q40_IRQ_KEYBOARD, NULL);

	q40kbd_flush();
}

//进行端口探测,并注册到serio总线
static int __devinit q40kbd_probe(struct platform_device *dev)
{
	q40kbd_port = kzalloc(sizeof(struct serio), GFP_KERNEL);
	if (!q40kbd_port)
		return -ENOMEM;

	q40kbd_port->id.type	= SERIO_8042;//说明是8042兼容型的,I8042是intel开发的键盘控制芯片
	q40kbd_port->open	= q40kbd_open;
	q40kbd_port->close	= q40kbd_close;
	q40kbd_port->dev.parent	= &dev->dev;
	strlcpy(q40kbd_port->name, "Q40 Kbd Port", sizeof(q40kbd_port->name));
	strlcpy(q40kbd_port->phys, "Q40", sizeof(q40kbd_port->phys));

	serio_register_port(q40kbd_port);
	printk(KERN_INFO "serio: Q40 kbd registered\n");

	return 0;
}

static int __devexit q40kbd_remove(struct platform_device *dev)
{
	serio_unregister_port(q40kbd_port);

	return 0;
}

static struct platform_driver q40kbd_driver = {
	.driver		= {
		.name	= "q40kbd",
		.owner	= THIS_MODULE,
	},
	.probe		= q40kbd_probe,
	.remove		= __devexit_p(q40kbd_remove),
};

//键盘控制器驱动,注册驱动程序到系统
//platform总线是虚拟的总线 物理上并不存在
static int __init q40kbd_init(void)
{
	int error;

	if (!MACH_IS_Q40)
		return -ENODEV;

	//进行platform总线驱动注册
	error = platform_driver_register(&q40kbd_driver);
	if (error)
		return error;

	//分配一个platform设备
	q40kbd_device = platform_device_alloc("q40kbd", -1);
	if (!q40kbd_device)
		goto err_unregister_driver;

	//platform设备注册
	error = platform_device_add(q40kbd_device);
	if (error)
		goto err_free_device;

	return 0;

 err_free_device:
	platform_device_put(q40kbd_device);
 err_unregister_driver:
	platform_driver_unregister(&q40kbd_driver);
	return error;
}

static void __exit q40kbd_exit(void)
{
	platform_device_unregister(q40kbd_device);
	platform_driver_unregister(&q40kbd_driver);
}

module_init(q40kbd_init);
module_exit(q40kbd_exit);
