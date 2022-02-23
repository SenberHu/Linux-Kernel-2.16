#ifndef _LINUX_ELF_H
#define _LINUX_ELF_H

#include <linux/types.h>
#include <linux/elf-em.h>
#ifdef __KERNEL__
#include <asm/elf.h>
#endif

struct file;

#ifndef elf_read_implies_exec
  /* Executables for which elf_read_implies_exec() returns TRUE will
     have the READ_IMPLIES_EXEC personality flag set automatically.
     Override in asm/elf.h as needed.  */
# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
#endif

/* 32-bit ELF base types. */
typedef __u32	Elf32_Addr;
typedef __u16	Elf32_Half;
typedef __u32	Elf32_Off;
typedef __s32	Elf32_Sword;
typedef __u32	Elf32_Word;

/* 64-bit ELF base types. */
typedef __u64	Elf64_Addr;
typedef __u16	Elf64_Half;
typedef __s16	Elf64_SHalf;
typedef __u64	Elf64_Off;
typedef __s32	Elf64_Sword;
typedef __u32	Elf64_Word;
typedef __u64	Elf64_Xword;
typedef __s64	Elf64_Sxword;

/* These constants are for the segment types stored in the image headers */
/*此数组元素未用。结构中其他成员都是未定义的*/
#define PT_NULL    0

/*此数组元素给出一个可加载的段,段的大小由 p_filesz 和 p_memsz 描述。
文件中的字节被映射到内存段开始处。如果 p_memsz 大于 p_filesz,“剩余”的字节要清零
_filesz 不能大于 p_memsz。可加载的段在程序头部表格中根据 p_vaddr 成员按升序排列*/
#define PT_LOAD    1//可加载段(代码节数据节)


#define PT_DYNAMIC 2//动态链接段(动态链接信息)

/*数组元素给出一个 NULL 结尾的字符串的位置和长度,该字符串将被当作解释器调用。
这种段类型仅对与可执行文件有意义(尽管也可能在共享目标文件上发生)。
在一个文件中不能出现一次以上。如果存在这种类型的段,它必须在所有可加载段项目的前面。*/
#define PT_INTERP  3//解释器段(动态连接器路径)

/*此数组元素给出附加信息的位置和大小。*/
#define PT_NOTE    4

/*此段类型被保留,不过语义未指定。包含这种类型的段的程序与 ABI不符*/
#define PT_SHLIB   5

/*程序头段。指明程序头表在文件和内存映像中的位置和大小 如果存在此类型段，则对应的程序头项必须出现在所有可加载段项的前面*/
#define PT_PHDR    6

#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */

/*此范围的类型保留给处理器专用语义。*/
#define PT_HIOS    0x6fffffff      /* OS-specific */

/*此范围的类型保留给处理器专用语义。*/
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME		0x6474e550
#define PT_GNU_STACK	(PT_LOOS + 0x474e551)
/***************************************************/

/* These constants define the different elf file types */
#define ET_NONE   0 //未知类型
#define ET_REL    1 //可重定向类型 .o
#define ET_EXEC   2 //可执行
#define ET_DYN    3 //动态库 .so 共享目标文件
#define ET_CORE   4 //core文件 转储格式
#define ET_LOPROC 0xff00 //特定处理器文件
#define ET_HIPROC 0xffff //特定处理器文件

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL		0
#define DT_NEEDED	1 //依赖库的名称  d_val存放的动态字符串表中的下标
#define DT_PLTRELSZ	2 //.rela.plt重定位表的总大小 d_val
#define DT_PLTGOT	3 //.got.plt 保存了重定位地址 d_ptr
#define DT_HASH		4 //d_ptr
#define DT_STRTAB	5 //动态字符串表地址d_ptr
#define DT_SYMTAB	6 //动态符号表地址 d_ptr
#define DT_RELA		7 //重定位表的地址d_ptr
#define DT_RELASZ	8 //DT_RELA 重定位表的总大小 d_val
#define DT_RELAENT	9 //DT_RELA 重定位项的大小 d_val 
#define DT_STRSZ	10 //DT_STRTAB 字符串表的总大小 d_val
#define DT_SYMENT	11 //DT_SYMTAB 符号项的大小
#define DT_INIT		12 //初始化函数的地址 d_ptr
#define DT_FINI		13 //终止函数的地址 d_ptr
#define DT_SONAME	14 //以空字符结尾的字符串的 DT_STRTAB 字符串表偏移，用于标识共享目标文件的名称 d_val
#define DT_RPATH 	15 //以空字符结尾的库搜索路径字符串的 DT_STRTAB 字符串表偏移。此元素的用途已被 d_val
                       //在编译的时候采用-Wl,-rpath=""指定动态库动态路径的时候 用来索引此路径的字符串
#define DT_SYMBOLIC	16 
#define DT_REL	    17 //与 DT_RELA 类似，但其表中包含隐式加数。此元素要求同时存在 DT_RELSZ 和 DT_RELENT 元素d_ptr
#define DT_RELSZ	18 //DT_REL 重定位表的总大小d_val
#define DT_RELENT	19 //DT_REL 重定位项的大小d_val 
#define DT_PLTREL	20 //d_val 表示过程链接表指向的重定位项的类型（DT_REL 或 DT_RELA）。过程链接表中的所有重定位都必须使用相同的重定位项
#define DT_DEBUG	21 //用于调试 d_ptr
#define DT_TEXTREL	22 //表示一个或多个重定位项可能会要求修改非可写段，并且运行时链接程序会进行相应准备。此元素已被 DF_TEXTREL 标志取代
#define DT_JMPREL	23 //d_ptr 与过程链接表单独关联的重定位项的地址
#define DT_ENCODING	32 
#define OLD_DT_LOOS	0x60000000
#define DT_LOOS		0x6000000d
#define DT_HIOS		0x6ffff000
#define DT_VALRNGLO	0x6ffffd00
#define DT_VALRNGHI	0x6ffffdff
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_VERSYM	0x6ffffff0 //.gnu.version节虚拟地址
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERDEF	0x6ffffffc
#define	DT_VERDEFNUM	0x6ffffffd
#define DT_VERNEED	0x6ffffffe //.gnu.version_r节的地址
#define	DT_VERNEEDNUM	0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

#define DT_GNU_HASH	0x6ffffef5


/* This info is needed when parsing the symbol table */
#define STB_LOCAL  0//局部符号，对于目标文件的外部不可见
#define STB_GLOBAL 1//全局符号，外部可见
#define STB_WEAK   2//弱引用

#if 0
#define STB_LOOS	10		/* OS-specific semantics */
#define STB_GNU_UNIQUE	10		/* Symbol is unique in namespace */
#define STB_HIOS	12		/* OS-specific semantics */
#define STB_LOPROC	13		/* Processor-specific semantics */
#define STB_HIPROC	15		/* Processor-specific semantics */
#endif


#define STT_NOTYPE  0//未知类型符号
#define STT_OBJECT  1//该符号是个数据对象，比如变量、数组等
#define STT_FUNC    2//该符号是个函数或其他可执行代码
#define STT_SECTION 3//该符号表示一个段，这种符号必须是STB_LOCAL的 表示下标为ndx的段的段名
#define STT_FILE    4//该符号表示文件名，一般都是该目标文件所对应的源文件名，它一定是STB_LOCAL类型的，
					 //并且它的st_shndx一定是SHN_ABS
#define STT_COMMON  5 //未初始化的全局变量
#define STT_TLS     6//线程本地数据

#if 0
#define STT_RELC	8		/* Complex relocation expression */
#define STT_SRELC	9		/* Signed Complex relocation expression */
#define STT_LOOS	10		/* OS-specific semantics */
#define STT_GNU_IFUNC	10		/* Symbol is an indirect code object */
#define STT_HIOS	12		/* OS-specific semantics */
#define STT_LOPROC	13		/* Processor-specific semantics */
#define STT_HIPROC	15		/* Processor-specific semantics */
#endif

#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)

#define ELF32_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)	ELF_ST_TYPE(x)

#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)//获得st_info的高四位
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)//获得st_info的高四位

typedef struct dynamic{
  Elf32_Sword d_tag;
  union{
    Elf32_Sword	d_val;
    Elf32_Addr	d_ptr;
  } d_un;
} Elf32_Dyn;

//对应段 .dynamic段 动态链接
/*
这个段保存动态连接器所需要的基本信息比如依赖那些共享对象,动态链接符号表的位置 动态链接重定位表的位置
共享对象初始化代码的位置等 
*/

/*
d_tag           d_un
DT_SYMTAB       d_ptr 表示.dynsym的地址
DT_STRTAB       d_ptr表示 .dynstr的地址
DT_STRSZ        d_val动态链接字符串表大小
DT_HASH         d_ptr动态链接HASH表的地址 .hash
DT_SONAME       本共享对象的SO name
DT_RPATH        动态链接共享对象搜索路径
DT_INIT         初始化代码
DT_FINIT        结束代码地址
DT_NEED         依赖的共享对象文件d_ptr 表示所依赖的共享对象文件名
DT_REL
DT_RELA         动态链接重定位表地址
*/
typedef struct {
  Elf64_Sxword d_tag;		/* entry tag value 控制下面消息的类型*/
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;

/* The following are used with relocations */
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)


typedef struct elf32_rel {
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
} Elf32_Rel;

typedef struct elf64_rel {
	                    //对可重定位文件 此值为所要修正位置的第一个字节相对于段起始的偏移
	                    //对于可执行文件或共享对象文件此值为所要修正位置的第一个字节的虚拟地址
  Elf64_Addr r_offset;	/* Location at which to apply the action 重定位入口的偏移*/

						/*
                            重定位入口的类型和符号 低8位表示重定位入口的类型 (R_386_32)
                            高24位表示重定位入口的符号在符号表中的下标
						*/
  Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela{
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
  Elf32_Sword	r_addend;
} Elf32_Rela;

//重定位表 每个被重定位的地方叫重定位入口
/*objdump -r xx
RELOCATION RECORDS FOR [.text]:
OFFSET            TYPE              VALUE 
0000000000000018  R_X86_64_PC32     shared-0x0000000000000004
0000000000000029  R_X86_64_PC32     add-0x0000000000000004
*/
typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action 相对于段的偏移值*/
  Elf64_Xword r_info;	/* R_X86_64_64 index and type of relocation 该字段指明重定位所作用的符号表索引和重定位的类型*/
  Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;

typedef struct elf32_sym{
  Elf32_Word	st_name;
  Elf32_Addr	st_value;
  Elf32_Word	st_size;
  unsigned char	st_info;
  unsigned char	st_other;
  Elf32_Half	st_shndx;
} Elf32_Sym;

//符号表保存了程序实现或使用的所有全局变量和函数
typedef struct elf64_sym {
  Elf64_Word st_name;		/* Symbol name, index in string tbl 符号名。这个成员包含了该符号名在字符串
							表中的下标 */
  unsigned char	st_info;	/* Type and binding attributes 
							该成员低4位表示符号的类型STT_FUNC
							高4位表示符号绑定信息 STB_LOCAL
							*/
							
  unsigned char	st_other;	/* No defined meaning, 0  该成员目前为0，没用*/
  
  Elf64_Half st_shndx;		/* Associated section index 相关节的索引
							符号所在段（st_shndx）如果符号定义在本目标文件中，
							那么这个成员表示符号所在的段在段表中的下标
							但是如果符号不是定义在本目标文件中，或者对于有些特殊符号，
							sh_shndx的值有些特殊(SHN_ABS)
  							*/


/*
      对于st_shndx不是SHN_COMMON  则st_value 表示该符号在段中的偏移,即st_shndx指定段 st_value指定在段的偏移
      对于st_shndx 是SHN_COMMON   则st_value 表示该符号的对齐属性
      在可执行文件中 st_value表示符号的虚拟地址
*/							
  Elf64_Addr st_value;		/* Value of the symbol  符号相对应的值。这个值跟符号有关，可能
							是一个绝对值，也可能是一个地址等，不同的符号，
							它所对应的值含义不同*/
							
  Elf64_Xword st_size;		/* Associated symbol size 符号大小。对于包含数据的符号，这个值是该数据
							类型的大小。比如一个double型的符号它占用8个字节
							如果该值为0，则表示该符号大小为0或未知
							*/
} Elf64_Sym;


#define EI_NIDENT	16

typedef struct elf32_hdr{
  unsigned char	e_ident[EI_NIDENT];         //0
  Elf32_Half	e_type;                     //16   ET_EXEC
  Elf32_Half	e_machine; //EM_NONE          //18
  Elf32_Word	e_version;                  //20 
  Elf32_Addr	e_entry;  /* Entry point */ //24 
  Elf32_Off	    e_phoff;                    //28
  Elf32_Off	    e_shoff;                    //32
  Elf32_Word	e_flags;                    //36
  Elf32_Half	e_ehsize;                   //40
  Elf32_Half	e_phentsize;                //42
  Elf32_Half	e_phnum;                    //44
  Elf32_Half	e_shentsize;                //46
  Elf32_Half	e_shnum;                    //48
  Elf32_Half	e_shstrndx;                 //50
} Elf32_Ehdr;

typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];	   /*ELF "magic number" */
  Elf64_Half e_type;               //执行文件 重定位文件(.o) 共享文件(.so)
  Elf64_Half e_machine;            //机器类型 //EM_NONE
  Elf64_Word e_version;            //文件版本 EV_CURRENT
  Elf64_Addr e_entry;		/* 程序入口虚拟地址 Entry point virtual address */
  Elf64_Off e_phoff;		/* 程序头部表偏移 Program header table file offset */
  Elf64_Off e_shoff;		/* 节区头部表偏移 Section header table file offset */
  Elf64_Word e_flags;	//处理器标记对于IA32为0
  Elf64_Half e_ehsize;	//elf64_hdr此结构体的大小
  Elf64_Half e_phentsize;//程序头部表，一个表项的大小
  Elf64_Half e_phnum;   //程序头部表 表项的个数
  Elf64_Half e_shentsize;//节区表 一个表项的大小
  Elf64_Half e_shnum;   //节区表项的个数
  Elf64_Half e_shstrndx;//节名字表的表项在节区头部表的索引此节的名字为shstrtab 注意与strtab的区别
  						/*shstrtab内存放的是每个节的名字,strtab存放的是用到的符号的名字此节在节区表的位置在(e_shnum-1)处*/
} Elf64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4/* Segment is readable 可读*/
#define PF_W		0x2/* Segment is writable 可写*/
#define PF_X		0x1/* Segment is executable 可执行*/

typedef struct elf32_phdr{
  Elf32_Word	p_type;           //0
  Elf32_Off	    p_offset;         ////4  
  Elf32_Addr	p_vaddr;          //8
  Elf32_Addr	p_paddr;          //12
  Elf32_Word	p_filesz;         //16 
  Elf32_Word	p_memsz;          //20 
  Elf32_Word	p_flags;          //24 
  Elf32_Word	p_align;          //28 
} Elf32_Phdr;

//段表项
typedef struct elf64_phdr {
  Elf64_Word p_type;//类型 具体看PT_LOAD
  Elf64_Word p_flags;//PF_R 读 写 执行
  Elf64_Off p_offset;		/* Segment file offset  段相对于文件的索引地址*/
  Elf64_Addr p_vaddr;		/* Segment virtual address 段在内存中的虚拟地址*/
  Elf64_Addr p_paddr;		/* Segment physical address 段的物理地址*/
  Elf64_Xword p_filesz;		/* Segment size in file  段在文件中所占的长度*/
  Elf64_Xword p_memsz;		/* Segment size in memory  段在内存中所占的长度*/
  Elf64_Xword p_align;		/* Segment alignment, file & memory 字节对其,p_vaddr 和 p_offset 对 p_align 取模后应该相等*/
} Elf64_Phdr;

/* sh_type */
#define SHT_NULL	0//此值标志节区头部是非活动的，没有对应的节区。此节区头部中的其他成员取值无意义
#define SHT_PROGBITS	1//程序、代码、数据都是此种类型 此节区包含程序定义的信息，其格式和含义都由程序来解释释
#define SHT_SYMTAB	2  //此节区包含一个符号表
#define SHT_STRTAB	3  //此节区包含字符串表。目标文件可能包含多个字符串表节区。
#define SHT_RELA	4  //重定位表，该段包含了重定位信息
#define SHT_HASH	5 //此节区包含符号哈希表。所有参与动态链接的目标都必须包含一个符号哈希表
#define SHT_DYNAMIC	6  //动态链接信息
#define SHT_NOTE	7 //提示性信息
#define SHT_NOBITS	8 //表示该段在文件中没有内容，比如.bss
#define SHT_REL		9 //此节区包含重定位表项，其中没有补齐（addends），例如 32 位目标文件中的 Elf32_rel 类型。目标文件中可以拥有多个重定位节区
#define SHT_SHLIB	10//该节区保留
#define SHT_DYNSYM	11 //动态链接的符号表
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE	0x1 //节区包含进程执行过程中将可写的数据
#define SHF_ALLOC	0x2 //该段在进程空间中必须分配内存 
#define SHF_EXECINSTR	0x4 //表示该段在进程空间中可以被执行 一般为代码段
#define SHF_MASKPROC	0xf0000000//所有包含于此掩码中的四位都用于处理器专用的语义

#if 0 
自己添加
#define SHF_MERGE	(1 << 4)	/* Data in this section can be merged */
#define SHF_STRINGS	(1 << 5)	/* Contains null terminated character strings */
#define SHF_INFO_LINK	(1 << 6)	/* sh_info holds section header table index */
#define SHF_LINK_ORDER	(1 << 7)	/* Preserve section ordering when linking */
#define SHF_OS_NONCONFORMING (1 << 8)	/* OS specific processing required */
#define SHF_GROUP	(1 << 9)	/* Member of a section group */
#define SHF_TLS		(1 << 10)	/* Thread local storage section */
#endif


/* special section indexes */
#define SHN_UNDEF	0//通常表示该符号在本文件中未定义 (外部符号)
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_ABS		0xfff1//表示该符号包含一个绝对的 (absolute) 值 (往往是一个地址)，不受重定位影响  如文件名
#define SHN_COMMON	0xfff2//表示该符号是一个 common 符号，通常未初始化的全局变量就是该类型的符号
#define SHN_HIRESERVE	0xffff
 
typedef struct {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type; //类型 SHT_NULL
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	    sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;

//节表项
typedef struct elf64_shdr {
  Elf64_Word sh_name;	/* Section name, index in string tbl (段名，位于一个叫“.shstrtab”的字符串表索引)*/
  Elf64_Word sh_type;	/* Type of section 节的类型 如SHT_PROGBITS*/
  Elf64_Xword sh_flags;		/* Miscellaneous section attributes段的标志位，如SHF_WRITE 指出了该段在进程虚拟空间中的属性 */
  Elf64_Addr sh_addr;		/* Section virtual addr at execution 段在被加载后在进程地址空间中的虚拟地址，当段不能被加载时，它为0*/
  Elf64_Off sh_offset;		/* Section file offset 段在elf文件中的偏移，如果该段不存在于文件中，则它无意义*/
  Elf64_Xword sh_size;		/* Size of section in bytes 段的长度 */


  /*
    sh_type                  sh_link                                   sh_info
    SHT_DYNAMIC              该段所使用的字符串表在段表中的下标        0
    SHT_HASH                 该段使用的符号表在段表中的下标            0
    SHT_REL                  同下                                      同下
    SHT_RELA                 该段所使用的相应符号表在段表中的下标      该重定位表所作用的段在段表中的下标
    SHT_SYMTAB               同下                                      同下
    SHT_DYNSYM               操作系统相关                              操作系统相关
  */
  
  Elf64_Word sh_link;		/* Index of another section 段的链接信息*/
  Elf64_Word sh_info;		/* Additional section information 段的链接信息*/


  Elf64_Xword sh_addralign;	/* Section alignment 	段地址对齐*/
  Elf64_Xword sh_entsize;	/* Entry size if section holds table 项的长度，有的段包含一些固定大小的项，比如符号表，sh_enrsize就是用来指示这些项的大小*/
} Elf64_Shdr;

/*对于sh_link sh_info的介绍 如下*****************************************************
sh_type	 				sh_link	 							 sh_info
SHT_DYNAMIC				该段所使用的字符串表在段表中的下标		0
SHT_HASH				该段所使用的符号表在段表中的下标	    0
SHT_REL,SHT_RELA		该段所使用的符号表在段表中的下标		该重定位表所作用的段在段表中的下标
SHT_SYMTAB、SHT_DNYSYM	
other					SHN_UNDEF								0
*******************************************************************************/
#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF" // '\'后跟的为8进制  也可以\xhh \x后跟16进制  \177 是ASCII中的 DEL
#define	SELFMAG		4

#define	ELFCLASSNONE	0	//未识别 I_CLASS */
#define	ELFCLASS32	1       //32为目标文件
#define	ELFCLASS64	2       //4位
#define	ELFCLASSNUM	3

#define ELFDATANONE	0		/* e_ident[EI_DATA] */
#define ELFDATA2LSB	1   //小段编码
#define ELFDATA2MSB	2   //大端编码

#define EV_NONE		0		/* e_version, EI_VERSION */
#define EV_CURRENT	1      
#define EV_NUM		2

#define ELFOSABI_NONE	0 //UNIX System V ABI
#define ELFOSABI_LINUX	3 //GNU/Linux

#ifndef ELF_OSABI
#define ELF_OSABI ELFOSABI_NONE
#endif

/* Notes used in ET_CORE */
#define NT_PRSTATUS	1
#define NT_PRFPREG	2
#define NT_PRPSINFO	3
#define NT_TASKSTRUCT	4
#define NT_AUXV		6
#define NT_PRXFPREG     0x46e62b7f      /* copied from gdb5.1/include/elf/common.h */
#define NT_PPC_VMX	0x100		/* PowerPC Altivec/VMX registers */
#define NT_PPC_SPE	0x101		/* PowerPC SPE/EVR registers */
#define NT_PPC_VSX	0x102		/* PowerPC VSX registers */
#define NT_386_TLS	0x200		/* i386 TLS slots (struct user_desc) */
#define NT_386_IOPERM	0x201		/* x86 io permission bitmap (1=deny) */
#define NT_PRXSTATUS	0x300		/* s390 upper register halves */


/* Note header in a PT_NOTE section */
typedef struct elf32_note {
  Elf32_Word	n_namesz;	/* Name size */
  Elf32_Word	n_descsz;	/* Content size */
  Elf32_Word	n_type;		/* Content type */
} Elf32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct elf64_note {
  Elf64_Word n_namesz;	/* Name size */
  Elf64_Word n_descsz;	/* Content size */
  Elf64_Word n_type;	/* Content type */
} Elf64_Nhdr;

#ifdef __KERNEL__
#if ELF_CLASS == ELFCLASS32

extern Elf32_Dyn _DYNAMIC [];
#define elfhdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_note	elf32_note
#define elf_addr_t	Elf32_Off

#else

extern Elf64_Dyn _DYNAMIC [];
#define elfhdr		elf64_hdr
#define elf_phdr	elf64_phdr
#define elf_note	elf64_note
#define elf_addr_t	Elf64_Off

#endif

/* Optional callbacks to write extra ELF notes. */
#ifndef ARCH_HAVE_EXTRA_ELF_NOTES
static inline int elf_coredump_extra_notes_size(void) { return 0; }
static inline int elf_coredump_extra_notes_write(struct file *file,
			loff_t *foffset) { return 0; }
#else
extern int elf_coredump_extra_notes_size(void);
extern int elf_coredump_extra_notes_write(struct file *file, loff_t *foffset);
#endif
#endif /* __KERNEL__ */
#endif /* _LINUX_ELF_H */
