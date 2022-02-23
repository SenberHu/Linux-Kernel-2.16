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
/*������Ԫ��δ�á��ṹ��������Ա����δ�����*/
#define PT_NULL    0

/*������Ԫ�ظ���һ���ɼ��صĶ�,�εĴ�С�� p_filesz �� p_memsz ������
�ļ��е��ֽڱ�ӳ�䵽�ڴ�ο�ʼ������� p_memsz ���� p_filesz,��ʣ�ࡱ���ֽ�Ҫ����
�p_filesz ���ܴ��� p_memsz���ɼ��صĶ��ڳ���ͷ������и��� p_vaddr ��Ա����������*/
#define PT_LOAD    1//�ɼ��ض�(��������ݽ�)


#define PT_DYNAMIC 2//��̬���Ӷ�(��̬������Ϣ)

/*����Ԫ�ظ���һ�� NULL ��β���ַ�����λ�úͳ���,���ַ��������������������á�
���ֶ����ͽ������ִ���ļ�������(����Ҳ�����ڹ���Ŀ���ļ��Ϸ���)��
��һ���ļ��в��ܳ���һ�����ϡ���������������͵Ķ�,�����������пɼ��ض���Ŀ��ǰ�档*/
#define PT_INTERP  3//��������(��̬������·��)

/*������Ԫ�ظ���������Ϣ��λ�úʹ�С��*/
#define PT_NOTE    4

/*�˶����ͱ�����,��������δָ���������������͵Ķεĳ����� ABI����*/
#define PT_SHLIB   5

/*����ͷ�Ρ�ָ������ͷ�����ļ����ڴ�ӳ���е�λ�úʹ�С ������ڴ����ͶΣ����Ӧ�ĳ���ͷ�������������пɼ��ض����ǰ��*/
#define PT_PHDR    6

#define PT_TLS     7               /* Thread local storage segment */
#define PT_LOOS    0x60000000      /* OS-specific */

/*�˷�Χ�����ͱ�����������ר�����塣*/
#define PT_HIOS    0x6fffffff      /* OS-specific */

/*�˷�Χ�����ͱ�����������ר�����塣*/
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_GNU_EH_FRAME		0x6474e550
#define PT_GNU_STACK	(PT_LOOS + 0x474e551)
/***************************************************/

/* These constants define the different elf file types */
#define ET_NONE   0 //δ֪����
#define ET_REL    1 //���ض������� .o
#define ET_EXEC   2 //��ִ��
#define ET_DYN    3 //��̬�� .so ����Ŀ���ļ�
#define ET_CORE   4 //core�ļ� ת����ʽ
#define ET_LOPROC 0xff00 //�ض��������ļ�
#define ET_HIPROC 0xffff //�ض��������ļ�

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL		0
#define DT_NEEDED	1 //�����������  d_val��ŵĶ�̬�ַ������е��±�
#define DT_PLTRELSZ	2 //.rela.plt�ض�λ����ܴ�С d_val
#define DT_PLTGOT	3 //.got.plt �������ض�λ��ַ d_ptr
#define DT_HASH		4 //d_ptr
#define DT_STRTAB	5 //��̬�ַ������ַd_ptr
#define DT_SYMTAB	6 //��̬���ű��ַ d_ptr
#define DT_RELA		7 //�ض�λ��ĵ�ַd_ptr
#define DT_RELASZ	8 //DT_RELA �ض�λ����ܴ�С d_val
#define DT_RELAENT	9 //DT_RELA �ض�λ��Ĵ�С d_val 
#define DT_STRSZ	10 //DT_STRTAB �ַ�������ܴ�С d_val
#define DT_SYMENT	11 //DT_SYMTAB ������Ĵ�С
#define DT_INIT		12 //��ʼ�������ĵ�ַ d_ptr
#define DT_FINI		13 //��ֹ�����ĵ�ַ d_ptr
#define DT_SONAME	14 //�Կ��ַ���β���ַ����� DT_STRTAB �ַ�����ƫ�ƣ����ڱ�ʶ����Ŀ���ļ������� d_val
#define DT_RPATH 	15 //�Կ��ַ���β�Ŀ�����·���ַ����� DT_STRTAB �ַ�����ƫ�ơ���Ԫ�ص���;�ѱ� d_val
                       //�ڱ����ʱ�����-Wl,-rpath=""ָ����̬�⶯̬·����ʱ�� ����������·�����ַ���
#define DT_SYMBOLIC	16 
#define DT_REL	    17 //�� DT_RELA ���ƣ�������а�����ʽ��������Ԫ��Ҫ��ͬʱ���� DT_RELSZ �� DT_RELENT Ԫ��d_ptr
#define DT_RELSZ	18 //DT_REL �ض�λ����ܴ�Сd_val
#define DT_RELENT	19 //DT_REL �ض�λ��Ĵ�Сd_val 
#define DT_PLTREL	20 //d_val ��ʾ�������ӱ�ָ����ض�λ������ͣ�DT_REL �� DT_RELA�����������ӱ��е������ض�λ������ʹ����ͬ���ض�λ��
#define DT_DEBUG	21 //���ڵ��� d_ptr
#define DT_TEXTREL	22 //��ʾһ�������ض�λ����ܻ�Ҫ���޸ķǿ�д�Σ���������ʱ���ӳ���������Ӧ׼������Ԫ���ѱ� DF_TEXTREL ��־ȡ��
#define DT_JMPREL	23 //d_ptr ��������ӱ����������ض�λ��ĵ�ַ
#define DT_ENCODING	32 
#define OLD_DT_LOOS	0x60000000
#define DT_LOOS		0x6000000d
#define DT_HIOS		0x6ffff000
#define DT_VALRNGLO	0x6ffffd00
#define DT_VALRNGHI	0x6ffffdff
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_ADDRRNGHI	0x6ffffeff
#define DT_VERSYM	0x6ffffff0 //.gnu.version�������ַ
#define DT_RELACOUNT	0x6ffffff9
#define DT_RELCOUNT	0x6ffffffa
#define DT_FLAGS_1	0x6ffffffb
#define DT_VERDEF	0x6ffffffc
#define	DT_VERDEFNUM	0x6ffffffd
#define DT_VERNEED	0x6ffffffe //.gnu.version_r�ڵĵ�ַ
#define	DT_VERNEEDNUM	0x6fffffff
#define OLD_DT_HIOS     0x6fffffff
#define DT_LOPROC	0x70000000
#define DT_HIPROC	0x7fffffff

#define DT_GNU_HASH	0x6ffffef5


/* This info is needed when parsing the symbol table */
#define STB_LOCAL  0//�ֲ����ţ�����Ŀ���ļ����ⲿ���ɼ�
#define STB_GLOBAL 1//ȫ�ַ��ţ��ⲿ�ɼ�
#define STB_WEAK   2//������

#if 0
#define STB_LOOS	10		/* OS-specific semantics */
#define STB_GNU_UNIQUE	10		/* Symbol is unique in namespace */
#define STB_HIOS	12		/* OS-specific semantics */
#define STB_LOPROC	13		/* Processor-specific semantics */
#define STB_HIPROC	15		/* Processor-specific semantics */
#endif


#define STT_NOTYPE  0//δ֪���ͷ���
#define STT_OBJECT  1//�÷����Ǹ����ݶ��󣬱�������������
#define STT_FUNC    2//�÷����Ǹ�������������ִ�д���
#define STT_SECTION 3//�÷��ű�ʾһ���Σ����ַ��ű�����STB_LOCAL�� ��ʾ�±�Ϊndx�ĶεĶ���
#define STT_FILE    4//�÷��ű�ʾ�ļ�����һ�㶼�Ǹ�Ŀ���ļ�����Ӧ��Դ�ļ�������һ����STB_LOCAL���͵ģ�
					 //��������st_shndxһ����SHN_ABS
#define STT_COMMON  5 //δ��ʼ����ȫ�ֱ���
#define STT_TLS     6//�̱߳�������

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

#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)//���st_info�ĸ���λ
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)//���st_info�ĸ���λ

typedef struct dynamic{
  Elf32_Sword d_tag;
  union{
    Elf32_Sword	d_val;
    Elf32_Addr	d_ptr;
  } d_un;
} Elf32_Dyn;

//��Ӧ�� .dynamic�� ��̬����
/*
����α��涯̬����������Ҫ�Ļ�����Ϣ����������Щ�������,��̬���ӷ��ű��λ�� ��̬�����ض�λ���λ��
��������ʼ�������λ�õ� 
*/

/*
d_tag           d_un
DT_SYMTAB       d_ptr ��ʾ.dynsym�ĵ�ַ
DT_STRTAB       d_ptr��ʾ .dynstr�ĵ�ַ
DT_STRSZ        d_val��̬�����ַ������С
DT_HASH         d_ptr��̬����HASH��ĵ�ַ .hash
DT_SONAME       ����������SO name
DT_RPATH        ��̬���ӹ����������·��
DT_INIT         ��ʼ������
DT_FINIT        ���������ַ
DT_NEED         �����Ĺ�������ļ�d_ptr ��ʾ�������Ĺ�������ļ���
DT_REL
DT_RELA         ��̬�����ض�λ���ַ
*/
typedef struct {
  Elf64_Sxword d_tag;		/* entry tag value ����������Ϣ������*/
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
	                    //�Կ��ض�λ�ļ� ��ֵΪ��Ҫ����λ�õĵ�һ���ֽ�����ڶ���ʼ��ƫ��
	                    //���ڿ�ִ���ļ���������ļ���ֵΪ��Ҫ����λ�õĵ�һ���ֽڵ������ַ
  Elf64_Addr r_offset;	/* Location at which to apply the action �ض�λ��ڵ�ƫ��*/

						/*
                            �ض�λ��ڵ����ͺͷ��� ��8λ��ʾ�ض�λ��ڵ����� (R_386_32)
                            ��24λ��ʾ�ض�λ��ڵķ����ڷ��ű��е��±�
						*/
  Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela{
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
  Elf32_Sword	r_addend;
} Elf32_Rela;

//�ض�λ�� ÿ�����ض�λ�ĵط����ض�λ���
/*objdump -r xx
RELOCATION RECORDS FOR [.text]:
OFFSET            TYPE              VALUE 
0000000000000018  R_X86_64_PC32     shared-0x0000000000000004
0000000000000029  R_X86_64_PC32     add-0x0000000000000004
*/
typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action ����ڶε�ƫ��ֵ*/
  Elf64_Xword r_info;	/* R_X86_64_64 index and type of relocation ���ֶ�ָ���ض�λ�����õķ��ű��������ض�λ������*/
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

//���ű����˳���ʵ�ֻ�ʹ�õ�����ȫ�ֱ����ͺ���
typedef struct elf64_sym {
  Elf64_Word st_name;		/* Symbol name, index in string tbl �������������Ա�����˸÷��������ַ���
							���е��±� */
  unsigned char	st_info;	/* Type and binding attributes 
							�ó�Ա��4λ��ʾ���ŵ�����STT_FUNC
							��4λ��ʾ���Ű���Ϣ STB_LOCAL
							*/
							
  unsigned char	st_other;	/* No defined meaning, 0  �ó�ԱĿǰΪ0��û��*/
  
  Elf64_Half st_shndx;		/* Associated section index ��ؽڵ�����
							�������ڶΣ�st_shndx��������Ŷ����ڱ�Ŀ���ļ��У�
							��ô�����Ա��ʾ�������ڵĶ��ڶα��е��±�
							����������Ų��Ƕ����ڱ�Ŀ���ļ��У����߶�����Щ������ţ�
							sh_shndx��ֵ��Щ����(SHN_ABS)
  							*/


/*
      ����st_shndx����SHN_COMMON  ��st_value ��ʾ�÷����ڶ��е�ƫ��,��st_shndxָ���� st_valueָ���ڶε�ƫ��
      ����st_shndx ��SHN_COMMON   ��st_value ��ʾ�÷��ŵĶ�������
      �ڿ�ִ���ļ��� st_value��ʾ���ŵ������ַ
*/							
  Elf64_Addr st_value;		/* Value of the symbol  �������Ӧ��ֵ�����ֵ�������йأ�����
							��һ������ֵ��Ҳ������һ����ַ�ȣ���ͬ�ķ��ţ�
							������Ӧ��ֵ���岻ͬ*/
							
  Elf64_Xword st_size;		/* Associated symbol size ���Ŵ�С�����ڰ������ݵķ��ţ����ֵ�Ǹ�����
							���͵Ĵ�С������һ��double�͵ķ�����ռ��8���ֽ�
							�����ֵΪ0�����ʾ�÷��Ŵ�СΪ0��δ֪
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
  Elf64_Half e_type;               //ִ���ļ� �ض�λ�ļ�(.o) �����ļ�(.so)
  Elf64_Half e_machine;            //�������� //EM_NONE
  Elf64_Word e_version;            //�ļ��汾 EV_CURRENT
  Elf64_Addr e_entry;		/* ������������ַ Entry point virtual address */
  Elf64_Off e_phoff;		/* ����ͷ����ƫ�� Program header table file offset */
  Elf64_Off e_shoff;		/* ����ͷ����ƫ�� Section header table file offset */
  Elf64_Word e_flags;	//��������Ƕ���IA32Ϊ0
  Elf64_Half e_ehsize;	//elf64_hdr�˽ṹ��Ĵ�С
  Elf64_Half e_phentsize;//����ͷ����һ������Ĵ�С
  Elf64_Half e_phnum;   //����ͷ���� ����ĸ���
  Elf64_Half e_shentsize;//������ һ������Ĵ�С
  Elf64_Half e_shnum;   //��������ĸ���
  Elf64_Half e_shstrndx;//�����ֱ�ı����ڽ���ͷ����������˽ڵ�����Ϊshstrtab ע����strtab������
  						/*shstrtab�ڴ�ŵ���ÿ���ڵ�����,strtab��ŵ����õ��ķ��ŵ����ִ˽��ڽ������λ����(e_shnum-1)��*/
} Elf64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4/* Segment is readable �ɶ�*/
#define PF_W		0x2/* Segment is writable ��д*/
#define PF_X		0x1/* Segment is executable ��ִ��*/

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

//�α���
typedef struct elf64_phdr {
  Elf64_Word p_type;//���� ���忴PT_LOAD
  Elf64_Word p_flags;//PF_R �� д ִ��
  Elf64_Off p_offset;		/* Segment file offset  ��������ļ���������ַ*/
  Elf64_Addr p_vaddr;		/* Segment virtual address �����ڴ��е������ַ*/
  Elf64_Addr p_paddr;		/* Segment physical address �ε������ַ*/
  Elf64_Xword p_filesz;		/* Segment size in file  �����ļ�����ռ�ĳ���*/
  Elf64_Xword p_memsz;		/* Segment size in memory  �����ڴ�����ռ�ĳ���*/
  Elf64_Xword p_align;		/* Segment alignment, file & memory �ֽڶ���,p_vaddr �� p_offset �� p_align ȡģ��Ӧ�����*/
} Elf64_Phdr;

/* sh_type */
#define SHT_NULL	0//��ֵ��־����ͷ���Ƿǻ�ģ�û�ж�Ӧ�Ľ������˽���ͷ���е�������Աȡֵ������
#define SHT_PROGBITS	1//���򡢴��롢���ݶ��Ǵ������� �˽����������������Ϣ�����ʽ�ͺ��嶼�ɳ�����������
#define SHT_SYMTAB	2  //�˽�������һ�����ű�
#define SHT_STRTAB	3  //�˽��������ַ�����Ŀ���ļ����ܰ�������ַ����������
#define SHT_RELA	4  //�ض�λ���öΰ������ض�λ��Ϣ
#define SHT_HASH	5 //�˽����������Ź�ϣ�����в��붯̬���ӵ�Ŀ�궼�������һ�����Ź�ϣ��
#define SHT_DYNAMIC	6  //��̬������Ϣ
#define SHT_NOTE	7 //��ʾ����Ϣ
#define SHT_NOBITS	8 //��ʾ�ö����ļ���û�����ݣ�����.bss
#define SHT_REL		9 //�˽��������ض�λ�������û�в��루addends�������� 32 λĿ���ļ��е� Elf32_rel ���͡�Ŀ���ļ��п���ӵ�ж���ض�λ����
#define SHT_SHLIB	10//�ý�������
#define SHT_DYNSYM	11 //��̬���ӵķ��ű�
#define SHT_NUM		12
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE	0x1 //������������ִ�й����н���д������
#define SHF_ALLOC	0x2 //�ö��ڽ��̿ռ��б�������ڴ� 
#define SHF_EXECINSTR	0x4 //��ʾ�ö��ڽ��̿ռ��п��Ա�ִ�� һ��Ϊ�����
#define SHF_MASKPROC	0xf0000000//���а����ڴ������е���λ�����ڴ�����ר�õ�����

#if 0 
�Լ����
#define SHF_MERGE	(1 << 4)	/* Data in this section can be merged */
#define SHF_STRINGS	(1 << 5)	/* Contains null terminated character strings */
#define SHF_INFO_LINK	(1 << 6)	/* sh_info holds section header table index */
#define SHF_LINK_ORDER	(1 << 7)	/* Preserve section ordering when linking */
#define SHF_OS_NONCONFORMING (1 << 8)	/* OS specific processing required */
#define SHF_GROUP	(1 << 9)	/* Member of a section group */
#define SHF_TLS		(1 << 10)	/* Thread local storage section */
#endif


/* special section indexes */
#define SHN_UNDEF	0//ͨ����ʾ�÷����ڱ��ļ���δ���� (�ⲿ����)
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_ABS		0xfff1//��ʾ�÷��Ű���һ�����Ե� (absolute) ֵ (������һ����ַ)�������ض�λӰ��  ���ļ���
#define SHN_COMMON	0xfff2//��ʾ�÷�����һ�� common ���ţ�ͨ��δ��ʼ����ȫ�ֱ������Ǹ����͵ķ���
#define SHN_HIRESERVE	0xffff
 
typedef struct {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type; //���� SHT_NULL
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	    sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;

//�ڱ���
typedef struct elf64_shdr {
  Elf64_Word sh_name;	/* Section name, index in string tbl (������λ��һ���С�.shstrtab�����ַ���������)*/
  Elf64_Word sh_type;	/* Type of section �ڵ����� ��SHT_PROGBITS*/
  Elf64_Xword sh_flags;		/* Miscellaneous section attributes�εı�־λ����SHF_WRITE ָ���˸ö��ڽ�������ռ��е����� */
  Elf64_Addr sh_addr;		/* Section virtual addr at execution ���ڱ����غ��ڽ��̵�ַ�ռ��е������ַ�����β��ܱ�����ʱ����Ϊ0*/
  Elf64_Off sh_offset;		/* Section file offset ����elf�ļ��е�ƫ�ƣ�����öβ��������ļ��У�����������*/
  Elf64_Xword sh_size;		/* Size of section in bytes �εĳ��� */


  /*
    sh_type                  sh_link                                   sh_info
    SHT_DYNAMIC              �ö���ʹ�õ��ַ������ڶα��е��±�        0
    SHT_HASH                 �ö�ʹ�õķ��ű��ڶα��е��±�            0
    SHT_REL                  ͬ��                                      ͬ��
    SHT_RELA                 �ö���ʹ�õ���Ӧ���ű��ڶα��е��±�      ���ض�λ�������õĶ��ڶα��е��±�
    SHT_SYMTAB               ͬ��                                      ͬ��
    SHT_DYNSYM               ����ϵͳ���                              ����ϵͳ���
  */
  
  Elf64_Word sh_link;		/* Index of another section �ε�������Ϣ*/
  Elf64_Word sh_info;		/* Additional section information �ε�������Ϣ*/


  Elf64_Xword sh_addralign;	/* Section alignment 	�ε�ַ����*/
  Elf64_Xword sh_entsize;	/* Entry size if section holds table ��ĳ��ȣ��еĶΰ���һЩ�̶���С���������ű�sh_enrsize��������ָʾ��Щ��Ĵ�С*/
} Elf64_Shdr;

/*����sh_link sh_info�Ľ��� ����*****************************************************
sh_type	 				sh_link	 							 sh_info
SHT_DYNAMIC				�ö���ʹ�õ��ַ������ڶα��е��±�		0
SHT_HASH				�ö���ʹ�õķ��ű��ڶα��е��±�	    0
SHT_REL,SHT_RELA		�ö���ʹ�õķ��ű��ڶα��е��±�		���ض�λ�������õĶ��ڶα��е��±�
SHT_SYMTAB��SHT_DNYSYM	
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
#define	ELFMAG		"\177ELF" // '\'�����Ϊ8����  Ҳ����\xhh \x���16����  \177 ��ASCII�е� DEL
#define	SELFMAG		4

#define	ELFCLASSNONE	0	//δʶ�� I_CLASS */
#define	ELFCLASS32	1       //32ΪĿ���ļ�
#define	ELFCLASS64	2       //4λ
#define	ELFCLASSNUM	3

#define ELFDATANONE	0		/* e_ident[EI_DATA] */
#define ELFDATA2LSB	1   //С�α���
#define ELFDATA2MSB	2   //��˱���

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
