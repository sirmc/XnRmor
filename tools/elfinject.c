/*
 * elfinject.c
 *
 * Dennis Andriesse <da.andriesse@few.vu.nl>
 * VU University Amsterdam
 * March 2014
 *
 * Inject an additional code section into an ELF binary by overwriting 
 * the .note.ABI-tag section.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <getopt.h>
#include <gelf.h>
#include <libelf.h>


#define ELFINJECT_VERSION  "elfinject v0.87"
#define ELFINJECT_CREDITS  "Copyright (C) 2014 Dennis Andriesse\n"                                       \
                           "This is free software; see the source for copying conditions. There is NO\n" \
                           "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

#define ABITAG_NAME    ".note.ABI-tag"
#define SHSTRTAB_NAME  ".shstrtab"
#define DYNINST_NAME   ".dyninstInst"

FILE* finfo;

typedef struct {
  int fd;         /* file descriptor */
  Elf *e;         /* main elf descriptor */
  int bits;       /* 32-bit or 64-bit */
  GElf_Ehdr ehdr; /* executable header */
} elf_data_t;

typedef struct {
  size_t pidx;    /* index of program header to overwrite */
  GElf_Phdr phdr; /* program header to overwrite */
  size_t sidx;    /* index of section header to overwrite */
  Elf_Scn *scn;   /* section to overwrite */
  GElf_Shdr shdr; /* section header to overwrite */
  off_t shstroff; /* offset to section name to overwrite */
  char *code;     /* code to inject */
  size_t len;     /* number of code bytes */
  long entry;     /* code buffer offset to entry point (-1 for none) */
  off_t off;      /* file offset to injected code */
  size_t secaddr; /* section address for injected code */
  char *secname;  /* section name for injected code */
} inject_data_t;


int verbosity = 0;


void
verbose(char *fmt, ...)
{
  va_list args;

  if(verbosity > 0) {
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
  }
}


void
print_err(char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  fprintf(stderr, "ERROR: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}


int
write_code(elf_data_t *elf, inject_data_t *inject, char **err)
{
  off_t off;
  size_t n, padding_len;
  char padding[4096];

  off = lseek(elf->fd, 0, SEEK_END);
  if(off < 0) {
    (*err) = "lseek failed";
    return -1;
  }

  padding_len = 4096 - (off % 4096);
  memset(padding, '\0', padding_len);

  verbose("injecting %lu padding bytes at offset %lu", padding_len, off);

  n = write(elf->fd, padding, padding_len);
  if(n != padding_len) {
    (*err) = "write failed";
    return -1;
  }

  off = off + padding_len;

  verbose("injecting %lu code bytes at offset %lu", inject->len, off);

  n = write(elf->fd, inject->code, inject->len);
  if(n != inject->len) {
    (*err) = "write failed";
    return -1;
  }

  inject->off = off;

  return 0;
}


int
write_ehdr(elf_data_t *elf, char **err)
{
  off_t off;
  size_t n, ehdr_size;
  void *ehdr_buf;

  if(!gelf_update_ehdr(elf->e, &elf->ehdr)) {
    (*err) = "failed to update executable header";
    return -1;
  }

  if(elf->bits == 32) {
    ehdr_buf = elf32_getehdr(elf->e);
    ehdr_size = sizeof(Elf32_Ehdr);
  } else {
    ehdr_buf = elf64_getehdr(elf->e);
    ehdr_size = sizeof(Elf64_Ehdr);
  }

  if(!ehdr_buf) {
    (*err) = "failed to get executable header";
    return -1;
  }

  off = lseek(elf->fd, 0, SEEK_SET);
  if(off < 0) {
    (*err) = "lseek failed";
    return -1;
  }

  n = write(elf->fd, ehdr_buf, ehdr_size);
  if(n != ehdr_size) {
    (*err) = "write failed";
    return -1;
  }

  return 0;
}


int
write_phdr(elf_data_t *elf, inject_data_t *inject, char **err)
{
  off_t off;
  size_t n, phdr_size;
  Elf32_Phdr *phdr_list32;
  Elf64_Phdr *phdr_list64;
  void *phdr_buf;

  if(!gelf_update_phdr(elf->e, inject->pidx, &inject->phdr)) {
    (*err) = "failed to update program header";
    return -1;
  }

  if(elf->bits == 32) {
    phdr_list32 = elf32_getphdr(elf->e);
    if(!phdr_list32) {
      phdr_buf = NULL;
    } else {
      phdr_buf = &phdr_list32[inject->pidx];
      phdr_size = sizeof(Elf32_Phdr);
    }
  } else {
    phdr_list64 = elf64_getphdr(elf->e);
    if(!phdr_list64) {
      phdr_buf = NULL;
    } else {
      phdr_buf = &phdr_list64[inject->pidx];
      phdr_size = sizeof(Elf64_Phdr);
    }
  }

  if(!phdr_buf) {
    (*err) = "failed to get program header";
    return -1;
  }

  off = lseek(elf->fd, elf->ehdr.e_phoff + inject->pidx*elf->ehdr.e_phentsize, SEEK_SET);
  if(off < 0) {
    (*err) = "lseek failed";
    return -1;
  }

  n = write(elf->fd, phdr_buf, phdr_size);
  if(n != phdr_size) {
    (*err) = "write failed";
    return -1;
  }

  return 0;
}


int
write_shdr(elf_data_t *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t sidx, char **err)
{
  off_t off;
  size_t n, shdr_size;
  void *shdr_buf;

  if(!gelf_update_shdr(scn, shdr)) {
    (*err) = "failed to update section header";
    return -1;
  }

  if(elf->bits == 32) {
    shdr_buf = elf32_getshdr(scn);
    shdr_size = sizeof(Elf32_Shdr);
  } else {
    shdr_buf = elf64_getshdr(scn);
    shdr_size = sizeof(Elf64_Shdr);
  }

  if(!shdr_buf) {
    (*err) = "failed to get section header";
    return -1;
  }

  off = lseek(elf->fd, elf->ehdr.e_shoff + sidx*elf->ehdr.e_shentsize, SEEK_SET);
  if(off < 0) {
    (*err) = "lseek failed";
    return -1;
  }
    
  n = write(elf->fd, shdr_buf, shdr_size);
  if(n != shdr_size) {
    (*err) = "write failed";
    return -1;
  }

  return 0;
}


int
reorder_shdrs(elf_data_t *elf, inject_data_t *inject, char **err)
{
  int direction, skip;
  size_t i;
  Elf_Scn *scn;
  GElf_Shdr shdr;

  direction = 0;

  scn = elf_getscn(elf->e, inject->sidx - 1);
  if(scn && !gelf_getshdr(scn, &shdr)) {
    (*err) = "failed to get section header";
    return -1;
  }
  if(scn && shdr.sh_addr > inject->shdr.sh_addr) {
    /* Injected section header must be moved left */
    direction = -1;
  }

  scn = elf_getscn(elf->e, inject->sidx + 1);
  if(scn && !gelf_getshdr(scn, &shdr)) {
    (*err) = "failed to get section header";
    return -1;
  }
  if(scn && shdr.sh_addr < inject->shdr.sh_addr) {
    /* Injected section header must be moved right */
    direction = 1;
  }

  if(direction == 0) {
    /* Section headers are already in order */
    return 0;
  }

  i = inject->sidx;

  /* Order section headers by increasing address */
  skip = 0;
  for(scn = elf_getscn(elf->e, inject->sidx + direction); 
      scn != NULL;
      scn = elf_getscn(elf->e, inject->sidx + direction + skip)) {
    if(!gelf_getshdr(scn, &shdr)) {
      (*err) = "failed to get section header";
      return -1;
    }

    if((direction < 0 && shdr.sh_addr <= inject->shdr.sh_addr)
       || (direction > 0 && shdr.sh_addr >= inject->shdr.sh_addr)) {
      /* The order is okay from this point on */
      break;
    }

    /* Only reorder code section headers */
    if(shdr.sh_type != SHT_PROGBITS) {
      skip += direction;
      continue;
    }

    /* Swap the injected shdr with its neighbor progbits header */
    if(write_shdr(elf, scn, &inject->shdr, elf_ndxscn(scn), err) < 0) {
      return -1;
    }
    if(write_shdr(elf, inject->scn, &shdr, inject->sidx, err) < 0) {
      return -1;
    }

    inject->sidx += direction + skip;
    inject->scn = elf_getscn(elf->e, inject->sidx);
    skip = 0;
  }

  verbose("reordered sections %lu - %lu", i, inject->sidx);

  return 0;
}


int
write_secname(elf_data_t *elf, inject_data_t *inject, char **err)
{
  off_t off;
  size_t n;

  off = lseek(elf->fd, inject->shstroff, SEEK_SET);
  if(off < 0) {
    (*err) = "lseek failed";
    return -1;
  }
  
  n = write(elf->fd, inject->secname, strlen(inject->secname));
  if(n != strlen(inject->secname)) {
    (*err) = "write failed";
    return -1;
  }

  n = strlen(ABITAG_NAME) - strlen(inject->secname);
  while(n > 0) {
    if(!write(elf->fd, "\0", 1)) {
      (*err) = "write failed";
      return -1;
    }
    n--;
  }

  return 0;
}


int
find_rewritable_segment(elf_data_t *elf, inject_data_t *inject, char **err)
{
  int ret;
  size_t i, n;

  /* Get number of program headers */
  ret = elf_getphdrnum(elf->e, &n);
  if(ret != 0) {
    (*err) = "cannot find any program headers";
    return -1;
  }

  /* Look for a rewritable program header */
  for(i = 0; i < n; i++) {
    if(!gelf_getphdr(elf->e, i, &inject->phdr)) {
      (*err) = "failed to get program header";
      return -1;
    }

    switch(inject->phdr.p_type) {
    case PT_NOTE:
      inject->pidx = i;
      return 0;
    case PT_NULL:
    case PT_LOAD:
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
    case PT_PHDR:
    case PT_TLS:
    default:
      break;
    }
  }

  (*err) = "cannot find segment to rewrite";
  return -1;
}


int
rewrite_code_segment(elf_data_t *elf, inject_data_t *inject, char **err)
{
  inject->phdr.p_type   = PT_LOAD;         /* type */
  inject->phdr.p_offset = inject->off;     /* file offset to start of segment */
  inject->phdr.p_vaddr  = inject->secaddr; /* virtual address to load segment at */
  inject->phdr.p_paddr  = inject->secaddr; /* physical address to load segment at */
  inject->phdr.p_filesz = inject->len;     /* byte size in file */
  inject->phdr.p_memsz  = inject->len;     /* byte size in memory */
  inject->phdr.p_flags  = PF_R | PF_X;     /* flags */
  inject->phdr.p_align  = 0x1000;          /* alignment in memory and file */

  verbose("rewriting program header %lu:", inject->pidx);
  verbose("  p_type   = PT_LOAD");
  verbose("  p_offset = %lu", inject->phdr.p_offset);
  verbose("  p_vaddr  = 0x%x", inject->phdr.p_vaddr);
  verbose("  p_paddr  = 0x%x", inject->phdr.p_paddr);
  verbose("  p_filesz = %lu", inject->phdr.p_filesz);
  verbose("  p_memsz  = %lu", inject->phdr.p_memsz);
  verbose("  p_flags  = PF_R | PF_X");
  verbose("  p_align  = 0x%x", inject->phdr.p_align);

  verbose("writing program header to file");

  if(write_phdr(elf, inject, err) < 0) {
    return -1;
  }

  return 0;
}

int
find_injected_secaddr(elf_data_t *elf, inject_data_t *inject)
{
  Elf_Scn *scn;
  GElf_Shdr shdr;
  uint64_t max_inject_addr = 0;
  char* s;
  size_t shstrndx;

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    return -1;
  }

  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      return -1;
    }
    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      return -1;
    }

    if(!strcmp(s, DYNINST_NAME))
		fprintf(finfo,"dyninst end=%lx\n",shdr.sh_addr + shdr.sh_size);
	if (shdr.sh_addr + shdr.sh_offset > max_inject_addr)
		max_inject_addr = shdr.sh_addr + shdr.sh_size;
  }
  inject->secaddr = max_inject_addr + inject->len + 0x4000;
  return 0;
}

int
rewrite_code_section(elf_data_t *elf, inject_data_t *inject, char **err)
{
  Elf_Scn *scn;
  GElf_Shdr shdr;
  char *s;
  size_t shstrndx;

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    (*err) = "failed to get string table section index";
    return -1;
  }

  printf("shstrndx : %d\n",shstrndx);

  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      (*err) = "failed to get section header";
      return -1;
    }

    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      (*err) = "failed to get section name";
      return -1;
    }
  	printf("section : %s\n",s);

    if(!strcmp(s, ABITAG_NAME)) {
      shdr.sh_name      = shdr.sh_name;              /* offset into string table */
      shdr.sh_type      = SHT_PROGBITS;              /* type */
      shdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR; /* flags */
      shdr.sh_addr      = inject->secaddr;           /* address to load section at */
      shdr.sh_offset    = inject->off;               /* file offset to start of section */
      shdr.sh_size      = inject->len;               /* size in bytes */
      shdr.sh_link      = 0;                         /* not used for code section */
      shdr.sh_info      = 0;                         /* not used for code section */
      shdr.sh_addralign = 16;                        /* memory alignment */
      shdr.sh_entsize   = 0;                         /* not used for code section */

      verbose("rewriting section header %lu:", elf_ndxscn(scn));
      verbose("  sh_name      = %u", shdr.sh_name);
      verbose("  sh_type      = SHT_PROGBITS");
      verbose("  sh_flags     = SHF_ALLOC | SHF_EXECINSTR"); 
      verbose("  sh_addr      = 0x%x", shdr.sh_addr);
      verbose("  sh_offset    = %lu", shdr.sh_offset);
      verbose("  sh_size      = %lu", shdr.sh_size);
      verbose("  sh_link      = 0");
      verbose("  sh_info      = 0");
      verbose("  sh_addralign = 0x%x", shdr.sh_addralign);
      verbose("  sh_entsize   = 0");

      inject->sidx = elf_ndxscn(scn);
      inject->scn = scn;
      memcpy(&inject->shdr, &shdr, sizeof(shdr));

      verbose("writing section header to file");

      if(write_shdr(elf, scn, &shdr, elf_ndxscn(scn), err) < 0) {
        return -1;
      }

      if(reorder_shdrs(elf, inject, err) < 0) {
        return -1;
      }

      break;
    }
  }

  if(!scn) {
    (*err) = "cannot find section to rewrite";
    return -1;
  }

  return 0;
}


int
rewrite_section_name(elf_data_t *elf, inject_data_t *inject, char **err)
{
  Elf_Scn *scn;
  GElf_Shdr shdr;
  char *s;
  size_t shstrndx, stroff, strbase;

  if(strlen(inject->secname) > strlen(ABITAG_NAME)) {
    (*err) = "section name too long";
    return -1;
  }

  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    (*err) = "failed to get string table section index";
    return -1;
  }

  stroff = 0;
  strbase = 0;
  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    if(!gelf_getshdr(scn, &shdr)) {
      (*err) = "failed to get section header";
      return -1;
    }

    s = elf_strptr(elf->e, shstrndx, shdr.sh_name);
    if(!s) {
      (*err) = "failed to get section name";
      return -1;
    }

    if(!strcmp(s, ABITAG_NAME)) {
      stroff = shdr.sh_name;   /* offset into shstrtab */
    } else if(!strcmp(s, SHSTRTAB_NAME)) {
      strbase = shdr.sh_offset; /* offset to start of shstrtab */
    }
  }

  if(stroff == 0) {
    (*err) = "cannot find shstrtab entry for injected section";
    return -1;
  } else if(strbase == 0) {
    (*err) = "cannot find shstrtab";
    return -1;
  }

  inject->shstroff = strbase + stroff;

  verbose("renaming rewritten section to \"%s\"", inject->secname);
  verbose("writing section string table to file");

  if(write_secname(elf, inject, err) < 0) {
    return -1;
  }

  return 0;
}


int
rewrite_entry_point(elf_data_t *elf, inject_data_t *inject, char **err)
{
  elf->ehdr.e_entry = inject->phdr.p_vaddr + inject->entry; /* virtual entry point address */

  verbose("updating entry point to 0x%x", elf->ehdr.e_entry);
  verbose("writing executable header to file");

  if(write_ehdr(elf, err) < 0) {
    return -1;
  }

  return 0;
}


int
inject_code(int fd, inject_data_t *inject, char **err)
{
  elf_data_t elf;
  int ret;
  off_t align;
  size_t n;

  elf.fd = fd;
  elf.e  = NULL;

  if(elf_version(EV_CURRENT) == EV_NONE) {
    (*err) = "failed to initialize libelf";
    goto fail;
  }

  /* Use libelf to read the file, but do writes manually */
  elf.e = elf_begin(elf.fd, ELF_C_READ, NULL);
  if(!elf.e) {
    (*err) = "failed to open elf file";
    goto fail;
  }

  if(elf_kind(elf.e) != ELF_K_ELF) {
    (*err) = "not an elf executable";
    goto fail;
  }

  ret = gelf_getclass(elf.e);
  switch(ret) {
  case ELFCLASSNONE:
    (*err) = "unknown elf class";
    goto fail;
  case ELFCLASS32:
    elf.bits = 32;
    break;
  default:
    elf.bits = 64;
    break;
  }

  /* Get executable header */
  if(!gelf_getehdr(elf.e, &elf.ehdr)) {
    (*err) = "failed to get executable header";
    goto fail;
  }

  /* Find a rewritable program header */
  if(find_rewritable_segment(&elf, inject, err) < 0) {
    goto fail;
  }

  /* Write the injected code to the binary */
  if(write_code(&elf, inject, err) < 0) {
    goto fail;
  }

  if (inject->secaddr == 0)
	  find_injected_secaddr(&elf,inject);

  /* Fix alignment of code address */
  align = 0x1000;
  inject->secaddr = inject->secaddr - inject->len;
  n = (inject->off % align) - (inject->secaddr % align);
  if(n > 0) {
    inject->secaddr -= align;
  }
  inject->secaddr += n;
  fprintf(finfo,"Inject=%lx\n",inject->secaddr);

  /* Rewrite a section for the injected code */
  if(rewrite_code_section(&elf, inject, err) < 0) {
    goto fail;
  }

  /* Update the name of the rewritten section */
  if(rewrite_section_name(&elf, inject, err) < 0) {
    goto fail;
  }

  /* Rewrite a segment for the added code section */
  if(rewrite_code_segment(&elf, inject, err) < 0) {
    goto fail;
  }

  /* Rewrite entry point if requested */
  if(inject->entry >= 0) {
    if(rewrite_entry_point(&elf, inject, err) < 0) {
      goto fail;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(elf.e) {
    elf_end(elf.e);
  }

  return ret;
}


void
print_usage(char *prog)
{
  printf(ELFINJECT_VERSION"\n");
  printf(ELFINJECT_CREDITS"\n");
  printf("\n%s [vh] -e <elf> -i <inject> -n <secname> -a <secaddr> [-s <entry>]\n", prog);
  printf("  -v : verbose\n");
  printf("  -h : help\n");
  printf("  -e : target elf binary\n");
  printf("  -i : code file to inject\n");
  printf("  -n : name for injected code section\n");
  printf("  -a : virtual address for injected code\n");
  printf("  -s : code offset to entry point\n");
  printf("\n");
}

int
main(int argc, char *argv[])
{
  FILE *inject_f;
  int elf_fd, opt, ret;
  size_t len, secaddr;
  long entry;
  char *elf_fname, *inject_fname, *secname, *code, *err;
  char optstr[] = "vhe:i:n:a:s:";
  inject_data_t inject;

  if(argc < 4) {
    print_usage(argv[0]);
    return 0;
  }

  inject_f     = NULL;
  elf_fd       = -1;
  secaddr      = 0;
  entry        = -1;
  code         = NULL;
  elf_fname    = NULL;
  inject_fname = NULL;
  secname      = NULL;

  opterr = 0;
  while((opt = getopt(argc, argv, optstr)) != -1) {
    switch(opt) {
    case 'v':
      verbosity++;
      break;
    case 'e':
      elf_fname = strdup(optarg);
      break;
    case 'i':
      inject_fname = strdup(optarg);
      break;
    case 'n':
      secname = strdup(optarg);
      break;
    case 'a':
      secaddr = strtoul(optarg, NULL, 0);
      break;
    case 's':
      entry = strtol(optarg, NULL, 0);
      break;
    case 'h':
    default:
      print_usage(argv[0]);
      return 0;
    }
  }

  if(!elf_fname || strlen(elf_fname) < 1) {
    print_err("no target binary");
    return 1;
  } else if(!inject_fname || strlen(inject_fname) < 1) {
    print_err("no code to inject");
    return 1;
  } else if(!secname || strlen(secname) < 1) {
    print_err("no section name for injected code");
    return 1;
  } /*else if(secaddr == 0) {
    print_err("no valid section address for injected code");
    return 1;
  }*/
  finfo = fopen("./info/section.info","w");

  verbose("opening \"%s\"", inject_fname);
  inject_f = fopen(inject_fname, "r");
  if(!inject_f) {
    print_err("failed to open \"%s\"", inject_fname);
    goto fail;
  }

  fseek(inject_f, 0, SEEK_END);
  len = ftell(inject_f);

  code = malloc(len);
  if(!code) {
    print_err("failed to alloc code buffer");
    goto fail;
  }

  fseek(inject_f, 0, SEEK_SET);
  fread(code, 1, len, inject_f);

  verbose("opening \"%s\"", elf_fname);
  elf_fd = open(elf_fname, O_RDWR);
  if(elf_fd < 0) {
    print_err("failed to open \"%s\"", elf_fname);
    goto fail;
  }

  inject.code    = code;
  inject.len     = len;
  inject.entry   = entry;
  inject.secname = secname;
  inject.secaddr = secaddr;

  ret = inject_code(elf_fd, &inject, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = 1;

cleanup:
  if(elf_fd >= 0) {
    close(elf_fd);
  }
  if(inject_f) {
    fclose(inject_f);
  }
  if(code) {
    free(code);
  }
  if(elf_fname) {
    free(elf_fname);
  }
  if(inject_fname) {
    free(inject_fname);
  }
  if(secname) {
    free(secname);
  }
  fclose(finfo);

  return ret;
}

