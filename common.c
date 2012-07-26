#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <dwarf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

static int
get_buildid (struct link_map *map, char *buildid)
{
#define NOTE_ALIGN(n) (((n) + 3) & -4U)

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *) map->l_addr;
  Elf64_Phdr *phdr = (Elf64_Phdr *) (map->l_addr + ehdr->e_phoff);
  for (size_t i = 0; i < ehdr->e_phnum; ++i)
    {
      Elf64_Phdr *phdr = (Elf64_Phdr *) (map->l_addr + ehdr->e_phoff
					 + i * ehdr->e_phentsize);
      if (phdr->p_type != PT_NOTE)
	continue;

      size_t sz = 0;
      do
	{
	  Elf64_Nhdr *nhdr = (Elf64_Nhdr *) (map->l_addr + phdr->p_offset + sz);
	  size_t namesz = NOTE_ALIGN (nhdr->n_namesz);
	  size_t descsz = NOTE_ALIGN (nhdr->n_descsz);
	  if (nhdr->n_type == NT_GNU_BUILD_ID
	      && nhdr->n_namesz == sizeof "GNU"
	      && !memcmp ((char *)(map->l_addr + phdr->p_offset + sz
				   + sizeof (Elf64_Nhdr)),
			  "GNU", sizeof "GNU"))
	    {
	      unsigned i;
	      for (i = 0; i < nhdr->n_descsz; ++i)
		snprintf (&buildid[2*i], 3, "%02hhx",
			  *(char *)(map->l_addr + phdr->p_offset + sz
				    + sizeof (Elf64_Nhdr) + namesz + i));
	      buildid[2*i] = '\0';
	      return 1;
	    }

	  sz += sizeof (Elf64_Nhdr) + namesz + descsz;
	}
      while (sz + sizeof (Elf64_Nhdr) < phdr->p_filesz);
    }

  return 0;

#undef NOTE_ALIGN
}

static struct dwtype
dwarf_type_to_type (Dwarf_Attribute *typeattr)
{
  struct dwtype type;
  Dwarf_Die typedie;
  type.type_tag = -1;
  type.type_encoding = -1;
  type.type_byte_size = -1;
  if (dwarf_formref_die (typeattr, &typedie) != NULL)
    {
      type.type_tag = dwarf_tag (&typedie);
      switch (type.type_tag)
	{
	case DW_TAG_typedef:
	case DW_TAG_const_type:
	  {
	    Dwarf_Attribute tdattr;
	    if (dwarf_attr (&typedie, DW_AT_type, &tdattr) != NULL)
	      return dwarf_type_to_type (&tdattr);
	    break;
	  }
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	  break;
	case DW_TAG_base_type:
	  {
	    Dwarf_Attribute szattr, encattr;
	    Dwarf_Word sz, enc;
	    if (dwarf_attr (&typedie, DW_AT_encoding, &encattr) != NULL
		&& dwarf_formudata (&encattr, &enc) == 0)
	      type.type_encoding = enc;
	    if (dwarf_attr (&typedie, DW_AT_byte_size, &szattr) != NULL
		&& dwarf_formudata (&szattr, &sz) == 0)
	      type.type_byte_size = sz;
	    break;
	  }
	}
    }

  return type;
}


static int
funcscb (Dwarf_Die *die, void *data)
{
  const char *name = dwarf_diename (die);
  Dwarf_Addr lowpc, highpc;
  struct dsohandle *fns = (struct dsohandle *) data;
  struct fnentry fn;
  if (dwarf_lowpc (die, &lowpc) != 0)
    return DWARF_CB_OK;
  fn.idx = 0;
  fn.name = strdup (dwarf_diename (die));
  fn.low_pc = lowpc;

  Dwarf_Attribute rettype;
  fn.type = (struct dwtype){ DW_TAG_base_type, DW_ATE_void, -1 };
  if (dwarf_attr (die, DW_AT_type, &rettype) != NULL)
    fn.type = dwarf_type_to_type (&rettype);

  fn.nargs = 0;
  fn.args = NULL;
  Dwarf_Die child;
  if (dwarf_child (die, &child) == 0)
    {
      do
	{
	  /* Assume DW_TAG_subprogram immediately follows all
	     DW_TAG_formal_parameter.  */
	  if (dwarf_tag (&child) != DW_TAG_formal_parameter)
	    break;

	  struct fnarg arg;
	  Dwarf_Attribute locat;
	  Dwarf_Attribute typeat;
	  Dwarf_Die paramdie;
	  arg.name = dwarf_diename (&child);
	  arg.regno.atom = 0;
	  if (dwarf_attr (&child, DW_AT_location, &locat) != NULL)
	    {
	      Dwarf_Op *buf;
	      size_t len;
	      if (dwarf_getlocation_addr (&locat, lowpc, &buf, &len, 1) == 1)
		arg.regno = buf[0];
	    }
	  arg.type = (struct dwtype){ -1, -1, -1 };
	  if (dwarf_attr (&child, DW_AT_type, &typeat) != NULL)
	    arg.type = dwarf_type_to_type (&typeat);
	  else if (dwarf_attr (&child, DW_AT_abstract_origin, &typeat) != NULL
		   && dwarf_formref_die (&typeat, &paramdie) != NULL
		   && dwarf_tag (&paramdie) == DW_TAG_formal_parameter
		   && dwarf_attr (&paramdie, DW_AT_type, &typeat) != NULL)
	    arg.type = dwarf_type_to_type (&typeat);

	  fn.args = realloc (fn.args, ++fn.nargs * sizeof (struct fnarg));
	  memcpy (&fn.args[fn.nargs - 1], &arg, sizeof (struct fnarg));
	}
      while (dwarf_siblingof (&child, &child) == 0);
    }

  fns->fns = realloc (fns->fns, ++fns->nfns * (sizeof (struct fnentry)));
  memcpy (&fns->fns[fns->nfns - 1], &fn, sizeof (struct fnentry));

  return DWARF_CB_OK;
}

static int
get_dwarf_1 (struct dsohandle *dso, char *debugfname)
{
  int fd = open (debugfname, O_RDONLY);
  if (fd == -1)
    return 0;
  Dwarf *dw = dwarf_begin (fd, DWARF_C_READ);
  if (!dw)
    return 0;

  /*dwarf_getpubnames (dw, pubnamescb, NULL, 0);*/

  Dwarf_Off cuoff = 0, next = 0;
  int res;
  dso->nfns = 0;
  dso->fns = NULL;
  do
    {
      Dwarf_Off abbrev_offset;
      size_t header_size;
      uint8_t address_size, offset_size;
      Dwarf_Die cudie;
      cuoff = next;
      res = dwarf_nextcu (dw, cuoff, &next, &header_size, &abbrev_offset,
			      &address_size, &offset_size);
      if (res == -1)
	break;
      if (dwarf_offdie (dw, cuoff + header_size, &cudie) != NULL)
	dwarf_getfuncs (&cudie, funcscb, dso, 0);
    }
  while (res == 0);

  dwarf_end (dw);
  close (fd);

  return 1;
}

int
get_dwarf (struct dsohandle *dso)
{
  char buildid[80];
  if (get_buildid (dso->map, buildid))
    {
      char debugfname[1024];
      snprintf (debugfname, 1023, "/usr/lib/debug/.build-id/%c%c/%s.debug",
		buildid[0], buildid[1], &buildid[2]);
      if (get_dwarf_1 (dso, debugfname))
	return 1;
    }

  return get_dwarf_1 (dso, dso->map->l_name);
}
