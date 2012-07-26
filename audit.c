#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <libelf.h>
#include <elfutils/libdw.h>
#include <stdlib.h>
#include <dwarf.h>
#include <string.h>

#include "common.h"

static FILE *outf;
static int ok = 0;
static const char *libstr;


unsigned int
la_version(unsigned int version)
{
  char *e = getenv ("LGTRACE_OUT");
  if (!e)
    outf = stderr;
  else
    outf = fopen (e, "w");
  libstr = getenv ("LGTRACE_LIB");
  return version;
}

unsigned int
la_objopen(struct link_map *map, Lmid_t lmid,
	   uintptr_t *cookie)
{
  if (!map->l_name)
    return 0;

  struct dsohandle *dso = malloc (sizeof (struct dsohandle));
  dso->map = map;
  dso->nfns = 0;
  dso->fns = NULL;
  *cookie = (uintptr_t) dso;

  /* Do not process PLTs that bind to the application.  */
  if (!map->l_name[0])
    return LA_FLG_BINDFROM;

  if (libstr
      && !strcasestr (map->l_name, libstr))
    return 0;

  if (get_dwarf (dso))
    fprintf (stderr, "processed debug info from %s\n",
	     dso->map->l_name[0] ? dso->map->l_name : "app");
  else
    fprintf (stderr, "no debug info for %s\n",
	     dso->map->l_name[0] ? dso->map->l_name : "app");

  return LA_FLG_BINDTO | (libstr ? 0 : LA_FLG_BINDFROM);
}

unsigned int
la_objclose(uintptr_t *cookie)
{
  struct dsohandle *dso = (struct dsohandle *) *cookie;
  if (!ok)
    return 0;

  /* ???  No more suitable place to do this.  */
  fflush (outf);

  /* Disable tracing again before we unload the main application.  */
  if (!dso->map->l_name[0])
    ok = 0;

  return 0;
}

void
la_preinit(uintptr_t *cookie)
{
  /* Start tracing.  */
  ok = 1;
}

uintptr_t
la_symbind64(Elf64_Sym *sym, unsigned int ndx,
	     uintptr_t *refcook, uintptr_t *defcook,
	     unsigned int *flags, const char *symname)
{
  struct dsohandle *dso = (struct dsohandle *) *defcook;

  *flags &= ~(LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT);

  if (ndx >= dso->nfns)
    {
      /* We should pre-allocate dso->fns from .dynsym */
      dso->fns = realloc (dso->fns, (ndx + 1) * (sizeof (struct fnentry)));
      memset (&dso->fns[dso->nfns], 0, (ndx + 1 - dso->nfns) * sizeof (struct fnentry));
      dso->nfns = ndx + 1;
#if 0
      fprintf (stderr, "symbind %s with too large index %d\n", symname, ndx);
      *flags |= LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT;
      return sym->st_value;
#endif
    }

  if (dso->fns[ndx].idx != ndx
      || sym->st_value != dso->fns[ndx].low_pc + dso->map->l_addr)
    {
      for (unsigned i = 0; i < dso->nfns; ++i)
	{
	  if (sym->st_value == dso->fns[i].low_pc + dso->map->l_addr)
	    {
	      /* Store index to be able to sort the table later in
		 la_preinit.  */
	      dso->fns[i].idx = ndx;
#if 0
	      fprintf (stderr, "symbind %s found at %d (%s)\n", symname, i,
		       dso->fns[i].name);
#endif
	      if (i != ndx)
		{
		  struct fnentry fn;
		  if (dso->fns[ndx].idx != 0)
		    fprintf (stderr, " double function!?\n");
		  fn = dso->fns[ndx];
		  dso->fns[ndx] = dso->fns[i];
		  dso->fns[i] = fn;
		}
	      return sym->st_value;
	    }
	}
    }
  else
    return sym->st_value;

  fprintf (stderr, "symbind %s with no debug at low_pc 0x%x\n", symname,
	   sym->st_value - dso->map->l_addr);
  *flags |= LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT;
  return sym->st_value;
}

static const char *
format_from_dwtype (struct dwtype *type)
{
  if (type->type_tag == DW_TAG_pointer_type
      || type->type_tag == DW_TAG_reference_type)
    return "%p";
  else if (type->type_tag == DW_TAG_base_type)
    {
      switch (type->type_encoding)
	{
	case DW_ATE_boolean:
	  return "%d";
	case DW_ATE_float:
	  if (type->type_byte_size > sizeof (double))
	    return "%Lg";
	  return "%g";
	case DW_ATE_signed:
	  if (type->type_byte_size > sizeof (long))
	    return "%lld";
	  else if (type->type_byte_size > sizeof (int))
	    return "%ld";
	  return "%d";
	case DW_ATE_unsigned:
	  if (type->type_byte_size > sizeof (long))
	    return "%llu";
	  else if (type->type_byte_size > sizeof (int))
	    return "%lu";
	  return "%u";
	case DW_ATE_signed_char:
	case DW_ATE_unsigned_char:
	  return "%c";
	}
    }

  return NULL;
}

static void
x86_64_print_arg (FILE *f, Dwarf_Op *regno, struct dwtype *type,
		  La_x86_64_regs *__regs)
{
  if (regno->atom == 0
      || type->type_tag == -1)
    fprintf (f, "???");
  else
    {
      const char *format = format_from_dwtype (type);
      if (!format)
	{
	  fprintf (f, "???");
	  return ;
	}
      switch (regno->atom)
	{
	case DW_OP_reg5:
	  fprintf (f, format, __regs->lr_rdi);
	  break;
	case DW_OP_reg4:
	  fprintf (f, format, __regs->lr_rsi);
	  break;
	case DW_OP_reg1:
	  fprintf (f, format, __regs->lr_rdx);
	  break;
	case DW_OP_reg2:
	  fprintf (f, format, __regs->lr_rcx);
	  break;
	case DW_OP_reg8:
	  fprintf (f, format, __regs->lr_r8);
	  break;
	case DW_OP_reg9:
	  fprintf (f, format, __regs->lr_r9);
	  break;
	case DW_OP_reg17:
	case DW_OP_reg18:
	case DW_OP_reg19:
	case DW_OP_reg20:
	case DW_OP_reg21:
	case DW_OP_reg22:
	case DW_OP_reg23:
	case DW_OP_reg24:
	  fprintf (f, format, __regs->lr_xmm[regno->atom - DW_OP_reg17]);
	  break;
	case DW_OP_fbreg:
	  fprintf (f, format, *(unsigned long * /* fixme? */)(__regs->lr_rsp + 8 /* return address */ + regno->number));
	  break;
	default:
	  fprintf (f, "(%d)0x%x",
		   type->type_tag, regno->atom); 
	}
    }
}

static int last_pltenter_p = 0;

Elf64_Addr
la_x86_64_gnu_pltenter (Elf64_Sym *__sym,
			unsigned int __ndx,
			uintptr_t *__refcook,
			uintptr_t *__defcook,
			La_x86_64_regs *__regs,
			unsigned int *__flags,
			const char *__symname,
			long int *__framesizep)
{
  if (!ok)
    return __sym->st_value;

  if (last_pltenter_p)
    fprintf (outf, "\n");
  last_pltenter_p = 1;

  struct dsohandle *dso = (struct dsohandle *) *__defcook;

  /* For calls not originating from the main executable print where
     it comes from and where it goes to.  */
  if (((struct dsohandle *) *__refcook)->map->l_name[0])
    fprintf (outf, "%s -> %s::",
	     ((struct dsohandle *) *__refcook)->map->l_name,
	     dso->map->l_name);

  if (__ndx >= dso->nfns
      || dso->fns[__ndx].idx != __ndx)
    fprintf (outf, "%s ???", __symname);
  else
    {
      fprintf (outf, "%s", __symname);
      if (dso->fns[__ndx].nargs != 0)
	{
	  fprintf (outf, "(");
	  for (int i = 0; i < dso->fns[__ndx].nargs; ++i)
	    {
	      if (i != 0)
		fprintf (outf, ", ");
	      x86_64_print_arg (outf, &dso->fns[__ndx].args[i].regno,
				&dso->fns[__ndx].args[i].type, __regs);
	    }
	  fprintf (outf, ")");
	}
      else
	fprintf (outf, "()");
    }

  /* No need to copy anything, we will not need the parameters in any case.  */
  *__framesizep = 0;

  return __sym->st_value;
}

unsigned int
la_x86_64_gnu_pltexit (Elf64_Sym *__sym,
		       unsigned int __ndx,
		       uintptr_t *__refcook,
		       uintptr_t *__defcook,
		       const La_x86_64_regs *__inregs,
		       La_x86_64_retval *__outregs,
		       const char *__symname)
{
  if (!ok)
    return 0;

  struct dsohandle *dso = (struct dsohandle *) *__defcook;
  if (__ndx >= dso->nfns
      || dso->fns[__ndx].idx != __ndx)
    {
      if (last_pltenter_p)
	fprintf (outf, "\n");
      last_pltenter_p = 0;
      return 0;
    }

  int type_tag = dso->fns[__ndx].type.type_tag;
  int type_encoding = dso->fns[__ndx].type.type_encoding;
  if (type_tag == DW_TAG_base_type
      && type_encoding == DW_ATE_void)
    {
      if (last_pltenter_p)
	fprintf (outf, "\n");
      last_pltenter_p = 0;
      return 0;
    }

  if (!last_pltenter_p)
    fprintf (outf, "%s() = ", __symname);
  else
    fprintf (outf, " = ");

  const char *format = format_from_dwtype (&dso->fns[__ndx].type);
  if (format)
    {
      if (type_tag == DW_TAG_pointer_type
	  || type_tag == DW_TAG_reference_type)
	fprintf (outf, format, __outregs->lrv_rax);
      else if (type_tag == DW_TAG_base_type)
	{
	  switch (type_encoding)
	    {
	    case DW_ATE_boolean:
	    case DW_ATE_signed:
	    case DW_ATE_unsigned:
	    case DW_ATE_signed_char:
	    case DW_ATE_unsigned_char:
	      fprintf (outf, format, __outregs->lrv_rax);
	      break;
	    case DW_ATE_float:
	      fprintf (outf, format, __outregs->lrv_xmm0);
	      break;
	    }
	}
      fprintf (outf, "\n");
    }
  else
    fprintf (outf, "???\n");

  last_pltenter_p = 0;
  return 0;
}
