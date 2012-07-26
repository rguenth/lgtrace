/* Copyright (C) 2012  Richard Guenther.

   This file is part of lgtrace.

   lgtrace is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   lgtrace is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with lgtrace; see the file COPYING3.  If not see
   <http://www.gnu.org/licenses/>.  */

#include <elfutils/libdw.h>

struct dwtype {
  int type_tag;       /* DW_TAG_pointer_type or DW_TAG_base_type */
  int type_encoding;  /* DW_AT_encoding */
  int type_byte_size; /* DW_AT_byte_size */
};

struct fnarg {
  const char *name;
  struct dwtype type;
  Dwarf_Op regno;
};

struct fnentry {
  unsigned idx;
  uintptr_t low_pc;
  const char *name;
  struct dwtype type;
  unsigned nargs;
  struct fnarg *args; 
};

struct dsohandle {
  struct link_map *map;
  unsigned nfns;
  struct fnentry *fns;
};

int get_dwarf (struct dsohandle *) __attribute__((visibility("hidden")));
