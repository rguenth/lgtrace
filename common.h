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
