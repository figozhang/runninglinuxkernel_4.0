#include <linux/module.h>

unsigned long foobar(struct module_sect_attrs *moosas)
{
  struct module_sect_attr msa = moosas->attrs[0];
  return msa.address;
}
