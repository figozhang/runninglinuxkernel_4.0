/* Some kernels have split preparing and starting ring_buffers. */
#include <linux/types.h>
#include <linux/ring_buffer.h>

void foo (void)
{
  ring_buffer_read_prepare(NULL, 1);
}
