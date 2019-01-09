/* Some kernels have place holder recording of dropped events in the
   ring_buffer peek and consume calls. */
#include <linux/types.h>
#include <linux/ring_buffer.h>

struct ring_buffer_event *foo (void)
{
  /* last field is not always there */
  return ring_buffer_peek(NULL, 1, NULL, NULL);
}
