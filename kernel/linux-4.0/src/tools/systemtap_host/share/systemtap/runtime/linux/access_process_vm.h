/*
 * The kernel's access_process_vm is not exported in kernel.org kernels, although
 * some distros export it on some architectures.  To workaround this inconsistency,
 * we copied and pasted it here.  Fortunately, everything it calls is exported.
 */
#include <linux/pagemap.h>
#include <asm/cacheflush.h>

static int
__access_process_vm_ (struct task_struct *tsk, unsigned long addr, void *buf,
		      int len, int write,
		      void (*writer) (struct vm_area_struct * vma,
				      struct page * page, unsigned long vaddr,
				      void *dst, void *src, int len),
		      void (*reader) (struct vm_area_struct * vma,
				      struct page * page, unsigned long vaddr,
				      void *dst, void *src, int len))
{
  struct mm_struct *mm;
  struct vm_area_struct *vma;
  struct page *page;
  void *old_buf = buf;

  mm = get_task_mm (tsk);
  if (!mm)
    return 0;

  down_read (&mm->mmap_sem);
  /* ignore errors, just check how much was successfully transferred */
  while (len)
    {
      int bytes, ret, offset;
      void *maddr;

      ret = get_user_pages (tsk, mm, addr, 1, write, 1, &page, &vma);
      if (ret <= 0)
	break;

      bytes = len;
      offset = addr & (PAGE_SIZE - 1);
      if (bytes > PAGE_SIZE - offset)
	bytes = PAGE_SIZE - offset;

      maddr = kmap (page);
      if (write)
	{
	  writer (vma, page, addr, maddr + offset, buf, bytes);
	  set_page_dirty_lock (page);
	}
      else
	{
	  reader (vma, page, addr, buf, maddr + offset, bytes);
	}
      kunmap (page);
      page_cache_release (page);
      len -= bytes;
      buf += bytes;
      addr += bytes;
    }
  up_read (&mm->mmap_sem);
  mmput (mm);

  return buf - old_buf;
}

static void
copy_to_user_page_ (struct vm_area_struct *vma, struct page *page,
		    unsigned long vaddr, void *dst, void *src, int len)
{
  copy_to_user_page (vma, page, vaddr, dst, src, len);
}

static void
copy_from_user_page_ (struct vm_area_struct *vma, struct page *page,
		      unsigned long vaddr, void *dst, void *src, int len)
{
  copy_from_user_page (vma, page, vaddr, dst, src, len);
}

static int
__access_process_vm (struct task_struct *tsk, unsigned long addr, void *buf,
		     int len, int write)
{
  return __access_process_vm_ (tsk, addr, buf, len, write, copy_to_user_page_,
			       copy_from_user_page_);
}

/*  This simpler version does not flush the caches.  */

static void
copy_to_user_page_noflush (struct vm_area_struct *vma, struct page *page,
			   unsigned long vaddr, void *dst, void *src, int len)
{
  memcpy (dst, src, len);
}

static void
copy_from_user_page_noflush (struct vm_area_struct *vma, struct page *page,
			     unsigned long vaddr, void *dst, void *src,
			     int len)
{
  memcpy (dst, src, len);
}

static int
__access_process_vm_noflush (struct task_struct *tsk, unsigned long addr,
			     void *buf, int len, int write)
{
  return __access_process_vm_ (tsk, addr, buf, len, write,
			       copy_to_user_page_noflush,
			       copy_from_user_page_noflush);
}
