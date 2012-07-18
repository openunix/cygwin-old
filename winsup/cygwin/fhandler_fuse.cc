/* fhandler_mem.cc.  See fhandler.h for a description of the fhandler classes.

   Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009,
   2010, 2011 Red Hat, Inc.

   This file is part of Cygwin.

   This software is a copyrighted work licensed under the terms of the
   Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
   details. */
#ifndef DEBUGGING
#define DEBUGGING

#include "winsup.h"
#include <unistd.h>

#include "cygerrno.h"
#include "path.h"
#include "fhandler.h"
#include "dtable.h"
#include "cygheap.h"
#include "sigproc.h"
#include "ntdll.h"

#define CHECK_IN(fmt, args...)						\
  do {									\
    debug_only_printf(fmt, ## args);					\
  }while(0)

#define CHECK_OUT(fmt, args...)						\
  do {									\
    debug_only_printf(fmt, ## args);					\
  }while(0)

/**********************************************************************/
/* fhandler_dev_fuse */
inline PSECURITY_ATTRIBUTES
sec_user_cloexec (bool cloexec, PSECURITY_ATTRIBUTES sa, PSID sid)
{
  return cloexec ? sec_user_nih (sa, sid) : sec_user (sa, sid);
}

fhandler_dev_fuse::fhandler_dev_fuse ()
  : fhandler_base ()
{
}

fhandler_dev_fuse::~fhandler_dev_fuse ()
{
}

int
fhandler_dev_fuse::open (int flags, mode_t)
{
  DWORD open_mode = FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX;
  LPSECURITY_ATTRIBUTES sa_buf;
  char char_sa_buf[1024];
  sa_buf = sec_user_cloexec (flags & O_CLOEXEC, (PSECURITY_ATTRIBUTES) char_sa_buf,
			     cygheap->user.sid());
  if(fhandler_pipe::create(sa_buf, &handout, &handin, 0, NULL, open_mode)){
    small_printf("create of pipe failed");
    goto error;
  }

  set_io_handle(handout);
  debug_printf ("Set IO HANDLE OK.");
  return 1;
 error:
  __seterrno();
  return 0;
}
#if 0
ssize_t __stdcall
fhandler_dev_fuse::write (const void *ptr, size_t ulen)
{
  return 0;
}

void __stdcall
fhandler_dev_fuse::read (void *ptr, size_t& ulen)
{
  ulen = 0;
  return;
}
_off64_t
fhandler_dev_fuse::lseek (_off64_t offset, int whence)
{
  set_errno (ESPIPE);
  return ILLEGAL_SEEK;
}
#endif	// 0
int
fhandler_dev_fuse::fstat (struct __stat64 *buf)
{
  fhandler_base::fstat (buf);
  return 0;
}
#if 0
HANDLE
fhandler_dev_fuse::mmap (caddr_t *addr, size_t len, int prot,
			 int flags, _off64_t off)
{
  set_errno (ENODEV);
  return INVALID_HANDLE_VALUE;
}

int
fhandler_dev_fuse::munmap (HANDLE h, caddr_t addr, size_t len)
{
  set_errno (ENODEV);
  return -1;
}

int
fhandler_dev_fuse::msync (HANDLE h, caddr_t addr, size_t len, int flags)
{
  set_errno (ENODEV);
  return -1;
}

bool
fhandler_dev_fuse::fixup_mmap_after_fork (HANDLE h, int prot, int flags,
				      _off64_t offset, DWORD size,
				      void *address)
{
  set_errno (ENODEV);
  return -1;
}
#endif

fhandler_fs_fuse::fhandler_fs_fuse ()
  : fhandler_virtual ()
{
  CHECK_IN("NULL %s", "IN");
  CHECK_OUT("%d", 0);
}

fhandler_fs_fuse::~fhandler_fs_fuse ()
{
  CHECK_IN("NULL %s", "IN");
  CHECK_OUT("%d", 0);
}

int
fhandler_fs_fuse::open (int flags, mode_t mode)
{
  int ret = 1;

  CHECK_IN("(%x, %x)", flags, (unsigned int)mode);
  CHECK_OUT("(%d)", ret);
  return ret;
}

int
fhandler_fs_fuse::fstat (struct __stat64 *buf)
{
  int ret = 1;

  CHECK_IN("(%p)", buf);
  ret = fhandler_base::fstat (buf);
  CHECK_OUT("(%d)", ret);

  return ret;
}

int
fhandler_fs_fuse::mount (const char *in, char *out)
{
  int ret = 0;
  
  CHECK_IN("(%s, %p)", in, out);
  strncpy(out, in, CYG_MAX_PATH);
  out[CYG_MAX_PATH - 1] = '\0';
  CHECK_OUT("(%s, %d)", out, ret);
  return ret;
}

virtual_ftype_t
fhandler_fs_fuse::exists ()
{
  virtual_ftype_t ret = virt_rootdir;

  CHECK_IN("(%d)", ret);
  CHECK_OUT("(%d)", ret);

  return ret;
  
}
#endif	/* DEBUGGING */
