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
#include <ctype.h>
#include <stdlib.h>

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

#define CHECK_DBG(fmt, args...)			\
  do {						\
    debug_only_printf(fmt, ## args);		\
  }while(0)

#define SMALL_PRINTF(fmt, args...)			\
  do {							\
    small_printf(fmt, ## args);				\
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

#define unlikely 

/*
 * Fake Linux Kernel Data Structures
 */
typedef unsigned __int64 __u64;
typedef unsigned __int64 u64;
typedef unsigned long __u32;
typedef unsigned long u32;

typedef unsigned short	u16, __u16;

typedef signed int	s32, __s32;
typedef signed long long s64, __s64;

struct super_block {
  struct fuse_conn *s_fs_info;
};

struct inode{
  struct super_block *i_sb;
};

struct qstr {
  unsigned int hash;
  unsigned int len;
  const unsigned char *name;
};

/*
 * From Linux Kernel include/linux/err.h
 */

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO 4095

#ifndef __ASSEMBLY__

#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
  return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long)ptr);
}

static inline long IS_ERR_OR_NULL(const void *ptr)
{
  return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

/**
 * ERR_CAST - Explicitly cast an error-valued pointer to another pointer type
 * @ptr: The pointer to cast.
 *
 * Explicitly cast an error-valued pointer to another pointer type in such a
 * way as to make it clear that's what's going on.
 */
static inline void *ERR_CAST(const void *ptr)
{
  /* cast away the const */
  return (void *) ptr;
}

#endif


/*
 * From Linux Kernel include/linux/fuse.h
 */

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

/** Version number of this interface */
#define FUSE_KERNEL_VERSION 7

/** Minor version number of this interface */
#define FUSE_KERNEL_MINOR_VERSION 13

/** The node ID of the root inode */
#define FUSE_ROOT_ID 1

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

struct fuse_attr {
	__u64	ino;
	__u64	size;
	__u64	blocks;
	__u64	atime;
	__u64	mtime;
	__u64	ctime;
	__u32	atimensec;
	__u32	mtimensec;
	__u32	ctimensec;
	__u32	mode;
	__u32	nlink;
	__u32	uid;
	__u32	gid;
	__u32	rdev;
	__u32	blksize;
	__u32	padding;
};

struct fuse_kstatfs {
	__u64	blocks;
	__u64	bfree;
	__u64	bavail;
	__u64	files;
	__u64	ffree;
	__u32	bsize;
	__u32	namelen;
	__u32	frsize;
	__u32	padding;
	__u32	spare[6];
};

struct fuse_file_lock {
	__u64	start;
	__u64	end;
	__u32	type;
	__u32	pid; /* tgid */
};

/**
 * Bitmasks for fuse_setattr_in.valid
 */
#define FATTR_MODE	(1 << 0)
#define FATTR_UID	(1 << 1)
#define FATTR_GID	(1 << 2)
#define FATTR_SIZE	(1 << 3)
#define FATTR_ATIME	(1 << 4)
#define FATTR_MTIME	(1 << 5)
#define FATTR_FH	(1 << 6)
#define FATTR_ATIME_NOW	(1 << 7)
#define FATTR_MTIME_NOW	(1 << 8)
#define FATTR_LOCKOWNER	(1 << 9)

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)

/**
 * INIT request/reply flags
 *
 * FUSE_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * FUSE_DONT_MASK: don't apply umask to file mode on create operations
 */
#define FUSE_ASYNC_READ		(1 << 0)
#define FUSE_POSIX_LOCKS	(1 << 1)
#define FUSE_FILE_OPS		(1 << 2)
#define FUSE_ATOMIC_O_TRUNC	(1 << 3)
#define FUSE_EXPORT_SUPPORT	(1 << 4)
#define FUSE_BIG_WRITES		(1 << 5)
#define FUSE_DONT_MASK		(1 << 6)

/**
 * CUSE INIT request/reply flags
 *
 * CUSE_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
#define CUSE_UNRESTRICTED_IOCTL	(1 << 0)

/**
 * Release flags
 */
#define FUSE_RELEASE_FLUSH	(1 << 0)

/**
 * Getattr flags
 */
#define FUSE_GETATTR_FH		(1 << 0)

/**
 * Lock flags
 */
#define FUSE_LK_FLOCK		(1 << 0)

/**
 * WRITE flags
 *
 * FUSE_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * FUSE_WRITE_LOCKOWNER: lock_owner field is valid
 */
#define FUSE_WRITE_CACHE	(1 << 0)
#define FUSE_WRITE_LOCKOWNER	(1 << 1)

/**
 * Read flags
 */
#define FUSE_READ_LOCKOWNER	(1 << 1)

/**
 * Ioctl flags
 *
 * FUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * FUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * FUSE_IOCTL_RETRY: retry with new iovecs
 *
 * FUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define FUSE_IOCTL_COMPAT	(1 << 0)
#define FUSE_IOCTL_UNRESTRICTED	(1 << 1)
#define FUSE_IOCTL_RETRY	(1 << 2)

#define FUSE_IOCTL_MAX_IOV	256

/**
 * Poll flags
 *
 * FUSE_POLL_SCHEDULE_NOTIFY: request poll notify
 */
#define FUSE_POLL_SCHEDULE_NOTIFY (1 << 0)

enum fuse_opcode {
	FUSE_LOOKUP	   = 1,
	FUSE_FORGET	   = 2,  /* no reply */
	FUSE_GETATTR	   = 3,
	FUSE_SETATTR	   = 4,
	FUSE_READLINK	   = 5,
	FUSE_SYMLINK	   = 6,
	FUSE_MKNOD	   = 8,
	FUSE_MKDIR	   = 9,
	FUSE_UNLINK	   = 10,
	FUSE_RMDIR	   = 11,
	FUSE_RENAME	   = 12,
	FUSE_LINK	   = 13,
	FUSE_OPEN	   = 14,
	FUSE_READ	   = 15,
	FUSE_WRITE	   = 16,
	FUSE_STATFS	   = 17,
	FUSE_RELEASE       = 18,
	FUSE_FSYNC         = 20,
	FUSE_SETXATTR      = 21,
	FUSE_GETXATTR      = 22,
	FUSE_LISTXATTR     = 23,
	FUSE_REMOVEXATTR   = 24,
	FUSE_FLUSH         = 25,
	FUSE_INIT          = 26,
	FUSE_OPENDIR       = 27,
	FUSE_READDIR       = 28,
	FUSE_RELEASEDIR    = 29,
	FUSE_FSYNCDIR      = 30,
	FUSE_GETLK         = 31,
	FUSE_SETLK         = 32,
	FUSE_SETLKW        = 33,
	FUSE_ACCESS        = 34,
	FUSE_CREATE        = 35,
	FUSE_INTERRUPT     = 36,
	FUSE_BMAP          = 37,
	FUSE_DESTROY       = 38,
	FUSE_IOCTL         = 39,
	FUSE_POLL          = 40,

	/* CUSE specific operations */
	CUSE_INIT          = 4096,
};

enum fuse_notify_code {
	FUSE_NOTIFY_POLL   = 1,
	FUSE_NOTIFY_INVAL_INODE = 2,
	FUSE_NOTIFY_INVAL_ENTRY = 3,
	FUSE_NOTIFY_CODE_MAX,
};

/* The read buffer is required to be at least 8k, but may be much larger */
#define FUSE_MIN_READ_BUFFER 8192

#define FUSE_COMPAT_ENTRY_OUT_SIZE 120

struct fuse_entry_out {
	__u64	nodeid;		/* Inode ID */
	__u64	generation;	/* Inode generation: nodeid:gen must
				   be unique for the fs's lifetime */
	__u64	entry_valid;	/* Cache timeout for the name */
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	entry_valid_nsec;
	__u32	attr_valid_nsec;
	struct fuse_attr attr;
};

struct fuse_forget_in {
	__u64	nlookup;
};

struct fuse_getattr_in {
	__u32	getattr_flags;
	__u32	dummy;
	__u64	fh;
};

#define FUSE_COMPAT_ATTR_OUT_SIZE 96

struct fuse_attr_out {
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	attr_valid_nsec;
	__u32	dummy;
	struct fuse_attr attr;
};

#define FUSE_COMPAT_MKNOD_IN_SIZE 8

struct fuse_mknod_in {
	__u32	mode;
	__u32	rdev;
	__u32	umask;
	__u32	padding;
};

struct fuse_mkdir_in {
	__u32	mode;
	__u32	umask;
};

struct fuse_rename_in {
	__u64	newdir;
};

struct fuse_link_in {
	__u64	oldnodeid;
};

struct fuse_setattr_in {
	__u32	valid;
	__u32	padding;
	__u64	fh;
	__u64	size;
	__u64	lock_owner;
	__u64	atime;
	__u64	mtime;
	__u64	unused2;
	__u32	atimensec;
	__u32	mtimensec;
	__u32	unused3;
	__u32	mode;
	__u32	unused4;
	__u32	uid;
	__u32	gid;
	__u32	unused5;
};

struct fuse_open_in {
	__u32	flags;
	__u32	unused;
};

struct fuse_create_in {
	__u32	flags;
	__u32	mode;
	__u32	umask;
	__u32	padding;
};

struct fuse_open_out {
	__u64	fh;
	__u32	open_flags;
	__u32	padding;
};

struct fuse_release_in {
	__u64	fh;
	__u32	flags;
	__u32	release_flags;
	__u64	lock_owner;
};

struct fuse_flush_in {
	__u64	fh;
	__u32	unused;
	__u32	padding;
	__u64	lock_owner;
};

struct fuse_read_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	read_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

#define FUSE_COMPAT_WRITE_IN_SIZE 24

struct fuse_write_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	write_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

struct fuse_write_out {
	__u32	size;
	__u32	padding;
};

#define FUSE_COMPAT_STATFS_SIZE 48

struct fuse_statfs_out {
	struct fuse_kstatfs st;
};

struct fuse_fsync_in {
	__u64	fh;
	__u32	fsync_flags;
	__u32	padding;
};

struct fuse_setxattr_in {
	__u32	size;
	__u32	flags;
};

struct fuse_getxattr_in {
	__u32	size;
	__u32	padding;
};

struct fuse_getxattr_out {
	__u32	size;
	__u32	padding;
};

struct fuse_lk_in {
	__u64	fh;
	__u64	owner;
	struct fuse_file_lock lk;
	__u32	lk_flags;
	__u32	padding;
};

struct fuse_lk_out {
	struct fuse_file_lock lk;
};

struct fuse_access_in {
	__u32	mask;
	__u32	padding;
};

struct fuse_init_in {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
};

struct fuse_init_out {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
	__u16   max_background;
	__u16   congestion_threshold;
	__u32	max_write;
};

#define CUSE_INIT_INFO_MAX 4096

struct cuse_init_in {
	__u32	major;
	__u32	minor;
	__u32	unused;
	__u32	flags;
};

struct cuse_init_out {
	__u32	major;
	__u32	minor;
	__u32	unused;
	__u32	flags;
	__u32	max_read;
	__u32	max_write;
	__u32	dev_major;		/* chardev major */
	__u32	dev_minor;		/* chardev minor */
	__u32	spare[10];
};

struct fuse_interrupt_in {
	__u64	unique;
};

struct fuse_bmap_in {
	__u64	block;
	__u32	blocksize;
	__u32	padding;
};

struct fuse_bmap_out {
	__u64	block;
};

struct fuse_ioctl_in {
	__u64	fh;
	__u32	flags;
	__u32	cmd;
	__u64	arg;
	__u32	in_size;
	__u32	out_size;
};

struct fuse_ioctl_out {
	__s32	result;
	__u32	flags;
	__u32	in_iovs;
	__u32	out_iovs;
};

struct fuse_poll_in {
	__u64	fh;
	__u64	kh;
	__u32	flags;
	__u32   padding;
};

struct fuse_poll_out {
	__u32	revents;
	__u32	padding;
};

struct fuse_notify_poll_wakeup_out {
	__u64	kh;
};

struct fuse_in_header {
	__u32	len;
	__u32	opcode;
	__u64	unique;
	__u64	nodeid;
	__u32	uid;
	__u32	gid;
	__u32	pid;
	__u32	padding;
};

struct fuse_out_header {
	__u32	len;
	__s32	error;
	__u64	unique;
};

struct fuse_dirent {
	__u64	ino;
	__u64	off;
	__u32	namelen;
	__u32	type;
	char name[0];
};

#define FUSE_NAME_OFFSET offsetof(struct fuse_dirent, name)
#define FUSE_DIRENT_ALIGN(x) (((x) + sizeof(__u64) - 1) & ~(sizeof(__u64) - 1))
#define FUSE_DIRENT_SIZE(d) \
	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

struct fuse_notify_inval_inode_out {
	__u64	ino;
	__s64	off;
	__s64	len;
};

struct fuse_notify_inval_entry_out {
	__u64	parent;
	__u32	namelen;
	__u32	padding;
};



/*
 * From Linux Kernel fs/fuse/fuse_i.h
 */
/** Max number of pages that can be used in a single read request */
#define FUSE_MAX_PAGES_PER_REQ 32

/** Bias for fi->writectr, meaning new writepages must not be sent */
#define FUSE_NOWRITE INT_MIN

/** It could be as large as PATH_MAX, but would that have any uses? */
#define FUSE_NAME_MAX 1024

/** Number of dentries for each connection in the control filesystem */
#define FUSE_CTL_NUM_DENTRIES 5

/** If the FUSE_DEFAULT_PERMISSIONS flag is given, the filesystem
    module will check permissions based on the file mode.  Otherwise no
    permission checking is done in the kernel */
#define FUSE_DEFAULT_PERMISSIONS (1 << 0)

/** If the FUSE_ALLOW_OTHER flag is given, then not only the user
    doing the mount will be allowed to access the filesystem */
#define FUSE_ALLOW_OTHER         (1 << 1)

/** List of active connections */
extern struct list_head fuse_conn_list;

/** Global mutex protecting fuse_conn_list and the control filesystem */
extern struct mutex fuse_mutex;

/** Module parameters */
extern unsigned max_user_bgreq;
extern unsigned max_user_congthresh;

/** FUSE inode */
struct fuse_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct fuse_req *forget_req;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	mode_t orig_i_mode;

	/** Version of last attribute change */
	u64 attr_version;
#if 0
	/** Files usable in writepage.  Protected by fc->lock */
	struct list_head write_files;

	/** Writepages pending on truncate or fsync */
	struct list_head queued_writes;

	/** Number of sent writes, a negative bias (FUSE_NOWRITE)
	 * means more writes are blocked */
	int writectr;

	/** Waitq for writepage completion */
	wait_queue_head_t page_waitq;

	/** List of writepage requestst (pending or sent) */
	struct list_head writepages;
#endif
};

struct fuse_conn;

/** FUSE specific file data */
struct fuse_file {
	/** Fuse connection for this file */
	struct fuse_conn *fc;

	/** Request reserved for flush and release */
	struct fuse_req *reserved_req;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

  struct fuse_attr attr;
#if 0
	/** Refcount */
	atomic_t count;
#endif
	/** FOPEN_* flags returned by open */
	u32 open_flags;
#if 0
	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/** RB node to be linked on fuse_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;
#endif
};

/** One input argument of a request */
struct fuse_in_arg {
	unsigned size;
	const void *value;
};

/** The request input */
struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** One output argument of a request */
struct fuse_arg {
	unsigned size;
	void *value;
};

/** The request output */
struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/*
	 * The following bitfields are not changed during the request
	 * processing
	 */

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;

	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;

	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_arg args[3];
};

/** The request state */
enum fuse_req_state {
	FUSE_REQ_INIT = 0,
	FUSE_REQ_PENDING,
	FUSE_REQ_READING,
	FUSE_REQ_SENT,
	FUSE_REQ_WRITING,
	FUSE_REQ_FINISHED
};

/**
 * A request to the client
 */
struct fuse_req {
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;
#if 0
	/** refcount */
	atomic_t count;
#endif

	/** Unique ID for the interrupt request */
	u64 intr_unique;

	/*
	 * The following bitfields are either set once before the
	 * request is queued or setting/clearing them is protected by
	 * fuse_conn->lock
	 */

	/** True if the request has reply */
	unsigned isreply:1;

	/** Force sending of the request even if interrupted */
	unsigned force:1;

	/** The request was aborted */
	unsigned aborted:1;

	/** Request is sent in the background */
	unsigned background:1;

	/** The request has been interrupted */
	unsigned interrupted:1;

	/** Data is being copied to/from the request */
	unsigned locked:1;

	/** Request is counted as "waiting" */
	unsigned waiting:1;

	/** State of the request */
	enum fuse_req_state state;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;
#if 0
	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;
#endif
	/** Data for asynchronous requests */
	union {
#if 0
		struct fuse_forget_in forget_in;
		struct {
			union {
				struct fuse_release_in in;
				struct work_struct work;
			};
			struct path path;
		} release;
#endif
		struct fuse_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct cuse_init_out cuse_init_out;
		struct {
			struct fuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
		} write;
		struct fuse_lk_in lk_in;
	} misc;

	/** page vector */
	struct page *pages[FUSE_MAX_PAGES_PER_REQ];

	/** number of pages in vector */
	unsigned num_pages;

	/** offset of data on first page */
	unsigned page_offset;

	/** File used in the request (or NULL) */
	struct fuse_file *ff;

	/** Inode used in the request or NULL */
	struct inode *inode;
#if 0
	/** Link on fi->writepages */
	struct list_head writepages_entry;
#endif

	/** Request completion callback */
	void (*end)(struct fuse_conn *, struct fuse_req *);
#if 0
	/** Request is stolen from fuse_file->reserved_req */
	struct file *stolen_file;
#endif
};

/**
 * A Fuse connection.
 *
 * This structure is created, when the filesystem is mounted, and is
 * destroyed, when the client device is closed and the filesystem is
 * unmounted.
 */
struct fuse_conn {
#if 0
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Mutex protecting against directory alias creation */
	struct mutex inst_mutex;

	/** Refcount */
	atomic_t count;

	/** The user id for this mount */
	uid_t user_id;

	/** The group id for this mount */
	gid_t group_id;

	/** The fuse mount flags for this mount */
	unsigned flags;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The list of pending requests */
	struct list_head pending;

	/** The list of requests being processed */
	struct list_head processing;

	/** The list of requests under I/O */
	struct list_head io;

	/** The next unique kernel file handle */
	u64 khctr;

	/** rbtree of fuse_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of background requests at which congestion starts */
	unsigned congestion_threshold;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** waitq for reserved requests */
	wait_queue_head_t reserved_req_waitq;

	/** The next unique request id */
	u64 reqctr;
#endif
	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;
  HANDLE h;
#if 0
	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readpages asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** Set if bdi is valid */
	unsigned bdi_initialized:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
  unsigned dont_mask:1;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;
#endif
	/** Negotiated minor version */
	unsigned minor;
#if 0
	/** Backing dev info */
	struct backing_dev_info bdi;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** Device ID from super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[FUSE_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;
#endif
	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Reserved request for the DESTROY message */
	struct fuse_req *destroy_req;

	/** Version counter for attribute changes */
	u64 attr_version;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

	/** Super block for this connection. */
	struct super_block *sb;

  struct inode *sticky_inode;
#if 0
	/** Read/write semaphore to hold when accessing sb. */
	struct rw_semaphore killsb;

#endif 
};

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

/*
 * From Linux Kernel fs/fuse/dev.c
 */
static void fuse_request_init(struct fuse_req *req)
{
}
struct fuse_req *fuse_request_alloc(void)
{
  struct fuse_req *req = (struct fuse_req *)malloc(sizeof(struct fuse_req));
	if (req)
		fuse_request_init(req);
	return req;
}

void fuse_request_free(struct fuse_req *req)
{
  free(req);
}

struct fuse_req *fuse_get_req(struct fuse_conn *fc)
{
  return fuse_request_alloc();
}

void fuse_put_request(struct fuse_conn *fc, struct fuse_req *req)
{
			fuse_request_free(req);
}

/*
 * The error coding system:
 *	< 0 - Linux kernel style error
 *	> 0 - Windows style error
 *	= 0 - No error
 */
static int
fuse_trans_one(struct fuse_conn *fc, void *val, unsigned size,
	       int send)
{
  DWORD rsize;
  int ret = 0;

  CHECK_IN("(%p, %p, %d, %s)", fc, val, size, send ? "send" : "recv");
  if (!fc || !fc->connected){
    ret = -EINVAL;
    goto out;
  }

  /* XXX Should we use loop here? */
  while (size){
    if (send)
      ret = WriteFile(fc->h, val, size, &rsize, NULL);
    else
      ret = ReadFile(fc->h, val, size, &rsize, NULL);
    if (!ret){
      ret = GetLastError();
      goto out;
    }
    CHECK_DBG("Want %d while get %d", size, rsize);
    size -= rsize;
  }
 
 out:
  CHECK_OUT("(%d)", ret);
  return ret;
}

static int
fuse_trans_args(struct fuse_conn *fc, unsigned numargs,
		struct fuse_arg *args, int send)
{
  int err = 0;
  unsigned i;
  
  CHECK_IN("(%p, %d, %p, %s)", fc, numargs, args, send ? "send" : "recv");
  
  for (i = 0; i < numargs; i++)  {
    struct fuse_arg *arg = &args[i];
    err = fuse_trans_one(fc, arg->value, arg->size, send);
    if (err)
      goto out;
  }

 out:
  CHECK_OUT("(%d)", err);
  return err;
}

static int
fuse_send_req(struct fuse_conn *fc, struct fuse_req *req)
{
  struct fuse_in *in = &req->in;
  int err = 0;
  
  CHECK_IN("(%p, %p, %p)", fc, req, in);

  err = fuse_trans_one(fc, &in->h, sizeof(in->h), 1);
  if (!err)
    err = fuse_trans_args(fc, in->numargs, (struct fuse_arg *)in->args, 1);
  
  
  CHECK_OUT("(%d)", err);
  return err;
}

static int
fuse_recv_req(struct fuse_conn *fc, struct fuse_req *req)
{
  int err = 0;
  struct fuse_out *out = &req->out;
  

  err = fuse_trans_one(fc, &out->h, sizeof(out->h), 0);

  if (!err)
    err = fuse_trans_args(fc, out->numargs, (struct fuse_arg *)out->args, 0);

  return err;
			  
}

static int
fuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
  int err = 0;

  err = fuse_send_req(fc, req);
  if (err)
    goto out;
  err = fuse_recv_req(fc, req);


 out:
  return err;
}
#if 0
static void fuse_request_send_nowait(struct fuse_conn *fc, struct fuse_req *req)
{
	spin_lock(&fc->lock);
	if (fc->connected) {
		fuse_request_send_nowait_locked(fc, req);
		spin_unlock(&fc->lock);
	} else {
		req->out.h.error = -ENOTCONN;
		request_end(fc, req);
	}
}

static void fuse_request_send_noreply(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 0;
	fuse_request_send_nowait(fc, req);
}

static void
fuse_request_send_background(struct fuse_conn *fc, struct fuse_req *req)
{
	req->isreply = 1;
	fuse_request_send_nowait(fc, req);
}
#endif
/* The following is stolen from Linux kernel dir.c*/

static void fuse_lookup_init(struct fuse_conn *fc, struct fuse_req *req,
			     u64 nodeid, struct qstr *name,
			     struct fuse_entry_out *outarg)
{
	memset(outarg, 0, sizeof(struct fuse_entry_out));
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.nodeid = nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = name->len + 1;
	req->in.args[0].value = name->name;
	req->out.numargs = 1;
#if 0
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
#endif
		req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
}

u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	/*
	 * The spin lock isn't actually needed on 64bit archs, but we
	 * don't yet care too much about such optimizations.
	 */
	//	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	//	spin_unlock(&fc->lock);

	return curr_version;
}


/*
 * The following is stolen from Linux Kernel inode.c
 */

#define simple_strtoul strtoul
#define simple_strtol strtol
#define strlen (signed)strlen

/* associates an integer enumerator with a pattern string. */
struct match_token {
	int token;
	const char *pattern;
};

typedef struct match_token match_table_t[];

/* Maximum number of arguments that match_token will find in a pattern */
enum {MAX_OPT_ARGS = 3};

/* Describe the location within a string of a substring */
typedef struct {
	char *from;
	char *to;
} substring_t;

int match_token(char *, const match_table_t table, substring_t args[]);
int match_string(substring_t *s, const char *str);
int match_int(substring_t *, int *result);
int match_octal(substring_t *, int *result);
int match_hex(substring_t *, int *result);
size_t match_strlcpy(char *, const substring_t *, size_t);

/**
 * match_one: - Determines if a string matches a simple pattern
 * @s: the string to examine for presense of the pattern
 * @p: the string containing the pattern
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Determines if the pattern @p is present in string @s. Can only
 * match extremely simple token=arg style patterns. If the pattern is found,
 * the location(s) of the arguments will be returned in the @args array.
 */
static int match_one(char *s, const char *p, substring_t args[])
{
	char *meta;
	int argc = 0;

	if (!p)
		return 1;

	while(1) {
		int len = -1;
		meta = strchr(p, '%');
		if (!meta)
			return strcmp(p, s) == 0;

		if (strncmp(p, s, meta-p))
			return 0;

		s += meta - p;
		p = meta + 1;

		if (isdigit(*p))
			len = simple_strtoul(p, (char **) &p, 10);
		else if (*p == '%') {
			if (*s++ != '%')
				return 0;
			p++;
			continue;
		}

		if (argc >= MAX_OPT_ARGS)
			return 0;

		args[argc].from = s;
		switch (*p++) {
		case 's':
			if (strlen(s) == 0)
				return 0;
			else if (len == -1 || len > strlen(s))
				len = strlen(s);
			args[argc].to = s + len;
			break;
		case 'd':
			simple_strtol(s, &args[argc].to, 0);
			goto num;
		case 'u':
			simple_strtoul(s, &args[argc].to, 0);
			goto num;
		case 'o':
			simple_strtoul(s, &args[argc].to, 8);
			goto num;
		case 'x':
			simple_strtoul(s, &args[argc].to, 16);
		num:
			if (args[argc].to == args[argc].from)
				return 0;
			break;
		default:
			return 0;
		}
		s = args[argc].to;
		argc++;
	}
}

/**
 * match_token: - Find a token (and optional args) in a string
 * @s: the string to examine for token/argument pairs
 * @table: match_table_t describing the set of allowed option tokens and the
 * arguments that may be associated with them. Must be terminated with a
 * &struct match_token whose pattern is set to the NULL pointer.
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Detects which if any of a set of token strings has been passed
 * to it. Tokens can include up to MAX_OPT_ARGS instances of basic c-style
 * format identifiers which will be taken into account when matching the
 * tokens, and whose locations will be returned in the @args array.
 */
int match_token(char *s, const match_table_t table, substring_t args[])
{
	const struct match_token *p;

	for (p = table; !match_one(s, p->pattern, args) ; p++)
		;

	return p->token;
}

/**
 * match_string: check for a particular parameter
 * @s: substring to be scanned
 * @str: string to scan for
 *
 * Description: Return if a &substring_t is equal to string @str.
 */
int match_string(substring_t *s, const char *str)
{
	return strlen(str) == s->to - s->from &&
	       !memcmp(str, s->from, s->to - s->from);
}

/**
 * match_number: scan a number in the given base from a substring_t
 * @s: substring to be scanned
 * @result: resulting integer on success
 * @base: base to use when converting string
 *
 * Description: Given a &substring_t and a base, attempts to parse the substring
 * as a number in that base. On success, sets @result to the integer represented
 * by the string and returns 0. Returns either -ENOMEM or -EINVAL on failure.
 */
static int match_number(substring_t *s, int *result, int base)
{
	char *endp;
	int ret;
	char buf[s->to - s->from + 1];

	memcpy(buf, s->from, s->to - s->from);
	buf[s->to - s->from] = '\0';
	*result = simple_strtol(buf, &endp, base);
	ret = 0;
	if (endp == buf)
		ret = -EINVAL;

	return ret;
}

/**
 * match_int: - scan a decimal representation of an integer from a substring_t
 * @s: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Description: Attempts to parse the &substring_t @s as a decimal integer. On
 * success, sets @result to the integer represented by the string and returns 0.
 * Returns either -ENOMEM or -EINVAL on failure.
 */
int match_int(substring_t *s, int *result)
{
	return match_number(s, result, 0);
}

/**
 * match_octal: - scan an octal representation of an integer from a substring_t
 * @s: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Description: Attempts to parse the &substring_t @s as an octal integer. On
 * success, sets @result to the integer represented by the string and returns
 * 0. Returns either -ENOMEM or -EINVAL on failure.
 */
int match_octal(substring_t *s, int *result)
{
	return match_number(s, result, 8);
}

/**
 * match_hex: - scan a hex representation of an integer from a substring_t
 * @s: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Description: Attempts to parse the &substring_t @s as a hexadecimal integer.
 * On success, sets @result to the integer represented by the string and
 * returns 0. Returns either -ENOMEM or -EINVAL on failure.
 */
int match_hex(substring_t *s, int *result)
{
	return match_number(s, result, 16);
}

/**
 * match_strlcpy: - Copy the characters from a substring_t to a sized buffer
 * @dest: where to copy to
 * @src: &substring_t to copy
 * @size: size of destination buffer
 *
 * Description: Copy the characters in &substring_t @src to the
 * c-style string @dest.  Copy no more than @size - 1 characters, plus
 * the terminating NUL.  Return length of @src.
 */
size_t match_strlcpy(char *dest, const substring_t *src, size_t size)
{
	size_t ret = src->to - src->from;

	if (size) {
		size_t len = ret >= size ? size - 1 : ret;
		memcpy(dest, src->from, len);
		dest[len] = '\0';
	}
	return ret;
}

#if 0
static void fuse_free_conn(struct fuse_conn *fc)
{
	free(fc);
}
#endif

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}


#define FUSE_SUPER_MAGIC 0x65735546

#define FUSE_DEFAULT_BLKSIZE 512

/** Maximum number of outstanding background requests */
#define FUSE_DEFAULT_MAX_BACKGROUND 12

/** Congestion starts at 75% of maximum */
#define FUSE_DEFAULT_CONGESTION_THRESHOLD (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4)


struct fuse_mount_data {
	int fd;
	unsigned rootmode;
	unsigned user_id;
	unsigned group_id;
	unsigned fd_present:1;
	unsigned rootmode_present:1;
	unsigned user_id_present:1;
	unsigned group_id_present:1;
	unsigned flags;
	unsigned max_read;
	unsigned blksize;
};

enum {
	OPT_FD,
	OPT_ROOTMODE,
	OPT_USER_ID,
	OPT_GROUP_ID,
	OPT_DEFAULT_PERMISSIONS,
	OPT_ALLOW_OTHER,
	OPT_MAX_READ,
	OPT_BLKSIZE,
	OPT_ERR
};

static const match_table_t tokens = {
	{OPT_FD,			"fd=%u"},
	{OPT_ROOTMODE,			"rootmode=%o"},
	{OPT_USER_ID,			"user_id=%u"},
	{OPT_GROUP_ID,			"group_id=%u"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_ALLOW_OTHER,		"allow_other"},
	{OPT_MAX_READ,			"max_read=%u"},
	{OPT_BLKSIZE,			"blksize=%u"},
	{OPT_ERR,			NULL}
};

static int parse_fuse_opt(char *opt, struct fuse_mount_data *d, int is_bdev)
{
	char *p;
	memset(d, 0, sizeof(struct fuse_mount_data));
	d->max_read = ~0;
	d->blksize = FUSE_DEFAULT_BLKSIZE;

	while ((p = strsep(&opt, ",")) != NULL) {
		int token;
		int value;
		substring_t args[MAX_OPT_ARGS];
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case OPT_FD:
			if (match_int(&args[0], &value))
				return 0;
			d->fd = value;
			d->fd_present = 1;
			break;

		case OPT_ROOTMODE:
			if (match_octal(&args[0], &value))
				return 0;
			if (!fuse_valid_type(value))
				return 0;
			d->rootmode = value;
			d->rootmode_present = 1;
			break;

		case OPT_USER_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->user_id = value;
			d->user_id_present = 1;
			break;

		case OPT_GROUP_ID:
			if (match_int(&args[0], &value))
				return 0;
			d->group_id = value;
			d->group_id_present = 1;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			d->flags |= FUSE_DEFAULT_PERMISSIONS;
			break;

		case OPT_ALLOW_OTHER:
			d->flags |= FUSE_ALLOW_OTHER;
			break;

		case OPT_MAX_READ:
			if (match_int(&args[0], &value))
				return 0;
			d->max_read = value;
			break;

		case OPT_BLKSIZE:
			if (!is_bdev || match_int(&args[0], &value))
				return 0;
			d->blksize = value;
			break;

		default:
			return 0;
		}
	}

	if (!d->fd_present || !d->rootmode_present ||
	    !d->user_id_present || !d->group_id_present)
		return 0;

	return 1;
}

static void fuse_init_init(struct fuse_req *req)
{
	struct fuse_init_in *arg = &req->misc.init_in;

	arg->major = FUSE_KERNEL_VERSION;
	arg->minor = FUSE_KERNEL_MINOR_VERSION;
#if 0
	arg->max_readahead = fc->bdi.ra_pages * PAGE_CACHE_SIZE;
#endif
	arg->flags |= FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_ATOMIC_O_TRUNC |
		FUSE_EXPORT_SUPPORT | FUSE_BIG_WRITES | FUSE_DONT_MASK;
	req->in.h.opcode = FUSE_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*arg);
	req->in.args[0].value = arg;
	req->out.numargs = 1;
	/* Variable length arguement used for backward compatibility
	   with interface version < 7.5.  Rest of init_out is zeroed
	   by do_get_request(), so a short reply is not a problem */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(struct fuse_init_out);
	req->out.args[0].value = &req->misc.init_out;
#if 0
	req->end = process_init_reply;
	fuse_request_send_background(fc, req);
#endif
}


static int
fuse_lookup_name(struct super_block *sb, u64 nodeid, struct qstr *name,
		     struct fuse_entry_out *outarg, struct inode **inode)
{
	struct fuse_conn *fc = get_fuse_conn_super(sb);
	struct fuse_req *req;
	struct fuse_req *forget_req;
	u64 attr_version;
	int err;

	if (inode)
	  *inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX)
		goto out;

	req = fuse_get_req(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	forget_req = fuse_get_req(fc);
	err = PTR_ERR(forget_req);
	if (IS_ERR(forget_req)) {
		fuse_put_request(fc, req);
		goto out;
	}

	attr_version = fuse_get_attr_version(fc);

	fuse_lookup_init(fc, req, nodeid, name, outarg);
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if (err || !outarg->nodeid)
		goto out_put_forget;

	err = -EIO;
	if (!outarg->nodeid)
		goto out_put_forget;
	if (!fuse_valid_type(outarg->attr.mode))
		goto out_put_forget;

	if (inode){
#if 0
	  *inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			     &outarg->attr, entry_attr_timeout(outarg),
			     attr_version);
	  err = -ENOMEM;
	  if (!*inode) {
	    fuse_send_forget(fc, forget_req, outarg->nodeid, 1);
	    goto out;
	  }
#endif
	}
	err = 0;

 out_put_forget:
	fuse_put_request(fc, forget_req);
 out:
	return err;
}

static int
fuse_lookup_path(struct fuse_conn *fc, const char *path,
		 struct fuse_entry_out *outarg)
{
  const unsigned char *cur = (const unsigned char *)path;
  struct super_block s;
  struct qstr name;
  int ret = 0;
  u64 nodeid = FUSE_ROOT_ID;

  CHECK_IN("(%s)", path);

  if (!*path)
    return EINVAL;

  s.s_fs_info = fc;
  do {
    while (*cur == '/') cur++;
    name.name = cur;
    while (*cur && *cur != '/') cur++;
    name.len = cur - name.name;
    ret = fuse_lookup_name(&s, nodeid, &name, outarg, NULL);
    if (ret)
      goto out;
    nodeid = outarg->nodeid;
  }while (*cur);

 out:
  CHECK_OUT("(%d)", ret);
  return ret;
}

static struct fuse_file *
fuse_file_alloc(struct fuse_conn *fc)
{
  struct fuse_file *ff;

  ff = (struct fuse_file *)malloc(sizeof(struct fuse_file));
  if (!ff)
    return NULL;

  ff->fc = fc;
  ff->reserved_req = fuse_request_alloc();
  if (!ff->reserved_req) {
    free(ff);
    return NULL;
  }

  return ff;
}

static void
fuse_file_update(struct fuse_file *ff, struct fuse_attr_out *out)
{
  ff->attr = out->attr;
}

static void
fuse_fillattr(struct fuse_attr *attr, __stat64 *stat)
{
  stat->st_ino = attr->ino;
  stat->st_mode = attr->mode & 07777;
  stat->st_nlink = attr->nlink;
  stat->st_uid = attr->uid;
  stat->st_gid = attr->gid;
  stat->st_atim.tv_sec = attr->atime;
  stat->st_atim.tv_nsec = attr->atimensec;
  stat->st_mtim.tv_sec = attr->mtime;
  stat->st_mtim.tv_nsec = attr->mtimensec;
  stat->st_ctim.tv_sec = attr->ctime;
  stat->st_ctim.tv_nsec = attr->ctimensec;
  stat->st_size = attr->size;
  stat->st_blocks = attr->blocks;
}


static int
fuse_do_getattr(struct fuse_file *ff, int opened_file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = ff->fc;
	struct fuse_req *req;
	u64 attr_version;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (opened_file && S_ISREG(ff->attr.mode)) {
		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
#if 0
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
#endif
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	fuse_file_update(ff, &outarg);

	return err;
}

fhandler_fs_fuse::fhandler_fs_fuse ()
  : fhandler_virtual (), path_conv_off(0), ff(NULL)
{
  CHECK_IN("NULL %s", "IN");
  CHECK_OUT("%d", 0);
}

void fuse_file_free(struct fuse_file *ff)
{
	fuse_request_free(ff->reserved_req);
	free(ff);
}

fhandler_fs_fuse::~fhandler_fs_fuse ()
{
  CHECK_IN("NULL %s", "IN");
  fuse_file_free(ff);
  CHECK_OUT("%d", 0);
}

static int
fuse_send_open(struct fuse_conn *fc, struct fuse_file *ff, int flags,
	       int opcode, struct fuse_open_out *outargp)
{
	struct fuse_open_in inarg;
	struct fuse_req *req;
	int err;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
#if 0
	if (!fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;
#endif
	req->in.h.opcode = opcode;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(*outargp);
	req->out.args[0].value = outargp;
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);

	return err;
}

static int
fuse_do_open(struct fuse_file *ff, int flags, mode_t mode, int isdir)
{
  struct fuse_conn *fc = ff->fc;
	struct fuse_open_out outarg;
	int err;
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;

	err = fuse_send_open(fc, ff, flags, opcode, &outarg);
	if (err) {
		return err;
	}

	if (isdir)
		outarg.open_flags &= ~FOPEN_DIRECT_IO;

	ff->fh = outarg.fh;
	ff->open_flags = outarg.open_flags;

	return 0;
}

int
fhandler_fs_fuse::open (int flags, mode_t mode)
{
  virtual_ftype_t vft = virt_rootdir;
  int ret = 1;

  CHECK_IN("(%x, %x)", flags, (unsigned int)mode);

  ret = fhandler_virtual::open(flags, mode);
  if (!ret)
    goto out;

  if (!ff || !ff->nodeid)
    vft = exists();
  if (vft == virt_none){
    set_errno(ENOENT);
    goto out;
  }

  ret = fuse_do_open(ff, flags, mode, 0);
  if (ret){
    set_errno(ret);
    ret = 0;
    goto out;
  }

  set_open_status();
  ret = 1;

 out:
  CHECK_OUT("(%d)", ret);
  return ret;
}

int
fhandler_fs_fuse::fstat (struct __stat64 *buf)
{
  virtual_ftype_t vft = virt_rootdir;
  int ret = -1;
  
  CHECK_IN("(%p)", buf);

  /* We need the st_dev from super */
  ret = fhandler_base::fstat(buf);
  if (ret)
    goto out;

  /* Double check, exists() should already be called before this. */
  if (!ff || !ff->nodeid)
    vft = exists();
  if (vft == virt_none){
    set_errno(ENOENT);
    goto out;
  }

  if (vft == virt_rootdir){
    ret  = fuse_do_getattr(ff, !!openflags);
    if (ret){
      set_errno(ret);
      ret = -1;
      goto out;
    }
  }

  fuse_fillattr(&(ff->attr), buf);

 out:
  CHECK_OUT("(%d)", ret);

  return ret;
}

int
fhandler_dev_fuse::backpush(struct fues_req *req)
{
  list_add_tail(&pending_req, &req->list);

  return 0
}

static void
fuse_conn_init(struct fuse_conn *fc)
{
}

int
fhandler_fs_fuse::mount (const char *in, char *out)
{
  int ret = 0;
  struct fuse_mount_data d;
  fhandler_dev_fuse *fh;
  struct fuse_req *init_req;
  
  CHECK_IN("(%s, %p)", in, out);

  /* We copy the mount string first for parsing */
  strncpy(out, in, CYG_MAX_PATH);
  out[CYG_MAX_PATH - 1] = '\0';
  ret = parse_fuse_opt(out, &d, 0);

  if (cygheap->fdtab.not_open (d.fd))
    {
      ret = -EBADF;
      goto out;
    }
  else
    {
      fh = (fhandler_dev_fuse *)(cygheap->fdtab[(d.fd)]);
    }

  /* Save to the new super */
  strcpy(out, "\\");
  fc = (struct fuse_conn *)(out + 4);
  fuse_conn_init(fc);
  fc->release = NULL;		/* Since we are not allocated */
  fc->flags = d.flags;
  fc->user_id = d.user_id;
  fc->group_id = d.group_id;
  fc->max_read = max_t(unsigned, 4096, d.max_read);

  // XXX Create root inode and lock it here!

  init_req = fuse_request_alloc();
  if (!init_req)
    {
      ret = ENOMEM;
      goto out;
    }
  

  fuse_init_init(fc, init_req);
  ret = fh->backpush(init_req);
  if (ret)
    goto out_free;
  fc->connected = 1;
  CHECK_OUT("(%s, %d)", out, ret);
  return ret;

 out_free:
  fuse_request_free(init_req);
 out:
  CHECK_OUT("(%s, %d)", out, ret);
  return ret;
}

void
fhandler_fs_fuse::set_name(path_conv &in_pc)
{
  const char *mount_point = in_pc.dev.name;
  const char *mount_opt = in_pc.dev.native;
  int len = 0;

  CHECK_IN("(%p, %s, dev:(0x%x, 0x%x, %d))", &in_pc, in_pc.normalized_path, 
	   in_pc.dev.d.devn_int, in_pc.dev.mode, in_pc.dev.dev_on_fs);

  fhandler_base::set_name(in_pc);

  if (mount_point)
    len = strlen(mount_point);
  else
    small_printf("Get a NULL mount point");

  if (!len)
    small_printf("Get an empty mount point");
  else if (!path_prefix_p(mount_point, in_pc.normalized_path, len, false))
    small_printf("Get an error mount point (%s, %s)",
		 in_pc.normalized_path, mount_point);
  else
    path_conv_off = len;
  CHECK_DBG("Get mount (%s, %s, %d)", mount_point, mount_opt, len);
  
  CHECK_OUT("(%s)", get_relative_name());
}

static void
fuse_file_fill(struct fuse_file *ff, struct fuse_entry_out *out)
{
  ff->attr = out->attr;
  ff->nodeid = out->nodeid;
}


virtual_ftype_t
fhandler_fs_fuse::exists ()
{
  virtual_ftype_t ret = virt_none;
  struct fuse_entry_out o;
  const char *path = get_relative_name();

  CHECK_IN("(%s, %s)", path, pc.dev.native);

  if (!ff)
    ff = fuse_file_alloc(NULL);
  if (!ff){
    SMALL_PRINTF("Alloc fuse file failed");
    goto out;
  }

  if (!*path){
    ret = virt_rootdir;
    goto out;
  }

  if (fuse_lookup_path(ff->fc, path, &o)){
    goto out;
  }

  fuse_file_fill(ff, &o);

  switch (ff->attr.mode & S_IFMT){
  case S_IFIFO:
    ret = virt_pipe;
    break;
  case S_IFCHR:
    ret = virt_chr;
    break;
  case S_IFDIR:
    ret = virt_directory;
    break;
  case S_IFBLK:
    ret = virt_blk;
    break;
  case S_IFREG:
    ret = virt_file;
    break;
  case S_IFLNK:
    ret = virt_symlink;
    break;
  case S_IFSOCK:
    ret = virt_socket;
    break;
  default:
    ret = virt_none;
  }

 out:
  CHECK_OUT("(%d)", ret);

  return ret;
  
}
#endif	/* DEBUGGING */
