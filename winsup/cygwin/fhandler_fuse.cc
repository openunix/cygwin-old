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

	/** FOPEN_* flags returned by open */
	u32 open_flags;
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
#if 0
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

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
		struct fuse_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct cuse_init_out cuse_init_out;
#endif
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

	/** Request completion callback */
	void (*end)(struct fuse_conn *, struct fuse_req *);
#endif
	/** Request is stolen from fuse_file->reserved_req */
	struct file *stolen_file;
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

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

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

	/** Negotiated minor version */
	unsigned minor;

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

void fuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{

}

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

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
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


fhandler_fs_fuse::fhandler_fs_fuse ()
  : fhandler_virtual (), path_conv_off(0), ff(NULL)
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
