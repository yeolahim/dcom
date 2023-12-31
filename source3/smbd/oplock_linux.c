/* 
   Unix SMB/CIFS implementation.
   kernel oplock processing for Linux
   Copyright (C) Andrew Tridgell 2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define DBGC_CLASS DBGC_LOCKING
#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"

#ifdef HAVE_KERNEL_OPLOCKS_LINUX

#ifndef RT_SIGNAL_LEASE
#define RT_SIGNAL_LEASE (SIGRTMIN+1)
#endif

/* 
 * Call to set the kernel lease signal handler
 */
int linux_set_lease_sighandler(int fd)
{
        if (fcntl(fd, F_SETSIG, RT_SIGNAL_LEASE) == -1) {
                DBG_NOTICE("Failed to set signal handler for kernel lease\n");
                return -1;
        }

	return 0;
}

/****************************************************************************
 Call SETLEASE. If we get EACCES then we try setting up the right capability and
 try again.
 Use the SMB_VFS_LINUX_SETLEASE instead of this call directly.
****************************************************************************/

int linux_setlease(int fd, int leasetype)
{
	int ret;
	int saved_errno = 0;

	/*
	 * Ensure the lease owner is root to allow
	 * correct delivery of lease-break signals.
	 */

	become_root();

	/* First set the signal handler. */
	if (linux_set_lease_sighandler(fd) == -1) {
		saved_errno = errno;
		ret = -1;
		goto out;
	}
	ret = fcntl(fd, F_SETLEASE, leasetype);
	if (ret == -1) {
		saved_errno = errno;
	}

  out:

	unbecome_root();

	if (ret == -1) {
		errno = saved_errno;
	}
	return ret;
}

/****************************************************************************
 * Deal with the Linux kernel <--> smbd
 * oplock break protocol.
****************************************************************************/

static void linux_oplock_signal_handler(struct tevent_context *ev_ctx,
					struct tevent_signal *se,
					int signum, int count,
					void *_info, void *private_data)
{
	struct kernel_oplocks *ctx =
		talloc_get_type_abort(private_data,
		struct kernel_oplocks);
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(ctx->private_data,
		struct smbd_server_connection);
	siginfo_t *info = (siginfo_t *)_info;
	int fd = info->si_fd;
	files_struct *fsp;

	fsp = file_find_fd(sconn, fd);
	if (fsp == NULL) {
		DBG_ERR("linux_oplock_signal_handler: failed to find fsp for file fd=%d (file was closed ?)\n", fd );
		return;
	}
	break_kernel_oplock(sconn->msg_ctx, fsp);
}

/****************************************************************************
 Attempt to set an kernel oplock on a file.
****************************************************************************/

static bool linux_set_kernel_oplock(struct kernel_oplocks *ctx,
				    files_struct *fsp, int oplock_type)
{
	struct file_id_buf idbuf;

	if ( SMB_VFS_LINUX_SETLEASE(fsp, F_WRLCK) == -1) {
		DBG_NOTICE("Refused oplock on file %s, "
			   "fd = %d, file_id = %s. (%s)\n",
			   fsp_str_dbg(fsp),
			   fsp_get_io_fd(fsp),
			   file_id_str_buf(fsp->file_id, &idbuf),
			   strerror(errno));
		return False;
	}
	
	DBG_NOTICE("got kernel oplock on file %s, "
		   "file_id = %s gen_id = %"PRIu64"\n",
		   fsp_str_dbg(fsp),
		   file_id_str_buf(fsp->file_id, &idbuf),
		   fh_get_gen_id(fsp->fh));

	return True;
}

/****************************************************************************
 Release a kernel oplock on a file.
****************************************************************************/

static void linux_release_kernel_oplock(struct kernel_oplocks *ctx,
					files_struct *fsp, int oplock_type)
{
	struct file_id_buf idbuf;

	if (DEBUGLVL(DBGLVL_DEBUG)) {
		/*
		 * Check and print out the current kernel
		 * oplock state of this file.
		 */
		int state = fcntl(fsp_get_io_fd(fsp), F_GETLEASE, 0);
		dbgtext("linux_release_kernel_oplock: file %s, file_id = %s "
			"gen_id = %"PRIu64" has kernel oplock state "
			"of %x.\n",
			fsp_str_dbg(fsp),
		        file_id_str_buf(fsp->file_id, &idbuf),
			fh_get_gen_id(fsp->fh),
			state);
	}

	/*
	 * Remove the kernel oplock on this file.
	 */
	if ( SMB_VFS_LINUX_SETLEASE(fsp, F_UNLCK) == -1) {
		if (DEBUGLVL(DBGLVL_ERR)) {
			dbgtext("linux_release_kernel_oplock: Error when "
				"removing kernel oplock on file " );
			dbgtext("%s, file_id = %s, gen_id = %"PRIu64". "
				"Error was %s\n",
				fsp_str_dbg(fsp),
				file_id_str_buf(fsp->file_id, &idbuf),
				fh_get_gen_id(fsp->fh),
				strerror(errno));
		}
	}
}

/****************************************************************************
 See if the kernel supports oplocks.
****************************************************************************/

static bool linux_oplocks_available(void)
{
	int fd, ret;
	fd = open("/dev/null", O_RDONLY);
	if (fd == -1)
		return False; /* uggh! */
	ret = fcntl(fd, F_GETLEASE, 0);
	close(fd);
	return ret == F_UNLCK;
}

/****************************************************************************
 Setup kernel oplocks.
****************************************************************************/

static const struct kernel_oplocks_ops linux_koplocks = {
	.set_oplock			= linux_set_kernel_oplock,
	.release_oplock			= linux_release_kernel_oplock,
};

struct kernel_oplocks *linux_init_kernel_oplocks(struct smbd_server_connection *sconn)
{
	struct kernel_oplocks *ctx;
	struct tevent_signal *se;

	if (!linux_oplocks_available()) {
		DBG_NOTICE("Linux kernel oplocks not available\n");
		return NULL;
	}

	ctx = talloc_zero(sconn, struct kernel_oplocks);
	if (!ctx) {
		DBG_ERR("Linux Kernel oplocks talloc_Zero failed\n");
		return NULL;
	}

	ctx->ops = &linux_koplocks;
	ctx->private_data = sconn;

	se = tevent_add_signal(sconn->ev_ctx,
			       ctx,
			       RT_SIGNAL_LEASE, SA_SIGINFO,
			       linux_oplock_signal_handler,
			       ctx);
	if (!se) {
		DBG_ERR("Failed to setup RT_SIGNAL_LEASE handler");
		TALLOC_FREE(ctx);
		return NULL;
	}

	DBG_NOTICE("Linux kernel oplocks enabled\n");

	return ctx;
}
#else
 void oplock_linux_dummy(void);

 void oplock_linux_dummy(void) {}
#endif /* HAVE_KERNEL_OPLOCKS_LINUX */
