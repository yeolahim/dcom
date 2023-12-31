/*
   Unix SMB/CIFS implementation.

   SMB2 Create Context Blob handling

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2008-2009

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

#ifndef _LIBCLI_SMB_SMB2_CREATE_BLOB_H_
#define _LIBCLI_SMB_SMB2_CREATE_BLOB_H_

#include "replace.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "libcli/util/ntstatus.h"

struct smb2_create_blob {
	char *tag;
	DATA_BLOB data;
};

struct smb2_create_blobs {
	uint32_t num_blobs;
	struct smb2_create_blob *blobs;
};

struct smb_create_returns {
	uint8_t oplock_level;
	uint8_t flags;
	uint32_t create_action;
	NTTIME creation_time;
	NTTIME last_access_time;
	NTTIME last_write_time;
	NTTIME change_time;
	uint64_t allocation_size;
	uint64_t end_of_file;
	uint32_t file_attributes;
};

/*
  parse a set of SMB2 create blobs
*/
NTSTATUS smb2_create_blob_parse(TALLOC_CTX *mem_ctx, const DATA_BLOB buffer,
				struct smb2_create_blobs *blobs);

/*
  create a buffer of a set of create blobs
*/
NTSTATUS smb2_create_blob_push(TALLOC_CTX *mem_ctx, DATA_BLOB *buffer,
			       const struct smb2_create_blobs blobs);

NTSTATUS smb2_create_blob_add(TALLOC_CTX *mem_ctx, struct smb2_create_blobs *b,
			      const char *tag, DATA_BLOB data);

/*
 * return the first blob with the given tag
 */
struct smb2_create_blob *smb2_create_blob_find(const struct smb2_create_blobs *b,
					       const char *tag);

void smb2_create_blob_remove(struct smb2_create_blobs *b, const char *tag);

#endif /* _LIBCLI_SMB_SMB2_CREATE_BLOB_H_ */
