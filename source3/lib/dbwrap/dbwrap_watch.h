/*
   Unix SMB/CIFS implementation.
   Watch dbwrap record changes
   Copyright (C) Volker Lendecke 2012

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

#ifndef __DBWRAP_WATCH_H__
#define __DBWRAP_WATCH_H__

#include <tevent.h>
#include "dbwrap/dbwrap.h"
#include "messages.h"

struct db_context *db_open_watched(TALLOC_CTX *mem_ctx,
				   struct db_context **backend,
				   struct messaging_context *msg);
uint64_t dbwrap_watched_watch_add_instance(struct db_record *rec);
void dbwrap_watched_watch_remove_instance(struct db_record *rec, uint64_t instance);
void dbwrap_watched_watch_skip_alerting(struct db_record *rec);
void dbwrap_watched_watch_reset_alerting(struct db_record *rec);
void dbwrap_watched_watch_force_alerting(struct db_record *rec);
struct tevent_req *dbwrap_watched_watch_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct db_record *rec,
					     uint64_t resume_instance,
					     struct server_id blocker);
NTSTATUS dbwrap_watched_watch_recv(struct tevent_req *req,
				   uint64_t *pkeep_instance,
				   bool *blockerdead,
				   struct server_id *blocker);

#endif /* __DBWRAP_WATCH_H__ */
