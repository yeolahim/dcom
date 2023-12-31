/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling ads structures

   Copyright (C) Guenther Deschner 2020

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

#include "includes.h"
#include "librpc/gen_ndr/ndr_ads.h"

enum ndr_err_code ndr_pull_ads_struct(struct ndr_pull *ndr, int ndr_flags, struct ads_struct *r)
{
	return NDR_ERR_SUCCESS;
}
enum ndr_err_code ndr_push_ads_struct(struct ndr_push *ndr, int ndr_flags, const struct ads_struct *r)
{
	return NDR_ERR_SUCCESS;
}
