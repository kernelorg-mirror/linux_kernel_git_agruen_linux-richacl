/*
 * Copyright (C)  2015 Red Hat, Inc.
 * Author: Andreas Gruenbacher <agruenba@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef __FS_XFS_RICHACL_H
#define __FS_XFS_RICHACL_H

struct richacl;

extern struct richacl *xfs_get_richacl(struct inode *);
extern int xfs_set_richacl(struct inode *, struct richacl *);

#endif  /* __FS_XFS_RICHACL_H */
