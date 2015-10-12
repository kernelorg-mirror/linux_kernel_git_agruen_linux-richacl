/*
 * Copyright (C) 2015  Red Hat, Inc.
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

#include "xfs.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_inode.h"
#include "xfs_attr.h"

#include <linux/xattr.h>
#include <linux/richacl_xattr.h>

struct richacl *
xfs_get_richacl(struct inode *inode)
{
	struct xfs_inode *ip = XFS_I(inode);
	struct richacl *acl = NULL;
	int size = XATTR_SIZE_MAX;
	void *value;
	int error;

	value = kmem_zalloc_large(size, KM_SLEEP);
	if (!value)
		return ERR_PTR(-ENOMEM);

	error = xfs_attr_get(ip, XATTR_RICHACL, value, &size, ATTR_ROOT);
	if (error) {
		/*
		 * If the attribute doesn't exist make sure we have a negative
		 * cache entry, for any other error assume it is transient and
		 * leave the cache entry as ACL_NOT_CACHED.
		 */
		if (error != -ENOATTR)
			acl = ERR_PTR(error);
	} else
		acl = richacl_from_xattr(&init_user_ns, value, size, -EIO);

	if (!IS_ERR(acl))
		set_cached_richacl(inode, acl);
	kfree(value);

	return acl;
}

static int
xfs_remove_richacl(struct inode *inode)
{
	struct xfs_inode *ip = XFS_I(inode);
	int error;

	error = xfs_attr_remove(ip, XATTR_RICHACL, ATTR_ROOT);
	if (error == -ENOATTR)
		error = 0;
	if (!error)
		set_cached_richacl(inode, NULL);
	return error;
}

static int
__xfs_set_richacl(struct inode *inode, struct richacl *acl, int xflags)
{
	struct xfs_inode *ip = XFS_I(inode);
	umode_t mode = inode->i_mode;
	int error, size;
	void *value;

	if (!acl)
		return xfs_remove_richacl(inode);

	/* Don't allow acls with unmapped identifiers. */
	if (richacl_has_unmapped_identifiers(acl))
		return -EINVAL;

	if (richacl_equiv_mode(acl, &mode) == 0) {
		xfs_set_mode(inode, mode);
		return xfs_remove_richacl(inode);
	}

	size = richacl_xattr_size(acl);
	value = kmem_zalloc_large(size, KM_SLEEP);
	if (!value)
		return -ENOMEM;
	richacl_to_xattr(&init_user_ns, acl, value, size);
	error = xfs_attr_set(ip, XATTR_RICHACL, value, size, xflags);
	kfree(value);
	if (error)
		return error;

	mode &= ~S_IRWXUGO;
	mode |= richacl_masks_to_mode(acl);
	xfs_set_mode(inode, mode);
	set_cached_richacl(inode, acl);

	return 0;
}

int
xfs_set_richacl(struct inode *inode, struct richacl *acl)
{
	return __xfs_set_richacl(inode, acl, ATTR_ROOT);
}

int
xfs_richacl_get_ioctl(struct inode *inode, void *value, int *len)
{
	struct user_namespace *user_ns = current_user_ns();
	struct richacl *acl;
	int error;

	acl = get_richacl(inode);
	if (IS_ERR_OR_NULL(acl))
		return PTR_ERR(acl);
	error = richacl_to_xattr(user_ns, acl, value, *len);
	if (error > 0) {
		*len = error;
		error = 0;
	}
	richacl_put(acl);
	return error;
}

int
xfs_richacl_set_ioctl(struct inode *inode, void *value, unsigned int size,
		      int xflags)
{
	struct user_namespace *user_ns = current_user_ns();
	struct richacl *acl = NULL;
	int error;

	if (!IS_RICHACL(inode))
		return -EOPNOTSUPP;
	if (value) {
		acl = richacl_from_xattr(user_ns, value, size, -EINVAL);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
	}
	error = __xfs_set_richacl(inode, acl, xflags);
	richacl_put(acl);
	return error;
}
