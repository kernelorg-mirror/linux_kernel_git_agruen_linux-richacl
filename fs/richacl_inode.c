/*
 * Copyright (C) 2010  Novell, Inc.
 * Copyright (C) 2015  Red Hat, Inc.
 * Written by Andreas Gruenbacher <agruen@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/richacl.h>

struct richacl *get_cached_richacl(struct inode *inode)
{
	struct richacl *acl;

	acl = (struct richacl *)ACCESS_ONCE(inode->i_acl);
	if (acl && IS_RICHACL(inode)) {
		spin_lock(&inode->i_lock);
		acl = (struct richacl *)inode->i_acl;
		if (acl != ACL_NOT_CACHED)
			acl = richacl_get(acl);
		spin_unlock(&inode->i_lock);
	}
	return acl;
}
EXPORT_SYMBOL_GPL(get_cached_richacl);

struct richacl *get_cached_richacl_rcu(struct inode *inode)
{
	return (struct richacl *)rcu_dereference(inode->i_acl);
}
EXPORT_SYMBOL_GPL(get_cached_richacl_rcu);

void set_cached_richacl(struct inode *inode, struct richacl *acl)
{
	struct base_acl *old = NULL;
	spin_lock(&inode->i_lock);
	old = inode->i_acl;
	rcu_assign_pointer(inode->i_acl, &richacl_get(acl)->a_base);
	spin_unlock(&inode->i_lock);
	if (old != ACL_NOT_CACHED)
		put_base_acl(old);
}
EXPORT_SYMBOL_GPL(set_cached_richacl);

void forget_cached_richacl(struct inode *inode)
{
	struct base_acl *old = NULL;
	spin_lock(&inode->i_lock);
	old = inode->i_acl;
	inode->i_acl = ACL_NOT_CACHED;
	spin_unlock(&inode->i_lock);
	if (old != ACL_NOT_CACHED)
		put_base_acl(old);
}
EXPORT_SYMBOL_GPL(forget_cached_richacl);

struct richacl *get_richacl(struct inode *inode)
{
	struct richacl *acl;

	acl = get_cached_richacl(inode);
	if (acl != ACL_NOT_CACHED)
		return acl;

	if (!IS_RICHACL(inode))
		return NULL;

	/*
	 * A filesystem can force a ACL callback by just never filling the
	 * ACL cache. But normally you'd fill the cache either at inode
	 * instantiation time, or on the first ->get_richacl call.
	 *
	 * If the filesystem doesn't have a get_richacl() function at all,
	 * we'll just create the negative cache entry.
	 */
	if (!inode->i_op->get_richacl) {
		set_cached_richacl(inode, NULL);
		return NULL;
	}
	return inode->i_op->get_richacl(inode);
}
EXPORT_SYMBOL_GPL(get_richacl);

/**
 * richacl_permission  -  richacl permission check algorithm
 * @inode:	inode to check
 * @acl:	rich acl of the inode
 * @want:	requested access (MAY_* flags)
 *
 * Checks if the current process is granted @mask flags in @acl.
 */
int
richacl_permission(struct inode *inode, const struct richacl *acl,
		   int want)
{
	const struct richace *ace;
	unsigned int mask = richacl_want_to_mask(want);
	unsigned int requested = mask, denied = 0;
	int in_owning_group = in_group_p(inode->i_gid);
	int in_owner_or_group_class = in_owning_group;

	/*
	 * A process is
	 *   - in the owner file class if it owns the file,
	 *   - in the group file class if it is in the file's owning group or
	 *     it matches any of the user or group entries, and
	 *   - in the other file class otherwise.
	 * The file class is only relevant for determining which file mask to
	 * apply, which only happens for masked acls.
	 */
	if (acl->a_flags & RICHACL_MASKED) {
		if (uid_eq(current_fsuid(), inode->i_uid)) {
			denied = requested & ~acl->a_owner_mask;
			goto out;
		}
	} else {
		/*
		 * We don't care which class the process is in when the acl is
		 * not masked.
		 */
		in_owner_or_group_class = 1;
	}

	/*
	 * Check if the acl grants the requested access and determine which
	 * file class the process is in.
	 */
	richacl_for_each_entry(ace, acl) {
		unsigned int ace_mask = ace->e_mask;

		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_owner(ace)) {
			if (!uid_eq(current_fsuid(), inode->i_uid))
				continue;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_user(ace)) {
			kuid_t uid = current_fsuid();

			if (!uid_eq(uid, ace->e_id.uid))
				continue;
		} else if (richace_is_unix_group(ace)) {
			if (!in_group_p(ace->e_id.gid))
				continue;
		} else
			goto entry_matches_everyone;

		/* The process is in the owner or group file class. */
		in_owner_or_group_class = 1;

entry_matches_everyone:
		/* Check which mask flags the ACE allows or denies. */
		if (richace_is_deny(ace))
			denied |= ace_mask & mask;
		mask &= ~ace_mask;

		/*
		 * Keep going until we know which file class
		 * the process is in.
		 */
		if (!mask && in_owner_or_group_class)
			break;
	}
	denied |= mask;

	if (acl->a_flags & RICHACL_MASKED) {
		/*
		 * The file class a process is in determines which file mask
		 * applies.  Check if that file mask also grants the requested
		 * access.
		 */
		if (in_owner_or_group_class)
			denied |= requested & ~acl->a_group_mask;
		else
			denied = requested & ~acl->a_other_mask;
	}

out:
	return denied ? -EACCES : 0;
}
EXPORT_SYMBOL_GPL(richacl_permission);

/**
 * richacl_inherit_inode  -  compute inherited acl and file mode
 * @dir_acl:	acl of the containing directory
 * @inode:	inode of the new file (create mode in i_mode)
 *
 * The file permission bits in inode->i_mode must be set to the create mode by
 * the caller.
 *
 * If there is an inheritable acl, the maximum permissions that the acl grants
 * will be computed and permissions not granted by the acl will be removed from
 * inode->i_mode.  If there is no inheritable acl, the umask will be applied
 * instead.
 */
static struct richacl *
richacl_inherit_inode(const struct richacl *dir_acl, struct inode *inode)
{
	struct richacl *acl;
	mode_t mask;

	acl = richacl_inherit(dir_acl, S_ISDIR(inode->i_mode));
	if (acl) {
		mask = inode->i_mode;
		if (richacl_equiv_mode(acl, &mask) == 0) {
			richacl_put(acl);
			acl = NULL;
		} else {
			/*
			 * We need to set RICHACL_PROTECTED because we are
			 * doing an implicit chmod
			 */
			if (richacl_is_auto_inherit(acl))
				acl->a_flags |= RICHACL_PROTECTED;

			richacl_compute_max_masks(acl, inode->i_uid);
			/*
			 * Ensure that the acl will not grant any permissions
			 * beyond the create mode.
			 */
			acl->a_flags |= RICHACL_MASKED;
			acl->a_owner_mask &= richacl_mode_to_mask(inode->i_mode >> 6);
			acl->a_group_mask &= richacl_mode_to_mask(inode->i_mode >> 3);
			acl->a_other_mask &= richacl_mode_to_mask(inode->i_mode);
			mask = ~S_IRWXUGO | richacl_masks_to_mode(acl);
		}
	} else
		mask = ~current_umask();

	inode->i_mode &= mask;
	return acl;
}

struct richacl *richacl_create(struct inode *inode, struct inode *dir)
{
	struct richacl *dir_acl, *acl = NULL;

	if (S_ISLNK(inode->i_mode))
		return NULL;
	dir_acl = get_richacl(dir);
	if (dir_acl) {
		if (IS_ERR(dir_acl))
			return dir_acl;
		acl = richacl_inherit_inode(dir_acl, inode);
		richacl_put(dir_acl);
	} else
		inode->i_mode &= ~current_umask();
	return acl;
}
EXPORT_SYMBOL_GPL(richacl_create);
