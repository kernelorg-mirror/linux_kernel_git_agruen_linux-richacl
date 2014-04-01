/*
 * Copyright (C) 2006, 2010  Novell, Inc.
 * Copyright (C) 2015  Red Hat, Inc.
 * Written by Andreas Gruenbacher <agruenba@redhat.com>
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

/**
 * richacl_alloc  -  allocate a richacl
 * @count:	number of entries
 */
struct richacl *
richacl_alloc(int count, gfp_t gfp)
{
	size_t size = sizeof(struct richacl) + count * sizeof(struct richace);
	struct richacl *acl = kzalloc(size, gfp);

	if (acl) {
		atomic_set(&acl->a_refcount, 1);
		acl->a_count = count;
	}
	return acl;
}
EXPORT_SYMBOL_GPL(richacl_alloc);

/**
 * richacl_clone  -  create a copy of a richacl
 */
struct richacl *
richacl_clone(const struct richacl *acl, gfp_t gfp)
{
	int count = acl->a_count;
	size_t size = sizeof(struct richacl) + count * sizeof(struct richace);
	struct richacl *dup = kmalloc(size, gfp);

	if (dup) {
		memcpy(dup, acl, size);
		atomic_set(&dup->a_refcount, 1);
	}
	return dup;
}

/**
 * richace_copy  -  copy an acl entry
 */
void
richace_copy(struct richace *to, const struct richace *from)
{
	memcpy(to, from, sizeof(struct richace));
}

/*
 * richacl_mask_to_mode  -  compute the file permission bits from mask
 * @mask:	%RICHACE_* permission mask
 *
 * Compute the file permission bits corresponding to a particular set of
 * richacl permissions.
 *
 * See richacl_masks_to_mode().
 */
static int
richacl_mask_to_mode(unsigned int mask)
{
	int mode = 0;

	if (mask & RICHACE_POSIX_MODE_READ)
		mode |= S_IROTH;
	if (mask & RICHACE_POSIX_MODE_WRITE)
		mode |= S_IWOTH;
	if (mask & RICHACE_POSIX_MODE_EXEC)
		mode |= S_IXOTH;

	return mode;
}

/**
 * richacl_masks_to_mode  -  compute file permission bits from file masks
 *
 * When setting a richacl, we set the file permission bits to indicate maximum
 * permissions: for example, we set the Write permission when a mask contains
 * RICHACE_APPEND_DATA even if it does not also contain RICHACE_WRITE_DATA.
 *
 * Permissions which are not in RICHACE_POSIX_MODE_READ,
 * RICHACE_POSIX_MODE_WRITE, or RICHACE_POSIX_MODE_EXEC cannot be represented
 * in the file permission bits.  Such permissions can still be effective, but
 * not for new files or after a chmod(); they must be explicitly enabled in the
 * richacl.
 */
int
richacl_masks_to_mode(const struct richacl *acl)
{
	return richacl_mask_to_mode(acl->a_owner_mask) << 6 |
	       richacl_mask_to_mode(acl->a_group_mask) << 3 |
	       richacl_mask_to_mode(acl->a_other_mask);
}
EXPORT_SYMBOL_GPL(richacl_masks_to_mode);

/**
 * richacl_mode_to_mask  - compute a file mask from the lowest three mode bits
 * @mode:	mode to convert to richacl permissions
 *
 * When the file permission bits of a file are set with chmod(), this specifies
 * the maximum permissions that processes will get.  All permissions beyond
 * that will be removed from the file masks, and become ineffective.
 */
unsigned int
richacl_mode_to_mask(umode_t mode)
{
	unsigned int mask = 0;

	if (mode & S_IROTH)
		mask |= RICHACE_POSIX_MODE_READ;
	if (mode & S_IWOTH)
		mask |= RICHACE_POSIX_MODE_WRITE;
	if (mode & S_IXOTH)
		mask |= RICHACE_POSIX_MODE_EXEC;

	return mask;
}

/**
 * richacl_want_to_mask  - convert the iop->permission want argument to a mask
 * @want:	@want argument of the permission inode operation
 *
 * When checking for append, create file, create dir, or delete child access,
 * MAY_WRITE is also set in @want.
 */
static unsigned int
richacl_want_to_mask(unsigned int want)
{
	unsigned int mask = 0;

	if (want & MAY_READ)
		mask |= RICHACE_READ_DATA;
	if (want & MAY_DELETE_SELF)
		mask |= RICHACE_DELETE;
	if (want & MAY_TAKE_OWNERSHIP)
		mask |= RICHACE_WRITE_OWNER;
	if (want & MAY_CHMOD)
		mask |= RICHACE_WRITE_ACL;
	if (want & MAY_SET_TIMES)
		mask |= RICHACE_WRITE_ATTRIBUTES;
	if (want & MAY_EXEC)
		mask |= RICHACE_EXECUTE;
	/*
	 * differentiate MAY_WRITE from these request
	 */
	if (want & (MAY_APPEND |
		    MAY_CREATE_FILE | MAY_CREATE_DIR |
		    MAY_DELETE_CHILD)) {
		if (want & MAY_APPEND)
			mask |= RICHACE_APPEND_DATA;
		if (want & MAY_CREATE_FILE)
			mask |= RICHACE_ADD_FILE;
		if (want & MAY_CREATE_DIR)
			mask |= RICHACE_ADD_SUBDIRECTORY;
		if (want & MAY_DELETE_CHILD)
			mask |= RICHACE_DELETE_CHILD;
	} else if (want & MAY_WRITE)
		mask |= RICHACE_WRITE_DATA;
	return mask;
}

/**
 * richacl_permission  -  richacl permission check algorithm
 * @inode:	inode to check
 * @acl:	rich acl of the inode
 * @want:	requested access (MAY_* flags)
 *
 * Checks if the current process is granted @want flags in @acl.
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
		if ((acl->a_flags & RICHACL_WRITE_THROUGH) &&
		    uid_eq(current_fsuid(), inode->i_uid)) {
			denied = requested & ~acl->a_owner_mask;
			goto out;
		}
	} else {
		/*
		 * When the acl is not masked, there is no need to determine if
		 * the process is in the group class and we can break out
		 * earlier of the loop below.
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
			goto entry_matches_owner;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_user(ace)) {
			if (!uid_eq(current_fsuid(), ace->e_id.uid))
				continue;
			if (uid_eq(current_fsuid(), inode->i_uid))
				goto entry_matches_owner;
		} else if (richace_is_unix_group(ace)) {
			if (!in_group_p(ace->e_id.gid))
				continue;
		} else
			goto entry_matches_everyone;

		/*
		 * Apply the group file mask to entries other than owner@ and
		 * everyone@ or user entries matching the owner.  This ensures
		 * that we grant the same permissions as the acl computed by
		 * richacl_apply_masks().
		 *
		 * Without this restriction, the following richacl would grant
		 * rw access to processes which are both the owner and in the
		 * owning group, but not to other users in the owning group,
		 * which could not be represented without masks:
		 *
		 *  owner:rw::mask
		 *  group@:rw::allow
		 */
		if ((acl->a_flags & RICHACL_MASKED) && richace_is_allow(ace))
			ace_mask &= acl->a_group_mask;

entry_matches_owner:
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
		if (uid_eq(current_fsuid(), inode->i_uid))
			denied |= requested & ~acl->a_owner_mask;
		else if (in_owner_or_group_class)
			denied |= requested & ~acl->a_group_mask;
		else {
			if (acl->a_flags & RICHACL_WRITE_THROUGH)
				denied = requested & ~acl->a_other_mask;
			else
				denied |= requested & ~acl->a_other_mask;
		}
	}

out:
	return denied ? -EACCES : 0;
}
EXPORT_SYMBOL_GPL(richacl_permission);
