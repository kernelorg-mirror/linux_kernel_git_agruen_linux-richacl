/*
 * Copyright (C) 2006, 2010  Novell, Inc.
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

#ifndef __RICHACL_H
#define __RICHACL_H

#define RICHACE_OWNER_SPECIAL_ID	0
#define RICHACE_GROUP_SPECIAL_ID	1
#define RICHACE_EVERYONE_SPECIAL_ID	2

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		kuid_t		uid;
		kgid_t		gid;
		unsigned int	special;
	} e_id;
};

struct richacl {
	atomic_t	a_refcount;
	unsigned int	a_owner_mask;
	unsigned int	a_group_mask;
	unsigned int	a_other_mask;
	unsigned short	a_count;
	unsigned short	a_flags;
	struct richace	a_entries[0];
};

#define richacl_for_each_entry(_ace, _acl) \
	for (_ace = (_acl)->a_entries; \
	     _ace != (_acl)->a_entries + (_acl)->a_count; \
	     _ace++)

#define richacl_for_each_entry_reverse(_ace, _acl) \
	for (_ace = (_acl)->a_entries + (_acl)->a_count - 1; \
	     _ace != (_acl)->a_entries - 1; \
	     _ace--)

/* a_flag values */
#define RICHACL_MASKED				0x80

#define RICHACL_VALID_FLAGS (					\
		RICHACL_MASKED)

/* e_type values */
#define RICHACE_ACCESS_ALLOWED_ACE_TYPE		0x0000
#define RICHACE_ACCESS_DENIED_ACE_TYPE		0x0001

/* e_flags bitflags */
#define RICHACE_FILE_INHERIT_ACE		0x0001
#define RICHACE_DIRECTORY_INHERIT_ACE		0x0002
#define RICHACE_NO_PROPAGATE_INHERIT_ACE	0x0004
#define RICHACE_INHERIT_ONLY_ACE		0x0008
#define RICHACE_IDENTIFIER_GROUP		0x0040
#define RICHACE_SPECIAL_WHO			0x4000

#define RICHACE_VALID_FLAGS (					\
	RICHACE_FILE_INHERIT_ACE |				\
	RICHACE_DIRECTORY_INHERIT_ACE |				\
	RICHACE_NO_PROPAGATE_INHERIT_ACE |			\
	RICHACE_INHERIT_ONLY_ACE |				\
	RICHACE_IDENTIFIER_GROUP |				\
	RICHACE_SPECIAL_WHO)

/* e_mask bitflags */
#define RICHACE_READ_DATA			0x00000001
#define RICHACE_LIST_DIRECTORY			0x00000001
#define RICHACE_WRITE_DATA			0x00000002
#define RICHACE_ADD_FILE			0x00000002
#define RICHACE_APPEND_DATA			0x00000004
#define RICHACE_ADD_SUBDIRECTORY		0x00000004
#define RICHACE_READ_NAMED_ATTRS		0x00000008
#define RICHACE_WRITE_NAMED_ATTRS		0x00000010
#define RICHACE_EXECUTE				0x00000020
#define RICHACE_DELETE_CHILD			0x00000040
#define RICHACE_READ_ATTRIBUTES			0x00000080
#define RICHACE_WRITE_ATTRIBUTES		0x00000100
#define RICHACE_WRITE_RETENTION			0x00000200
#define RICHACE_WRITE_RETENTION_HOLD		0x00000400
#define RICHACE_DELETE				0x00010000
#define RICHACE_READ_ACL			0x00020000
#define RICHACE_WRITE_ACL			0x00040000
#define RICHACE_WRITE_OWNER			0x00080000
#define RICHACE_SYNCHRONIZE			0x00100000

/* Valid RICHACE_* flags for directories and non-directories */
#define RICHACE_VALID_MASK (					\
	RICHACE_READ_DATA | RICHACE_LIST_DIRECTORY |		\
	RICHACE_WRITE_DATA | RICHACE_ADD_FILE |			\
	RICHACE_APPEND_DATA | RICHACE_ADD_SUBDIRECTORY |	\
	RICHACE_READ_NAMED_ATTRS |				\
	RICHACE_WRITE_NAMED_ATTRS |				\
	RICHACE_EXECUTE |					\
	RICHACE_DELETE_CHILD |					\
	RICHACE_READ_ATTRIBUTES |				\
	RICHACE_WRITE_ATTRIBUTES |				\
	RICHACE_WRITE_RETENTION |				\
	RICHACE_WRITE_RETENTION_HOLD |				\
	RICHACE_DELETE |					\
	RICHACE_READ_ACL |					\
	RICHACE_WRITE_ACL |					\
	RICHACE_WRITE_OWNER |					\
	RICHACE_SYNCHRONIZE)

/*
 * The POSIX permissions are supersets of the following NFSv4 permissions:
 *
 *  - MAY_READ maps to READ_DATA or LIST_DIRECTORY, depending on the type
 *    of the file system object.
 *
 *  - MAY_WRITE maps to WRITE_DATA or RICHACE_APPEND_DATA for files, and to
 *    ADD_FILE, RICHACE_ADD_SUBDIRECTORY, or RICHACE_DELETE_CHILD for directories.
 *
 *  - MAY_EXECUTE maps to RICHACE_EXECUTE.
 *
 *  (Some of these NFSv4 permissions have the same bit values.)
 */
#define RICHACE_POSIX_MODE_READ (			\
		RICHACE_READ_DATA |		\
		RICHACE_LIST_DIRECTORY)
#define RICHACE_POSIX_MODE_WRITE (			\
		RICHACE_WRITE_DATA |		\
		RICHACE_ADD_FILE |			\
		RICHACE_APPEND_DATA |		\
		RICHACE_ADD_SUBDIRECTORY |		\
		RICHACE_DELETE_CHILD)
#define RICHACE_POSIX_MODE_EXEC RICHACE_EXECUTE
#define RICHACE_POSIX_MODE_ALL (			\
		RICHACE_POSIX_MODE_READ |		\
		RICHACE_POSIX_MODE_WRITE |		\
		RICHACE_POSIX_MODE_EXEC)
/*
 * These permissions are always allowed
 * no matter what the acl says.
 */
#define RICHACE_POSIX_ALWAYS_ALLOWED (	\
		RICHACE_SYNCHRONIZE |	\
		RICHACE_READ_ATTRIBUTES |	\
		RICHACE_READ_ACL)
/*
 * The owner is implicitly granted
 * these permissions under POSIX.
 */
#define RICHACE_POSIX_OWNER_ALLOWED (		\
		RICHACE_WRITE_ATTRIBUTES |		\
		RICHACE_WRITE_OWNER |		\
		RICHACE_WRITE_ACL)
/**
 * richacl_get  -  grab another reference to a richacl handle
 */
static inline struct richacl *
richacl_get(struct richacl *acl)
{
	if (acl)
		atomic_inc(&acl->a_refcount);
	return acl;
}

/**
 * richacl_put  -  free a richacl handle
 */
static inline void
richacl_put(struct richacl *acl)
{
	if (acl && atomic_dec_and_test(&acl->a_refcount))
		kfree(acl);
}

/**
 * richace_is_owner  -  check if @ace is an OWNER@ entry
 */
static inline bool
richace_is_owner(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_OWNER_SPECIAL_ID;
}

/**
 * richace_is_group  -  check if @ace is a GROUP@ entry
 */
static inline bool
richace_is_group(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_GROUP_SPECIAL_ID;
}

/**
 * richace_is_everyone  -  check if @ace is an EVERYONE@ entry
 */
static inline bool
richace_is_everyone(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_EVERYONE_SPECIAL_ID;
}

/**
 * richace_is_unix_user  -  check if @ace applies to a specific user
 */
static inline bool
richace_is_unix_user(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       !(ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

/**
 * richace_is_unix_group  -  check if @ace applies to a specific group
 */
static inline bool
richace_is_unix_group(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       (ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

/**
 * richace_is_inherit_only  -  check if @ace is for inheritance only
 *
 * ACEs with the %RICHACE_INHERIT_ONLY_ACE flag set have no effect during
 * permission checking.
 */
static inline bool
richace_is_inherit_only(const struct richace *ace)
{
	return ace->e_flags & RICHACE_INHERIT_ONLY_ACE;
}

/**
 * richace_is_inheritable  -  check if @ace is inheritable
 */
static inline bool
richace_is_inheritable(const struct richace *ace)
{
	return ace->e_flags & (RICHACE_FILE_INHERIT_ACE |
			       RICHACE_DIRECTORY_INHERIT_ACE);
}

/**
 * richace_clear_inheritance_flags  - clear all inheritance flags in @ace
 */
static inline void
richace_clear_inheritance_flags(struct richace *ace)
{
	ace->e_flags &= ~(RICHACE_FILE_INHERIT_ACE |
			  RICHACE_DIRECTORY_INHERIT_ACE |
			  RICHACE_NO_PROPAGATE_INHERIT_ACE |
			  RICHACE_INHERIT_ONLY_ACE);
}

/**
 * richace_is_allow  -  check if @ace is an %ALLOW type entry
 */
static inline bool
richace_is_allow(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_ALLOWED_ACE_TYPE;
}

/**
 * richace_is_deny  -  check if @ace is a %DENY type entry
 */
static inline bool
richace_is_deny(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_DENIED_ACE_TYPE;
}

/**
 * richace_is_same_identifier  -  are both identifiers the same?
 */
static inline bool
richace_is_same_identifier(const struct richace *a, const struct richace *b)
{
	return !((a->e_flags ^ b->e_flags) &
		 (RICHACE_SPECIAL_WHO | RICHACE_IDENTIFIER_GROUP)) &&
	       !memcmp(&a->e_id, &b->e_id, sizeof(a->e_id));
}

extern struct richacl *richacl_alloc(int, gfp_t);
extern struct richacl *richacl_clone(const struct richacl *, gfp_t);
extern void richace_copy(struct richace *, const struct richace *);
extern int richacl_masks_to_mode(const struct richacl *);
extern unsigned int richacl_mode_to_mask(mode_t);
extern unsigned int richacl_want_to_mask(unsigned int);
extern void richacl_compute_max_masks(struct richacl *, kuid_t);
extern struct richacl *richacl_chmod(struct richacl *, mode_t);

#endif /* __RICHACL_H */
