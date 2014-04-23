#ifndef __LINUX_ACL_H
#define __LINUX_ACL_H

#include <linux/posix_acl.h>
#include <linux/richacl.h>

static inline int
acl_chmod(struct inode *inode)
{
	if (IS_RICHACL(inode))
		return richacl_chmod(inode, inode->i_mode);
	return posix_acl_chmod(inode, inode->i_mode);
}

#endif
