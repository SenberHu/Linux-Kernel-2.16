/*
 * Filesystem access notification for Linux
 *
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 */

#ifndef __LINUX_FSNOTIFY_BACKEND_H
#define __LINUX_FSNOTIFY_BACKEND_H

#ifdef __KERNEL__

#include <linux/idr.h> /* inotify uses this */
#include <linux/fs.h> /* struct inode */
#include <linux/list.h>
#include <linux/path.h> /* struct path */
#include <linux/spinlock.h>
#include <linux/types.h>

#include <asm/atomic.h>

/*
 * IN_* from inotfy.h lines up EXACTLY with FS_*, this is so we can easily
 * convert between them.  dnotify only needs conversion at watch creation
 * so no perf loss there.  fanotify isn't defined yet, so it can use the
 * wholes if it needs more events.
 */
#define FS_ACCESS		0x00000001	/* File was accessed */
#define FS_MODIFY		0x00000002	/* File was modified */
#define FS_ATTRIB		0x00000004	/* Metadata changed */
#define FS_CLOSE_WRITE		0x00000008	/* Writtable file was closed */
#define FS_CLOSE_NOWRITE	0x00000010	/* Unwrittable file closed */
#define FS_OPEN			0x00000020	/* File was opened */
#define FS_MOVED_FROM		0x00000040	/* File was moved from X */
#define FS_MOVED_TO		0x00000080	/* File was moved to Y */
#define FS_CREATE		0x00000100	/* Subfile was created */
#define FS_DELETE		0x00000200	/* Subfile was deleted */
#define FS_DELETE_SELF		0x00000400	/* Self was deleted */
#define FS_MOVE_SELF		0x00000800	/* Self was moved */

#define FS_UNMOUNT		0x00002000	/* inode on umount fs */
#define FS_Q_OVERFLOW		0x00004000	/* Event queued overflowed */
#define FS_IN_IGNORED		0x00008000	/* last inotify event here */

#define FS_IN_ISDIR		0x40000000	/* event occurred against dir */
#define FS_IN_ONESHOT		0x80000000	/* only send event once */

#define FS_DN_RENAME		0x10000000	/* file renamed */
#define FS_DN_MULTISHOT		0x20000000	/* dnotify multishot */

/* This inode cares about things that happen to its children.  Always set for
 * dnotify and inotify. */
#define FS_EVENT_ON_CHILD	0x08000000

/* This is a list of all events that may get sent to a parernt based on fs event
 * happening to inodes inside that directory */
#define FS_EVENTS_POSS_ON_CHILD   (FS_ACCESS | FS_MODIFY | FS_ATTRIB |\
				   FS_CLOSE_WRITE | FS_CLOSE_NOWRITE | FS_OPEN |\
				   FS_MOVED_FROM | FS_MOVED_TO | FS_CREATE |\
				   FS_DELETE)

/* listeners that hard code group numbers near the top */
#define DNOTIFY_GROUP_NUM	UINT_MAX
#define INOTIFY_GROUP_NUM	(DNOTIFY_GROUP_NUM-1)

struct fsnotify_group;
struct fsnotify_event;
struct fsnotify_mark_entry;
struct fsnotify_event_private_data;

/*
 * Each group much define these ops.  The fsnotify infrastructure will call
 * these operations for each relevant group.
 *
 * should_send_event - given a group, inode, and mask this function determines
 *		if the group is interested in this event.
 * handle_event - main call for a group to handle an fs event
 * free_group_priv - called when a group refcnt hits 0 to clean up the private union
 * freeing-mark - this means that a mark has been flagged to die when everything
 *		finishes using it.  The function is supplied with what must be a
 *		valid group and inode to use to clean up.
 */
struct fsnotify_ops {
	bool (*should_send_event)(struct fsnotify_group *group, struct inode *inode, __u32 mask);
	int (*handle_event)(struct fsnotify_group *group, struct fsnotify_event *event);
	void (*free_group_priv)(struct fsnotify_group *group);
	void (*freeing_mark)(struct fsnotify_mark_entry *entry, struct fsnotify_group *group);
	void (*free_event_priv)(struct fsnotify_event_private_data *priv);
};

/*
 * A group is a "thing" that wants to receive notification about filesystem
 * events.  The mask holds the subset of event types this group cares about.
 * refcnt on a group is up to the implementor and at any moment if it goes 0
 * everything will be cleaned up.
 */
 //???????????????inotify?????????????????????????????????fsnotify_group
 //inotify_init()
struct fsnotify_group {
	/*
	 * global list of all groups receiving events from fsnotify.
	 * anchored by fsnotify_groups and protected by either fsnotify_grp_mutex
	 * or fsnotify_grp_srcu depending on write vs read.
	 */
	struct list_head group_list;

	/*
	 * Defines all of the event types in which this group is interested.
	 * This mask is a bitwise OR of the FS_* events from above.  Each time
	 * this mask changes for a group (if it changes) the correct functions
	 * must be called to update the global structures which indicate global
	 * interest in event types.
	 */
	__u32 mask; //??????????????????????????????

	/*
	 * How the refcnt is used is up to each group.  When the refcnt hits 0
	 * fsnotify will clean up all of the resources associated with this group.
	 * As an example, the dnotify group will always have a refcnt=1 and that
	 * will never change.  Inotify, on the other hand, has a group per
	 * inotify_init() and the refcnt will hit 0 only when that fd has been
	 * closed.
	 */
	atomic_t refcnt;		/* things with interest in this group */ /* ???????????? */
	unsigned int group_num;		/* simply prevents accidental group collision */

	const struct fsnotify_ops *ops;	/* how this group handles things *//* ??????????????????????????? inotify_fsnotify_ops*/

	/* needed to send notification to userspace */
	struct mutex notification_mutex;	/* protect the notification_list */
	struct list_head notification_list;	/* list of event_holder this group needs to send to userspace *//* ????????????group????????????????????????????????????????????? */
	wait_queue_head_t notification_waitq;	/* read() on the notification file blocks on this waitq */ /* ???????????????????????????????????? */
	unsigned int q_len;			/* events on the queue */
	unsigned int max_events;		/* maximum events allowed on the list */

	/* stores all fastapth entries assoc with this group so they can be cleaned on unregister */
	spinlock_t mark_lock;		/* protect mark_entries list */
	atomic_t num_marks;		/* 1 for each mark entry and 1 for not being
					 * past the point of no return when freeing
					 * a group */
	struct list_head mark_entries;	/* all inode mark entries for this group */

	/* prevents double list_del of group_list.  protected by global fsnotify_grp_mutex */
	bool on_group_list;

	/* groups can define private fields here or use the void *private */
	union {
		void *private;
#ifdef CONFIG_INOTIFY_USER
		struct inotify_group_private_data {
			spinlock_t	idr_lock;
			struct idr      idr;
			u32             last_wd;
			struct fasync_struct    *fa;    /* async notification */
			struct user_struct      *user;
		} inotify_data;
#endif
	};
};

/*
 * A single event can be queued in multiple group->notification_lists.
 *
 * each group->notification_list will point to an event_holder which in turns points
 * to the actual event that needs to be sent to userspace.
 *
 * Seemed cheaper to create a refcnt'd event and a small holder for every group
 * than create a different event for every group
 *
 */
struct fsnotify_event_holder {
	struct fsnotify_event *event;
	struct list_head event_list;
};

/*
 * Inotify needs to tack data onto an event.  This struct lets us later find the
 * correct private data of the correct group.
 */
struct fsnotify_event_private_data {
	struct fsnotify_group *group;
	struct list_head event_list;
};

/*
 * all of the information about the original object we want to now send to
 * a group.  If you want to carry more info from the accessing task to the
 * listener this structure is where you need to be adding fields.
 */
struct fsnotify_event {
	/*
	 * If we create an event we are also likely going to need a holder
	 * to link to a group.  So embed one holder in the event.  Means only
	 * one allocation for the common case where we only have one group
	 */
	struct fsnotify_event_holder holder;
	spinlock_t lock;	/* protection for the associated event_holder and private_list */
	/* to_tell may ONLY be dereferenced during handle_event(). */
	struct inode *to_tell;	/* either the inode the event happened to or its parent */
	/*
	 * depending on the event type we should have either a path or inode
	 * We hold a reference on path, but NOT on inode.  Since we have the ref on
	 * the path, it may be dereferenced at any point during this object's
	 * lifetime.  That reference is dropped when this object's refcnt hits
	 * 0.  If this event contains an inode instead of a path, the inode may
	 * ONLY be used during handle_event().
	 */
	union {
		struct path path;
		struct inode *inode;
	};
/* when calling fsnotify tell it if the data is a path or inode */
#define FSNOTIFY_EVENT_NONE	0
#define FSNOTIFY_EVENT_PATH	1
#define FSNOTIFY_EVENT_INODE	2
#define FSNOTIFY_EVENT_FILE	3
	int data_type;		/* which of the above union we have */
	atomic_t refcnt;	/* how many groups still are using/need to send this event */
	__u32 mask;		/* the type of access, bitwise OR for FS_* event types */

	u32 sync_cookie;	/* used to corrolate events, namely inotify mv events */
	char *file_name;
	size_t name_len;

	struct list_head private_data_list;	/* groups can store private data here */
};

/*
 * a mark is simply an entry attached to an in core inode which allows an
 * fsnotify listener to indicate they are either no longer interested in events
 * of a type matching mask or only interested in those events.
 *
 * these are flushed when an inode is evicted from core and may be flushed
 * when the inode is modified (as seen by fsnotify_access).  Some fsnotify users
 * (such as dnotify) will flush these when the open fd is closed and not at
 * inode eviction or modification.
 */
struct fsnotify_mark_entry {
	__u32 mask;			/* mask this mark entry is for */
	/* we hold ref for each i_list and g_list.  also one ref for each 'thing'
	 * in kernel that found and may be using this mark. */
	atomic_t refcnt;		/* active things looking at this mark */
	struct inode *inode;		/* inode this entry is associated with ?????????????????????inode*/
	struct fsnotify_group *group;	/* group this mark entry is for ???????????????group*/
	struct hlist_node i_list;	/* list of mark_entries by inode->i_fsnotify_mark_entries */
	struct list_head g_list;	/* list of mark_entries by group->i_fsnotify_mark_entries */
	spinlock_t lock;		/* protect group, inode, and killme */
	struct list_head free_i_list;	/* tmp list used when freeing this mark */
	struct list_head free_g_list;	/* tmp list used when freeing this mark */
	void (*free_mark)(struct fsnotify_mark_entry *entry); /* called on final put+free */
};

#ifdef CONFIG_FSNOTIFY

/* called from the vfs helpers */

/* main fsnotify call to send events */
extern void fsnotify(struct inode *to_tell, __u32 mask, void *data, int data_is,
		     const char *name, u32 cookie);
extern void __fsnotify_parent(struct dentry *dentry, __u32 mask);
extern void __fsnotify_inode_delete(struct inode *inode);
extern u32 fsnotify_get_cookie(void);

static inline int fsnotify_inode_watches_children(struct inode *inode)
{
	/* FS_EVENT_ON_CHILD is set if the inode may care */
	if (!(inode->i_fsnotify_mask & FS_EVENT_ON_CHILD))
		return 0;
	/* this inode might care about child events, does it care about the
	 * specific set of events that can happen on a child? */
	return inode->i_fsnotify_mask & FS_EVENTS_POSS_ON_CHILD;
}

/*
 * Update the dentry with a flag indicating the interest of its parent to receive
 * filesystem events when those events happens to this dentry->d_inode.
 */
static inline void __fsnotify_update_dcache_flags(struct dentry *dentry)
{
	struct dentry *parent;

	assert_spin_locked(&dcache_lock);
	assert_spin_locked(&dentry->d_lock);

	parent = dentry->d_parent;
	if (parent->d_inode && fsnotify_inode_watches_children(parent->d_inode))
		dentry->d_flags |= DCACHE_FSNOTIFY_PARENT_WATCHED;
	else
		dentry->d_flags &= ~DCACHE_FSNOTIFY_PARENT_WATCHED;
}

/*
 * fsnotify_d_instantiate - instantiate a dentry for inode
 * Called with dcache_lock held.
 */
static inline void __fsnotify_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (!inode)
		return;

	assert_spin_locked(&dcache_lock);

	spin_lock(&dentry->d_lock);
	__fsnotify_update_dcache_flags(dentry);
	spin_unlock(&dentry->d_lock);
}

/* called from fsnotify listeners, such as fanotify or dnotify */

/* must call when a group changes its ->mask */
extern void fsnotify_recalc_global_mask(void);
/* get a reference to an existing or create a new group */
extern struct fsnotify_group *fsnotify_obtain_group(unsigned int group_num,
						    __u32 mask,
						    const struct fsnotify_ops *ops);
/* run all marks associated with this group and update group->mask */
extern void fsnotify_recalc_group_mask(struct fsnotify_group *group);
/* drop reference on a group from fsnotify_obtain_group */
extern void fsnotify_put_group(struct fsnotify_group *group);

/* take a reference to an event */
extern void fsnotify_get_event(struct fsnotify_event *event);
extern void fsnotify_put_event(struct fsnotify_event *event);
/* find private data previously attached to an event and unlink it */
extern struct fsnotify_event_private_data *fsnotify_remove_priv_from_event(struct fsnotify_group *group,
									   struct fsnotify_event *event);

/* attach the event to the group notification queue */
extern int fsnotify_add_notify_event(struct fsnotify_group *group, struct fsnotify_event *event,
				     struct fsnotify_event_private_data *priv);
/* true if the group notification queue is empty */
extern bool fsnotify_notify_queue_is_empty(struct fsnotify_group *group);
/* return, but do not dequeue the first event on the notification queue */
extern struct fsnotify_event *fsnotify_peek_notify_event(struct fsnotify_group *group);
/* return AND dequeue the first event on the notification queue */
extern struct fsnotify_event *fsnotify_remove_notify_event(struct fsnotify_group *group);

/* functions used to manipulate the marks attached to inodes */

/* run all marks associated with an inode and update inode->i_fsnotify_mask */
extern void fsnotify_recalc_inode_mask(struct inode *inode);
extern void fsnotify_init_mark(struct fsnotify_mark_entry *entry, void (*free_mark)(struct fsnotify_mark_entry *entry));
/* find (and take a reference) to a mark associated with group and inode */
extern struct fsnotify_mark_entry *fsnotify_find_mark_entry(struct fsnotify_group *group, struct inode *inode);
/* attach the mark to both the group and the inode */
extern int fsnotify_add_mark(struct fsnotify_mark_entry *entry, struct fsnotify_group *group, struct inode *inode);
/* given a mark, flag it to be freed when all references are dropped */
extern void fsnotify_destroy_mark_by_entry(struct fsnotify_mark_entry *entry);
/* run all the marks in a group, and flag them to be freed */
extern void fsnotify_clear_marks_by_group(struct fsnotify_group *group);
extern void fsnotify_get_mark(struct fsnotify_mark_entry *entry);
extern void fsnotify_put_mark(struct fsnotify_mark_entry *entry);
extern void fsnotify_unmount_inodes(struct list_head *list);

/* put here because inotify does some weird stuff when destroying watches */
extern struct fsnotify_event *fsnotify_create_event(struct inode *to_tell, __u32 mask,
						    void *data, int data_is, const char *name,
						    u32 cookie, gfp_t gfp);

#else

static inline void fsnotify(struct inode *to_tell, __u32 mask, void *data, int data_is,
			    const char *name, u32 cookie)
{}

static inline void __fsnotify_parent(struct dentry *dentry, __u32 mask)
{}

static inline void __fsnotify_inode_delete(struct inode *inode)
{}

static inline void __fsnotify_update_dcache_flags(struct dentry *dentry)
{}

static inline void __fsnotify_d_instantiate(struct dentry *dentry, struct inode *inode)
{}

static inline u32 fsnotify_get_cookie(void)
{
	return 0;
}

static inline void fsnotify_unmount_inodes(struct list_head *list)
{}

#endif	/* CONFIG_FSNOTIFY */

#endif	/* __KERNEL __ */

#endif	/* __LINUX_FSNOTIFY_BACKEND_H */
