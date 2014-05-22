#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <asm/cputime.h>
#ifdef CONFIG_MEMCG
#include <linux/cgroup.h>
#endif

int get_cgroup_uptime(struct timespec *cgroup_uptime)
{
#ifdef CONFIG_MEMCG
	struct task_struct *root_tsk;
	struct cgroup_subsys_state *css = NULL;
	// initialize uptime in case something fails
	cgroup_uptime->tv_sec = 0;
	cgroup_uptime->tv_nsec = 0;
	css = task_css(current, mem_cgroup_subsys_id);
	if (strlen(css->cgroup->name->name) > 1) {
		/* now, get the first process from this cgroup */
		int count = 0;
		struct cgrp_cset_link *link;
		list_for_each_entry(link, &css->cgroup->cset_links, cset_link) {
			struct css_set *cset = link->cset;
			list_for_each_entry(root_tsk, &cset->tasks, cg_list) {
				if (count > 10000) {
					break;
				} else {
					/* Assign the uptime here, otherwise the pointer will be invalid. */
					cgroup_uptime = root_tsk->start_time;
				}
				count++;
			}
		}
		// In cgroup
		return 1;
	}
#endif
	// not in cgroup
	return 0;
}

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime;
	struct timespec idle;
	struct timespec cgroup_uptime;
	u64 idletime;
	u64 nsec;
	u32 rem;
	int i;

	idletime = 0;
	uptime.tv_sec = 0;
	uptime.tv_nsec = 0;

	for_each_possible_cpu(i)
		idletime += (__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

	get_monotonic_boottime(&uptime);
	nsec = cputime64_to_jiffies64(idletime) * TICK_NSEC;
	idle.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
	idle.tv_nsec = rem;

	if (get_cgroup_uptime(&cgroup_uptime))
		seq_printf(m, "%lu.%02lu 0.0\n",
			(unsigned long) uptime.tv_sec - cgroup_uptime.tv_sec,
			((uptime.tv_nsec - cgroup_uptime.tv_nsec) / (NSEC_PER_SEC / 100)));
	else
		seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int uptime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, uptime_proc_show, NULL);
}

static const struct file_operations uptime_proc_fops = {
	.open		= uptime_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_uptime_init(void)
{
	proc_create("uptime", S_IRUGO, NULL, &uptime_proc_fops);
	return 0;
}
module_init(proc_uptime_init);
