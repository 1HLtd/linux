#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <asm/cputime.h>

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime;
	struct timespec idle;
	u64 idletime;
	u64 nsec;
	u32 rem;
	int i;
#ifdef CONFIG_MMCG
	struct task_struct *tsk;
	struct cgroup_subsys_state *css = NULL;
	tsk = current_thread_info()->task;
	int in_cgroup = 0;
#endif

	idletime = 0;
#ifdef CONFIG_MEMCG
	if (tsk != NULL) {
		css = task_css(tsk, mem_cgroup_subsys_id);
		if (strlen(css->cgroup->name->name) > 1) {
			uptime = tsk->real_start_time;
//			uptime = tsk->start_time;
		}
	} else {
#endif
		for_each_possible_cpu(i)
			idletime += (__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

		get_monotonic_boottime(&uptime);
		nsec = cputime64_to_jiffies64(idletime) * TICK_NSEC;
		idle.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
		idle.tv_nsec = rem;
#ifdef CONFIG_MEMCG
	}
#endif

	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			in_cgroup ? 0 : (unsigned long) idle.tv_sec,
			in_cgroup ? 0 : (idle.tv_nsec / (NSEC_PER_SEC / 100)));
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
	proc_create("uptime", 0, NULL, &uptime_proc_fops);
	return 0;
}
module_init(proc_uptime_init);
