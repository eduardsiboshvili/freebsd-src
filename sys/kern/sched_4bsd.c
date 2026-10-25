/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_hwpmc_hooks.h"
#include "opt_hwt_hooks.h"
#include "opt_sched.h"
#include "opt_doorfs.h"

#include <sys/systm.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/runq.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#ifdef DOORFS
#include <sys/sleepqueue.h>
#endif
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/turnstile.h>
#include <sys/umtxvar.h>
#include <machine/pcb.h>
#include <machine/smp.h>

#ifdef HWPMC_HOOKS
#include <sys/pmckern.h>
#endif

#ifdef HWT_HOOKS
#include <dev/hwt/hwt_hook.h>
#endif

/*
 * INVERSE_ESTCPU_WEIGHT is only suitable for statclock() frequencies in
 * the range 100-256 Hz (approximately).
 */
#define	INVERSE_ESTCPU_WEIGHT	8	/* 1 / (priorities per estcpu level). */
#define	NICE_WEIGHT		1	/* Priorities per nice level. */
_Static_assert(NICE_WEIGHT * (PRIO_MAX - PRIO_MIN)
    <= PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE,
    "Priority range accounting for nice values cannot exceed the including "
    "timeshare span.");
#define	ESTCPULIM(e)							\
	min((e), INVERSE_ESTCPU_WEIGHT *				\
	    (PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE -			\
	    (PRIO_MAX - PRIO_MIN) * NICE_WEIGHT)			\
	    + INVERSE_ESTCPU_WEIGHT - 1)

#define	TS_NAME_LEN (MAXCOMLEN + sizeof(" td ") + sizeof(__XSTRING(UINT_MAX)))

/*
 * The schedulable entity that runs a context.
 * This is  an extension to the thread structure and is tailored to
 * the requirements of this scheduler.
 * All fields are protected by the scheduler lock.
 */
struct td_sched {
	fixpt_t		ts_pctcpu;	/* %cpu during p_swtime. */
	u_int		ts_estcpu;	/* Estimated cpu utilization. */
	int		ts_cpticks;	/* Ticks of cpu time. */
	int		ts_slptime;	/* Seconds !RUNNING. */
	int		ts_slice;	/* Remaining part of time slice. */
	int		ts_flags;
	int		ts_rqcpu;	/* That CPU's runq or NOCPU => global */
#ifdef DOORFS
	struct sched_shuttle ts_shuttle; /* Scheduler handoff state. */
#endif
#ifdef KTR
	char		ts_name[TS_NAME_LEN];
#endif
};

/* flags kept in td_flags */
#define TDF_DIDRUN	TDF_SCHED0	/* thread actually ran. */
#define TDF_BOUND	TDF_SCHED1	/* Bound to one CPU. */
#define	TDF_SLICEEND	TDF_SCHED2	/* Thread time slice is over. */

#define	TDP_RESCHED	TDP_SCHED1	/* Reschedule due to maybe_resched(). */

/* flags kept in ts_flags */
#define	TSF_AFFINITY	0x0001		/* Has a non-"full" CPU set. */
#define	TSF_DOOR_LOCAL	0x0002		/* Keep an active Door thread local. */

#ifdef SMP
#define TS_RUNQ_PTR(ts)	((ts)->ts_rqcpu == NOCPU ?	\
		(&runq_global) : (DPCPU_ID_PTR((ts)->ts_rqcpu, runq_pcpu)))
#else
#define TS_RUNQ_PTR(ts)	(&runq_global)
#endif

#define	THREAD_CAN_SCHED(td, cpu)	\
    CPU_ISSET((cpu), &(td)->td_cpuset->cs_mask)

_Static_assert(sizeof(struct thread) + sizeof(struct td_sched) <=
    sizeof(struct thread0_storage),
    "increase struct thread0_storage.t0st_sched size");

static struct mtx sched_lock;

static int	realstathz = 127; /* stathz is sometimes 0 and run off of hz. */
static int	sched_tdcnt;	/* Total runnable threads in the system. */
static int	sched_slice = 12; /* Thread run time before rescheduling. */

static inline void
sched_update_hogticks(void)
{
	hogticks = imax(1, (2 * hz * sched_slice + realstathz / 2) /
	    realstathz);
}

static void	setup_runqs(void);
static void	schedcpu(void);
static void	schedcpu_thread(void);
static void	sched_priority(struct thread *td, u_char prio);
static void	maybe_resched(struct thread *td);
static void	updatepri(struct thread *td);
static void	resetpriority(struct thread *td);
static void	resetpriority_thread(struct thread *td);
#ifdef DOORFS
static inline struct sched_shuttle *sched_4bsd_shuttle_state(struct thread *);
static void sched_4bsd_wakeup_account(struct thread *);
static struct thread *sched_4bsd_shuttle_choose(void);
static enum sched_shuttle_result sched_4bsd_shuttle_resume_to(struct thread *,
    struct thread *, int);
static enum sched_shuttle_result sched_4bsd_shuttle_park(struct thread *, int);
static enum sched_shuttle_result sched_4bsd_shuttle_switch(struct thread *,
    int);
static enum sched_shuttle_result sched_4bsd_shuttle_wakeup(struct thread *,
    int);
static void sched_4bsd_shuttle_wakeup_async(struct thread *);
static void sched_4bsd_shuttle_cancel(struct thread *, int);
static void sched_4bsd_shuttle_unpark(struct thread *, int);
static void sched_4bsd_shuttle_abort(struct thread *);
static void sched_4bsd_shuttle_restore_locked(struct sched_shuttle_token *);
#endif
#ifdef SMP
static int	sched_pickcpu(struct thread *td);
static int	sched_pickcpu_door(struct thread *td);
static int	forward_wakeup(int cpunum);
static void	kick_other_cpu(struct thread *td, int cpuid, bool equal);
#endif

static struct kproc_desc sched_kp = {
        "schedcpu",
        schedcpu_thread,
        NULL
};

static void
sched_4bsd_sysinit(void)
{
	kproc_start(&sched_kp);
}

/*
 * Global run queue.
 */
static struct runq runq_global;

#ifdef SMP
/*
 * Per-CPU run queues
 */
DPCPU_DEFINE_STATIC(struct runq, runq_pcpu);
DPCPU_DEFINE_STATIC(long, runq_length);
#ifdef DOORFS
DPCPU_DEFINE_STATIC(u_int, door_idle_hot);
DPCPU_DEFINE_STATIC(u_int, door_idle_spinning);
DPCPU_DEFINE_STATIC(u_char, door_remote_handoff);
DPCPU_DEFINE_STATIC(struct thread *, door_idle_handoff);
#endif

static cpuset_t idle_cpus_mask;
#endif

struct pcpuidlestat {
	u_int idlecalls;
	u_int oldidlecalls;
};
DPCPU_DEFINE_STATIC(struct pcpuidlestat, idlestat);

#ifdef DOORFS
/* One exact successor reservation per CPU, protected by sched_lock. */
DPCPU_DEFINE_STATIC(struct sched_shuttle_token, shuttle_token);
#endif

static void
setup_runqs(void)
{
#ifdef SMP
	int cpu;

	CPU_FOREACH(cpu)
		runq_init(DPCPU_ID_PTR(cpu, runq_pcpu));
#endif

	runq_init(&runq_global);
}

static int
sysctl_kern_4bsd_quantum(SYSCTL_HANDLER_ARGS)
{
	int error, new_val, period;

	period = 1000000 / realstathz;
	new_val = period * sched_slice;
	error = sysctl_handle_int(oidp, &new_val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (new_val <= 0)
		return (EINVAL);
	sched_slice = imax(1, (new_val + period / 2) / period);
	sched_update_hogticks();
	return (0);
}

static int
sysctl_kern_slice(SYSCTL_HANDLER_ARGS)
{
	int error, new_val;

	new_val = sched_slice;
	error = sysctl_handle_int(oidp, &new_val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (new_val <= 0)
		return (EINVAL);
	sched_slice = new_val;
	sched_update_hogticks();
	return (0);
}

SYSCTL_NODE(_kern_sched, OID_AUTO, 4bsd, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "4BSD Scheduler");

SYSCTL_PROC(_kern_sched_4bsd, OID_AUTO, quantum,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_kern_4bsd_quantum, "I",
    "Quantum for timeshare threads in microseconds");
SYSCTL_PROC(_kern_sched_4bsd, OID_AUTO, slice,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_kern_slice, "I",
    "Quantum for timeshare threads in stathz ticks");
#ifdef SMP
/* Enable forwarding of wakeups to all other cpus */
static SYSCTL_NODE(_kern_sched_4bsd, OID_AUTO, ipiwakeup,
    CTLFLAG_RD | CTLFLAG_MPSAFE, NULL,
    "Kernel SMP");

static int runq_fuzz = 1;
SYSCTL_INT(_kern_sched_4bsd, OID_AUTO, runq_fuzz, CTLFLAG_RW,
    &runq_fuzz, 0, "");

#ifdef DOORFS
/* Match ULE's default length, but spin only after Door activity. */
static u_int door_idlespins = 10000;
SYSCTL_UINT(_kern_sched_4bsd, OID_AUTO, door_idlespins, CTLFLAG_RWTUN,
    &door_idlespins, 0, "Door-hot idle spin iterations");


#endif

static int forward_wakeup_enabled = 1;
SYSCTL_INT(_kern_sched_4bsd_ipiwakeup, OID_AUTO, enabled, CTLFLAG_RW,
	   &forward_wakeup_enabled, 0,
	   "Forwarding of wakeup to idle CPUs");

static int forward_wakeups_requested = 0;
SYSCTL_INT(_kern_sched_4bsd_ipiwakeup, OID_AUTO, requested, CTLFLAG_RD,
	   &forward_wakeups_requested, 0,
	   "Requests for Forwarding of wakeup to idle CPUs");

static int forward_wakeups_delivered = 0;
SYSCTL_INT(_kern_sched_4bsd_ipiwakeup, OID_AUTO, delivered, CTLFLAG_RD,
	   &forward_wakeups_delivered, 0,
	   "Completed Forwarding of wakeup to idle CPUs");

static int forward_wakeup_use_mask = 1;
SYSCTL_INT(_kern_sched_4bsd_ipiwakeup, OID_AUTO, usemask, CTLFLAG_RW,
	   &forward_wakeup_use_mask, 0,
	   "Use the mask of idle cpus");

static int forward_wakeup_use_loop = 0;
SYSCTL_INT(_kern_sched_4bsd_ipiwakeup, OID_AUTO, useloop, CTLFLAG_RW,
	   &forward_wakeup_use_loop, 0,
	   "Use a loop to find idle cpus");

#endif

static __inline void
sched_load_add(void)
{

	sched_tdcnt++;
	KTR_COUNTER0(KTR_SCHED, "load", "global load", sched_tdcnt);
	SDT_PROBE2(sched, , , load__change, NOCPU, sched_tdcnt);
}

static __inline void
sched_load_rem(void)
{

	sched_tdcnt--;
	KTR_COUNTER0(KTR_SCHED, "load", "global load", sched_tdcnt);
	SDT_PROBE2(sched, , , load__change, NOCPU, sched_tdcnt);
}

static void
maybe_resched_ast(struct thread *td, int tda)
{
	MPASS(td == curthread);		/* We are AST */
	if ((td->td_pflags & TDP_RESCHED) != 0) {
		td->td_pflags &= ~TDP_RESCHED;
		ast_scheduler(td, tda);
	}
}

/*
 * Arrange to reschedule if necessary, taking the priorities and
 * schedulers into account.
 */
static void
maybe_resched(struct thread *td)
{
	struct thread *ctd;

	ctd = curthread;
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (td->td_priority < ctd->td_priority)
		ctd->td_pflags |= TDP_RESCHED;
}

/*
 * This function is called when a thread is about to be put on run queue
 * because it has been made runnable or its priority has been adjusted.  It
 * determines if the new thread should preempt the current thread.  If so,
 * it sets td_owepreempt to request a preemption.
 */
static int
maybe_preempt(struct thread *td)
{
#ifdef PREEMPTION
	struct thread *ctd;
	int cpri, pri;

	/*
	 * The new thread should not preempt the current thread if any of the
	 * following conditions are true:
	 *
	 *  - The kernel is in the throes of crashing (panicstr).
	 *  - The current thread has a higher (numerically lower) or
	 *    equivalent priority.  Note that this prevents curthread from
	 *    trying to preempt to itself.
	 *  - The current thread has an inhibitor set or is in the process of
	 *    exiting.  In this case, the current thread is about to switch
	 *    out anyways, so there's no point in preempting.  If we did,
	 *    the current thread would not be properly resumed as well, so
	 *    just avoid that whole landmine.
	 *  - If the new thread's priority is not an interrupt priority and
	 *    the current thread's priority is not an idle priority and
	 *    FULL_PREEMPTION is disabled.
	 *
	 * If all of these conditions are false, but the current thread is in
	 * a nested critical section, then we have to defer the preemption
	 * until we exit the critical section.  Otherwise, switch immediately
	 * to the new thread.
	 */
	ctd = curthread;
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT((td->td_inhibitors == 0),
			("maybe_preempt: trying to run inhibited thread"));
	pri = td->td_priority;
	cpri = ctd->td_priority;
	if (KERNEL_PANICKED() || pri >= cpri || TD_IS_INHIBITED(ctd))
		return (0);
#ifndef FULL_PREEMPTION
	if (pri > PRI_MAX_ITHD && cpri < PRI_MIN_IDLE)
		return (0);
#endif

	CTR0(KTR_PROC, "maybe_preempt: scheduling preemption");
	ctd->td_owepreempt = 1;
	return (1);
#else
	return (0);
#endif
}

/*
 * Constants for digital decay and forget:
 *	90% of (ts_estcpu) usage in 5 * loadav time
 *	95% of (ts_pctcpu) usage in 60 seconds (load insensitive)
 *          Note that, as ps(1) mentions, this can let percentages
 *          total over 100% (I've seen 137.9% for 3 processes).
 *
 * Note that sched_clock() updates ts_estcpu and p_cpticks asynchronously.
 *
 * We wish to decay away 90% of ts_estcpu in (5 * loadavg) seconds.
 * That is, the system wants to compute a value of decay such
 * that the following for loop:
 * 	for (i = 0; i < (5 * loadavg); i++)
 * 		ts_estcpu *= decay;
 * will compute
 * 	ts_estcpu *= 0.1;
 * for all values of loadavg:
 *
 * Mathematically this loop can be expressed by saying:
 * 	decay ** (5 * loadavg) ~= .1
 *
 * The system computes decay as:
 * 	decay = (2 * loadavg) / (2 * loadavg + 1)
 *
 * We wish to prove that the system's computation of decay
 * will always fulfill the equation:
 * 	decay ** (5 * loadavg) ~= .1
 *
 * If we compute b as:
 * 	b = 2 * loadavg
 * then
 * 	decay = b / (b + 1)
 *
 * We now need to prove two things:
 *	1) Given factor ** (5 * loadavg) ~= .1, prove factor == b/(b+1)
 *	2) Given b/(b+1) ** power ~= .1, prove power == (5 * loadavg)
 *
 * Facts:
 *         For x close to zero, exp(x) =~ 1 + x, since
 *              exp(x) = 0! + x**1/1! + x**2/2! + ... .
 *              therefore exp(-1/b) =~ 1 - (1/b) = (b-1)/b.
 *         For x close to zero, ln(1+x) =~ x, since
 *              ln(1+x) = x - x**2/2 + x**3/3 - ...     -1 < x < 1
 *              therefore ln(b/(b+1)) = ln(1 - 1/(b+1)) =~ -1/(b+1).
 *         ln(.1) =~ -2.30
 *
 * Proof of (1):
 *    Solve (factor)**(power) =~ .1 given power (5*loadav):
 *	solving for factor,
 *      ln(factor) =~ (-2.30/5*loadav), or
 *      factor =~ exp(-1/((5/2.30)*loadav)) =~ exp(-1/(2*loadav)) =
 *          exp(-1/b) =~ (b-1)/b =~ b/(b+1).                    QED
 *
 * Proof of (2):
 *    Solve (factor)**(power) =~ .1 given factor == (b/(b+1)):
 *	solving for power,
 *      power*ln(b/(b+1)) =~ -2.30, or
 *      power =~ 2.3 * (b + 1) = 4.6*loadav + 2.3 =~ 5*loadav.  QED
 *
 * Actual power values for the implemented algorithm are as follows:
 *      loadav: 1       2       3       4
 *      power:  5.68    10.32   14.94   19.55
 */

/* calculations for digital decay to forget 90% of usage in 5*loadav sec */
#define	loadfactor(loadav)	(2 * (loadav))
#define	decay_cpu(loadfac, cpu)	(((loadfac) * (cpu)) / ((loadfac) + FSCALE))

extern fixpt_t ccpu;

/*
 * If `ccpu' is not equal to `exp(-1/20)' and you still want to use the
 * faster/more-accurate formula, you'll have to estimate CCPU_SHIFT below
 * and possibly adjust FSHIFT in "param.h" so that (FSHIFT >= CCPU_SHIFT).
 *
 * To estimate CCPU_SHIFT for exp(-1/20), the following formula was used:
 *	1 - exp(-1/20) ~= 0.0487 ~= 0.0488 == 1 (fixed pt, *11* bits).
 *
 * If you don't want to bother with the faster/more-accurate formula, you
 * can set CCPU_SHIFT to (FSHIFT + 1) which will use a slower/less-accurate
 * (more general) method of calculating the %age of CPU used by a process.
 */
#define	CCPU_SHIFT	11

/*
 * Recompute process priorities, every hz ticks.
 * MP-safe, called without the Giant mutex.
 */
/* ARGSUSED */
static void
schedcpu(void)
{
	fixpt_t loadfac = loadfactor(averunnable.ldavg[0]);
	struct thread *td;
	struct proc *p;
	struct td_sched *ts;
	int awake;

	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);
		if (p->p_state == PRS_NEW) {
			PROC_UNLOCK(p);
			continue;
		}
		FOREACH_THREAD_IN_PROC(p, td) {
			awake = 0;
			ts = td_get_sched(td);
			thread_lock(td);
			/*
			 * Increment sleep time (if sleeping).  We
			 * ignore overflow, as above.
			 */
			if (TD_ON_RUNQ(td)) {
				awake = 1;
				td->td_flags &= ~TDF_DIDRUN;
			} else if (TD_IS_RUNNING(td)) {
				awake = 1;
				/* Do not clear TDF_DIDRUN */
			} else if (td->td_flags & TDF_DIDRUN) {
				awake = 1;
				td->td_flags &= ~TDF_DIDRUN;
			}

			/*
			 * ts_pctcpu is only for ps and ttyinfo().
			 */
			ts->ts_pctcpu = (ts->ts_pctcpu * ccpu) >> FSHIFT;
			if (ts->ts_cpticks != 0) {
#if	(FSHIFT >= CCPU_SHIFT)
				ts->ts_pctcpu += (realstathz == 100)
				    ? ((fixpt_t) ts->ts_cpticks) <<
				    (FSHIFT - CCPU_SHIFT) :
				    100 * (((fixpt_t) ts->ts_cpticks)
				    << (FSHIFT - CCPU_SHIFT)) / realstathz;
#else
				ts->ts_pctcpu += ((FSCALE - ccpu) *
				    (ts->ts_cpticks *
				    FSCALE / realstathz)) >> FSHIFT;
#endif
				ts->ts_cpticks = 0;
			}

			if (awake) {
				if (ts->ts_slptime > 1) {
					/*
					 * In an ideal world, this should not
					 * happen, because whoever woke us
					 * up from the long sleep should have
					 * unwound the slptime and reset our
					 * priority before we run at the stale
					 * priority.  Should KASSERT at some
					 * point when all the cases are fixed.
					 */
					updatepri(td);
				}
				ts->ts_slptime = 0;
			} else
				ts->ts_slptime++;

			/*
			 * If the td_sched has been idle the entire second,
			 * stop recalculating its priority until
			 * it wakes up.
			 */
			if (ts->ts_slptime > 1) {
				thread_unlock(td);
				continue;
			}
			ts->ts_estcpu = decay_cpu(loadfac, ts->ts_estcpu);
		      	resetpriority(td);
			resetpriority_thread(td);
			thread_unlock(td);
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&allproc_lock);
}

/*
 * Main loop for a kthread that executes schedcpu once a second.
 */
static void
schedcpu_thread(void)
{

	for (;;) {
		schedcpu();
		pause("-", hz);
	}
}

/*
 * Recalculate the priority of a process after it has slept for a while.
 * For all load averages >= 1 and max ts_estcpu of 255, sleeping for at
 * least six times the loadfactor will decay ts_estcpu to zero.
 */
static void
updatepri(struct thread *td)
{
	struct td_sched *ts;
	fixpt_t loadfac;
	unsigned int newcpu;

	ts = td_get_sched(td);
	loadfac = loadfactor(averunnable.ldavg[0]);
	if (ts->ts_slptime > 5 * loadfac)
		ts->ts_estcpu = 0;
	else {
		newcpu = ts->ts_estcpu;
		/* schedcpu() performs one decay_cpu() on its own. */
		ts->ts_slptime--;
		while (newcpu && --ts->ts_slptime)
			newcpu = decay_cpu(loadfac, newcpu);
		ts->ts_estcpu = newcpu;
	}
}

/*
 * Compute the priority of a process when running in user mode.
 * Arrange to reschedule if the resulting priority is better
 * than that of the current process.
 */
static void
resetpriority(struct thread *td)
{
	u_int newpriority;

	if (td->td_pri_class != PRI_TIMESHARE)
		return;
	newpriority = PRI_MIN_TIMESHARE +
	    td_get_sched(td)->ts_estcpu / INVERSE_ESTCPU_WEIGHT +
	    NICE_WEIGHT * (td->td_proc->p_nice - PRIO_MIN);
	KASSERT(PRI_MIN_TIMESHARE <= newpriority &&
	    newpriority <= PRI_MAX_TIMESHARE,
	    ("Out-of-bounds priority, probably 'ts_estcpu' not clamped "
	    "correctly, see ESTCPULIM()"));
	sched_user_prio(td, newpriority);
}

/*
 * Update the thread's priority when the associated process's user
 * priority changes.
 */
static void
resetpriority_thread(struct thread *td)
{

	/* Only change threads with a time sharing user priority. */
	if (td->td_priority < PRI_MIN_TIMESHARE ||
	    td->td_priority > PRI_MAX_TIMESHARE)
		return;

	/* XXX the whole needresched thing is broken, but not silly. */
	maybe_resched(td);

	sched_prio(td, td->td_user_pri);
}

static void
sched_4bsd_setup(void)
{
	/*
	 * Decay 95% of `ts_pctcpu' in 60 seconds; see CCPU_SHIFT
	 * before changing.
	 */
	ccpu = 0.95122942450071400909 * FSCALE;	/* exp(-1/20) */

	setup_runqs();

	/* Account for thread0. */
	sched_load_add();

	ast_register(TDA_SCHED_PRIV, ASTR_UNCOND, 0, maybe_resched_ast);
}

/*
 * This routine determines time constants after stathz and hz are setup.
 */
static void
sched_4bsd_initticks(void)
{

	realstathz = stathz ? stathz : hz;
	sched_slice = realstathz / 10;	/* ~100ms */
	sched_update_hogticks();
}

/* External interfaces start here */

/*
 * Very early in the boot some setup of scheduler-specific
 * parts of proc0 and of some scheduler resources needs to be done.
 * Called from:
 *  proc0_init()
 */
static void
sched_4bsd_init(void)
{

	/*
	 * Set up the scheduler specific parts of thread0.
	 */
	thread0.td_lock = &sched_lock;
	td_get_sched(&thread0)->ts_slice = sched_slice;
	mtx_init(&sched_lock, "sched lock", NULL, MTX_SPIN);
}

static void
sched_4bsd_init_ap(void)
{

	/* Nothing needed. */
}

static bool
sched_4bsd_runnable(void)
{
#ifdef SMP
	return (runq_not_empty(&runq_global) ||
	    runq_not_empty(DPCPU_PTR(runq_pcpu)));
#else
	return (runq_not_empty(&runq_global));
#endif
}

static int
sched_4bsd_rr_interval(void)
{

	/* Convert sched_slice from stathz to hz. */
	return (imax(1, (sched_slice * hz + realstathz / 2) / realstathz));
}

/*
 * We adjust the priority of the current process.  The priority of a
 * process gets worse as it accumulates CPU time.  The cpu usage
 * estimator (ts_estcpu) is increased here.  resetpriority() will
 * compute a different priority each time ts_estcpu increases by
 * INVERSE_ESTCPU_WEIGHT (until PRI_MAX_TIMESHARE is reached).  The
 * cpu usage estimator ramps up quite quickly when the process is
 * running (linearly), and decays away exponentially, at a rate which
 * is proportionally slower when the system is busy.  The basic
 * principle is that the system will 90% forget that the process used
 * a lot of CPU time in 5 * loadav seconds.  This causes the system to
 * favor processes which haven't run much recently, and to round-robin
 * among other processes.
 */
static void
sched_clock_tick(struct thread *td)
{
	struct pcpuidlestat *stat;
	struct td_sched *ts;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	ts = td_get_sched(td);

	ts->ts_cpticks++;
	ts->ts_estcpu = ESTCPULIM(ts->ts_estcpu + 1);
	if ((ts->ts_estcpu % INVERSE_ESTCPU_WEIGHT) == 0) {
		resetpriority(td);
		resetpriority_thread(td);
	}

	/*
	 * Force a context switch if the current thread has used up a full
	 * time slice (default is 100ms).
	 */
	if (!TD_IS_IDLETHREAD(td) && --ts->ts_slice <= 0) {
		ts->ts_slice = sched_slice;

		/*
		 * If an ithread uses a full quantum, demote its
		 * priority and preempt it.
		 */
		if (PRI_BASE(td->td_pri_class) == PRI_ITHD) {
			SCHED_STAT_INC(ithread_preemptions);
			td->td_owepreempt = 1;
			if (td->td_base_pri + RQ_PPQ < PRI_MAX_ITHD) {
				SCHED_STAT_INC(ithread_demotions);
				sched_prio(td, td->td_base_pri + RQ_PPQ);
			}
		} else {
			td->td_flags |= TDF_SLICEEND;
			ast_sched_locked(td, TDA_SCHED);
		}
	}

	stat = DPCPU_PTR(idlestat);
	stat->oldidlecalls = stat->idlecalls;
	stat->idlecalls = 0;
}

static void
sched_4bsd_clock(struct thread *td, int cnt)
{

	for ( ; cnt > 0; cnt--)
		sched_clock_tick(td);
}

/*
 * Charge child's scheduling CPU usage to parent.
 */
static void
sched_4bsd_exit(struct proc *p, struct thread *td)
{

	KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "proc exit",
	    "prio:%d", td->td_priority);

	PROC_LOCK_ASSERT(p, MA_OWNED);
	sched_exit_thread(FIRST_THREAD_IN_PROC(p), td);
}

static void
sched_4bsd_exit_thread(struct thread *td, struct thread *child)
{

	KTR_STATE1(KTR_SCHED, "thread", sched_tdname(child), "exit",
	    "prio:%d", child->td_priority);
	thread_lock(td);
	td_get_sched(td)->ts_estcpu = ESTCPULIM(td_get_sched(td)->ts_estcpu +
	    td_get_sched(child)->ts_estcpu);
	thread_unlock(td);
	thread_lock(child);
	if ((child->td_flags & TDF_NOLOAD) == 0)
		sched_load_rem();
	thread_unlock(child);
}

static void
sched_4bsd_fork(struct thread *td, struct thread *childtd)
{
	sched_fork_thread(td, childtd);
}

static void
sched_4bsd_fork_thread(struct thread *td, struct thread *childtd)
{
	struct td_sched *ts, *tsc;

	childtd->td_oncpu = NOCPU;
	childtd->td_lastcpu = NOCPU;
	childtd->td_lock = &sched_lock;
	childtd->td_cpuset = cpuset_ref(td->td_cpuset);
	childtd->td_domain.dr_policy = td->td_cpuset->cs_domain;
	childtd->td_priority = childtd->td_base_pri;
	ts = td_get_sched(childtd);
	bzero(ts, sizeof(*ts));
	tsc = td_get_sched(td);
	ts->ts_estcpu = tsc->ts_estcpu;
	ts->ts_flags |= (tsc->ts_flags & TSF_AFFINITY);
	ts->ts_slice = 1;
}

static void
sched_4bsd_nice(struct proc *p, int nice)
{
	struct thread *td;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	p->p_nice = nice;
	FOREACH_THREAD_IN_PROC(p, td) {
		thread_lock(td);
		resetpriority(td);
		resetpriority_thread(td);
		thread_unlock(td);
	}
}

static void
sched_4bsd_class(struct thread *td, int class)
{
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	td->td_pri_class = class;
}

/*
 * Adjust the priority of a thread.
 */
static void
sched_priority(struct thread *td, u_char prio)
{

	KTR_POINT3(KTR_SCHED, "thread", sched_tdname(td), "priority change",
	    "prio:%d", td->td_priority, "new prio:%d", prio, KTR_ATTR_LINKED,
	    sched_tdname(curthread));
	SDT_PROBE3(sched, , , change__pri, td, td->td_proc, prio);
	if (td != curthread && prio > td->td_priority) {
		KTR_POINT3(KTR_SCHED, "thread", sched_tdname(curthread),
		    "lend prio", "prio:%d", td->td_priority, "new prio:%d",
		    prio, KTR_ATTR_LINKED, sched_tdname(td));
		SDT_PROBE4(sched, , , lend__pri, td, td->td_proc, prio, 
		    curthread);
	}
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (td->td_priority == prio)
		return;
	td->td_priority = prio;
	if (TD_ON_RUNQ(td) && td->td_rqindex != RQ_PRI_TO_QUEUE_IDX(prio)) {
		sched_rem(td);
		sched_add(td, SRQ_BORING | SRQ_HOLDTD);
	}
}

/*
 * Update a thread's priority when it is lent another thread's
 * priority.
 */
static void
sched_4bsd_lend_prio(struct thread *td, u_char prio)
{

	td->td_flags |= TDF_BORROWING;
	sched_priority(td, prio);
}

/*
 * Restore a thread's priority when priority propagation is
 * over.  The prio argument is the minimum priority the thread
 * needs to have to satisfy other possible priority lending
 * requests.  If the thread's regulary priority is less
 * important than prio the thread will keep a priority boost
 * of prio.
 */
static void
sched_4bsd_unlend_prio(struct thread *td, u_char prio)
{
	u_char base_pri;

	if (td->td_base_pri >= PRI_MIN_TIMESHARE &&
	    td->td_base_pri <= PRI_MAX_TIMESHARE)
		base_pri = td->td_user_pri;
	else
		base_pri = td->td_base_pri;
	if (prio >= base_pri) {
		td->td_flags &= ~TDF_BORROWING;
		sched_prio(td, base_pri);
	} else
		sched_lend_prio(td, prio);
}

static void
sched_4bsd_prio(struct thread *td, u_char prio)
{
	u_char oldprio;

	/* First, update the base priority. */
	td->td_base_pri = prio;

	/*
	 * If the thread is borrowing another thread's priority, don't ever
	 * lower the priority.
	 */
	if (td->td_flags & TDF_BORROWING && td->td_priority < prio)
		return;

	/* Change the real priority. */
	oldprio = td->td_priority;
	sched_priority(td, prio);

	/*
	 * If the thread is on a turnstile, then let the turnstile update
	 * its state.
	 */
	if (TD_ON_LOCK(td) && oldprio != prio)
		turnstile_adjust(td, oldprio);
}

static void
sched_4bsd_ithread_prio(struct thread *td, u_char prio)
{
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	MPASS(td->td_pri_class == PRI_ITHD);
	td->td_base_ithread_pri = prio;
	sched_prio(td, prio);
}

static void
sched_4bsd_user_prio(struct thread *td, u_char prio)
{

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	td->td_base_user_pri = prio;
	if (td->td_lend_user_pri <= prio)
		return;
	td->td_user_pri = prio;
}

static void
sched_4bsd_lend_user_prio(struct thread *td, u_char prio)
{

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	td->td_lend_user_pri = prio;
	td->td_user_pri = min(prio, td->td_base_user_pri);
	if (td->td_priority > td->td_user_pri)
		sched_prio(td, td->td_user_pri);
	else if (td->td_priority != td->td_user_pri)
		ast_sched_locked(td, TDA_SCHED);
}

/*
 * Like the above but first check if there is anything to do.
 */
static void
sched_4bsd_lend_user_prio_cond(struct thread *td, u_char prio)
{

	if (td->td_lend_user_pri == prio)
		return;

	thread_lock(td);
	sched_lend_user_prio(td, prio);
	thread_unlock(td);
}

static void
sched_4bsd_sleep(struct thread *td, int pri)
{

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	/* A real sleep ends the active Door run-to-wait interval. */
	td_get_sched(td)->ts_flags &= ~TSF_DOOR_LOCAL;
	td->td_slptick = ticks;
	td_get_sched(td)->ts_slptime = 0;
	if (pri != 0 && PRI_BASE(td->td_pri_class) == PRI_TIMESHARE)
		sched_prio(td, pri);
}

static void
sched_4bsd_switch(struct thread *td, int flags)
{
	struct thread *newtd;
	struct mtx *tmtx;
	int preempted;

	tmtx = &sched_lock;

	THREAD_LOCK_ASSERT(td, MA_OWNED);

	td->td_lastcpu = td->td_oncpu;
	preempted = (td->td_flags & TDF_SLICEEND) == 0 &&
	    (flags & SW_PREEMPT) != 0;
#ifdef DOORFS
#ifdef SMP
	/*
	 * An equal-priority remote Door wake must leave the interrupted thread
	 * behind the worker already published on this CPU's run queue.  Merely
	 * requesting a preemption would otherwise reinsert the current thread at
	 * the head through SRQ_PREEMPTED and can make the scheduler select it
	 * again before servicing the Door.
	 */
	if (atomic_load_char(DPCPU_PTR(door_remote_handoff)) != 0) {
		atomic_store_char(DPCPU_PTR(door_remote_handoff), 0);
		preempted = 0;
	}
#endif
#endif
	td->td_flags &= ~TDF_SLICEEND;
	ast_unsched_locked(td, TDA_SCHED);
	td->td_owepreempt = 0;
	td->td_oncpu = NOCPU;

	/*
	 * At the last moment, if this thread is still marked RUNNING,
	 * then put it back on the run queue as it has not been suspended
	 * or stopped or any thing else similar.  We never put the idle
	 * threads on the run queue, however.
	 */
	if (td->td_flags & TDF_IDLETD) {
		TD_SET_CAN_RUN(td);
#ifdef SMP
		CPU_CLR(PCPU_GET(cpuid), &idle_cpus_mask);
#endif
	} else {
		if (TD_IS_RUNNING(td)) {
			/* Put us back on the run queue. */
			sched_add(td, SRQ_HOLDTD | SRQ_OURSELF | SRQ_YIELDING |
			    (preempted ? SRQ_PREEMPTED : 0));
		}
	}

	/* 
	 * Switch to the sched lock to fix things up and pick
	 * a new thread.  Block the td_lock in order to avoid
	 * breaking the critical path.
	 */
	if (td->td_lock != &sched_lock) {
		mtx_lock_spin(&sched_lock);
		tmtx = thread_lock_block(td);
		mtx_unlock_spin(tmtx);
	}

	if ((td->td_flags & TDF_NOLOAD) == 0)
		sched_load_rem();

	newtd = choosethread();
	MPASS(newtd->td_lock == &sched_lock);

#if (KTR_COMPILE & KTR_SCHED) != 0
	if (TD_IS_IDLETHREAD(td))
		KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "idle",
		    "prio:%d", td->td_priority);
	else
		KTR_STATE3(KTR_SCHED, "thread", sched_tdname(td), KTDSTATE(td),
		    "prio:%d", td->td_priority, "wmesg:\"%s\"", td->td_wmesg,
		    "lockname:\"%s\"", td->td_lockname);
#endif

	if (td != newtd) {
#ifdef	HWPMC_HOOKS
		if (PMC_PROC_IS_USING_PMCS(td->td_proc))
			PMC_SWITCH_CONTEXT(td, PMC_FN_CSW_OUT);
#endif

#ifdef HWT_HOOKS
		HWT_CALL_HOOK(td, HWT_SWITCH_OUT, NULL);
		HWT_CALL_HOOK(newtd, HWT_SWITCH_IN, NULL);
#endif

		SDT_PROBE2(sched, , , off__cpu, newtd, newtd->td_proc);

                /* I feel sleepy */
		lock_profile_release_lock(&sched_lock.lock_object, true);
#ifdef KDTRACE_HOOKS
		/*
		 * If DTrace has set the active vtime enum to anything
		 * other than INACTIVE (0), then it should have set the
		 * function to call.
		 */
		if (dtrace_vtime_active)
			(*dtrace_vtime_switch_func)(newtd);
#endif

		cpu_switch(td, newtd, tmtx);
		lock_profile_obtain_lock_success(&sched_lock.lock_object, true,
		    0, 0, __FILE__, __LINE__);
		/*
		 * Where am I?  What year is it?
		 * We are in the same thread that went to sleep above,
		 * but any amount of time may have passed. All our context
		 * will still be available as will local variables.
		 * PCPU values however may have changed as we may have
		 * changed CPU so don't trust cached values of them.
		 * New threads will go to fork_exit() instead of here
		 * so if you change things here you may need to change
		 * things there too.
		 *
		 * If the thread above was exiting it will never wake
		 * up again here, so either it has saved everything it
		 * needed to, or the thread_wait() or wait() will
		 * need to reap it.
		 */

		SDT_PROBE0(sched, , , on__cpu);
#ifdef	HWPMC_HOOKS
		if (PMC_PROC_IS_USING_PMCS(td->td_proc))
			PMC_SWITCH_CONTEXT(td, PMC_FN_CSW_IN);
#endif
	} else {
		td->td_lock = &sched_lock;
		SDT_PROBE0(sched, , , remain__cpu);
	}

	KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "running",
	    "prio:%d", td->td_priority);

#ifdef SMP
	if (td->td_flags & TDF_IDLETD)
		CPU_SET(PCPU_GET(cpuid), &idle_cpus_mask);
#endif
	sched_lock.mtx_lock = (uintptr_t)td;
	td->td_oncpu = PCPU_GET(cpuid);
	spinlock_enter();
	mtx_unlock_spin(&sched_lock);
}

static void
sched_4bsd_wakeup_account(struct thread *td)
{
	struct td_sched *ts;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	ts = td_get_sched(td);
	if (ts->ts_slptime > 1) {
		updatepri(td);
		resetpriority(td);
	}
	td->td_slptick = 0;
	ts->ts_slptime = 0;
	ts->ts_slice = sched_slice;

	/*
	 * When resuming an idle ithread, restore its base ithread
	 * priority.
	 */
	if (PRI_BASE(td->td_pri_class) == PRI_ITHD &&
	    td->td_base_pri != td->td_base_ithread_pri)
		sched_prio(td, td->td_base_ithread_pri);
}

static void
sched_4bsd_wakeup(struct thread *td, int srqflags)
{

	sched_4bsd_wakeup_account(td);

	sched_add(td, srqflags);
}

#ifdef SMP
static int
forward_wakeup(int cpunum)
{
	struct pcpu *pc;
	cpuset_t dontuse, map, map2;
	u_int id, me;
	int iscpuset;

	mtx_assert(&sched_lock, MA_OWNED);

	CTR0(KTR_RUNQ, "forward_wakeup()");

	if ((!forward_wakeup_enabled) ||
	     (forward_wakeup_use_mask == 0 && forward_wakeup_use_loop == 0))
		return (0);
	if (!smp_started || KERNEL_PANICKED())
		return (0);

	forward_wakeups_requested++;

	/*
	 * Check the idle mask we received against what we calculated
	 * before in the old version.
	 */
	me = PCPU_GET(cpuid);

	/* Don't bother if we should be doing it ourself. */
	if (CPU_ISSET(me, &idle_cpus_mask) &&
	    (cpunum == NOCPU || me == cpunum))
		return (0);

	CPU_SETOF(me, &dontuse);
	CPU_OR(&dontuse, &dontuse, &stopped_cpus);
	CPU_ZERO(&map2);
	if (forward_wakeup_use_loop) {
		STAILQ_FOREACH(pc, &cpuhead, pc_allcpu) {
			id = pc->pc_cpuid;
			if (!CPU_ISSET(id, &dontuse) &&
			    pc->pc_curthread == pc->pc_idlethread) {
				CPU_SET(id, &map2);
			}
		}
	}

	if (forward_wakeup_use_mask) {
		map = idle_cpus_mask;
		CPU_ANDNOT(&map, &map, &dontuse);

		/* If they are both on, compare and use loop if different. */
		if (forward_wakeup_use_loop) {
			if (CPU_CMP(&map, &map2)) {
				printf("map != map2, loop method preferred\n");
				map = map2;
			}
		}
	} else {
		map = map2;
	}

	/* If we only allow a specific CPU, then mask off all the others. */
	if (cpunum != NOCPU) {
		KASSERT((cpunum <= mp_maxcpus),("forward_wakeup: bad cpunum."));
		iscpuset = CPU_ISSET(cpunum, &map);
		if (iscpuset == 0)
			CPU_ZERO(&map);
		else
			CPU_SETOF(cpunum, &map);
	}
	if (!CPU_EMPTY(&map)) {
		forward_wakeups_delivered++;
		STAILQ_FOREACH(pc, &cpuhead, pc_allcpu) {
			id = pc->pc_cpuid;
			if (!CPU_ISSET(id, &map))
				continue;
			if (cpu_idle_wakeup(pc->pc_cpuid))
				CPU_CLR(id, &map);
		}
		if (!CPU_EMPTY(&map))
			ipi_selected(map, IPI_AST);
		return (1);
	}
	if (cpunum == NOCPU)
		printf("forward_wakeup: Idle processor not found\n");
	return (0);
}

static void
kick_other_cpu(struct thread *td, int cpuid, bool equal)
{
	struct pcpu *pcpu;
	int cpri, idle_woken, pri;

	mtx_assert(&sched_lock, MA_OWNED);
	pri = td->td_priority;
	pcpu = pcpu_find(cpuid);
	/* Publish the per-CPU runq insertion before sampling remote idle state. */
	if (equal) {
#ifdef DOORFS
		atomic_store_int(DPCPU_ID_PTR(cpuid, door_idle_hot), 1);
#endif
		atomic_thread_fence_seq_cst();
	}
	if (CPU_ISSET(cpuid, &idle_cpus_mask)) {
#ifdef DOORFS
		if (equal) {

			/*
			 * Reserve the exact Door worker for the idle CPU.  The worker
			 * remains on its per-CPU run queue, so cancellation and all
			 * ordinary scheduler invariants continue to work.  The slot is
			 * only a fast selection hint consumed under sched_lock.
			 */
			if (*DPCPU_ID_PTR(cpuid, door_idle_handoff) == NULL) {
				*DPCPU_ID_PTR(cpuid, door_idle_handoff) = td;
			}
			/*
			 * A spinning idle thread makes a fenced runq check before
			 * clearing this flag.  It will observe the work just published,
			 * so neither an MD wakeup nor an IPI is required.
			 */
			if (atomic_load_int(DPCPU_ID_PTR(cpuid,
			    door_idle_spinning)) != 0) {
				return;
			}
		}
#endif
		/*
		 * 4BSD marks a CPU idle before its final runnable check.  The
		 * hardware wake may race ahead of the actual idle entry; use an
		 * AST IPI if it did not wake the target CPU.  IPI_PREEMPT is
		 * unsafe while the idle thread owns an MD critical section.
		 */
		forward_wakeups_delivered++;
		idle_woken = cpu_idle_wakeup(cpuid);
		if (!idle_woken)
			ipi_cpu(cpuid, IPI_AST);
		return;
	}

	cpri = pcpu->pc_curthread->td_priority;
	if (pri > cpri || (!equal && pri == cpri)) {
		return;
	}

	if (equal) {
		/*
		 * A Door wake deliberately requests an equal-priority handoff.
		 * Mark the remote thread as owing a preemption and publish a scheduler
		 * AST.  Also mark the target CPU so sched_4bsd_switch() requeues the
		 * interrupted equal-priority thread behind the Door worker instead of
		 * restoring it at the head through SRQ_PREEMPTED.
		 */
		if (pcpu->pc_curthread->td_lock == &sched_lock) {
			pcpu->pc_curthread->td_owepreempt = 1;
			ast_sched_locked(pcpu->pc_curthread, TDA_SCHED);
#ifdef DOORFS
			atomic_store_char(DPCPU_ID_PTR(cpuid,
			    door_remote_handoff), 1);
#endif
			ipi_cpu(cpuid, IPI_AST);
		}
		return;
	}
#if defined(IPI_PREEMPTION) && defined(PREEMPTION)
#if !defined(FULL_PREEMPTION)
	if (pri <= PRI_MAX_ITHD)
#endif /* ! FULL_PREEMPTION */
	{
		ipi_cpu(cpuid, IPI_PREEMPT);
		return;
	}
#endif /* defined(IPI_PREEMPTION) && defined(PREEMPTION) */

	if (pcpu->pc_curthread->td_lock == &sched_lock) {
		ast_sched_locked(pcpu->pc_curthread, TDA_SCHED);
		ipi_cpu(cpuid, IPI_AST);
	}
}
#endif /* SMP */

#ifdef SMP
static int
sched_pickcpu(struct thread *td)
{
	int best, cpu;

	mtx_assert(&sched_lock, MA_OWNED);

	if (td->td_lastcpu != NOCPU && THREAD_CAN_SCHED(td, td->td_lastcpu))
		best = td->td_lastcpu;
	else
		best = NOCPU;
	CPU_FOREACH(cpu) {
		if (!THREAD_CAN_SCHED(td, cpu))
			continue;

		if (best == NOCPU)
			best = cpu;
		else if (DPCPU_ID_GET(cpu, runq_length) < DPCPU_ID_GET(best, runq_length))
			best = cpu;
	}
	KASSERT(best != NOCPU, ("no valid CPUs"));

	return (best);
}

/*
 * Select a concrete CPU for an unbound Door worker wakeup.  The stock
 * 4BSD picker only compares per-CPU runq lengths, so a CPU executing a thread
 * and an actually idle CPU both appear to have load zero.  Account for the
 * current thread as one unit of load.  On equal load, avoid competing with
 * the producer and its SMT sibling before considering last-CPU locality.
 */
static int
sched_pickcpu_door(struct thread *td)
{
	struct cpu_group *cg, *smt;
	struct pcpu *pc;
	int best, bestcost, bestload, cost, cpu, load, producer;

	mtx_assert(&sched_lock, MA_OWNED);
	producer = PCPU_GET(cpuid);
	smt = NULL;
	if (cpu_top != NULL) {
		cg = smp_topo_find(cpu_top, producer);
		for (; cg != NULL; cg = cg->cg_parent) {
			if ((cg->cg_flags & CG_FLAG_THREAD) != 0) {
				smt = cg;
				break;
			}
		}
	}
	best = NOCPU;
	bestcost = 0;
	bestload = 0;
	CPU_FOREACH(cpu) {
		if (!THREAD_CAN_SCHED(td, cpu))
			continue;
		pc = pcpu_find(cpu);
		load = DPCPU_ID_GET(cpu, runq_length);
		if (pc->pc_curthread != pc->pc_idlethread)
			load++;
		if (cpu == producer)
			cost = 2;
		else if (smt != NULL && CPU_ISSET(cpu, &smt->cg_mask))
			cost = 1;
		else
			cost = 0;
		if (best == NOCPU || load < bestload ||
		    (load == bestload && cost < bestcost) ||
		    (load == bestload && cost == bestcost &&
		    cpu == td->td_lastcpu)) {
			best = cpu;
			bestload = load;
			bestcost = cost;
		}
	}
	KASSERT(best != NOCPU, ("no valid Door wake CPU"));
	return (best);
}
#endif

static void
sched_4bsd_add(struct thread *td, int flags)
#ifdef SMP
{
	cpuset_t tidlemsk;
	struct td_sched *ts;
	u_int cpu, cpuid;
	int forwarded = 0;
	int single_cpu = 0;

	ts = td_get_sched(td);
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT((td->td_inhibitors == 0),
	    ("sched_add: trying to run inhibited thread"));
	KASSERT((TD_CAN_RUN(td) || TD_IS_RUNNING(td)),
	    ("sched_add: bad thread state"));
	KASSERT(td->td_flags & TDF_INMEM,
	    ("sched_add: thread swapped out"));

	KTR_STATE2(KTR_SCHED, "thread", sched_tdname(td), "runq add",
	    "prio:%d", td->td_priority, KTR_ATTR_LINKED,
	    sched_tdname(curthread));
	KTR_POINT1(KTR_SCHED, "thread", sched_tdname(curthread), "wokeup",
	    KTR_ATTR_LINKED, sched_tdname(td));
	SDT_PROBE4(sched, , , enqueue, td, td->td_proc, NULL, 
	    flags & SRQ_PREEMPTED);

	/*
	 * Now that the thread is moving to the run-queue, set the lock
	 * to the scheduler's lock.
	 */
	if (td->td_lock != &sched_lock) {
		mtx_lock_spin(&sched_lock);
		if ((flags & SRQ_HOLD) != 0)
			td->td_lock = &sched_lock;
		else
			thread_lock_set(td, &sched_lock);
	}
	TD_SET_RUNQ(td);

	/*
	 * If SMP is started and the thread is pinned or otherwise limited to
	 * a specific set of CPUs, queue the thread to a per-CPU run queue.
	 * Otherwise, queue the thread to the global run queue.
	 *
	 * If SMP has not yet been started we must use the global run queue
	 * as per-CPU state may not be initialized yet and we may crash if we
	 * try to access the per-CPU run queues.
	 */
	if (smp_started && ((flags & SRQ_DOOR_WAKE) != 0 ||
	    (ts->ts_flags & TSF_DOOR_LOCAL) != 0 ||
	    td->td_pinned != 0 || td->td_flags & TDF_BOUND ||
	    ts->ts_flags & TSF_AFFINITY)) {
		if (td->td_pinned != 0)
			cpu = td->td_lastcpu;
		else if (td->td_flags & TDF_BOUND) {
			/* Find CPU from bound runq. */
			KASSERT(ts->ts_rqcpu != NOCPU,
			    ("sched_add: bound td_sched not on cpu runq"));
			cpu = ts->ts_rqcpu;
		} else if (ts->ts_flags & TSF_AFFINITY) {
			/* Find a valid CPU for our cpuset. */
			cpu = sched_pickcpu(td);
		}
		else if ((flags & SRQ_DOOR_WAKE) != 0)
			cpu = sched_pickcpu_door(td);
		else {
			cpu = td->td_lastcpu;
		}
		ts->ts_rqcpu = cpu;
		single_cpu = 1;
		CTR3(KTR_RUNQ,
		    "sched_add: Put td_sched:%p(td:%p) on cpu%d runq", ts, td,
		    cpu);
	} else {
		CTR2(KTR_RUNQ,
		    "sched_add: adding td_sched:%p (td:%p) to gbl runq", ts,
		    td);
		cpu = NOCPU;
		ts->ts_rqcpu = NOCPU;
	}

	if ((td->td_flags & TDF_NOLOAD) == 0)
		sched_load_add();
	if ((flags & SRQ_DOOR_WAKE) != 0) {
		ts->ts_flags |= TSF_DOOR_LOCAL;
	}
	runq_add(TS_RUNQ_PTR(ts), td, flags);
	if (cpu != NOCPU)
		(*DPCPU_ID_PTR(cpu, runq_length))++;

	cpuid = PCPU_GET(cpuid);
	if (single_cpu && cpu != cpuid) {
	        kick_other_cpu(td, cpu,
		    (flags & SRQ_DOOR_WAKE) != 0);
	} else {
		if (!single_cpu) {
			tidlemsk = idle_cpus_mask;
			CPU_CLR(cpuid, &tidlemsk);

			if (!CPU_ISSET(cpuid, &idle_cpus_mask) &&
			    ((flags & SRQ_INTR) == 0) &&
			    !CPU_EMPTY(&tidlemsk))
				forwarded = forward_wakeup(cpu);
		}

		if (!forwarded) {
			if (!maybe_preempt(td))
				maybe_resched(td);
		}
	}
	if ((flags & SRQ_HOLDTD) == 0)
		thread_unlock(td);
}
#else /* SMP */
{
	struct td_sched *ts;

	ts = td_get_sched(td);
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT((td->td_inhibitors == 0),
	    ("sched_add: trying to run inhibited thread"));
	KASSERT((TD_CAN_RUN(td) || TD_IS_RUNNING(td)),
	    ("sched_add: bad thread state"));
	KASSERT(td->td_flags & TDF_INMEM,
	    ("sched_add: thread swapped out"));
	KTR_STATE2(KTR_SCHED, "thread", sched_tdname(td), "runq add",
	    "prio:%d", td->td_priority, KTR_ATTR_LINKED,
	    sched_tdname(curthread));
	KTR_POINT1(KTR_SCHED, "thread", sched_tdname(curthread), "wokeup",
	    KTR_ATTR_LINKED, sched_tdname(td));
	SDT_PROBE4(sched, , , enqueue, td, td->td_proc, NULL, 
	    flags & SRQ_PREEMPTED);

	/*
	 * Now that the thread is moving to the run-queue, set the lock
	 * to the scheduler's lock.
	 */
	if (td->td_lock != &sched_lock) {
		mtx_lock_spin(&sched_lock);
		if ((flags & SRQ_HOLD) != 0)
			td->td_lock = &sched_lock;
		else
			thread_lock_set(td, &sched_lock);
	}
	TD_SET_RUNQ(td);
	CTR2(KTR_RUNQ, "sched_add: adding td_sched:%p (td:%p) to runq", ts, td);
	ts->ts_rqcpu = NOCPU;

	if ((td->td_flags & TDF_NOLOAD) == 0)
		sched_load_add();
	runq_add(TS_RUNQ_PTR(ts), td, flags);
	if (!maybe_preempt(td))
		maybe_resched(td);
	if ((flags & SRQ_HOLDTD) == 0)
		thread_unlock(td);
}
#endif /* SMP */

static void
sched_4bsd_rem(struct thread *td)
{
	struct td_sched *ts;

	ts = td_get_sched(td);
	KASSERT(td->td_flags & TDF_INMEM,
	    ("sched_rem: thread swapped out"));
	KASSERT(TD_ON_RUNQ(td),
	    ("sched_rem: thread not on run queue"));
	mtx_assert(&sched_lock, MA_OWNED);
#ifdef DOORFS
#ifdef SMP
	if (ts->ts_rqcpu != NOCPU &&
	    *DPCPU_ID_PTR(ts->ts_rqcpu, door_idle_handoff) == td) {
		*DPCPU_ID_PTR(ts->ts_rqcpu, door_idle_handoff) = NULL;
	}
#endif
#endif
	KTR_STATE2(KTR_SCHED, "thread", sched_tdname(td), "runq rem",
	    "prio:%d", td->td_priority, KTR_ATTR_LINKED,
	    sched_tdname(curthread));
	SDT_PROBE3(sched, , , dequeue, td, td->td_proc, NULL);

	if ((td->td_flags & TDF_NOLOAD) == 0)
		sched_load_rem();
#ifdef SMP
	if (ts->ts_rqcpu != NOCPU)
		(*DPCPU_ID_PTR(ts->ts_rqcpu, runq_length))--;
#endif
	runq_remove(TS_RUNQ_PTR(ts), td);
	TD_SET_CAN_RUN(td);
}

#ifdef DOORFS
/* Return a validated exact successor or leave the ordinary chooser intact. */
static struct thread *
sched_4bsd_door_choose(void)
{
	struct thread *td;
#ifdef SMP
	struct td_sched *ts;
#endif

	mtx_assert(&sched_lock, MA_OWNED);
	td = sched_4bsd_shuttle_choose();
	if (__predict_false(td != NULL))
		return (td);
#ifdef SMP
	/*
	 * Fast path for a Door worker which woke this CPU from idle.  Keep the
	 * worker on the run queue until this point, and accept the reservation
	 * only if it is still runnable on this CPU and no better-priority thread
	 * is waiting globally or locally.  Every failed validation falls through
	 * to the stock chooser without changing scheduler semantics.
	 */
	td = *DPCPU_PTR(door_idle_handoff);
	if (__predict_false(td != NULL)) {
		*DPCPU_PTR(door_idle_handoff) = NULL;
		ts = td_get_sched(td);
		if (TD_ON_RUNQ(td) && ts->ts_rqcpu == PCPU_GET(cpuid) &&
		    (ts->ts_flags & TSF_DOOR_LOCAL) != 0) {
			struct thread *globaltd, *localtd;

			globaltd = runq_choose(&runq_global);
			localtd = runq_choose(DPCPU_PTR(runq_pcpu));
			if ((globaltd == NULL ||
			    td->td_priority <= globaltd->td_priority) &&
			    (localtd == NULL ||
			    td->td_priority <= localtd->td_priority)) {
				(*DPCPU_PTR(runq_length))--;
				runq_remove(DPCPU_PTR(runq_pcpu), td);
				td->td_flags |= TDF_DIDRUN;
				KASSERT(td->td_flags & TDF_INMEM,
				    ("sched_choose: handoff thread swapped out"));
				return (td);
			}
		}
	}
#endif

	return (NULL);
}
#endif

/*
 * Select threads to run.  Note that running threads still consume a
 * slot.
 */
static struct thread *
sched_4bsd_choose(void)
{
	struct thread *td;
	struct runq *runq;

	mtx_assert(&sched_lock,  MA_OWNED);
#ifdef DOORFS
	td = sched_4bsd_door_choose();
	if (__predict_false(td != NULL))
		return (td);
#endif
#ifdef SMP
	struct thread *tdcpu;

	runq = &runq_global;
	td = runq_choose_fuzz(&runq_global, runq_fuzz);
	tdcpu = runq_choose(DPCPU_PTR(runq_pcpu));

	if (td == NULL ||
	    (tdcpu != NULL &&
	     (tdcpu->td_priority < td->td_priority ||
	      (tdcpu->td_priority == td->td_priority &&
	       (td_get_sched(tdcpu)->ts_flags & TSF_DOOR_LOCAL) != 0)))) {
		CTR2(KTR_RUNQ, "choosing td %p from pcpu runq %d", tdcpu,
		     PCPU_GET(cpuid));
		td = tdcpu;
		runq = DPCPU_PTR(runq_pcpu);
	} else {
		CTR1(KTR_RUNQ, "choosing td_sched %p from main runq", td);
	}

#else
	runq = &runq_global;
	td = runq_choose(&runq_global);
#endif

	if (td) {
#ifdef SMP
		if (td == tdcpu)
			(*DPCPU_PTR(runq_length))--;
#endif
		runq_remove(runq, td);
		td->td_flags |= TDF_DIDRUN;

		KASSERT(td->td_flags & TDF_INMEM,
		    ("sched_choose: thread swapped out"));
		return (td);
	}
	return (PCPU_GET(idlethread));
}

static void
sched_4bsd_preempt(struct thread *td)
{
	int flags;

	MPASS(td == curthread);
	SDT_PROBE2(sched, , , surrender, td, td->td_proc);
	if (td->td_critnest > 1) {
		td->td_owepreempt = 1;
	} else {
		thread_lock(td);
		flags = SW_INVOL | SW_PREEMPT;
		flags |= TD_IS_IDLETHREAD(td) ? SWT_REMOTEWAKEIDLE :
		    SWT_REMOTEPREEMPT;
		mi_switch(flags);
	}
}

static void
sched_4bsd_userret_slowpath(struct thread *td)
{
	thread_lock(td);
	td->td_priority = td->td_user_pri;
	td->td_base_pri = td->td_user_pri;
	thread_unlock(td);
}

static void
sched_4bsd_bind(struct thread *td, int cpu)
{
#ifdef SMP
	struct td_sched *ts = td_get_sched(td);
#endif

	THREAD_LOCK_ASSERT(td, MA_OWNED|MA_NOTRECURSED);
	KASSERT(td == curthread, ("sched_bind: can only bind curthread"));

	td->td_flags |= TDF_BOUND;
#ifdef SMP
	ts->ts_rqcpu = cpu;
	if (PCPU_GET(cpuid) == cpu)
		return;

	mi_switch(SW_VOL | SWT_BIND);
	thread_lock(td);
#endif
}

static void
sched_4bsd_unbind(struct thread* td)
{
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT(td == curthread, ("sched_unbind: can only bind curthread"));
	td->td_flags &= ~TDF_BOUND;
}

static int
sched_4bsd_is_bound(struct thread *td)
{
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	return (td->td_flags & TDF_BOUND);
}

static void
sched_4bsd_relinquish(struct thread *td)
{
	thread_lock(td);
	mi_switch(SW_VOL | SWT_RELINQUISH);
}

static int
sched_4bsd_load(void)
{
	return (sched_tdcnt);
}

static int
sched_4bsd_sizeof_proc(void)
{
	return (sizeof(struct proc));
}

static int
sched_4bsd_sizeof_thread(void)
{
	return (sizeof(struct thread) + sizeof(struct td_sched));
}

static fixpt_t
sched_4bsd_pctcpu(struct thread *td)
{
	struct td_sched *ts;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	ts = td_get_sched(td);
	return (ts->ts_pctcpu);
}

static u_int
sched_4bsd_estcpu(struct thread *td)
{

	return (td_get_sched(td)->ts_estcpu);
}

/*
 * The actual idle process.
 */
static void
sched_4bsd_idletd(void *dummy)
{
	struct pcpuidlestat *stat;
#ifdef DOORFS
#ifdef SMP
	u_int i;
#endif
#endif

	THREAD_NO_SLEEPING();
	stat = DPCPU_PTR(idlestat);
	for (;;) {
		mtx_assert(&Giant, MA_NOTOWNED);

		while (!sched_runnable()) {
#ifdef DOORFS
#ifdef SMP
			if (door_idlespins != 0 &&
			    atomic_load_int(DPCPU_PTR(door_idle_hot)) != 0) {
				atomic_store_int(DPCPU_PTR(door_idle_hot), 0);
				atomic_store_int(DPCPU_PTR(door_idle_spinning), 1);
				/* Publish spinning before the first lockless runq check. */
				atomic_thread_fence_seq_cst();
				for (i = 0; i < door_idlespins; i++) {
					if (sched_runnable())
						break;
					cpu_spinwait();
				}
				atomic_store_int(DPCPU_PTR(door_idle_spinning), 0);
				/*
				 * A waker which observed spinning may omit its IPI.
				 * Recheck after withdrawing that promise and before
				 * entering cpu_idle().
				 */
				atomic_thread_fence_seq_cst();
				if (sched_runnable())
					continue;
			}
#endif
#endif
			cpu_idle(stat->idlecalls + stat->oldidlecalls > 64);
			stat->idlecalls++;
		}

		mtx_lock_spin(&sched_lock);
		mi_switch(SW_VOL | SWT_IDLE);
	}
}

static void
sched_throw_tail(struct thread *td)
{
	struct thread *newtd;

	mtx_assert(&sched_lock, MA_OWNED);
	KASSERT(curthread->td_md.md_spinlock_count == 1, ("invalid count"));

	newtd = choosethread();

#ifdef HWT_HOOKS
	if (td)
		HWT_CALL_HOOK(td, HWT_SWITCH_OUT, NULL);
	HWT_CALL_HOOK(newtd, HWT_SWITCH_IN, NULL);
#endif

	cpu_throw(td, newtd);	/* doesn't return */
}

/*
 * A CPU is entering for the first time.
 */
static void
sched_4bsd_ap_entry(void)
{

	/*
	 * Correct spinlock nesting.  The idle thread context that we are
	 * borrowing was created so that it would start out with a single
	 * spin lock (sched_lock) held in fork_trampoline().  Since we've
	 * explicitly acquired locks in this function, the nesting count
	 * is now 2 rather than 1.  Since we are nested, calling
	 * spinlock_exit() will simply adjust the counts without allowing
	 * spin lock using code to interrupt us.
	 */
	mtx_lock_spin(&sched_lock);
	spinlock_exit();
	PCPU_SET(switchtime, cpu_ticks());
	PCPU_SET(switchticks, ticks);

	sched_throw_tail(NULL);
}

/*
 * A thread is exiting.
 */
static void
sched_4bsd_throw(struct thread *td)
{

	MPASS(td != NULL);
	MPASS(td->td_lock == &sched_lock);

	lock_profile_release_lock(&sched_lock.lock_object, true);
	td->td_lastcpu = td->td_oncpu;
	td->td_oncpu = NOCPU;

	sched_throw_tail(td);
}

static void
sched_4bsd_fork_exit(struct thread *td)
{

	/*
	 * Finish setting up thread glue so that it begins execution in a
	 * non-nested critical section with sched_lock held but not recursed.
	 */
	td->td_oncpu = PCPU_GET(cpuid);
	sched_lock.mtx_lock = (uintptr_t)td;
	lock_profile_obtain_lock_success(&sched_lock.lock_object, true,
	    0, 0, __FILE__, __LINE__);
	THREAD_LOCK_ASSERT(td, MA_OWNED | MA_NOTRECURSED);

	KTR_STATE1(KTR_SCHED, "thread", sched_tdname(td), "running",
	    "prio:%d", td->td_priority);
	SDT_PROBE0(sched, , , on__cpu);
}

static char *
sched_4bsd_tdname(struct thread *td)
{
#ifdef KTR
	struct td_sched *ts;

	ts = td_get_sched(td);
	if (ts->ts_name[0] == '\0')
		snprintf(ts->ts_name, sizeof(ts->ts_name),
		    "%s tid %d", td->td_name, td->td_tid);
	return (ts->ts_name);
#else   
	return (td->td_name);
#endif
}

static void
sched_4bsd_clear_tdname(struct thread *td)
{
#ifdef KTR
	struct td_sched *ts;

	ts = td_get_sched(td);
	ts->ts_name[0] = '\0';
#endif
}

static void
sched_4bsd_affinity(struct thread *td)
{
#ifdef SMP
	struct td_sched *ts;
	int cpu;

	THREAD_LOCK_ASSERT(td, MA_OWNED);	

	/*
	 * Set the TSF_AFFINITY flag if there is at least one CPU this
	 * thread can't run on.
	 */
	ts = td_get_sched(td);
	ts->ts_flags &= ~TSF_AFFINITY;
	CPU_FOREACH(cpu) {
		if (!THREAD_CAN_SCHED(td, cpu)) {
			ts->ts_flags |= TSF_AFFINITY;
			break;
		}
	}

	/*
	 * If this thread can run on all CPUs, nothing else to do.
	 */
	if (!(ts->ts_flags & TSF_AFFINITY))
		return;

	/* Pinned threads and bound threads should be left alone. */
	if (td->td_pinned != 0 || td->td_flags & TDF_BOUND)
		return;

	switch (TD_GET_STATE(td)) {
	case TDS_RUNQ:
		/*
		 * If we are on a per-CPU runqueue that is in the set,
		 * then nothing needs to be done.
		 */
		if (ts->ts_rqcpu != NOCPU && THREAD_CAN_SCHED(td, ts->ts_rqcpu))
			return;

		/* Put this thread on a valid per-CPU runqueue. */
		sched_rem(td);
		sched_add(td, SRQ_HOLDTD | SRQ_BORING);
		break;
	case TDS_RUNNING:
		/*
		 * See if our current CPU is in the set.  If not, force a
		 * context switch.
		 */
		if (THREAD_CAN_SCHED(td, td->td_oncpu))
			return;

		ast_sched_locked(td, TDA_SCHED);
		if (td != curthread)
			ipi_cpu(cpu, IPI_AST);
		break;
#ifdef DOORFS
	case TDS_SHUTTLE:
		/* A reserved target must be requeued under its new affinity. */
		sched_4bsd_shuttle_cancel(td, SRQ_HOLDTD | SRQ_BORING);
		break;
	case TDS_SHUTTLE_WAIT:
		/* Off-runq private waiters are placed correctly when resumed. */
		break;
#endif
	default:
		break;
	}
#endif
}

#ifdef DOORFS
static inline struct sched_shuttle *
sched_4bsd_shuttle_state(struct thread *td)
{

	return (&td_get_sched(td)->ts_shuttle);
}

/*
 * Consume the current CPU's exact-successor reservation from the ordinary
 * 4BSD chooser.  This keeps all context-switch accounting in
 * sched_4bsd_switch(); only selection of the next thread is overridden.
 */
static struct thread *
sched_4bsd_shuttle_choose(void)
{
	struct sched_shuttle_token *token;
	struct sched_shuttle *ss;
	struct thread *peer;
	int cpu;

	mtx_assert(&sched_lock, MA_OWNED);
	token = DPCPU_PTR(shuttle_token);
	if ((token->sst_flags & (SCHED_SHUTTLE_TOKEN_RESERVED |
	    SCHED_SHUTTLE_TOKEN_WAKE_RESERVED)) !=
	    (SCHED_SHUTTLE_TOKEN_RESERVED |
	    SCHED_SHUTTLE_TOKEN_WAKE_RESERVED) ||
	    token->sst_cur != curthread ||
	    token->sst_cpu != PCPU_GET(cpuid))
		return (NULL);

	peer = token->sst_peer;
	cpu = PCPU_GET(cpuid);
	ss = peer != NULL ? sched_4bsd_shuttle_state(peer) : NULL;
	if (peer == NULL || peer->td_lock != &sched_lock ||
	    !TD_IS_SHUTTLE(peer) || ss->ss_state != SCHED_SHUTTLE_RESUMING ||
	    ss->ss_peer != curthread ||
	    ss->ss_generation != token->sst_generation ||
	    !THREAD_CAN_SCHED(peer, cpu)) {
		sched_4bsd_shuttle_restore_locked(token);
		return (NULL);
	}
#ifdef SMP
	if ((peer->td_pinned != 0 || (peer->td_flags & TDF_BOUND) != 0) &&
	    td_get_sched(peer)->ts_rqcpu != cpu) {
		sched_4bsd_shuttle_restore_locked(token);
		return (NULL);
	}
#endif

	/* The parked target was not included in sched_tdcnt. */
	TD_SET_CAN_RUN(peer);
	sched_4bsd_wakeup_account(peer);
	if ((peer->td_flags & TDF_NOLOAD) == 0)
		sched_load_add();
	bzero(token, sizeof(*token));
	return (peer);
}

static void
sched_4bsd_shuttle_restore_locked(struct sched_shuttle_token *token)
{
	struct thread *peer;

	mtx_assert(&sched_lock, MA_OWNED);
	if (token == NULL ||
	    (token->sst_flags & SCHED_SHUTTLE_TOKEN_RESERVED) == 0)
		return;
	peer = token->sst_peer;
	KASSERT(peer != NULL && peer->td_lock == &sched_lock,
	    ("4bsd shuttle restore lost scheduler ownership"));
	bzero(token, sizeof(*token));
	if (TD_IS_SHUTTLE(peer)) {
		TD_SET_CAN_RUN(peer);
		sched_4bsd_wakeup(peer, SRQ_HOLDTD | SRQ_BORING);
	}
}

/*
 * 4BSD shuttle protocol.  Private waiters remain outside the sleep queue and
 * an already parked waiter may be reserved as the current CPU's exact next
 * thread.  The ordinary 4BSD switch performs accounting; its chooser consumes
 * the reservation under sched_lock.
 */
static enum sched_shuttle_result
sched_4bsd_shuttle_prepare(struct thread *td, struct thread *peer,
    const void *wchan, int flags)
{
	struct sched_shuttle *ss;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (wchan == NULL || peer == NULL || peer == td)
		return (SCHED_SHUTTLE_ABORTED);

	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_NONE)
		return (SCHED_SHUTTLE_RETRY);

	ss->ss_peer = peer;
	ss->ss_wchan = wchan;
	ss->ss_flags = flags;
	ss->ss_pending = 0;
	ss->ss_generation++;
	ss->ss_state = SCHED_SHUTTLE_PREPARED;
	return (SCHED_SHUTTLE_OK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_commit(struct thread *td, int flags)
{
	struct sched_shuttle *ss;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT(td == curthread, ("shuttle commit for non-current thread"));
	KASSERT(TD_IS_SLEEPING(td),
	    ("shuttle commit for non-sleeping thread %p", td));

	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_PREPARED)
		return (SCHED_SHUTTLE_FALLBACK);
	ss->ss_flags |= flags;
	if (ss->ss_pending != 0)
		return (SCHED_SHUTTLE_ABORTED);
	if (!TD_ON_SLEEPQ(td) || td->td_wchan != ss->ss_wchan)
		return (SCHED_SHUTTLE_ABORTED);
	ss->ss_state = SCHED_SHUTTLE_COMMITTED;
	return (SCHED_SHUTTLE_OK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_resume(struct thread *td, int flags)
{
	struct sched_shuttle *ss;
	const void *wchan;
	enum sched_shuttle_result result;

	thread_lock(td);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state == SCHED_SHUTTLE_PREPARED ||
	    ss->ss_state == SCHED_SHUTTLE_COMMITTED) {
		ss->ss_flags |= flags;
		ss->ss_pending = 1;
		thread_unlock(td);
		return (SCHED_SHUTTLE_RETRY);
	}
	if ((flags & SCHED_SHUTTLE_F_ASYNC_WAKE) != 0 &&
	    TD_IS_SHUTTLE_WAIT(td) &&
	    ss->ss_state == SCHED_SHUTTLE_SLEEPING) {
		ss->ss_peer = NULL;
		ss->ss_wchan = NULL;
		ss->ss_flags = 0;
		ss->ss_pending = 0;
		ss->ss_state = SCHED_SHUTTLE_NONE;
		ss->ss_generation++;
		TD_SET_CAN_RUN(td);
		sched_4bsd_shuttle_wakeup_async(td);
		return (SCHED_SHUTTLE_OK);
	}
	if (TD_IS_SHUTTLE_WAIT(td) &&
	    ss->ss_state == SCHED_SHUTTLE_SLEEPING) {
		ss->ss_flags |= flags;
		ss->ss_state = SCHED_SHUTTLE_RESUMING;
		TD_SET_CAN_RUN(td);
		result = sched_4bsd_shuttle_wakeup(td, flags);
		if (result == SCHED_SHUTTLE_OK)
			return (SCHED_SHUTTLE_OK);
		ss = sched_4bsd_shuttle_state(td);
		ss->ss_peer = NULL;
		ss->ss_wchan = NULL;
		ss->ss_flags = 0;
		ss->ss_pending = 0;
		ss->ss_state = SCHED_SHUTTLE_NONE;
		ss->ss_generation++;
		sched_4bsd_wakeup(td, SRQ_DOOR_WAKE);
		return (SCHED_SHUTTLE_OK);
	}
	if ((ss->ss_state != SCHED_SHUTTLE_COMMITTED &&
	    ss->ss_state != SCHED_SHUTTLE_SLEEPING) ||
	    ss->ss_wchan == NULL || !TD_ON_SLEEPQ(td)) {
		thread_unlock(td);
		return (SCHED_SHUTTLE_ABORTED);
	}

	ss->ss_flags |= flags;
	ss->ss_state = SCHED_SHUTTLE_RESUMING;
	wchan = ss->ss_wchan;
	thread_unlock(td);
	sleepq_remove(td, wchan);

	thread_lock(td);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state == SCHED_SHUTTLE_RESUMING) {
		ss->ss_wchan = NULL;
		ss->ss_pending = 0;
		ss->ss_state = SCHED_SHUTTLE_NONE;
		ss->ss_generation++;
	}
	thread_unlock(td);
	return (SCHED_SHUTTLE_OK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_dispatch(struct thread *td, struct thread *peer,
    const void *wchan, int flags)
{
	struct sched_shuttle *ss;

	if (td == NULL || peer == NULL || peer != curthread || peer == td ||
	    wchan == NULL)
		return (SCHED_SHUTTLE_ABORTED);

	thread_lock(td);
	ss = sched_4bsd_shuttle_state(td);
	if ((ss->ss_flags & SCHED_SHUTTLE_F_IDLE_WAIT) == 0 ||
	    ss->ss_peer != NULL || ss->ss_wchan != wchan) {
		thread_unlock(td);
		return (SCHED_SHUTTLE_FALLBACK);
	}
	if (ss->ss_state == SCHED_SHUTTLE_PREPARED) {
		ss->ss_peer = peer;
		ss->ss_flags |= flags;
		ss->ss_pending = 1;
		thread_unlock(td);
		return (SCHED_SHUTTLE_OK);
	}
	thread_unlock(td);
	return (sched_4bsd_shuttle_resume_to(td, peer, flags));
}

static enum sched_shuttle_result
sched_4bsd_shuttle_sleep(struct thread *td, struct thread *peer,
    const void *wchan, int flags)
{
	struct sched_shuttle *ss;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (td != curthread || !TD_IS_RUNNING(td) || wchan == NULL ||
	    peer == td ||
	    (peer != NULL && (flags & SCHED_SHUTTLE_F_IDLE_WAIT) != 0))
		return (SCHED_SHUTTLE_ABORTED);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_NONE)
		return (SCHED_SHUTTLE_RETRY);
	ss->ss_peer = peer;
	ss->ss_wchan = wchan;
	ss->ss_flags = flags;
	ss->ss_pending = 0;
	ss->ss_state = SCHED_SHUTTLE_PREPARED;
	ss->ss_generation++;
	return (SCHED_SHUTTLE_OK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_resume_to(struct thread *td, struct thread *owner,
    int flags)
{
	struct sched_shuttle *ss;
	enum sched_shuttle_result result;

	if (td == NULL || owner == NULL || owner != curthread || td == owner)
		return (SCHED_SHUTTLE_ABORTED);
	thread_lock(td);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_peer == NULL) {
		if ((ss->ss_flags & SCHED_SHUTTLE_F_IDLE_WAIT) == 0) {
			thread_unlock(td);
			return (SCHED_SHUTTLE_FALLBACK);
		}
		ss->ss_peer = owner;
	} else if (ss->ss_peer != owner) {
		thread_unlock(td);
		return (SCHED_SHUTTLE_FALLBACK);
	}

	if (ss->ss_state == SCHED_SHUTTLE_PREPARED ||
	    ss->ss_state == SCHED_SHUTTLE_COMMITTED) {
		ss->ss_flags |= flags;
		ss->ss_pending = 1;
		thread_unlock(td);
		return (SCHED_SHUTTLE_RETRY);
	}
	if (!TD_IS_SHUTTLE_WAIT(td) ||
	    ss->ss_state != SCHED_SHUTTLE_SLEEPING) {
		if ((ss->ss_flags & SCHED_SHUTTLE_F_IDLE_WAIT) != 0)
			ss->ss_peer = NULL;
		thread_unlock(td);
		return (SCHED_SHUTTLE_FALLBACK);
	}

	ss->ss_flags |= flags;
	if ((flags & SCHED_SHUTTLE_F_ASYNC_WAKE) != 0) {
		ss->ss_peer = NULL;
		ss->ss_wchan = NULL;
		ss->ss_flags = 0;
		ss->ss_pending = 0;
		ss->ss_state = SCHED_SHUTTLE_NONE;
		ss->ss_generation++;
		TD_SET_CAN_RUN(td);
		sched_4bsd_shuttle_wakeup_async(td);
		return (SCHED_SHUTTLE_OK);
	}

	ss->ss_state = SCHED_SHUTTLE_RESUMING;
	TD_SET_CAN_RUN(td);
	result = sched_4bsd_shuttle_wakeup(td, flags);
	if (result == SCHED_SHUTTLE_OK)
		return (SCHED_SHUTTLE_OK);

	/* Reservation missed; publish the waiter through the normal run queue. */
	ss = sched_4bsd_shuttle_state(td);
	ss->ss_peer = NULL;
	ss->ss_wchan = NULL;
	ss->ss_flags = 0;
	ss->ss_pending = 0;
	ss->ss_state = SCHED_SHUTTLE_NONE;
	ss->ss_generation++;
	sched_4bsd_wakeup(td, SRQ_DOOR_WAKE);
	return (SCHED_SHUTTLE_FALLBACK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_swtch(struct thread *td, int flags)
{
	struct sched_shuttle *ss;
	enum sched_shuttle_result result;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (td != curthread)
		return (SCHED_SHUTTLE_FALLBACK);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state == SCHED_SHUTTLE_PREPARED) {
		result = sched_4bsd_shuttle_park(td, flags);
		if (result != SCHED_SHUTTLE_OK) {
			if (result == SCHED_SHUTTLE_ABORTED &&
			    ss->ss_state == SCHED_SHUTTLE_PREPARED)
				sched_4bsd_shuttle_abort(td);
			KASSERT(result != SCHED_SHUTTLE_ABORTED ||
			    ss->ss_state != SCHED_SHUTTLE_PREPARED,
			    ("shuttle abort left PREPARED intent"));
			return (result);
		}
	}
	if (!TD_IS_SHUTTLE_WAIT(td))
		return (SCHED_SHUTTLE_FALLBACK);
	return (sched_4bsd_shuttle_switch(td, flags));
}

static enum sched_shuttle_result
sched_4bsd_shuttle_wakeup(struct thread *td, int flags)
{
	struct sched_shuttle_token *token;
	struct sched_shuttle *ss;
	struct td_sched *ts;
	int cpu;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (__predict_false(KERNEL_PANICKED()) || !TD_CAN_RUN(td)) {
		return (SCHED_SHUTTLE_FALLBACK);
	}
	/* An asynchronous waker cannot own an exact-successor reservation. */
	if ((flags & SCHED_SHUTTLE_F_ASYNC_WAKE) != 0) {
		return (SCHED_SHUTTLE_FALLBACK);
	}
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_RESUMING ||
	    ss->ss_peer != curthread) {
		return (SCHED_SHUTTLE_FALLBACK);
	}

	cpu = PCPU_GET(cpuid);
	ts = td_get_sched(td);
	if (!THREAD_CAN_SCHED(td, cpu)) {
		return (SCHED_SHUTTLE_FALLBACK);
	}
#ifdef SMP
	if ((td->td_pinned != 0 || (td->td_flags & TDF_BOUND) != 0) &&
	    ts->ts_rqcpu != cpu) {
		return (SCHED_SHUTTLE_FALLBACK);
	}
#else
	(void)ts;
#endif

	/* Move the private waiter into the global 4BSD scheduler lock domain. */
	if (td->td_lock != &sched_lock) {
		mtx_lock_spin(&sched_lock);
		thread_lock_set(td, &sched_lock);
	}
	token = DPCPU_PTR(shuttle_token);
	if ((token->sst_flags & SCHED_SHUTTLE_TOKEN_RESERVED) != 0) {
		return (SCHED_SHUTTLE_FALLBACK);
	}

	TD_SET_SHUTTLE(td);
	bzero(token, sizeof(*token));
	token->sst_cur = curthread;
	token->sst_peer = td;
	token->sst_candidate = td;
	token->sst_sched_data = &sched_lock;
	token->sst_generation = ss->ss_generation;
	token->sst_flags = SCHED_SHUTTLE_TOKEN_VALIDATED |
	    SCHED_SHUTTLE_TOKEN_LOCAL | SCHED_SHUTTLE_TOKEN_RESERVED |
	    SCHED_SHUTTLE_TOKEN_WAKE_RESERVED;
	token->sst_cpu = cpu;
	token->sst_rqindex = -1;
	token->sst_xferable = false;
	mtx_unlock_spin(&sched_lock);
	return (SCHED_SHUTTLE_OK);
}

/*
 * Publish an asynchronous shuttle waiter through the ordinary 4BSD run
 * queue.  maybe_resched() deliberately ignores an equal-priority thread.
 * That is normally correct, but lets a same-CPU ONEWAY producer retain its
 * whole quantum while the only Door worker waits on that CPU.  Since the
 * producer returns to userspace instead of entering mi_switch_shuttle(), ask
 * a real scheduler AST to choose again after a local enqueue.
 *
 * SRQ_HOLDTD keeps the scheduler lock stable long enough to inspect the
 * selected run queue.  An unbound Door worker has already been assigned a
 * concrete CPU by sched_pickcpu_door().  Remote targets are handled by the
 * Door-aware kick_other_cpu() path and do not reschedule this CPU.
 */
static void
sched_4bsd_shuttle_wakeup_async(struct thread *td)
{
#ifdef SMP
	struct td_sched *ts;
	int cpu;
#endif

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	sched_4bsd_wakeup(td, SRQ_HOLDTD | SRQ_DOOR_WAKE);

#ifdef SMP
	ts = td_get_sched(td);
	cpu = PCPU_GET(cpuid);
	if (ts->ts_rqcpu == cpu || ts->ts_rqcpu == NOCPU)
		ast_sched_locked(curthread, TDA_SCHED);
#else
	ast_sched_locked(curthread, TDA_SCHED);
#endif
	thread_unlock(td);
}

static void
sched_4bsd_shuttle_cancel(struct thread *td, int srqflags)
{
	struct sched_shuttle_token *token;
	int cpu;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	if (TD_IS_SHUTTLE_WAIT(td)) {
		sched_4bsd_shuttle_unpark(td, srqflags);
		return;
	}
	KASSERT(TD_IS_SHUTTLE(td),
	    ("4bsd shuttle cancel: td %p state %d", td, TD_GET_STATE(td)));
	KASSERT(td->td_lock == &sched_lock,
	    ("4bsd shuttle cancel without sched_lock ownership"));
	token = NULL;
	CPU_FOREACH(cpu) {
		struct sched_shuttle_token *candidate;

		candidate = DPCPU_ID_PTR(cpu, shuttle_token);
		if ((candidate->sst_flags & SCHED_SHUTTLE_TOKEN_RESERVED) != 0 &&
		    candidate->sst_peer == td) {
			token = candidate;
			break;
		}
	}
	KASSERT(token != NULL,
	    ("4bsd shuttle target %p has no reservation", td));
	if (token != NULL)
		bzero(token, sizeof(*token));
	TD_SET_CAN_RUN(td);
	sched_4bsd_wakeup(td, srqflags);
}

static void
sched_4bsd_shuttle_unpark(struct thread *td, int srqflags)
{

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT(TD_IS_SHUTTLE_WAIT(td),
	    ("4bsd shuttle unpark: td %p state %d", td, TD_GET_STATE(td)));

	/* Preserve interruptible-wait state; the resumed target owns cleanup. */
	TD_SET_CAN_RUN(td);
	sched_4bsd_wakeup(td, srqflags);
}


static enum sched_shuttle_result
sched_4bsd_shuttle_park(struct thread *td, int flags)
{
	struct sched_shuttle *ss;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT(td == curthread, ("shuttle park for non-current thread"));
	if (!TD_IS_RUNNING(td))
		return (SCHED_SHUTTLE_FALLBACK);
	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_PREPARED)
		return (SCHED_SHUTTLE_FALLBACK);
	ss->ss_flags |= flags;
	if (ss->ss_pending != 0)
		return (SCHED_SHUTTLE_ABORTED);
	/*
	 * Close the running-to-wait signal race.  The earlier Door-side AST
	 * check is necessarily performed before thread_lock(td), so a signal
	 * may become pending after that check while the thread is still running.
	 * In that state tdsigwakeup() only posts the AST; it cannot unpark a
	 * waiter which has not yet published TDS_SHUTTLE_WAIT.  Recheck under
	 * td_lock immediately before publishing the private wait.  A later
	 * signal must acquire the same lock and will therefore observe
	 * TDS_SHUTTLE_WAIT together with TDF_SINTR and unpark it normally.
	 */
	if ((flags & SCHED_SHUTTLE_F_INTERRUPTIBLE) != 0 &&
	    ((td->td_pflags & TDP_WAKEUP) != 0 ||
	    td_ast_pending(td, TDA_SIG) ||
	    td_ast_pending(td, TDA_SUSPEND)))
		return (SCHED_SHUTTLE_ABORTED);
	sched_sleep(td, 0);
	if ((flags & SCHED_SHUTTLE_F_INTERRUPTIBLE) != 0) {
		td->td_flags |= TDF_SINTR;
		td->td_intrval = 0;
	}
	TD_SET_SHUTTLE_WAIT(td);
	ss->ss_state = SCHED_SHUTTLE_COMMITTED;
	return (SCHED_SHUTTLE_OK);
}

static enum sched_shuttle_result
sched_4bsd_shuttle_switch(struct thread *td, int flags)
{
	struct sched_shuttle *ss;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	KASSERT(td == curthread, ("shuttle switch for non-current thread"));
	KASSERT(TD_IS_SLEEPING(td) || TD_IS_SHUTTLE_WAIT(td),
	    ("shuttle switch for non-blocked thread %p", td));

	ss = sched_4bsd_shuttle_state(td);
	if (ss->ss_state != SCHED_SHUTTLE_COMMITTED)
		return (SCHED_SHUTTLE_FALLBACK);
	if (ss->ss_pending != 0) {
		if (TD_IS_SHUTTLE_WAIT(td))
			TD_SET_RUNNING(td);
		sched_4bsd_shuttle_abort(td);
		return (SCHED_SHUTTLE_ABORTED);
	}

	ss->ss_flags |= flags;
	ss->ss_state = SCHED_SHUTTLE_SLEEPING;

	mi_switch_shuttle(SW_VOL | SWT_SHUTTLE);

	thread_lock(td);
	ss = sched_4bsd_shuttle_state(td);
	ss->ss_peer = NULL;
	ss->ss_wchan = NULL;
	ss->ss_flags = 0;
	ss->ss_pending = 0;
	ss->ss_state = SCHED_SHUTTLE_NONE;
	ss->ss_generation++;
	thread_unlock(td);
	return (SCHED_SHUTTLE_OK);
}





static void
sched_4bsd_shuttle_abort(struct thread *td)
{
	struct sched_shuttle_token *token;
	struct sched_shuttle *ss;
	struct mtx *old;

	THREAD_LOCK_ASSERT(td, MA_OWNED);
	ss = sched_4bsd_shuttle_state(td);
	ss->ss_peer = NULL;
	ss->ss_wchan = NULL;
	ss->ss_flags = 0;
	ss->ss_pending = 0;
	ss->ss_state = SCHED_SHUTTLE_NONE;
	ss->ss_generation++;

	/*
	 * An early wake can leave current owning a reservation for another
	 * waiter while current itself aborts its pending sleep.  Move current
	 * back to the 4BSD scheduler lock and publish that reserved target
	 * normally so it cannot be stranded outside every run queue.
	 */
	if (td == curthread && TD_IS_RUNNING(td)) {
		if (td->td_lock != &sched_lock) {
			old = thread_lock_block(td);
			spinlock_enter();
			mtx_unlock_spin(old);
			mtx_lock_spin(&sched_lock);
			thread_lock_unblock(td, &sched_lock);
			spinlock_exit();
		}
		token = DPCPU_PTR(shuttle_token);
		if ((token->sst_flags & (SCHED_SHUTTLE_TOKEN_RESERVED |
		    SCHED_SHUTTLE_TOKEN_WAKE_RESERVED)) ==
		    (SCHED_SHUTTLE_TOKEN_RESERVED |
		    SCHED_SHUTTLE_TOKEN_WAKE_RESERVED) &&
		    token->sst_cur == td)
			sched_4bsd_shuttle_restore_locked(token);
	}
}

static void
sched_4bsd_shuttle_sswitch(struct thread *td, int flags)
{

	/* The ordinary chooser consumes the current CPU's exact reservation. */
	sched_4bsd_switch(td, flags);
}
#endif /* DOORFS */

static int
sched_4bsd_find_l2_neighbor(int cpu)
{
	return (-1);
}

DECLARE_SCHEDULER(4bsd, "4BSD");
