#include <sys/param.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/kthread.h>
#include <sys/eventhandler.h>
#include <sys/sched.h>
#include <sys/ctype.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/endian.h>
#include <sys/bus.h>

#define countof(x)  (sizeof(x)/sizeof((x)[0]))
#define NTHREADS     4

#define MYSTATE_SIZE 30

static void kproc_main(void*);
static void kproc_main_thread(void*);
static void kproc_main_thread_x(void*);
static struct proc* pkproc = NULL;
static boolean_t unloading = FALSE;
static boolean_t stop_thread_x = FALSE;
static struct thread* pktd[NTHREADS];
static struct thread* pktd_x[NTHREADS];
static lwpid_t x_tid[NTHREADS];
static pid_t x_pid[NTHREADS];

static char* mystate(char* myst);
static int dump_devtree(device_t dev, boolean_t recurse, int level);

/* The offset in sysent[] allocated for our syscall */
static int sysent_offset = NO_SYSCALL;

static struct mtx co_mtx;
static struct callout co;
static struct rwlock mydev_rwlock;

MALLOC_DECLARE(M_MYDEV_BUF);
MALLOC_DEFINE(M_MYDEV_BUF, "mydevbuf", "mydev buffer");
static char* mydev_buf = NULL;
unsigned long mydev_buf_size = 0;

static d_open_t mydev_open;
static d_close_t mydev_close;
static d_read_t  mydev_read;
static d_write_t mydev_write;
static d_ioctl_t mydev_ioctl;

struct cdev* mydev_dev = NULL;

static struct cdevsw mydev_cdevsw = 
{
    .d_version =  D_VERSION,
    .d_open =     mydev_open,
    .d_close =    mydev_close,
    .d_read =     mydev_read,
    .d_write =    mydev_write,
    .d_ioctl =    mydev_ioctl,
    .d_name =     "mydev",
};

static void 
mytest_callout(void* vpc)
{
    /* called holding co_mtx */
    struct callout* c = (struct callout*) vpc;
    char myst[MYSTATE_SIZE];

    /* callout just had been rescheduled */
    if (callout_pending(c))
        return;

    /* check if we had been cancelled with callout_cancel or callout_drain */
    if (! callout_active(c))
        return;

    printf("mytest: callout%s\n", mystate(myst));

    /* check if we had been cancelled with callout_cancel or callout_drain */
    if (callout_active(c))
        callout_schedule(c, hz * 10);
}

static int 
mytest_handler(module_t mod, int /*modeventtype_t*/ what, void* arg)
{
    int error;
    struct thread* td;
    int i;
    char myst[MYSTATE_SIZE];

    /* called with GIANT */

    switch (what)
    {
    case MOD_LOAD:
        printf("mytest: MOD_LOAD, version 1.01%s\n", mystate(myst));
        printf("mytest: loaded at syscall number %d\n", sysent_offset);

        mtx_init(& co_mtx, "mytest callout mutex", NULL, MTX_DEF | MTX_RECURSE);
        callout_init_mtx(& co, & co_mtx, 0);
        callout_reset(& co, hz * 10, mytest_callout, & co);

        rw_init(&mydev_rwlock, "mydev_rwlock");

        error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
                            &mydev_dev,
                            &mydev_cdevsw,
                            NULL,
                            UID_ROOT,
                            GID_WHEEL,
                            0600,
                            "mydev");
        if (error != 0)  printf("failed to create device mydev, error %d\n", error);

        error = kproc_create(kproc_main, "kproc-arg", &pkproc, RFHIGHPID, 0, "mytest");
        if (error)  printf("failed to create process, error %d\n", error);

        if (pkproc != NULL)
        {
            PROC_LOCK(pkproc);
            td = FIRST_THREAD_IN_PROC(pkproc);
            PROC_UNLOCK(pkproc);

            thread_lock(td);
            sched_prio(td, PRIBIO);
            thread_unlock(td);

            for (i = 0;  i < NTHREADS;  i++)
            {
                pktd[i] = NULL;
                error = kthread_add(kproc_main_thread, (void*) (long) i, pkproc, &pktd[i], 0, 0, "mytest-kt%d", i);

                if (error)
                    printf("failed to create thread, error %d\n", error);

                if (pktd[i] != NULL)
                {
                    thread_lock(pktd[i]);
                    sched_prio(pktd[i], PVFS);
                    thread_unlock(pktd[i]);
                }
            }

            for (i = 0;  i < NTHREADS;  i++)
            {
                pktd_x[i] = NULL;
                error = kthread_add(kproc_main_thread_x, (void*) (long) i, pkproc, &pktd_x[i], 0, 0, "mytest-ktx%d", i);

                if (error)
                    printf("failed to create thread_x, error %d\n", error);

                if (pktd[i] != NULL)
                {
                    x_pid[i] = pktd[i]->td_proc->p_pid;
                    x_tid[i] = pktd[i]->td_tid;

                    thread_lock(pktd[i]);
                    sched_prio(pktd[i], PVFS);
                    thread_unlock(pktd[i]);
                }
            }
        }

        return 0;

    case MOD_QUIESCE:
        printf("mytest: MOD_QUIESCE%s\n", mystate(myst));

        /* 
         * stop the callout and wait for its completion if it is running;
         * then kill it again if it rescheduled itself
         */
        do 
        {
            callout_drain(& co);
        }
        while (co.c_flags & (CALLOUT_PENDING | CALLOUT_ACTIVE));

        /* stop "x" threads */
        printf("mytest: stopping x-threads\n");
        for (i = 0;  i < NTHREADS;  i++)
        {
            stop_thread_x = true;
            if (pktd_x[i] != NULL)
            {
                wakeup(&pktd_x[i]);

                /* 
                 * Wait for the thread to complete.
                 *
                 * FreeBSD does not provide good primitive to wait for kernel threads to complete
                 * (EVENTHANDLER for thread_dtor would be ok in resident kernel but not suitable for unloadable modules),
                 * so we have to just poll for pid/tid invalidation.
                 */
                for (;;)
                {
                    struct thread* td = tdfind(x_tid[i], x_pid[i]);
                    if (td == NULL)  
                    {
                        break;
                    }
                    else if (td != pktd_x[i])
                    {
                        /* normally should not happen */
                        PROC_UNLOCK(td->td_proc);
                        break;
                    }
                    else
                    {
                        PROC_UNLOCK(td->td_proc);
                        pause("MOD_UNLOAD", max(hz / 100, 1));
                    }
                }

                pktd_x[i] = NULL;
            }
        }
        printf("mytest: stopped x-threads\n");

        /* stop process */
        printf("mytest: stopping kernel process\n");
        if (pkproc != NULL)
        {
            int pid;
            PROC_LOCK(pkproc);
            unloading = TRUE;
            wakeup(&pkproc);
            pid = pkproc->p_pid;
            while (pid == pkproc->p_pid && pkproc->p_state != PRS_ZOMBIE)
                cv_timedwait(&pkproc->p_pwait, &pkproc->p_mtx, max(hz / 20, 1));
            PROC_UNLOCK(pkproc);
        }
        printf("mytest: stopped kernel process\n");

        if (mydev_dev)
        {
            printf("mytest: unloading mydev...\n");
            destroy_dev(mydev_dev);
            destroy_dev_drain(&mydev_cdevsw);
            mydev_dev = NULL;
            printf("mytest: unloaded mydev\n");
        }
        return 0;

    case MOD_UNLOAD:
        printf("mytest: MOD_UNLOAD%s\n", mystate(myst));
        mtx_destroy(& co_mtx);
        rw_destroy(&mydev_rwlock);
        if (mydev_buf)  free(mydev_buf, M_MYDEV_BUF);
        printf("mytest: unloaded from syscall number %d\n", sysent_offset);
        return 0;

    case MOD_SHUTDOWN:
        printf("mytest: MOD_SHUTDOWN%s\n", mystate(myst));
        return 0;

    default:
        return EOPNOTSUPP;
    }
}

struct mytest_args
{
    int code;
    size_t  in_size;
    void*   in_addr;
    size_t  out_maxsize;
    void*   out_addr;
    size_t* out_size;
};

static int
mytest_syscall(struct thread *td, struct mytest_args* uap)
{
    int error = 0;
    int i;
    char myst[MYSTATE_SIZE];

    switch (uap->code)
    {
    case 0:
        {
            char buf[200];
            error = copyinstr(uap->in_addr, buf, countof(buf), NULL);
            if (error)  return error;
            printf("mytest: [%s]%s\n", buf, mystate(myst));
        }
        break;

    case 10:
        dev_lock();
        error = dump_devtree(root_bus, true, 0);
        dev_unlock();
        break;

    case 100:
        printf("mytest: syncing\n");
        for (i = 0;  i < 10;  i++)
        {
            sys_sync(curthread, NULL);
            DELAY(100000);
        }
        printf("mytest: triggering panic\n");
        panic("mytest: user-caused panic");
        break;
        
    default:
        printf("mytest: executing \"undefined\" function\n");
        return EINVAL;
    }
    return error;
}

static struct sysent mytest_sysent = 
{
    6,                             /* sy_narg */
    (sy_call_t*) mytest_syscall    /* sy_call */
};

// static moduledata_t module_data = 
// {
//     "mytest",
//     mytest_handler,
//     0
// };

MODULE_VERSION(mytest, 1);
// MODULE_DEPEND(mytest, othermodule, 1, 3, 4);
// DECLARE_MODULE used for generic module, SYSCALL_MODULE used for module that installs syscalls
// DECLARE_MODULE(mytest, module_data, SI_SUB_EXEC, SI_ORDER_ANY);
SYSCALL_MODULE(mytest, &sysent_offset, &mytest_sysent, mytest_handler, NULL);

static void 
kproc_main(void* arg)
{
    static eventhandler_tag ev_tag = 0;
    unsigned long count = 0;
    int i;
    char myst[MYSTATE_SIZE];

    printf("mytest: kproc: %s%s\n", (char*) arg, mystate(myst));

    /* this process needs to be suspended prior to shutdown sync */
    ev_tag = EVENTHANDLER_REGISTER(shutdown_pre_sync, kproc_shutdown, pkproc, SHUTDOWN_PRI_DEFAULT);

    for (;;)
    {
        kproc_suspend_check(pkproc);
        tsleep(&pkproc, PZERO, "loop sleep", hz * 1);

        if (unloading)
        {
            printf("mytest: kproc: stopping threads\n");
            for (i = 0;  i < NTHREADS;  i++)
            {
                if (pktd[i] != NULL)
                    wakeup(&pktd[i]);
            }
            /* kproc_exit below will wait till all the threads terminate */
            printf("mytest: kproc: requested threads to stop%s\n", mystate(myst));
            printf("mytest: kproc: exiting%s\n", mystate(myst));
            EVENTHANDLER_DEREGISTER(shutdown_pre_sync, ev_tag);
            kproc_exit(0);
        }

        if (0 == (count++ % 10))
            printf("mytest: kproc: loop%s\n", mystate(myst));
    }
}

static void 
kproc_main_thread(void* arg)
{
    static eventhandler_tag ev_tag[NTHREADS];
    unsigned long count = 0;
    int tn = (int) (long) arg;
    struct thread* td = pktd[tn];
    char myst[MYSTATE_SIZE];

    printf("mytest: kthread: %d%s\n", tn, mystate(myst));

    /* 
     * This process/thread needs to be suspended prior to shutdown sync.
     *
     * Note: since both process and thread handlers use the same invocation priority,
     *       process can (and likely will) be supsended before secondary threads.
     */
    ev_tag[tn] = EVENTHANDLER_REGISTER(shutdown_pre_sync, kthread_shutdown, td, SHUTDOWN_PRI_DEFAULT);

    for (;;)
    {
        kthread_suspend_check();
        tsleep(&pktd[tn], PZERO, "loop sleep", hz * 1);

        if (unloading)
        {
            printf("mytest: kthread %d: exiting%s\n", tn, mystate(myst));
            EVENTHANDLER_DEREGISTER(shutdown_pre_sync, ev_tag[tn]);
            kthread_exit();
        }

        if (0 == (count++ % 10))
            printf("mytest: kthread %d: loop%s\n", tn, mystate(myst));
    }
}

static void 
kproc_main_thread_x(void* arg)
{
    static eventhandler_tag ev_tag[NTHREADS];
    unsigned long count = 0;
    int tn = (int) (long) arg;
    struct thread* td = curthread;
    char myst[MYSTATE_SIZE];

    printf("mytest: kthread: x%d%s\n", tn, mystate(myst));

    /* 
     * This thread needs to be suspended prior to shutdown sync.
     *
     * Note: since both process and thread handlers use the same invocation priority,
     *       process can (and likely will) be supsended before secondary threads.
     */
    ev_tag[tn] = EVENTHANDLER_REGISTER(shutdown_pre_sync, kthread_shutdown, td, SHUTDOWN_PRI_DEFAULT);

    for (;;)
    {
        kthread_suspend_check();
        tsleep(&pktd_x[tn], PZERO, "loop sleep", hz * 1);

        if (stop_thread_x || unloading)
        {
            printf("mytest: kthread x%d: exiting%s\n", tn, mystate(myst));
            EVENTHANDLER_DEREGISTER(shutdown_pre_sync, ev_tag[tn]);
            kthread_exit();
        }

        if (0 == (count++ % 10))
            printf("mytest: kthread x%d: loop%s\n", tn, mystate(myst));
    }
}

static char* 
mystate(char* myst)
{
    if (mtx_owned(&Giant))
        strcpy(myst, ", GIANT");
    else
        strcpy(myst, ", MPSAFE");
    return myst;
}

/*
 * caller must hold dev_lock()
 */
static int
dump_devtree(device_t dev, boolean_t recurse, int level)
{
    int error = 0;
    device_t* devlist = NULL;
    int k, devcount = 0;

    const char* name = device_get_name(dev);
    const char* nameunit = device_get_nameunit(dev);
    const char* desc = device_get_desc(dev);
    driver_t* driver = device_get_driver(dev);
    devclass_t devclass = device_get_devclass(dev);
    const char* cname = devclass ? devclass_get_name(devclass) : NULL;
    const char* drvname = driver ? driver->name : NULL;

    if (name == NULL)  name = "<none>";
    if (nameunit == NULL)  nameunit = "<none>";
    if (desc == NULL)  desc = "<none>";
    if (cname == NULL)  cname = "<none>";
    if (drvname == NULL)  drvname = "<none>";

    for (k = 0;  k < level;  k++)
        printf("  ");
    printf("device: %s, nameunit: %s, desc: %s, class: %s, driver: %s\n", name, nameunit, desc, cname, drvname);

    if (recurse)
    {
        error = device_get_children(dev, &devlist, & devcount);
        if (error == 0)
        {
            for (k = 0;  k < devcount;  k++)
            {
                error = dump_devtree(devlist[k], recurse, level + 1);
                if (error)  break;
            }
        }
    }

    if (devlist)
        free(devlist, M_TEMP);

    return error;
}

static int
mydev_open(struct cdev* dev __unused, int oflags __unused, int devtype __unused, struct thread* p __unused)
{
    int error = 0;
    return error;
}

static int
mydev_close(struct cdev* dev __unused, int fflag __unused, int devtype __unused, struct thread* p __unused)
{
    int error = 0;
    return error;
}

static int
mydev_write(struct cdev* dev __unused, struct uio* uio, int ioflag __unused)
{
    /* we always append, so ignore uio->uio_offset */
    unsigned long offset;
    ssize_t amt;
    char* p;
    int error = 0;

    rw_wlock(&mydev_rwlock);

    /* we always append, so ignore uio->uio_offset */
    offset = mydev_buf_size;

    if (mydev_buf == NULL)
        p = malloc(uio->uio_resid, M_MYDEV_BUF, M_WAITOK);
    else
        p = realloc(mydev_buf, uio->uio_resid + mydev_buf_size, M_MYDEV_BUF, M_WAITOK);

    if (p == NULL)
    {
        rw_wunlock(&mydev_rwlock);
        return ENOMEM;
    }

    mydev_buf = p;
    amt = uio->uio_resid;
    error = uiomove(p + offset, amt, uio);
    if (error == 0)
        mydev_buf_size += amt;

    rw_wunlock(&mydev_rwlock);

    return error;
}


static int
mydev_read(struct cdev* dev __unused, struct uio* uio, int ioflag __unused)
{
    int error = 0;
    ssize_t amt;

    rw_rlock(&mydev_rwlock);

    amt = (ssize_t) MIN(uio->uio_resid, (ssize_t) mydev_buf_size - (ssize_t) uio->uio_offset);
    if (amt < 0)  amt = 0;

    /* uiomove decrements uio_resid and advances uio_offset */
    if (amt)
        error = uiomove(mydev_buf + uio->uio_offset, amt, uio);

    rw_runlock(&mydev_rwlock);

    return error;
}

static int
mydev_ioctl(struct cdev* dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
    /* fflag is struct file.f_flag, incl. FREAD and FWRITE */
    return ENXIO;
}
