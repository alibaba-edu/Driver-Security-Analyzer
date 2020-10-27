typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef short __int16_t;
typedef unsigned short __uint16_t;
typedef int __int32_t;
typedef unsigned int __uint32_t;
typedef long long __int64_t;
typedef unsigned long long __uint64_t;
typedef long __darwin_intptr_t;
typedef unsigned int __darwin_natural_t;
typedef int __darwin_ct_rune_t;
typedef union {
char __mbstate8[128];
long long _mbstateL;
} __mbstate_t;
typedef __mbstate_t __darwin_mbstate_t;
typedef long int __darwin_ptrdiff_t;
typedef long unsigned int __darwin_size_t;
typedef __builtin_va_list __darwin_va_list;
typedef int __darwin_wchar_t;
typedef __darwin_wchar_t __darwin_rune_t;
typedef int __darwin_wint_t;
typedef unsigned long __darwin_clock_t;
typedef __uint32_t __darwin_socklen_t;
typedef long __darwin_ssize_t;
typedef long __darwin_time_t;
typedef __int64_t __darwin_blkcnt_t;
typedef __int32_t __darwin_blksize_t;
typedef __int32_t __darwin_dev_t;
typedef unsigned int __darwin_fsblkcnt_t;
typedef unsigned int __darwin_fsfilcnt_t;
typedef __uint32_t __darwin_gid_t;
typedef __uint32_t __darwin_id_t;
typedef __uint64_t __darwin_ino64_t;
typedef __uint32_t __darwin_ino_t;
typedef __darwin_natural_t __darwin_mach_port_name_t;
typedef __darwin_mach_port_name_t __darwin_mach_port_t;
typedef __uint16_t __darwin_mode_t;
typedef __int64_t __darwin_off_t;
typedef __int32_t __darwin_pid_t;
typedef __uint32_t __darwin_sigset_t;
typedef __int32_t __darwin_suseconds_t;
typedef __uint32_t __darwin_uid_t;
typedef __uint32_t __darwin_useconds_t;
typedef unsigned char __darwin_uuid_t[16];
typedef char __darwin_uuid_string_t[37];
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long long u_int64_t;
typedef int64_t register_t;
typedef __darwin_intptr_t intptr_t;
typedef unsigned long uintptr_t;
typedef u_int64_t user_addr_t;
typedef u_int64_t user_size_t;
typedef int64_t user_ssize_t;
typedef int64_t user_long_t;
typedef u_int64_t user_ulong_t;
typedef int64_t user_time_t;
typedef int64_t user_off_t;
typedef __uint64_t user64_addr_t ;
typedef __uint64_t user64_size_t ;
typedef __int64_t user64_ssize_t ;
typedef __int64_t user64_long_t ;
typedef __uint64_t user64_ulong_t ;
typedef __int64_t user64_time_t ;
typedef __int64_t user64_off_t ;
typedef __uint32_t user32_addr_t;
typedef __uint32_t user32_size_t;
typedef __int32_t user32_ssize_t;
typedef __int32_t user32_long_t;
typedef __uint32_t user32_ulong_t;
typedef __int32_t user32_time_t;
typedef __int64_t user32_off_t ;
typedef u_int64_t syscall_arg_t;
static inline
__uint16_t
_OSSwapInt16(
__uint16_t _data
)
{
return ((__uint16_t)((_data << 8) | (_data >> 8)));
}
static inline
__uint32_t
_OSSwapInt32(
__uint32_t _data
)
{
return __builtin_bswap32(_data);
}
static inline
__uint64_t
_OSSwapInt64(
__uint64_t _data
)
{
return __builtin_bswap64(_data);
}
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef u_int64_t u_quad_t;
typedef int64_t quad_t;
typedef quad_t * qaddr_t;
typedef char * caddr_t;
typedef int32_t daddr_t;
typedef __darwin_dev_t dev_t;
typedef u_int32_t fixpt_t;
typedef __darwin_blkcnt_t blkcnt_t;
typedef __darwin_blksize_t blksize_t;
typedef __darwin_gid_t gid_t;
typedef __uint32_t in_addr_t;
typedef __uint16_t in_port_t;
typedef __darwin_ino_t ino_t;
typedef __darwin_ino64_t ino64_t;
typedef __int32_t key_t;
typedef __darwin_mode_t mode_t;
typedef __uint16_t nlink_t;
typedef __darwin_id_t id_t;
typedef __darwin_pid_t pid_t;
typedef __darwin_off_t off_t;
typedef int32_t segsz_t;
typedef int32_t swblk_t;
typedef __darwin_uid_t uid_t;
typedef __darwin_clock_t clock_t;
typedef __darwin_size_t size_t;
typedef __darwin_ssize_t ssize_t;
typedef __darwin_time_t time_t;
typedef __darwin_useconds_t useconds_t;
typedef __darwin_suseconds_t suseconds_t;
typedef __darwin_size_t rsize_t;
typedef int errno_t;
typedef struct fd_set {
__int32_t fds_bits[((((1024) % ((sizeof(__int32_t) * 8))) == 0) ? ((1024) / ((sizeof(__int32_t) * 8))) : (((1024) / ((sizeof(__int32_t) * 8))) + 1))];
} fd_set;
static  int
__darwin_fd_isset(int _n, const struct fd_set *_p)
{
return (_p->fds_bits[(unsigned long)_n/(sizeof(__int32_t) * 8)] & ((__int32_t)(((unsigned long)1)<<((unsigned long)_n % (sizeof(__int32_t) * 8)))));
}
typedef __int32_t fd_mask;
typedef __darwin_fsblkcnt_t fsblkcnt_t;
typedef __darwin_fsfilcnt_t fsfilcnt_t;
typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;
typedef int8_t int_least8_t;
typedef int16_t int_least16_t;
typedef int32_t int_least32_t;
typedef int64_t int_least64_t;
typedef uint8_t uint_least8_t;
typedef uint16_t uint_least16_t;
typedef uint32_t uint_least32_t;
typedef uint64_t uint_least64_t;
typedef int8_t int_fast8_t;
typedef int16_t int_fast16_t;
typedef int32_t int_fast32_t;
typedef int64_t int_fast64_t;
typedef uint8_t uint_fast8_t;
typedef uint16_t uint_fast16_t;
typedef uint32_t uint_fast32_t;
typedef uint64_t uint_fast64_t;
typedef long long intmax_t;
typedef unsigned long long uintmax_t;
struct timespec
{
__darwin_time_t tv_sec;
long tv_nsec;
};
struct timeval
{
__darwin_time_t tv_sec;
__darwin_suseconds_t tv_usec;
};
struct timeval64
{
__int64_t tv_sec;
__int64_t tv_usec;
};
struct user_timespec
{
user_time_t tv_sec;
user_long_t tv_nsec;
};
struct user32_timespec
{
user32_time_t tv_sec;
user32_long_t tv_nsec;
};
struct user64_timespec
{
user64_time_t tv_sec;
user64_long_t tv_nsec;
};
struct user_timeval
{
user_time_t tv_sec;
__int32_t tv_usec;
};
struct user32_timeval
{
user32_time_t tv_sec;
__int32_t tv_usec;
};
struct user64_timeval
{
user64_time_t tv_sec;
__int32_t tv_usec;
};
struct user32_itimerval
{
struct user32_timeval it_interval;
struct user32_timeval it_value;
};
struct user64_itimerval
{
struct user64_timeval it_interval;
struct user64_timeval it_value;
};
struct itimerval {
struct timeval it_interval;
struct timeval it_value;
};
struct timezone {
int tz_minuteswest;
int tz_dsttime;
};
struct clockinfo {
int hz;
int tick;
int tickadj;
int stathz;
int profhz;
};
void microtime(struct timeval *tv);
void microtime_with_abstime(struct timeval *tv, uint64_t *abstime);
void microuptime(struct timeval *tv);
void nanotime(struct timespec *ts);
void nanouptime(struct timespec *ts);
void timevaladd(struct timeval *t1, struct timeval *t2);
void timevalsub(struct timeval *t1, struct timeval *t2);
void timevalfix(struct timeval *t1);
typedef __uint64_t rlim_t;
struct rusage {
struct timeval ru_utime;
struct timeval ru_stime;
long ru_maxrss;
long ru_ixrss;
long ru_idrss;
long ru_isrss;
long ru_minflt;
long ru_majflt;
long ru_nswap;
long ru_inblock;
long ru_oublock;
long ru_msgsnd;
long ru_msgrcv;
long ru_nsignals;
long ru_nvcsw;
long ru_nivcsw;
};
typedef void *rusage_info_t;
struct rusage_info_v0 {
uint8_t ri_uuid[16];
uint64_t ri_user_time;
uint64_t ri_system_time;
uint64_t ri_pkg_idle_wkups;
uint64_t ri_interrupt_wkups;
uint64_t ri_pageins;
uint64_t ri_wired_size;
uint64_t ri_resident_size;
uint64_t ri_phys_footprint;
uint64_t ri_proc_start_abstime;
uint64_t ri_proc_exit_abstime;
};
struct rusage_info_v1 {
uint8_t ri_uuid[16];
uint64_t ri_user_time;
uint64_t ri_system_time;
uint64_t ri_pkg_idle_wkups;
uint64_t ri_interrupt_wkups;
uint64_t ri_pageins;
uint64_t ri_wired_size;
uint64_t ri_resident_size;
uint64_t ri_phys_footprint;
uint64_t ri_proc_start_abstime;
uint64_t ri_proc_exit_abstime;
uint64_t ri_child_user_time;
uint64_t ri_child_system_time;
uint64_t ri_child_pkg_idle_wkups;
uint64_t ri_child_interrupt_wkups;
uint64_t ri_child_pageins;
uint64_t ri_child_elapsed_abstime;
};
struct rusage_info_v2 {
uint8_t ri_uuid[16];
uint64_t ri_user_time;
uint64_t ri_system_time;
uint64_t ri_pkg_idle_wkups;
uint64_t ri_interrupt_wkups;
uint64_t ri_pageins;
uint64_t ri_wired_size;
uint64_t ri_resident_size;
uint64_t ri_phys_footprint;
uint64_t ri_proc_start_abstime;
uint64_t ri_proc_exit_abstime;
uint64_t ri_child_user_time;
uint64_t ri_child_system_time;
uint64_t ri_child_pkg_idle_wkups;
uint64_t ri_child_interrupt_wkups;
uint64_t ri_child_pageins;
uint64_t ri_child_elapsed_abstime;
uint64_t ri_diskio_bytesread;
uint64_t ri_diskio_byteswritten;
};
struct rusage_info_v3 {
uint8_t ri_uuid[16];
uint64_t ri_user_time;
uint64_t ri_system_time;
uint64_t ri_pkg_idle_wkups;
uint64_t ri_interrupt_wkups;
uint64_t ri_pageins;
uint64_t ri_wired_size;
uint64_t ri_resident_size;
uint64_t ri_phys_footprint;
uint64_t ri_proc_start_abstime;
uint64_t ri_proc_exit_abstime;
uint64_t ri_child_user_time;
uint64_t ri_child_system_time;
uint64_t ri_child_pkg_idle_wkups;
uint64_t ri_child_interrupt_wkups;
uint64_t ri_child_pageins;
uint64_t ri_child_elapsed_abstime;
uint64_t ri_diskio_bytesread;
uint64_t ri_diskio_byteswritten;
uint64_t ri_cpu_time_qos_default;
uint64_t ri_cpu_time_qos_maintenance;
uint64_t ri_cpu_time_qos_background;
uint64_t ri_cpu_time_qos_utility;
uint64_t ri_cpu_time_qos_legacy;
uint64_t ri_cpu_time_qos_user_initiated;
uint64_t ri_cpu_time_qos_user_interactive;
uint64_t ri_billed_system_time;
uint64_t ri_serviced_system_time;
};
struct rusage_info_v4 {
uint8_t ri_uuid[16];
uint64_t ri_user_time;
uint64_t ri_system_time;
uint64_t ri_pkg_idle_wkups;
uint64_t ri_interrupt_wkups;
uint64_t ri_pageins;
uint64_t ri_wired_size;
uint64_t ri_resident_size;
uint64_t ri_phys_footprint;
uint64_t ri_proc_start_abstime;
uint64_t ri_proc_exit_abstime;
uint64_t ri_child_user_time;
uint64_t ri_child_system_time;
uint64_t ri_child_pkg_idle_wkups;
uint64_t ri_child_interrupt_wkups;
uint64_t ri_child_pageins;
uint64_t ri_child_elapsed_abstime;
uint64_t ri_diskio_bytesread;
uint64_t ri_diskio_byteswritten;
uint64_t ri_cpu_time_qos_default;
uint64_t ri_cpu_time_qos_maintenance;
uint64_t ri_cpu_time_qos_background;
uint64_t ri_cpu_time_qos_utility;
uint64_t ri_cpu_time_qos_legacy;
uint64_t ri_cpu_time_qos_user_initiated;
uint64_t ri_cpu_time_qos_user_interactive;
uint64_t ri_billed_system_time;
uint64_t ri_serviced_system_time;
uint64_t ri_logical_writes;
uint64_t ri_lifetime_max_phys_footprint;
uint64_t ri_instructions;
uint64_t ri_cycles;
uint64_t ri_billed_energy;
uint64_t ri_serviced_energy;
uint64_t ri_unused[2];
};
typedef struct rusage_info_v4 rusage_info_current;
struct rusage_superset {
struct rusage ru;
rusage_info_current ri;
};
struct rusage_info_child {
uint64_t ri_child_user_time;
uint64_t ri_child_system_time;
uint64_t ri_child_pkg_idle_wkups;
uint64_t ri_child_interrupt_wkups;
uint64_t ri_child_pageins;
uint64_t ri_child_elapsed_abstime;
};
struct user64_rusage {
struct user64_timeval ru_utime;
struct user64_timeval ru_stime;
user64_long_t ru_maxrss;
user64_long_t ru_ixrss;
user64_long_t ru_idrss;
user64_long_t ru_isrss;
user64_long_t ru_minflt;
user64_long_t ru_majflt;
user64_long_t ru_nswap;
user64_long_t ru_inblock;
user64_long_t ru_oublock;
user64_long_t ru_msgsnd;
user64_long_t ru_msgrcv;
user64_long_t ru_nsignals;
user64_long_t ru_nvcsw;
user64_long_t ru_nivcsw;
};
struct user32_rusage {
struct user32_timeval ru_utime;
struct user32_timeval ru_stime;
user32_long_t ru_maxrss;
user32_long_t ru_ixrss;
user32_long_t ru_idrss;
user32_long_t ru_isrss;
user32_long_t ru_minflt;
user32_long_t ru_majflt;
user32_long_t ru_nswap;
user32_long_t ru_inblock;
user32_long_t ru_oublock;
user32_long_t ru_msgsnd;
user32_long_t ru_msgrcv;
user32_long_t ru_nsignals;
user32_long_t ru_nvcsw;
user32_long_t ru_nivcsw;
};
struct rlimit {
rlim_t rlim_cur;
rlim_t rlim_max;
};
struct proc_rlimit_control_wakeupmon {
uint32_t wm_flags;
int32_t wm_rate;
};
typedef uid_t au_id_t;
typedef pid_t au_asid_t;
typedef u_int16_t au_event_t;
typedef u_int16_t au_emod_t;
typedef u_int32_t au_class_t;
typedef u_int64_t au_asflgs_t ;
struct au_tid {
dev_t port;
u_int32_t machine;
};
typedef struct au_tid au_tid_t;
struct au_tid_addr {
dev_t at_port;
u_int32_t at_type;
u_int32_t at_addr[4];
};
typedef struct au_tid_addr au_tid_addr_t;
struct au_mask {
unsigned int am_success;
unsigned int am_failure;
};
typedef struct au_mask au_mask_t;
struct auditinfo {
au_id_t ai_auid;
au_mask_t ai_mask;
au_tid_t ai_termid;
au_asid_t ai_asid;
};
typedef struct auditinfo auditinfo_t;
struct auditinfo_addr {
au_id_t ai_auid;
au_mask_t ai_mask;
au_tid_addr_t ai_termid;
au_asid_t ai_asid;
au_asflgs_t ai_flags;
};
typedef struct auditinfo_addr auditinfo_addr_t;
struct auditpinfo {
pid_t ap_pid;
au_id_t ap_auid;
au_mask_t ap_mask;
au_tid_t ap_termid;
au_asid_t ap_asid;
};
typedef struct auditpinfo auditpinfo_t;
struct auditpinfo_addr {
pid_t ap_pid;
au_id_t ap_auid;
au_mask_t ap_mask;
au_tid_addr_t ap_termid;
au_asid_t ap_asid;
au_asflgs_t ap_flags;
};
typedef struct auditpinfo_addr auditpinfo_addr_t;
struct au_session {
auditinfo_addr_t *as_aia_p;
au_mask_t as_mask;
};
typedef struct au_session au_session_t;
typedef struct au_token token_t;
struct au_qctrl {
int aq_hiwater;
int aq_lowater;
int aq_bufsz;
int aq_delay;
int aq_minfree;
};
typedef struct au_qctrl au_qctrl_t;
struct audit_stat {
unsigned int as_version;
unsigned int as_numevent;
int as_generated;
int as_nonattrib;
int as_kernel;
int as_audit;
int as_auditctl;
int as_enqueue;
int as_written;
int as_wblocked;
int as_rblocked;
int as_dropped;
int as_totalsize;
unsigned int as_memused;
};
typedef struct audit_stat au_stat_t;
struct audit_fstat {
u_int64_t af_filesz;
u_int64_t af_currsz;
};
typedef struct audit_fstat au_fstat_t;
struct au_evclass_map {
au_event_t ec_number;
au_class_t ec_class;
};
typedef struct au_evclass_map au_evclass_map_t;
struct label;
struct ucred {
struct { struct ucred *tqe_next; struct ucred **tqe_prev; } cr_link;
u_long cr_ref;
struct posix_cred {
uid_t cr_uid;
uid_t cr_ruid;
uid_t cr_svuid;
short cr_ngroups;
gid_t cr_groups[16];
gid_t cr_rgid;
gid_t cr_svgid;
uid_t cr_gmuid;
int cr_flags;
} cr_posix;
struct label *cr_label;
struct au_session cr_audit;
};
typedef struct ucred *kauth_cred_t;
typedef struct posix_cred *posix_cred_t;
struct xucred {
u_int cr_version;
uid_t cr_uid;
short cr_ngroups;
gid_t cr_groups[16];
};
int crcmp(kauth_cred_t cr1, kauth_cred_t cr2);
int suser(kauth_cred_t cred, u_short *acflag);
int set_security_token(struct proc * p);
int set_security_token_task_internal(struct proc *p, void *task);
void cru2x(kauth_cred_t cr, struct xucred *xcr);
struct iovec {
void * iov_base;
size_t iov_len;
};
enum uio_rw { UIO_READ, UIO_WRITE };
typedef int64_t daddr64_t;
struct buf;
typedef struct buf * buf_t;
struct file;
typedef struct file * file_t;
struct mount;
typedef struct mount * mount_t;
struct vnode;
typedef struct vnode * vnode_t;
struct proc;
typedef struct proc * proc_t;
struct uio;
typedef struct uio * uio_t;
struct vfs_context;
typedef struct vfs_context * vfs_context_t;
struct vfstable;
typedef struct vfstable * vfstable_t;
struct __ifnet;
struct __mbuf;
struct __pkthdr;
struct __socket;
struct __sockopt;
struct __ifaddr;
struct __ifmultiaddr;
struct __ifnet_filter;
struct __rtentry;
struct __if_clone;
struct __bufattr;
typedef struct __ifnet* ifnet_t;
typedef struct __mbuf* mbuf_t;
typedef struct __pkthdr* pkthdr_t;
typedef struct __socket* socket_t;
typedef struct __sockopt* sockopt_t;
typedef struct __ifaddr* ifaddr_t;
typedef struct __ifmultiaddr* ifmultiaddr_t;
typedef struct __ifnet_filter* interface_filter_t;
typedef struct __rtentry* route_t;
typedef struct __if_clone* if_clone_t;
typedef struct __bufattr* bufattr_t;
typedef struct {
unsigned char g_guid[16];
} guid_t;
struct kauth_ace;
typedef struct kauth_ace * kauth_ace_t;
struct kauth_acl;
typedef struct kauth_acl * kauth_acl_t;
struct kauth_filesec;
typedef struct kauth_filesec * kauth_filesec_t;
typedef int kauth_action_t;
enum uio_seg {
UIO_USERSPACE = 0,
UIO_SYSSPACE = 2,
UIO_USERSPACE32 = 5,
UIO_USERSPACE64 = 8,
UIO_SYSSPACE32 = 11
};
uio_t uio_create( int a_iovcount,
off_t a_offset,
int a_spacetype,
int a_iodirection );
void uio_reset( uio_t a_uio,
off_t a_offset,
int a_spacetype,
int a_iodirection );
uio_t uio_duplicate( uio_t a_uio );
void uio_free( uio_t a_uio );
int uio_addiov( uio_t a_uio, user_addr_t a_baseaddr, user_size_t a_length );
int uio_getiov( uio_t a_uio,
int a_index,
user_addr_t * a_baseaddr_p,
user_size_t * a_length_p );
void uio_update( uio_t a_uio, user_size_t a_count );
user_ssize_t uio_resid( uio_t a_uio );
void uio_setresid( uio_t a_uio, user_ssize_t a_value );
int uio_iovcnt( uio_t a_uio );
off_t uio_offset( uio_t a_uio );
void uio_setoffset( uio_t a_uio, off_t a_offset );
int uio_rw( uio_t a_uio );
void uio_setrw( uio_t a_uio, int a_value );
int uio_isuserspace( uio_t a_uio );
user_addr_t uio_curriovbase( uio_t a_uio );
user_size_t uio_curriovlen( uio_t a_uio );
extern int uiomove(const char * cp, int n, struct uio *uio);
extern int uiomove64(const __uint64_t cp, int n, struct uio *uio);
typedef int sig_atomic_t;
struct i386_thread_state
{
unsigned int eax;
unsigned int ebx;
unsigned int ecx;
unsigned int edx;
unsigned int edi;
unsigned int esi;
unsigned int ebp;
unsigned int esp;
unsigned int ss;
unsigned int eflags;
unsigned int eip;
unsigned int cs;
unsigned int ds;
unsigned int es;
unsigned int fs;
unsigned int gs;
};
struct fp_control
{
unsigned short invalid :1,
denorm :1,
zdiv :1,
ovrfl :1,
undfl :1,
precis :1,
:2,
pc :2,
rc :2,
:1,
:3;
};
typedef struct fp_control fp_control_t;
struct fp_status
{
unsigned short invalid :1,
denorm :1,
zdiv :1,
ovrfl :1,
undfl :1,
precis :1,
stkflt :1,
errsumm :1,
c0 :1,
c1 :1,
c2 :1,
tos :3,
c3 :1,
busy :1;
};
typedef struct fp_status fp_status_t;
struct mmst_reg
{
char mmst_reg[10];
char mmst_rsrv[6];
};
struct xmm_reg
{
char xmm_reg[16];
};
struct ymm_reg
{
char ymm_reg[32];
};
struct zmm_reg
{
char zmm_reg[64];
};
struct opmask_reg
{
char opmask_reg[8];
};
struct i386_float_state
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
char fpu_rsrv4[14*16];
int fpu_reserved1;
};
struct i386_avx_state
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
char fpu_rsrv4[14*16];
int fpu_reserved1;
char avx_reserved1[64];
struct xmm_reg fpu_ymmh0;
struct xmm_reg fpu_ymmh1;
struct xmm_reg fpu_ymmh2;
struct xmm_reg fpu_ymmh3;
struct xmm_reg fpu_ymmh4;
struct xmm_reg fpu_ymmh5;
struct xmm_reg fpu_ymmh6;
struct xmm_reg fpu_ymmh7;
};
struct i386_avx512_state
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
char fpu_rsrv4[14*16];
int fpu_reserved1;
char avx_reserved1[64];
struct xmm_reg fpu_ymmh0;
struct xmm_reg fpu_ymmh1;
struct xmm_reg fpu_ymmh2;
struct xmm_reg fpu_ymmh3;
struct xmm_reg fpu_ymmh4;
struct xmm_reg fpu_ymmh5;
struct xmm_reg fpu_ymmh6;
struct xmm_reg fpu_ymmh7;
struct opmask_reg fpu_k0;
struct opmask_reg fpu_k1;
struct opmask_reg fpu_k2;
struct opmask_reg fpu_k3;
struct opmask_reg fpu_k4;
struct opmask_reg fpu_k5;
struct opmask_reg fpu_k6;
struct opmask_reg fpu_k7;
struct ymm_reg fpu_zmmh0;
struct ymm_reg fpu_zmmh1;
struct ymm_reg fpu_zmmh2;
struct ymm_reg fpu_zmmh3;
struct ymm_reg fpu_zmmh4;
struct ymm_reg fpu_zmmh5;
struct ymm_reg fpu_zmmh6;
struct ymm_reg fpu_zmmh7;
};
struct i386_exception_state
{
__uint16_t trapno;
__uint16_t cpu;
__uint32_t err;
__uint32_t faultvaddr;
};
struct x86_debug_state32
{
unsigned int dr0;
unsigned int dr1;
unsigned int dr2;
unsigned int dr3;
unsigned int dr4;
unsigned int dr5;
unsigned int dr6;
unsigned int dr7;
};
struct x86_thread_state64
{
__uint64_t rax;
__uint64_t rbx;
__uint64_t rcx;
__uint64_t rdx;
__uint64_t rdi;
__uint64_t rsi;
__uint64_t rbp;
__uint64_t rsp;
__uint64_t r8;
__uint64_t r9;
__uint64_t r10;
__uint64_t r11;
__uint64_t r12;
__uint64_t r13;
__uint64_t r14;
__uint64_t r15;
__uint64_t rip;
__uint64_t rflags;
__uint64_t cs;
__uint64_t fs;
__uint64_t gs;
};
struct x86_float_state64
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
struct xmm_reg fpu_xmm8;
struct xmm_reg fpu_xmm9;
struct xmm_reg fpu_xmm10;
struct xmm_reg fpu_xmm11;
struct xmm_reg fpu_xmm12;
struct xmm_reg fpu_xmm13;
struct xmm_reg fpu_xmm14;
struct xmm_reg fpu_xmm15;
char fpu_rsrv4[6*16];
int fpu_reserved1;
};
struct x86_avx_state64
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
struct xmm_reg fpu_xmm8;
struct xmm_reg fpu_xmm9;
struct xmm_reg fpu_xmm10;
struct xmm_reg fpu_xmm11;
struct xmm_reg fpu_xmm12;
struct xmm_reg fpu_xmm13;
struct xmm_reg fpu_xmm14;
struct xmm_reg fpu_xmm15;
char fpu_rsrv4[6*16];
int fpu_reserved1;
char avx_reserved1[64];
struct xmm_reg fpu_ymmh0;
struct xmm_reg fpu_ymmh1;
struct xmm_reg fpu_ymmh2;
struct xmm_reg fpu_ymmh3;
struct xmm_reg fpu_ymmh4;
struct xmm_reg fpu_ymmh5;
struct xmm_reg fpu_ymmh6;
struct xmm_reg fpu_ymmh7;
struct xmm_reg fpu_ymmh8;
struct xmm_reg fpu_ymmh9;
struct xmm_reg fpu_ymmh10;
struct xmm_reg fpu_ymmh11;
struct xmm_reg fpu_ymmh12;
struct xmm_reg fpu_ymmh13;
struct xmm_reg fpu_ymmh14;
struct xmm_reg fpu_ymmh15;
};
struct x86_avx512_state64
{
int fpu_reserved[2];
struct fp_control fpu_fcw;
struct fp_status fpu_fsw;
__uint8_t fpu_ftw;
__uint8_t fpu_rsrv1;
__uint16_t fpu_fop;
__uint32_t fpu_ip;
__uint16_t fpu_cs;
__uint16_t fpu_rsrv2;
__uint32_t fpu_dp;
__uint16_t fpu_ds;
__uint16_t fpu_rsrv3;
__uint32_t fpu_mxcsr;
__uint32_t fpu_mxcsrmask;
struct mmst_reg fpu_stmm0;
struct mmst_reg fpu_stmm1;
struct mmst_reg fpu_stmm2;
struct mmst_reg fpu_stmm3;
struct mmst_reg fpu_stmm4;
struct mmst_reg fpu_stmm5;
struct mmst_reg fpu_stmm6;
struct mmst_reg fpu_stmm7;
struct xmm_reg fpu_xmm0;
struct xmm_reg fpu_xmm1;
struct xmm_reg fpu_xmm2;
struct xmm_reg fpu_xmm3;
struct xmm_reg fpu_xmm4;
struct xmm_reg fpu_xmm5;
struct xmm_reg fpu_xmm6;
struct xmm_reg fpu_xmm7;
struct xmm_reg fpu_xmm8;
struct xmm_reg fpu_xmm9;
struct xmm_reg fpu_xmm10;
struct xmm_reg fpu_xmm11;
struct xmm_reg fpu_xmm12;
struct xmm_reg fpu_xmm13;
struct xmm_reg fpu_xmm14;
struct xmm_reg fpu_xmm15;
char fpu_rsrv4[6*16];
int fpu_reserved1;
char avx_reserved1[64];
struct xmm_reg fpu_ymmh0;
struct xmm_reg fpu_ymmh1;
struct xmm_reg fpu_ymmh2;
struct xmm_reg fpu_ymmh3;
struct xmm_reg fpu_ymmh4;
struct xmm_reg fpu_ymmh5;
struct xmm_reg fpu_ymmh6;
struct xmm_reg fpu_ymmh7;
struct xmm_reg fpu_ymmh8;
struct xmm_reg fpu_ymmh9;
struct xmm_reg fpu_ymmh10;
struct xmm_reg fpu_ymmh11;
struct xmm_reg fpu_ymmh12;
struct xmm_reg fpu_ymmh13;
struct xmm_reg fpu_ymmh14;
struct xmm_reg fpu_ymmh15;
struct opmask_reg fpu_k0;
struct opmask_reg fpu_k1;
struct opmask_reg fpu_k2;
struct opmask_reg fpu_k3;
struct opmask_reg fpu_k4;
struct opmask_reg fpu_k5;
struct opmask_reg fpu_k6;
struct opmask_reg fpu_k7;
struct ymm_reg fpu_zmmh0;
struct ymm_reg fpu_zmmh1;
struct ymm_reg fpu_zmmh2;
struct ymm_reg fpu_zmmh3;
struct ymm_reg fpu_zmmh4;
struct ymm_reg fpu_zmmh5;
struct ymm_reg fpu_zmmh6;
struct ymm_reg fpu_zmmh7;
struct ymm_reg fpu_zmmh8;
struct ymm_reg fpu_zmmh9;
struct ymm_reg fpu_zmmh10;
struct ymm_reg fpu_zmmh11;
struct ymm_reg fpu_zmmh12;
struct ymm_reg fpu_zmmh13;
struct ymm_reg fpu_zmmh14;
struct ymm_reg fpu_zmmh15;
struct zmm_reg fpu_zmm16;
struct zmm_reg fpu_zmm17;
struct zmm_reg fpu_zmm18;
struct zmm_reg fpu_zmm19;
struct zmm_reg fpu_zmm20;
struct zmm_reg fpu_zmm21;
struct zmm_reg fpu_zmm22;
struct zmm_reg fpu_zmm23;
struct zmm_reg fpu_zmm24;
struct zmm_reg fpu_zmm25;
struct zmm_reg fpu_zmm26;
struct zmm_reg fpu_zmm27;
struct zmm_reg fpu_zmm28;
struct zmm_reg fpu_zmm29;
struct zmm_reg fpu_zmm30;
struct zmm_reg fpu_zmm31;
};
struct x86_exception_state64
{
__uint16_t trapno;
__uint16_t cpu;
__uint32_t err;
__uint64_t faultvaddr;
};
struct x86_debug_state64
{
__uint64_t dr0;
__uint64_t dr1;
__uint64_t dr2;
__uint64_t dr3;
__uint64_t dr4;
__uint64_t dr5;
__uint64_t dr6;
__uint64_t dr7;
};
struct x86_cpmu_state64
{
__uint64_t ctrs[16];
};
struct mcontext32
{
struct i386_exception_state es;
struct i386_thread_state ss;
struct i386_float_state fs;
};
struct mcontext_avx32
{
struct i386_exception_state es;
struct i386_thread_state ss;
struct i386_avx_state fs;
};
struct mcontext_avx512_32
{
struct i386_exception_state es;
struct i386_thread_state ss;
struct i386_avx512_state fs;
};
struct mcontext64
{
struct x86_exception_state64 es;
struct x86_thread_state64 ss;
struct x86_float_state64 fs;
};
struct mcontext_avx64
{
struct x86_exception_state64 es;
struct x86_thread_state64 ss;
struct x86_avx_state64 fs;
};
struct mcontext_avx512_64
{
struct x86_exception_state64 es;
struct x86_thread_state64 ss;
struct x86_avx512_state64 fs;
};
typedef struct mcontext64 *mcontext_t;
struct sigaltstack
{
void *ss_sp;
__darwin_size_t ss_size;
int ss_flags;
};
typedef struct sigaltstack stack_t;
struct ucontext
{
int uc_onstack;
__darwin_sigset_t uc_sigmask;
struct sigaltstack uc_stack;
struct ucontext *uc_link;
__darwin_size_t uc_mcsize;
struct mcontext64 *uc_mcontext;
};
typedef struct ucontext ucontext_t;
typedef __darwin_sigset_t sigset_t;
union sigval {
int sival_int;
void *sival_ptr;
};
typedef struct __siginfo {
int si_signo;
int si_errno;
int si_code;
pid_t si_pid;
uid_t si_uid;
int si_status;
void *si_addr;
union sigval si_value;
long si_band;
unsigned long __pad[7];
} siginfo_t;
union __sigaction_u {
void (*__sa_handler)(int);
void (*__sa_sigaction)(int, struct __siginfo *,
void *);
};
struct __sigaction {
union __sigaction_u __sigaction_u;
void (*sa_tramp)(void *, int, int, siginfo_t *, void *);
sigset_t sa_mask;
int sa_flags;
};
struct sigaction {
union __sigaction_u __sigaction_u;
sigset_t sa_mask;
int sa_flags;
};
typedef void (*sig_t)(int);
struct sigvec {
void (*sv_handler)(int);
int sv_mask;
int sv_flags;
};
struct sigstack {
char *ss_sp;
int ss_onstack;
};
void (*signal(int, void (*)(int)))(int);
struct winsize {
unsigned short ws_row;
unsigned short ws_col;
unsigned short ws_xpixel;
unsigned short ws_ypixel;
};
struct ttysize {
unsigned short ts_lines;
unsigned short ts_cols;
unsigned short ts_xxx;
unsigned short ts_yyy;
};
extern void *_MALLOC(
size_t size,
int type,
int flags);
extern void _FREE(
void *addr,
int type);
extern void *_REALLOC(
void *addr,
size_t size,
int type,
int flags);
extern void *_MALLOC_ZONE(
size_t size,
int type,
int flags);
extern void _FREE_ZONE(
void *elem,
size_t size,
int type);
struct kevent {
uintptr_t ident;
int16_t filter;
uint16_t flags;
uint32_t fflags;
intptr_t data;
void *udata;
};
struct kevent64_s {
uint64_t ident;
int16_t filter;
uint16_t flags;
uint32_t fflags;
int64_t data;
uint64_t udata;
uint64_t ext[2];
};
enum {
eNoteReapDeprecated  = 0x10000000
};
enum {
eNoteExitReparentedDeprecated  = 0x00080000
};
struct selinfo;
extern int selwait;
void selrecord(proc_t selector, struct selinfo *, void *);
void selwakeup(struct selinfo *);
void selthreadclear(struct selinfo *);
typedef int boolean_t;
typedef __darwin_natural_t natural_t;
typedef int integer_t;
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_size_t;
typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_offset_t;
typedef uint64_t mach_vm_size_t;
typedef uint64_t vm_map_offset_t;
typedef uint64_t vm_map_address_t;
typedef uint64_t vm_map_size_t;
typedef mach_vm_address_t mach_port_context_t;
typedef natural_t mach_port_name_t;
typedef mach_port_name_t *mach_port_name_array_t;
struct ipc_port ;
typedef struct ipc_port *ipc_port_t;
typedef ipc_port_t mach_port_t;
typedef mach_port_t *mach_port_array_t;
typedef natural_t mach_port_right_t;
typedef natural_t mach_port_type_t;
typedef mach_port_type_t *mach_port_type_array_t;
typedef natural_t mach_port_urefs_t;
typedef integer_t mach_port_delta_t;
typedef natural_t mach_port_seqno_t;
typedef natural_t mach_port_mscount_t;
typedef natural_t mach_port_msgcount_t;
typedef natural_t mach_port_rights_t;
typedef unsigned int mach_port_srights_t;
typedef struct mach_port_status {
mach_port_rights_t mps_pset;
mach_port_seqno_t mps_seqno;
mach_port_mscount_t mps_mscount;
mach_port_msgcount_t mps_qlimit;
mach_port_msgcount_t mps_msgcount;
mach_port_rights_t mps_sorights;
boolean_t mps_srights;
boolean_t mps_pdrequest;
boolean_t mps_nsrequest;
natural_t mps_flags;
} mach_port_status_t;
typedef struct mach_port_limits {
mach_port_msgcount_t mpl_qlimit;
} mach_port_limits_t;
typedef struct mach_port_info_ext {
mach_port_status_t mpie_status;
mach_port_msgcount_t mpie_boost_cnt;
uint32_t reserved[6];
} mach_port_info_ext_t;
typedef integer_t *mach_port_info_t;
typedef int mach_port_flavor_t;
typedef struct mach_port_qos {
unsigned int name:1;
unsigned int prealloc:1;
boolean_t pad1:30;
natural_t len;
} mach_port_qos_t;
typedef struct mach_port_options {
uint32_t flags;
mach_port_limits_t mpl;
uint64_t reserved[2];
}mach_port_options_t;
typedef mach_port_options_t *mach_port_options_ptr_t;
enum mach_port_guard_exception_codes {
kGUARD_EXC_DESTROY = 1u << 0,
kGUARD_EXC_MOD_REFS = 1u << 1,
kGUARD_EXC_SET_CONTEXT = 1u << 2,
kGUARD_EXC_UNGUARDED = 1u << 3,
kGUARD_EXC_INCORRECT_GUARD = 1u << 4
};
typedef mach_port_t port_t;
typedef mach_port_name_t port_name_t;
typedef mach_port_name_t *port_name_array_t;
typedef int kern_return_t;
typedef natural_t mach_msg_timeout_t;
typedef unsigned int mach_msg_bits_t;
typedef natural_t mach_msg_size_t;
typedef integer_t mach_msg_id_t;
typedef unsigned int mach_msg_priority_t;
typedef unsigned int mach_msg_type_name_t;
typedef unsigned int mach_msg_copy_options_t;
typedef unsigned int mach_msg_descriptor_type_t;
typedef struct
{
natural_t pad1;
mach_msg_size_t pad2;
unsigned int pad3 : 24;
mach_msg_descriptor_type_t type : 8;
} mach_msg_type_descriptor_t;
typedef struct
{
mach_port_t name;
mach_msg_size_t pad1;
unsigned int pad2 : 16;
mach_msg_type_name_t disposition : 8;
mach_msg_descriptor_type_t type : 8;
uint32_t pad_end;
} mach_msg_port_descriptor_t;
typedef struct
{
uint32_t address;
mach_msg_size_t size;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
unsigned int pad1: 8;
mach_msg_descriptor_type_t type: 8;
} mach_msg_ool_descriptor32_t;
typedef struct
{
uint64_t address;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
unsigned int pad1: 8;
mach_msg_descriptor_type_t type: 8;
mach_msg_size_t size;
} mach_msg_ool_descriptor64_t;
typedef struct
{
void* address;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
unsigned int pad1: 8;
mach_msg_descriptor_type_t type: 8;
mach_msg_size_t size;
} mach_msg_ool_descriptor_t;
typedef struct
{
uint32_t address;
mach_msg_size_t count;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
mach_msg_type_name_t disposition : 8;
mach_msg_descriptor_type_t type : 8;
} mach_msg_ool_ports_descriptor32_t;
typedef struct
{
uint64_t address;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
mach_msg_type_name_t disposition : 8;
mach_msg_descriptor_type_t type : 8;
mach_msg_size_t count;
} mach_msg_ool_ports_descriptor64_t;
typedef struct
{
void* address;
boolean_t deallocate: 8;
mach_msg_copy_options_t copy: 8;
mach_msg_type_name_t disposition : 8;
mach_msg_descriptor_type_t type : 8;
mach_msg_size_t count;
} mach_msg_ool_ports_descriptor_t;
typedef union
{
mach_msg_port_descriptor_t port;
mach_msg_ool_descriptor_t out_of_line;
mach_msg_ool_ports_descriptor_t ool_ports;
mach_msg_type_descriptor_t type;
} mach_msg_descriptor_t;
typedef struct
{
mach_msg_size_t msgh_descriptor_count;
} mach_msg_body_t;
typedef struct
{
mach_msg_bits_t msgh_bits;
mach_msg_size_t msgh_size;
mach_port_t msgh_remote_port;
mach_port_t msgh_local_port;
mach_port_name_t msgh_voucher_port;
mach_msg_id_t msgh_id;
} mach_msg_header_t;
typedef struct
{
mach_msg_header_t header;
mach_msg_body_t body;
} mach_msg_base_t;
typedef unsigned int mach_msg_trailer_type_t;
typedef unsigned int mach_msg_trailer_size_t;
typedef char *mach_msg_trailer_info_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
} mach_msg_trailer_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
mach_port_seqno_t msgh_seqno;
} mach_msg_seqno_trailer_t;
typedef struct
{
unsigned int val[2];
} security_token_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
mach_port_seqno_t msgh_seqno;
security_token_t msgh_sender;
} mach_msg_security_trailer_t;
typedef struct
{
unsigned int val[8];
} audit_token_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
mach_port_seqno_t msgh_seqno;
security_token_t msgh_sender;
audit_token_t msgh_audit;
} mach_msg_audit_trailer_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
mach_port_seqno_t msgh_seqno;
security_token_t msgh_sender;
audit_token_t msgh_audit;
mach_port_context_t msgh_context;
} mach_msg_context_trailer_t;
typedef struct
{
mach_port_name_t sender;
} msg_labels_t;
typedef struct
{
mach_msg_trailer_type_t msgh_trailer_type;
mach_msg_trailer_size_t msgh_trailer_size;
mach_port_seqno_t msgh_seqno;
security_token_t msgh_sender;
audit_token_t msgh_audit;
mach_port_context_t msgh_context;
int msgh_ad;
msg_labels_t msgh_labels;
} mach_msg_mac_trailer_t;
typedef mach_msg_mac_trailer_t mach_msg_max_trailer_t;
typedef mach_msg_security_trailer_t mach_msg_format_0_trailer_t;
extern security_token_t KERNEL_SECURITY_TOKEN;
extern audit_token_t KERNEL_AUDIT_TOKEN;
typedef integer_t mach_msg_options_t;
typedef struct
{
mach_msg_header_t header;
} mach_msg_empty_send_t;
typedef struct
{
mach_msg_header_t header;
mach_msg_trailer_t trailer;
} mach_msg_empty_rcv_t;
typedef union
{
mach_msg_empty_send_t send;
mach_msg_empty_rcv_t rcv;
} mach_msg_empty_t;
typedef natural_t mach_msg_type_size_t;
typedef natural_t mach_msg_type_number_t;
typedef integer_t mach_msg_option_t;
typedef kern_return_t mach_msg_return_t;
 
extern mach_msg_return_t mach_msg_overwrite(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify,
mach_msg_header_t *rcv_msg,
mach_msg_size_t rcv_limit);
struct vm_statistics {
natural_t free_count;
natural_t active_count;
natural_t inactive_count;
natural_t wire_count;
natural_t zero_fill_count;
natural_t reactivations;
natural_t pageins;
natural_t pageouts;
natural_t faults;
natural_t cow_faults;
natural_t lookups;
natural_t hits;
natural_t purgeable_count;
natural_t purges;
natural_t speculative_count;
};
typedef struct vm_statistics *vm_statistics_t;
typedef struct vm_statistics vm_statistics_data_t;
struct vm_statistics64 {
natural_t free_count;
natural_t active_count;
natural_t inactive_count;
natural_t wire_count;
uint64_t zero_fill_count;
uint64_t reactivations;
uint64_t pageins;
uint64_t pageouts;
uint64_t faults;
uint64_t cow_faults;
uint64_t lookups;
uint64_t hits;
uint64_t purges;
natural_t purgeable_count;
natural_t speculative_count;
uint64_t decompressions;
uint64_t compressions;
uint64_t swapins;
uint64_t swapouts;
natural_t compressor_page_count;
natural_t throttled_count;
natural_t external_page_count;
natural_t internal_page_count;
uint64_t total_uncompressed_pages_in_compressor;
} ;
typedef struct vm_statistics64 *vm_statistics64_t;
typedef struct vm_statistics64 vm_statistics64_data_t;
struct vm_extmod_statistics {
int64_t task_for_pid_count;
int64_t task_for_pid_caller_count;
int64_t thread_creation_count;
int64_t thread_creation_caller_count;
int64_t thread_set_state_count;
int64_t thread_set_state_caller_count;
} ;
typedef struct vm_extmod_statistics *vm_extmod_statistics_t;
typedef struct vm_extmod_statistics vm_extmod_statistics_data_t;
typedef struct vm_purgeable_stat {
uint64_t count;
uint64_t size;
}vm_purgeable_stat_t;
struct vm_purgeable_info {
vm_purgeable_stat_t fifo_data[8];
vm_purgeable_stat_t obsolete_data;
vm_purgeable_stat_t lifo_data[8];
};
typedef struct vm_purgeable_info *vm_purgeable_info_t;
typedef integer_t cpu_type_t;
typedef integer_t cpu_subtype_t;
typedef integer_t cpu_threadtype_t;
struct time_value {
integer_t seconds;
integer_t microseconds;
};
typedef struct time_value time_value_t;
typedef integer_t *host_info_t;
typedef integer_t *host_info64_t;
typedef integer_t host_info_data_t[(1024)];
typedef char kernel_version_t[(512)];
typedef char kernel_boot_info_t[(4096)];
typedef integer_t host_flavor_t;
struct host_can_has_debugger_info {
boolean_t can_has_debugger;
};
typedef struct host_can_has_debugger_info host_can_has_debugger_info_data_t;
typedef struct host_can_has_debugger_info *host_can_has_debugger_info_t;
struct host_basic_info {
integer_t max_cpus;
integer_t avail_cpus;
natural_t memory_size;
cpu_type_t cpu_type;
cpu_subtype_t cpu_subtype;
cpu_threadtype_t cpu_threadtype;
integer_t physical_cpu;
integer_t physical_cpu_max;
integer_t logical_cpu;
integer_t logical_cpu_max;
uint64_t max_mem;
};
typedef struct host_basic_info host_basic_info_data_t;
typedef struct host_basic_info *host_basic_info_t;
struct host_sched_info {
integer_t min_timeout;
integer_t min_quantum;
};
typedef struct host_sched_info host_sched_info_data_t;
typedef struct host_sched_info *host_sched_info_t;
struct kernel_resource_sizes {
natural_t task;
natural_t thread;
natural_t port;
natural_t memory_region;
natural_t memory_object;
};
typedef struct kernel_resource_sizes kernel_resource_sizes_data_t;
typedef struct kernel_resource_sizes *kernel_resource_sizes_t;
struct host_priority_info {
integer_t kernel_priority;
integer_t system_priority;
integer_t server_priority;
integer_t user_priority;
integer_t depress_priority;
integer_t idle_priority;
integer_t minimum_priority;
integer_t maximum_priority;
};
typedef struct host_priority_info host_priority_info_data_t;
typedef struct host_priority_info *host_priority_info_t;
struct host_load_info {
integer_t avenrun[3];
integer_t mach_factor[3];
};
typedef struct host_load_info host_load_info_data_t;
typedef struct host_load_info *host_load_info_t;
typedef struct vm_purgeable_info host_purgable_info_data_t;
typedef struct vm_purgeable_info *host_purgable_info_t;
struct host_cpu_load_info {
natural_t cpu_ticks[4];
};
typedef struct host_cpu_load_info host_cpu_load_info_data_t;
typedef struct host_cpu_load_info *host_cpu_load_info_t;
typedef int vm_prot_t;
typedef unsigned vm_sync_t;
typedef vm_offset_t pointer_t;
typedef vm_offset_t vm_address_t;
typedef uint64_t addr64_t;
typedef uint32_t reg64_t;
typedef uint32_t ppnum_t;
typedef mach_port_t vm_map_t;
typedef uint64_t vm_object_offset_t;
typedef uint64_t vm_object_size_t;
typedef mach_port_t upl_t;
typedef mach_port_t vm_named_entry_t;
typedef unsigned long long memory_object_offset_t;
typedef unsigned long long memory_object_size_t;
typedef natural_t memory_object_cluster_size_t;
typedef natural_t * memory_object_fault_info_t;
typedef unsigned long long vm_object_id_t;
typedef mach_port_t memory_object_t;
typedef mach_port_t memory_object_control_t;
typedef memory_object_t *memory_object_array_t;
typedef mach_port_t memory_object_name_t;
typedef mach_port_t memory_object_default_t;
typedef int memory_object_copy_strategy_t;
typedef int memory_object_return_t;
typedef int *memory_object_info_t;
typedef int memory_object_flavor_t;
typedef int memory_object_info_data_t[(1024)];
struct memory_object_perf_info {
memory_object_cluster_size_t cluster_size;
boolean_t may_cache;
};
struct memory_object_attr_info {
memory_object_copy_strategy_t copy_strategy;
memory_object_cluster_size_t cluster_size;
boolean_t may_cache_object;
boolean_t temporary;
};
struct memory_object_behave_info {
memory_object_copy_strategy_t copy_strategy;
boolean_t temporary;
boolean_t invalidate;
boolean_t silent_overwrite;
boolean_t advisory_pageout;
};
typedef struct memory_object_behave_info *memory_object_behave_info_t;
typedef struct memory_object_behave_info memory_object_behave_info_data_t;
typedef struct memory_object_perf_info *memory_object_perf_info_t;
typedef struct memory_object_perf_info memory_object_perf_info_data_t;
typedef struct memory_object_attr_info *memory_object_attr_info_t;
typedef struct memory_object_attr_info memory_object_attr_info_data_t;
struct upl_page_info {
unsigned int opaque[2];
};
typedef struct upl_page_info upl_page_info_t;
typedef upl_page_info_t *upl_page_info_array_t;
typedef upl_page_info_array_t upl_page_list_ptr_t;
typedef uint32_t upl_offset_t;
typedef uint32_t upl_size_t;
typedef uint64_t upl_control_flags_t;
extern boolean_t upl_page_present(upl_page_info_t *upl, int index);
extern boolean_t upl_dirty_page(upl_page_info_t *upl, int index);
extern boolean_t upl_valid_page(upl_page_info_t *upl, int index);
extern void upl_deallocate(upl_t upl);
extern void upl_mark_decmp(upl_t upl);
extern void upl_unmark_decmp(upl_t upl);
struct x86_state_hdr {
uint32_t flavor;
uint32_t count;
};
typedef struct x86_state_hdr x86_state_hdr_t;
typedef struct i386_thread_state i386_thread_state_t;
typedef struct i386_thread_state x86_thread_state32_t;
typedef struct i386_float_state i386_float_state_t;
typedef struct i386_float_state x86_float_state32_t;
typedef struct i386_avx_state x86_avx_state32_t;
typedef struct i386_avx512_state x86_avx512_state32_t;
typedef struct i386_exception_state i386_exception_state_t;
typedef struct i386_exception_state x86_exception_state32_t;
typedef struct x86_debug_state32 x86_debug_state32_t;
typedef struct x86_thread_state64 x86_thread_state64_t;
typedef struct x86_float_state64 x86_float_state64_t;
typedef struct x86_avx_state64 x86_avx_state64_t;
typedef struct x86_avx512_state64 x86_avx512_state64_t;
typedef struct x86_exception_state64 x86_exception_state64_t;
typedef struct x86_debug_state64 x86_debug_state64_t;
struct x86_thread_state {
x86_state_hdr_t tsh;
union {
x86_thread_state32_t ts32;
x86_thread_state64_t ts64;
} uts;
};
struct x86_float_state {
x86_state_hdr_t fsh;
union {
x86_float_state32_t fs32;
x86_float_state64_t fs64;
} ufs;
};
struct x86_exception_state {
x86_state_hdr_t esh;
union {
x86_exception_state32_t es32;
x86_exception_state64_t es64;
} ues;
};
struct x86_debug_state {
x86_state_hdr_t dsh;
union {
x86_debug_state32_t ds32;
x86_debug_state64_t ds64;
} uds;
};
struct x86_avx_state {
x86_state_hdr_t ash;
union {
x86_avx_state32_t as32;
x86_avx_state64_t as64;
} ufs;
};
struct x86_avx512_state {
x86_state_hdr_t ash;
union {
x86_avx512_state32_t as32;
x86_avx512_state64_t as64;
} ufs;
};
typedef struct x86_thread_state x86_thread_state_t;
typedef struct x86_float_state x86_float_state_t;
typedef struct x86_exception_state x86_exception_state_t;
typedef struct x86_debug_state x86_debug_state_t;
typedef struct x86_avx_state x86_avx_state_t;
typedef struct x86_avx512_state x86_avx512_state_t;
typedef natural_t *thread_state_t;
typedef natural_t thread_state_data_t[(614)];
typedef int thread_state_flavor_t;
typedef thread_state_flavor_t *thread_state_flavor_array_t;
typedef int exception_type_t;
typedef integer_t exception_data_type_t;
typedef int64_t mach_exception_data_type_t;
typedef int exception_behavior_t;
typedef exception_data_type_t *exception_data_t;
typedef mach_exception_data_type_t *mach_exception_data_t;
typedef unsigned int exception_mask_t;
typedef exception_mask_t *exception_mask_array_t;
typedef exception_behavior_t *exception_behavior_array_t;
typedef thread_state_flavor_t *exception_flavor_array_t;
typedef mach_port_t *exception_port_array_t;
typedef mach_exception_data_type_t mach_exception_code_t;
typedef mach_exception_data_type_t mach_exception_subcode_t;
typedef __darwin_uuid_t uuid_t;
typedef mach_port_t mach_voucher_t;
typedef mach_port_name_t mach_voucher_name_t;
typedef mach_voucher_name_t *mach_voucher_name_array_t;
struct ipc_voucher ;
typedef struct ipc_voucher *ipc_voucher_t;
typedef uint32_t mach_voucher_selector_t;
typedef uint32_t mach_voucher_attr_key_t;
typedef mach_voucher_attr_key_t *mach_voucher_attr_key_array_t;
typedef uint8_t *mach_voucher_attr_content_t;
typedef uint32_t mach_voucher_attr_content_size_t;
typedef uint32_t mach_voucher_attr_command_t;
typedef uint32_t mach_voucher_attr_recipe_command_t;
typedef mach_voucher_attr_recipe_command_t *mach_voucher_attr_recipe_command_array_t;
typedef struct mach_voucher_attr_recipe_data {
mach_voucher_attr_key_t key;
mach_voucher_attr_recipe_command_t command;
mach_voucher_name_t previous_voucher;
mach_voucher_attr_content_size_t content_size;
uint8_t content[];
} mach_voucher_attr_recipe_data_t;
typedef mach_voucher_attr_recipe_data_t *mach_voucher_attr_recipe_t;
typedef mach_msg_type_number_t mach_voucher_attr_recipe_size_t;
typedef uint8_t *mach_voucher_attr_raw_recipe_t;
typedef mach_voucher_attr_raw_recipe_t mach_voucher_attr_raw_recipe_array_t;
typedef mach_msg_type_number_t mach_voucher_attr_raw_recipe_size_t;
typedef mach_msg_type_number_t mach_voucher_attr_raw_recipe_array_size_t;
typedef mach_port_t mach_voucher_attr_manager_t;
typedef mach_port_t mach_voucher_attr_control_t;
struct ipc_voucher_attr_manager ;
struct ipc_voucher_attr_control ;
typedef struct ipc_voucher_attr_manager *ipc_voucher_attr_manager_t;
typedef struct ipc_voucher_attr_control *ipc_voucher_attr_control_t;
typedef uint64_t mach_voucher_attr_value_handle_t;
typedef mach_voucher_attr_value_handle_t *mach_voucher_attr_value_handle_array_t;
typedef mach_msg_type_number_t mach_voucher_attr_value_handle_array_size_t;
typedef uint32_t mach_voucher_attr_value_reference_t;
typedef uint32_t mach_voucher_attr_value_flags_t;
typedef uint32_t mach_voucher_attr_control_flags_t;
typedef uint32_t mach_voucher_attr_importance_refs;
typedef integer_t *processor_info_t;
typedef integer_t *processor_info_array_t;
typedef integer_t processor_info_data_t[(1024)];
typedef integer_t *processor_set_info_t;
typedef integer_t processor_set_info_data_t[(1024)];
typedef int processor_flavor_t;
struct processor_basic_info {
cpu_type_t cpu_type;
cpu_subtype_t cpu_subtype;
boolean_t running;
int slot_num;
boolean_t is_master;
};
typedef struct processor_basic_info processor_basic_info_data_t;
typedef struct processor_basic_info *processor_basic_info_t;
struct processor_cpu_load_info {
unsigned int cpu_ticks[4];
};
typedef struct processor_cpu_load_info processor_cpu_load_info_data_t;
typedef struct processor_cpu_load_info *processor_cpu_load_info_t;
typedef int processor_set_flavor_t;
struct processor_set_basic_info {
int processor_count;
int default_policy;
};
typedef struct processor_set_basic_info processor_set_basic_info_data_t;
typedef struct processor_set_basic_info *processor_set_basic_info_t;
struct processor_set_load_info {
int task_count;
int thread_count;
integer_t load_average;
integer_t mach_factor;
};
typedef struct processor_set_load_info processor_set_load_info_data_t;
typedef struct processor_set_load_info *processor_set_load_info_t;
typedef int policy_t;
typedef integer_t *policy_info_t;
typedef integer_t *policy_base_t;
typedef integer_t *policy_limit_t;
struct policy_timeshare_base {
integer_t base_priority;
};
struct policy_timeshare_limit {
integer_t max_priority;
};
struct policy_timeshare_info {
integer_t max_priority;
integer_t base_priority;
integer_t cur_priority;
boolean_t depressed;
integer_t depress_priority;
};
typedef struct policy_timeshare_base *policy_timeshare_base_t;
typedef struct policy_timeshare_limit *policy_timeshare_limit_t;
typedef struct policy_timeshare_info *policy_timeshare_info_t;
typedef struct policy_timeshare_base policy_timeshare_base_data_t;
typedef struct policy_timeshare_limit policy_timeshare_limit_data_t;
typedef struct policy_timeshare_info policy_timeshare_info_data_t;
struct policy_rr_base {
integer_t base_priority;
integer_t quantum;
};
struct policy_rr_limit {
integer_t max_priority;
};
struct policy_rr_info {
integer_t max_priority;
integer_t base_priority;
integer_t quantum;
boolean_t depressed;
integer_t depress_priority;
};
typedef struct policy_rr_base *policy_rr_base_t;
typedef struct policy_rr_limit *policy_rr_limit_t;
typedef struct policy_rr_info *policy_rr_info_t;
typedef struct policy_rr_base policy_rr_base_data_t;
typedef struct policy_rr_limit policy_rr_limit_data_t;
typedef struct policy_rr_info policy_rr_info_data_t;
struct policy_fifo_base {
integer_t base_priority;
};
struct policy_fifo_limit {
integer_t max_priority;
};
struct policy_fifo_info {
integer_t max_priority;
integer_t base_priority;
boolean_t depressed;
integer_t depress_priority;
};
typedef struct policy_fifo_base *policy_fifo_base_t;
typedef struct policy_fifo_limit *policy_fifo_limit_t;
typedef struct policy_fifo_info *policy_fifo_info_t;
typedef struct policy_fifo_base policy_fifo_base_data_t;
typedef struct policy_fifo_limit policy_fifo_limit_data_t;
typedef struct policy_fifo_info policy_fifo_info_data_t;
struct policy_bases {
policy_timeshare_base_data_t ts;
policy_rr_base_data_t rr;
policy_fifo_base_data_t fifo;
};
struct policy_limits {
policy_timeshare_limit_data_t ts;
policy_rr_limit_data_t rr;
policy_fifo_limit_data_t fifo;
};
struct policy_infos {
policy_timeshare_info_data_t ts;
policy_rr_info_data_t rr;
policy_fifo_info_data_t fifo;
};
typedef struct policy_bases policy_base_data_t;
typedef struct policy_limits policy_limit_data_t;
typedef struct policy_infos policy_info_data_t;
typedef natural_t task_flavor_t;
typedef integer_t *task_info_t;
typedef integer_t task_info_data_t[(1024)];
struct task_basic_info_32 {
integer_t suspend_count;
natural_t virtual_size;
natural_t resident_size;
time_value_t user_time;
time_value_t system_time;
policy_t policy;
};
typedef struct task_basic_info_32 task_basic_info_32_data_t;
typedef struct task_basic_info_32 *task_basic_info_32_t;
struct task_basic_info_64 {
integer_t suspend_count;
mach_vm_size_t virtual_size;
mach_vm_size_t resident_size;
time_value_t user_time;
time_value_t system_time;
policy_t policy;
};
typedef struct task_basic_info_64 task_basic_info_64_data_t;
typedef struct task_basic_info_64 *task_basic_info_64_t;
struct task_basic_info {
integer_t suspend_count;
vm_size_t virtual_size;
vm_size_t resident_size;
time_value_t user_time;
time_value_t system_time;
policy_t policy;
};
typedef struct task_basic_info task_basic_info_data_t;
typedef struct task_basic_info *task_basic_info_t;
struct task_events_info {
integer_t faults;
integer_t pageins;
integer_t cow_faults;
integer_t messages_sent;
integer_t messages_received;
integer_t syscalls_mach;
integer_t syscalls_unix;
integer_t csw;
};
typedef struct task_events_info task_events_info_data_t;
typedef struct task_events_info *task_events_info_t;
struct task_thread_times_info {
time_value_t user_time;
time_value_t system_time;
};
typedef struct task_thread_times_info task_thread_times_info_data_t;
typedef struct task_thread_times_info *task_thread_times_info_t;
struct task_absolutetime_info {
uint64_t total_user;
uint64_t total_system;
uint64_t threads_user;
uint64_t threads_system;
};
typedef struct task_absolutetime_info task_absolutetime_info_data_t;
typedef struct task_absolutetime_info *task_absolutetime_info_t;
struct task_kernelmemory_info {
uint64_t total_palloc;
uint64_t total_pfree;
uint64_t total_salloc;
uint64_t total_sfree;
};
typedef struct task_kernelmemory_info task_kernelmemory_info_data_t;
typedef struct task_kernelmemory_info *task_kernelmemory_info_t;
struct task_affinity_tag_info {
integer_t set_count;
integer_t min;
integer_t max;
integer_t task_count;
};
typedef struct task_affinity_tag_info task_affinity_tag_info_data_t;
typedef struct task_affinity_tag_info *task_affinity_tag_info_t;
struct task_dyld_info {
mach_vm_address_t all_image_info_addr;
mach_vm_size_t all_image_info_size;
integer_t all_image_info_format;
};
typedef struct task_dyld_info task_dyld_info_data_t;
typedef struct task_dyld_info *task_dyld_info_t;
struct task_extmod_info {
unsigned char task_uuid[16];
vm_extmod_statistics_data_t extmod_statistics;
};
typedef struct task_extmod_info task_extmod_info_data_t;
typedef struct task_extmod_info *task_extmod_info_t;
struct mach_task_basic_info {
mach_vm_size_t virtual_size;
mach_vm_size_t resident_size;
mach_vm_size_t resident_size_max;
time_value_t user_time;
time_value_t system_time;
policy_t policy;
integer_t suspend_count;
};
typedef struct mach_task_basic_info mach_task_basic_info_data_t;
typedef struct mach_task_basic_info *mach_task_basic_info_t;
struct task_power_info {
uint64_t total_user;
uint64_t total_system;
uint64_t task_interrupt_wakeups;
uint64_t task_platform_idle_wakeups;
uint64_t task_timer_wakeups_bin_1;
uint64_t task_timer_wakeups_bin_2;
};
typedef struct task_power_info task_power_info_data_t;
typedef struct task_power_info *task_power_info_t;
struct task_vm_info {
mach_vm_size_t virtual_size;
integer_t region_count;
integer_t page_size;
mach_vm_size_t resident_size;
mach_vm_size_t resident_size_peak;
mach_vm_size_t device;
mach_vm_size_t device_peak;
mach_vm_size_t internal;
mach_vm_size_t internal_peak;
mach_vm_size_t external;
mach_vm_size_t external_peak;
mach_vm_size_t reusable;
mach_vm_size_t reusable_peak;
mach_vm_size_t purgeable_volatile_pmap;
mach_vm_size_t purgeable_volatile_resident;
mach_vm_size_t purgeable_volatile_virtual;
mach_vm_size_t compressed;
mach_vm_size_t compressed_peak;
mach_vm_size_t compressed_lifetime;
mach_vm_size_t phys_footprint;
mach_vm_address_t min_address;
mach_vm_address_t max_address;
};
typedef struct task_vm_info task_vm_info_data_t;
typedef struct task_vm_info *task_vm_info_t;
typedef struct vm_purgeable_info task_purgable_info_t;
struct task_trace_memory_info {
uint64_t user_memory_address;
uint64_t buffer_size;
uint64_t mailbox_array_size;
};
typedef struct task_trace_memory_info task_trace_memory_info_data_t;
typedef struct task_trace_memory_info * task_trace_memory_info_t;
struct task_wait_state_info {
uint64_t total_wait_state_time;
uint64_t total_wait_sfi_state_time;
uint32_t _reserved[4];
};
typedef struct task_wait_state_info task_wait_state_info_data_t;
typedef struct task_wait_state_info * task_wait_state_info_t;
typedef struct {
uint64_t task_gpu_utilisation;
uint64_t task_gpu_stat_reserved0;
uint64_t task_gpu_stat_reserved1;
uint64_t task_gpu_stat_reserved2;
} gpu_energy_data;
typedef gpu_energy_data *gpu_energy_data_t;
struct task_power_info_v2 {
task_power_info_data_t cpu_energy;
gpu_energy_data gpu_energy;
uint64_t task_ptime;
uint64_t task_pset_switches;
};
typedef struct task_power_info_v2 task_power_info_v2_data_t;
typedef struct task_power_info_v2 *task_power_info_v2_t;
struct task_flags_info {
uint32_t flags;
};
typedef struct task_flags_info task_flags_info_data_t;
typedef struct task_flags_info * task_flags_info_t;
typedef natural_t task_inspect_flavor_t;
enum task_inspect_flavor {
TASK_INSPECT_BASIC_COUNTS = 1,
};
struct task_inspect_basic_counts {
uint64_t instructions;
uint64_t cycles;
};
typedef struct task_inspect_basic_counts task_inspect_basic_counts_data_t;
typedef struct task_inspect_basic_counts *task_inspect_basic_counts_t;
typedef integer_t *task_inspect_info_t;
typedef natural_t task_policy_flavor_t;
typedef integer_t *task_policy_t;
enum task_role {
TASK_RENICED = -1,
TASK_UNSPECIFIED = 0,
TASK_FOREGROUND_APPLICATION,
TASK_BACKGROUND_APPLICATION,
TASK_CONTROL_APPLICATION,
TASK_GRAPHICS_SERVER,
TASK_THROTTLE_APPLICATION,
TASK_NONUI_APPLICATION,
TASK_DEFAULT_APPLICATION
};
typedef integer_t task_role_t;
struct task_category_policy {
task_role_t role;
};
typedef struct task_category_policy task_category_policy_data_t;
typedef struct task_category_policy *task_category_policy_t;
enum task_latency_qos {
LATENCY_QOS_TIER_UNSPECIFIED = 0x0,
LATENCY_QOS_TIER_0 = ((0xFF<<16) | 1),
LATENCY_QOS_TIER_1 = ((0xFF<<16) | 2),
LATENCY_QOS_TIER_2 = ((0xFF<<16) | 3),
LATENCY_QOS_TIER_3 = ((0xFF<<16) | 4),
LATENCY_QOS_TIER_4 = ((0xFF<<16) | 5),
LATENCY_QOS_TIER_5 = ((0xFF<<16) | 6)
};
typedef integer_t task_latency_qos_t;
enum task_throughput_qos {
THROUGHPUT_QOS_TIER_UNSPECIFIED = 0x0,
THROUGHPUT_QOS_TIER_0 = ((0xFE<<16) | 1),
THROUGHPUT_QOS_TIER_1 = ((0xFE<<16) | 2),
THROUGHPUT_QOS_TIER_2 = ((0xFE<<16) | 3),
THROUGHPUT_QOS_TIER_3 = ((0xFE<<16) | 4),
THROUGHPUT_QOS_TIER_4 = ((0xFE<<16) | 5),
THROUGHPUT_QOS_TIER_5 = ((0xFE<<16) | 6),
};
typedef integer_t task_throughput_qos_t;
struct task_qos_policy {
task_latency_qos_t task_latency_qos_tier;
task_throughput_qos_t task_throughput_qos_tier;
};
typedef struct task_qos_policy *task_qos_policy_t;
typedef int task_special_port_t;
typedef natural_t thread_flavor_t;
typedef integer_t *thread_info_t;
typedef integer_t thread_info_data_t[(32)];
struct thread_basic_info {
time_value_t user_time;
time_value_t system_time;
integer_t cpu_usage;
policy_t policy;
integer_t run_state;
integer_t flags;
integer_t suspend_count;
integer_t sleep_time;
};
typedef struct thread_basic_info thread_basic_info_data_t;
typedef struct thread_basic_info *thread_basic_info_t;
struct thread_identifier_info {
uint64_t thread_id;
uint64_t thread_handle;
uint64_t dispatch_qaddr;
};
typedef struct thread_identifier_info thread_identifier_info_data_t;
typedef struct thread_identifier_info *thread_identifier_info_t;
struct thread_extended_info {
uint64_t pth_user_time;
uint64_t pth_system_time;
int32_t pth_cpu_usage;
int32_t pth_policy;
int32_t pth_run_state;
int32_t pth_flags;
int32_t pth_sleep_time;
int32_t pth_curpri;
int32_t pth_priority;
int32_t pth_maxpriority;
char pth_name[64];
};
typedef struct thread_extended_info thread_extended_info_data_t;
typedef struct thread_extended_info * thread_extended_info_t;
struct io_stat_entry {
uint64_t count;
uint64_t size;
};
struct io_stat_info {
struct io_stat_entry disk_reads;
struct io_stat_entry io_priority[4];
struct io_stat_entry paging;
struct io_stat_entry metadata;
struct io_stat_entry total_io;
};
typedef struct io_stat_info *io_stat_info_t;
typedef natural_t thread_policy_flavor_t;
typedef integer_t *thread_policy_t;
struct thread_standard_policy {
natural_t no_data;
};
typedef struct thread_standard_policy thread_standard_policy_data_t;
typedef struct thread_standard_policy *thread_standard_policy_t;
struct thread_extended_policy {
boolean_t timeshare;
};
typedef struct thread_extended_policy thread_extended_policy_data_t;
typedef struct thread_extended_policy *thread_extended_policy_t;
struct thread_time_constraint_policy {
uint32_t period;
uint32_t computation;
uint32_t constraint;
boolean_t preemptible;
};
typedef struct thread_time_constraint_policy thread_time_constraint_policy_data_t;
typedef struct thread_time_constraint_policy *thread_time_constraint_policy_t;
struct thread_precedence_policy {
integer_t importance;
};
typedef struct thread_precedence_policy thread_precedence_policy_data_t;
typedef struct thread_precedence_policy *thread_precedence_policy_t;
struct thread_affinity_policy {
integer_t affinity_tag;
};
typedef struct thread_affinity_policy thread_affinity_policy_data_t;
typedef struct thread_affinity_policy *thread_affinity_policy_t;
struct thread_background_policy {
integer_t priority;
};
typedef struct thread_background_policy thread_background_policy_data_t;
typedef struct thread_background_policy *thread_background_policy_t;
typedef integer_t thread_latency_qos_t;
struct thread_latency_qos_policy {
thread_latency_qos_t thread_latency_qos_tier;
};
typedef struct thread_latency_qos_policy thread_latency_qos_policy_data_t;
typedef struct thread_latency_qos_policy *thread_latency_qos_policy_t;
typedef integer_t thread_throughput_qos_t;
struct thread_throughput_qos_policy {
thread_throughput_qos_t thread_throughput_qos_tier;
};
typedef struct thread_throughput_qos_policy thread_throughput_qos_policy_data_t;
typedef struct thread_throughput_qos_policy *thread_throughput_qos_policy_t;
typedef int alarm_type_t;
typedef int sleep_type_t;
typedef int clock_id_t;
typedef int clock_flavor_t;
typedef int *clock_attr_t;
typedef int clock_res_t;
struct mach_timespec {
unsigned int tv_sec;
clock_res_t tv_nsec;
};
typedef struct mach_timespec mach_timespec_t;
typedef unsigned int vm_machine_attribute_t;
typedef int vm_machine_attribute_val_t;
typedef unsigned int vm_inherit_t;
typedef int vm_purgable_t;
typedef int vm_behavior_t;
typedef uint32_t vm32_object_id_t;
typedef int *vm_region_info_t;
typedef int *vm_region_info_64_t;
typedef int *vm_region_recurse_info_t;
typedef int *vm_region_recurse_info_64_t;
typedef int vm_region_flavor_t;
typedef int vm_region_info_data_t[(1024)];
struct vm_region_basic_info_64 {
vm_prot_t protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
boolean_t shared;
boolean_t reserved;
memory_object_offset_t offset;
vm_behavior_t behavior;
unsigned short user_wired_count;
};
typedef struct vm_region_basic_info_64 *vm_region_basic_info_64_t;
typedef struct vm_region_basic_info_64 vm_region_basic_info_data_64_t;
struct vm_region_basic_info {
vm_prot_t protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
boolean_t shared;
boolean_t reserved;
uint32_t offset;
vm_behavior_t behavior;
unsigned short user_wired_count;
};
typedef struct vm_region_basic_info *vm_region_basic_info_t;
typedef struct vm_region_basic_info vm_region_basic_info_data_t;
struct vm_region_extended_info {
vm_prot_t protection;
unsigned int user_tag;
unsigned int pages_resident;
unsigned int pages_shared_now_private;
unsigned int pages_swapped_out;
unsigned int pages_dirtied;
unsigned int ref_count;
unsigned short shadow_depth;
unsigned char external_pager;
unsigned char share_mode;
unsigned int pages_reusable;
};
typedef struct vm_region_extended_info *vm_region_extended_info_t;
typedef struct vm_region_extended_info vm_region_extended_info_data_t;
struct vm_region_top_info {
unsigned int obj_id;
unsigned int ref_count;
unsigned int private_pages_resident;
unsigned int shared_pages_resident;
unsigned char share_mode;
};
typedef struct vm_region_top_info *vm_region_top_info_t;
typedef struct vm_region_top_info vm_region_top_info_data_t;
struct vm_region_submap_info {
vm_prot_t protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
uint32_t offset;
unsigned int user_tag;
unsigned int pages_resident;
unsigned int pages_shared_now_private;
unsigned int pages_swapped_out;
unsigned int pages_dirtied;
unsigned int ref_count;
unsigned short shadow_depth;
unsigned char external_pager;
unsigned char share_mode;
boolean_t is_submap;
vm_behavior_t behavior;
vm32_object_id_t object_id;
unsigned short user_wired_count;
};
typedef struct vm_region_submap_info *vm_region_submap_info_t;
typedef struct vm_region_submap_info vm_region_submap_info_data_t;
struct vm_region_submap_info_64 {
vm_prot_t protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
memory_object_offset_t offset;
unsigned int user_tag;
unsigned int pages_resident;
unsigned int pages_shared_now_private;
unsigned int pages_swapped_out;
unsigned int pages_dirtied;
unsigned int ref_count;
unsigned short shadow_depth;
unsigned char external_pager;
unsigned char share_mode;
boolean_t is_submap;
vm_behavior_t behavior;
vm32_object_id_t object_id;
unsigned short user_wired_count;
unsigned int pages_reusable;
};
typedef struct vm_region_submap_info_64 *vm_region_submap_info_64_t;
typedef struct vm_region_submap_info_64 vm_region_submap_info_data_64_t;
struct vm_region_submap_short_info_64 {
vm_prot_t protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
memory_object_offset_t offset;
unsigned int user_tag;
unsigned int ref_count;
unsigned short shadow_depth;
unsigned char external_pager;
unsigned char share_mode;
boolean_t is_submap;
vm_behavior_t behavior;
vm32_object_id_t object_id;
unsigned short user_wired_count;
};
typedef struct vm_region_submap_short_info_64 *vm_region_submap_short_info_64_t;
typedef struct vm_region_submap_short_info_64 vm_region_submap_short_info_data_64_t;
struct mach_vm_read_entry {
mach_vm_address_t address;
mach_vm_size_t size;
};
struct vm_read_entry {
vm_address_t address;
vm_size_t size;
};
typedef struct mach_vm_read_entry mach_vm_read_entry_t[(256)];
typedef struct vm_read_entry vm_read_entry_t[(256)];
typedef int *vm_page_info_t;
typedef int vm_page_info_data_t[];
typedef int vm_page_info_flavor_t;
struct vm_page_info_basic {
int disposition;
int ref_count;
vm_object_id_t object_id;
memory_object_offset_t offset;
int depth;
int __pad;
};
typedef struct vm_page_info_basic *vm_page_info_basic_t;
typedef struct vm_page_info_basic vm_page_info_basic_data_t;
typedef int kmod_t;
struct kmod_info;
typedef kern_return_t kmod_start_func_t(struct kmod_info * ki, void * data);
typedef kern_return_t kmod_stop_func_t(struct kmod_info * ki, void * data);
typedef struct kmod_reference {
struct kmod_reference * next;
struct kmod_info * info;
} kmod_reference_t;
typedef struct kmod_info {
struct kmod_info * next;
int32_t info_version;
uint32_t id;
char name[64];
char version[64];
int32_t reference_count;
kmod_reference_t * reference_list;
vm_address_t address;
vm_size_t size;
vm_size_t hdr_size;
kmod_start_func_t * start;
kmod_stop_func_t * stop;
} kmod_info_t;
typedef struct kmod_info_32_v1 {
uint32_t next_addr;
int32_t info_version;
uint32_t id;
uint8_t name[64];
uint8_t version[64];
int32_t reference_count;
uint32_t reference_list_addr;
uint32_t address;
uint32_t size;
uint32_t hdr_size;
uint32_t start_addr;
uint32_t stop_addr;
} kmod_info_32_v1_t;
typedef struct kmod_info_64_v1 {
uint64_t next_addr;
int32_t info_version;
uint32_t id;
uint8_t name[64];
uint8_t version[64];
int32_t reference_count;
uint64_t reference_list_addr;
uint64_t address;
uint64_t size;
uint64_t hdr_size;
uint64_t start_addr;
uint64_t stop_addr;
} kmod_info_64_v1_t;
typedef void * kmod_args_t;
typedef int kmod_control_flavor_t;
typedef kmod_info_t * kmod_info_array_t;
typedef struct fsid { int32_t val[2]; } fsid_t;
typedef struct fsobj_id {
u_int32_t fid_objno;
u_int32_t fid_generation;
} fsobj_id_t;
struct dyld_kernel_image_info {
uuid_t uuid;
fsobj_id_t fsobjid;
fsid_t fsid;
uint64_t load_addr;
};
struct dyld_kernel_process_info {
struct dyld_kernel_image_info cache_image_info;
uint64_t timestamp;
uint32_t imageCount;
uint32_t initialImageCount;
uint8_t dyldState;
boolean_t no_cache;
boolean_t private_cache;
};
typedef struct dyld_kernel_image_info dyld_kernel_image_info_t;
typedef struct dyld_kernel_process_info dyld_kernel_process_info_t;
typedef dyld_kernel_image_info_t *dyld_kernel_image_info_array_t;
typedef void (*os_function_t)(void *);
typedef void (*os_block_t)(void);
#ifndef _Bool
#define _Bool uint8_t
#endif
_Bool inline  
__os_warn_unused(const _Bool x)
{
return x;
}
static inline int 
mach_vm_round_page_overflow(mach_vm_offset_t in, mach_vm_offset_t *out)
{
return __os_warn_unused(({ _Bool __ovr = __os_warn_unused(__builtin_add_overflow((in), ((__typeof__(*out))(4096 - 1)), (out))); *out &= ~((__typeof__(*out))(4096 - 1)); __ovr; }));
}
extern vm_size_t mem_size;
extern uint64_t max_mem;
extern vm_size_t page_size;
extern vm_size_t page_mask;
extern int page_shift;
typedef struct task *task_t, *task_name_t, *task_inspect_t, *task_suspension_token_t;
typedef struct thread *thread_t, *thread_act_t, *thread_inspect_t;
typedef struct ipc_space *ipc_space_t, *ipc_space_inspect_t;
typedef struct coalition *coalition_t;
typedef struct host *host_t;
typedef struct host *host_priv_t;
typedef struct host *host_security_t;
typedef struct processor *processor_t;
typedef struct processor_set *processor_set_t;
typedef struct processor_set *processor_set_control_t;
typedef struct semaphore *semaphore_t;
typedef struct ledger *ledger_t;
typedef struct alarm *alarm_t;
typedef struct clock *clock_serv_t;
typedef struct clock *clock_ctrl_t;
typedef struct lock_set *lock_set_t;
struct lock_set ;
struct task ;
struct thread ;
struct host ;
struct processor ;
struct processor_set ;
struct semaphore ;
struct ledger ;
struct alarm ;
struct clock ;
typedef processor_set_t processor_set_name_t;
typedef mach_port_t clock_reply_t;
typedef mach_port_t bootstrap_t;
typedef mach_port_t mem_entry_name_port_t;
typedef mach_port_t exception_handler_t;
typedef exception_handler_t *exception_handler_array_t;
typedef mach_port_t vm_task_entry_t;
typedef mach_port_t io_master_t;
typedef mach_port_t UNDServerRef;
typedef task_t *task_array_t;
typedef thread_t *thread_array_t;
typedef processor_set_t *processor_set_array_t;
typedef processor_set_t *processor_set_name_array_t;
typedef processor_t *processor_array_t;
typedef thread_act_t *thread_act_array_t;
typedef ledger_t *ledger_array_t;
typedef task_t task_port_t;
typedef task_array_t task_port_array_t;
typedef thread_t thread_port_t;
typedef thread_array_t thread_port_array_t;
typedef ipc_space_t ipc_space_port_t;
typedef host_t host_name_t;
typedef host_t host_name_port_t;
typedef processor_set_t processor_set_port_t;
typedef processor_set_t processor_set_name_port_t;
typedef processor_set_array_t processor_set_name_port_array_t;
typedef processor_set_t processor_set_control_port_t;
typedef processor_t processor_port_t;
typedef processor_array_t processor_port_array_t;
typedef thread_act_t thread_act_port_t;
typedef thread_act_array_t thread_act_port_array_t;
typedef semaphore_t semaphore_port_t;
typedef lock_set_t lock_set_port_t;
typedef ledger_t ledger_port_t;
typedef ledger_array_t ledger_port_array_t;
typedef alarm_t alarm_port_t;
typedef clock_serv_t clock_serv_port_t;
typedef clock_ctrl_t clock_ctrl_port_t;
typedef exception_handler_t exception_port_t;
typedef exception_handler_array_t exception_port_arrary_t;
typedef natural_t ledger_item_t;
typedef int64_t ledger_amount_t;
typedef mach_vm_offset_t *emulation_vector_t;
typedef char *user_subsystem_t;
typedef char *labelstr_t;
typedef void *event_t;
typedef uint64_t event64_t;
typedef int wait_result_t;
typedef void (*thread_continue_t)(void *, wait_result_t);
typedef int wait_interrupt_t;
typedef int wait_timeout_urgency_t;
/*
typedef struct __lck_spin_t__ lck_spin_t;
typedef struct __lck_mtx_t__ lck_mtx_t;
typedef struct __lck_mtx_ext_t__ lck_mtx_ext_t;
typedef struct __lck_rw_t__ lck_rw_t;
*/
typedef struct {
unsigned long    opaque[10];
} lck_spin_t;
typedef struct {
unsigned long		opaque[2];
} lck_mtx_t;
typedef struct {
unsigned long		opaque[10];
} lck_mtx_ext_t;
typedef struct {
uint32_t		opaque[3];
uint32_t		opaque4;
} lck_rw_t;
typedef unsigned int lck_sleep_action_t;
typedef struct __lck_grp__ lck_grp_t;
typedef struct __lck_grp_attr__ lck_grp_attr_t;
extern lck_grp_attr_t *lck_grp_attr_alloc_init(
void);
extern void lck_grp_attr_setdefault(
lck_grp_attr_t *attr);
extern void lck_grp_attr_setstat(
lck_grp_attr_t *attr);
extern void lck_grp_attr_free(
lck_grp_attr_t *attr);
extern lck_grp_t *lck_grp_alloc_init(
const char* grp_name,
lck_grp_attr_t *attr);
extern void lck_grp_free(
lck_grp_t *grp);
typedef struct __lck_attr__ lck_attr_t;
extern lck_attr_t *lck_attr_alloc_init(
void);
extern void lck_attr_setdefault(
lck_attr_t *attr);
extern void lck_attr_setdebug(
lck_attr_t *attr);
extern void lck_attr_cleardebug(
lck_attr_t *attr);
extern void lck_attr_free(
lck_attr_t *attr);
extern lck_spin_t *lck_spin_alloc_init(
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_spin_init(
lck_spin_t *lck,
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_spin_lock(
lck_spin_t *lck);
extern void lck_spin_unlock(
lck_spin_t *lck);
extern void lck_spin_destroy(
lck_spin_t *lck,
lck_grp_t *grp);
extern void lck_spin_free(
lck_spin_t *lck,
lck_grp_t *grp);
extern wait_result_t lck_spin_sleep(
lck_spin_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible);
extern wait_result_t lck_spin_sleep_deadline(
lck_spin_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible,
uint64_t deadline);
extern lck_mtx_t *lck_mtx_alloc_init(
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_mtx_init(
lck_mtx_t *lck,
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_mtx_lock(
lck_mtx_t *lck);
extern void lck_mtx_unlock(
lck_mtx_t *lck);
extern void lck_mtx_destroy(
lck_mtx_t *lck,
lck_grp_t *grp);
extern void lck_mtx_free(
lck_mtx_t *lck,
lck_grp_t *grp);
extern wait_result_t lck_mtx_sleep(
lck_mtx_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible);
extern wait_result_t lck_mtx_sleep_deadline(
lck_mtx_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible,
uint64_t deadline);
extern void lck_mtx_assert(
lck_mtx_t *lck,
unsigned int type);
typedef unsigned int lck_rw_type_t;
extern lck_rw_t *lck_rw_alloc_init(
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_rw_init(
lck_rw_t *lck,
lck_grp_t *grp,
lck_attr_t *attr);
extern void lck_rw_lock(
lck_rw_t *lck,
lck_rw_type_t lck_rw_type);
extern void lck_rw_unlock(
lck_rw_t *lck,
lck_rw_type_t lck_rw_type);
extern void lck_rw_lock_shared(
lck_rw_t *lck);
extern void lck_rw_unlock_shared(
lck_rw_t *lck);
extern boolean_t lck_rw_lock_yield_shared(
lck_rw_t *lck,
boolean_t force_yield);
extern void lck_rw_lock_exclusive(
lck_rw_t *lck);
extern void lck_rw_unlock_exclusive(
lck_rw_t *lck);
extern void lck_rw_destroy(
lck_rw_t *lck,
lck_grp_t *grp);
extern void lck_rw_free(
lck_rw_t *lck,
lck_grp_t *grp);
extern wait_result_t lck_rw_sleep(
lck_rw_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible);
extern wait_result_t lck_rw_sleep_deadline(
lck_rw_t *lck,
lck_sleep_action_t lck_sleep_action,
event_t event,
wait_interrupt_t interruptible,
uint64_t deadline);
extern boolean_t lck_rw_lock_shared_to_exclusive(
lck_rw_t *lck);
extern void lck_rw_lock_exclusive_to_shared(
lck_rw_t *lck);
extern boolean_t lck_rw_try_lock(
lck_rw_t *lck,
lck_rw_type_t lck_rw_type);
typedef __darwin_uuid_string_t uuid_string_t;
static const uuid_t UUID_NULL  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
void uuid_clear(uuid_t uu);
int uuid_compare(const uuid_t uu1, const uuid_t uu2);
void uuid_copy(uuid_t dst, const uuid_t src);
void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);
void uuid_generate_time(uuid_t out);
int uuid_is_null(const uuid_t uu);
int uuid_parse(const uuid_string_t in, uuid_t uu);
void uuid_unparse(const uuid_t uu, uuid_string_t out);
void uuid_unparse_lower(const uuid_t uu, uuid_string_t out);
void uuid_unparse_upper(const uuid_t uu, uuid_string_t out);
extern proc_t kernproc;
extern int proc_is_classic(proc_t p);
proc_t current_proc_EXTERNAL(void);
extern int msleep(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg, struct timespec * ts );
extern void wakeup(void *chan);
extern void wakeup_one(caddr_t chan);
extern int proc_selfpid(void);
extern int proc_selfppid(void);
extern int proc_selfcsflags(void);
extern void proc_signal(int pid, int signum);
extern int proc_issignal(int pid, sigset_t mask);
extern int proc_isinferior(int pid1, int pid2);
void proc_name(int pid, char * buf, int size);
void proc_selfname(char * buf, int size);
extern proc_t proc_find(int pid);
extern proc_t proc_self(void);
extern int proc_rele(proc_t p);
extern int proc_pid(proc_t);
extern int proc_ppid(proc_t);
extern int proc_noremotehang(proc_t);
extern int proc_forcequota(proc_t);
extern int proc_chrooted(proc_t);
extern int proc_is64bit(proc_t);
extern int proc_exiting(proc_t);
int proc_suser(proc_t p);
kauth_cred_t proc_ucred(proc_t p);
extern int proc_tbe(proc_t);
pid_t proc_selfpgrpid(void);
pid_t proc_pgrpid(proc_t p);
typedef __builtin_va_list va_list;
typedef __builtin_va_list __gnuc_va_list;
extern void *memcpy(void *, const void *, size_t);
extern int memcmp(const void *, const void *, size_t);
extern void *memmove(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern int memset_s(void *, size_t, int, size_t);
extern size_t strlen(const char *);
extern size_t strnlen(const char *, size_t);
extern char *strcpy(char *, const char *) ;
extern char *strncpy(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);
extern size_t strlcpy(char *, const char *, size_t);
extern char *strcat(char *, const char *) ;
extern char *strncat(char *, const char *, size_t);
extern int strcmp(const char *, const char *);
extern int strncmp(const char *,const char *, size_t);
extern int strcasecmp(const char *s1, const char *s2);
extern int strncasecmp(const char *s1, const char *s2, size_t n);
extern char *strnstr(char *s, const char *find, size_t slen);
extern char *strchr(const char *s, int c);
extern char *STRDUP(const char *, int);
extern int strprefix(const char *s1, const char *s2);
extern int bcmp(const void *, const void *, size_t);
extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);
extern u_char const bcd2bin_data[];
extern u_char const bin2bcd_data[];
extern char const hex2ascii_data[];
static inline int
imax(int a, int b)
{
return (a > b ? a : b);
}
static inline int
imin(int a, int b)
{
return (a < b ? a : b);
}
static inline long
lmax(long a, long b)
{
return (a > b ? a : b);
}
static inline long
lmin(long a, long b)
{
return (a < b ? a : b);
}
static inline u_int
max(u_int a, u_int b)
{
return (a > b ? a : b);
}
static inline u_int
min(u_int a, u_int b)
{
return (a < b ? a : b);
}
static inline u_int32_t
ulmax(u_int32_t a, u_int32_t b)
{
return (a > b ? a : b);
}
static inline u_int32_t
ulmin(u_int32_t a, u_int32_t b)
{
return (a < b ? a : b);
}
extern int ffs(int);
extern int ffsll(unsigned long long);
extern int fls(int);
extern int flsll(unsigned long long);
extern u_int32_t random(void);
extern int scanc(u_int, u_char *, const u_char *, int);
extern int skpc(int, int, char *);
extern long strtol(const char*, char **, int);
extern u_long strtoul(const char *, char **, int);
extern quad_t strtoq(const char *, char **, int);
extern u_quad_t strtouq(const char *, char **, int);
extern char *strsep(char **, const char *);
extern void *memchr(const void *, int, size_t);
extern void url_decode(char *str);
int snprintf(char *, size_t, const char *, ...) ;
int sprintf(char *bufp, const char *, ...)  ;
int sscanf(const char *, char const *, ...) ;
int printf(const char *, ...) ;
uint16_t crc16(uint16_t crc, const void *bufp, size_t len);
uint32_t crc32(uint32_t crc, const void *bufp, size_t len);
int copystr(const void *kfaddr, void *kdaddr, size_t len, size_t *done);
int copyinstr(const user_addr_t uaddr, void *kaddr, size_t len, size_t *done);
int copyoutstr(const void *kaddr, user_addr_t udaddr, size_t len, size_t *done);
int copyin(const user_addr_t uaddr, void *kaddr, size_t len);
int copyout(const void *kaddr, user_addr_t udaddr, size_t len);
int vsscanf(const char *, char const *, va_list);
extern int vprintf(const char *, va_list) ;
extern int vsnprintf(char *, size_t, const char *, va_list) ;
extern int vsprintf(char *bufp, const char *, va_list)  ;
extern void invalidate_icache(vm_offset_t, unsigned, int);
extern void flush_dcache(vm_offset_t, unsigned, int);
extern void invalidate_icache64(addr64_t, unsigned, int);
extern void flush_dcache64(addr64_t, unsigned, int);
static inline int
clz(unsigned int num)
{
return num ? __builtin_clz(num) : sizeof(num) * 8;
}
extern vm_offset_t vm_kernel_addrhash(vm_offset_t addr);
extern void vm_kernel_addrhide(
vm_offset_t addr,
vm_offset_t *hide_addr);
extern vm_offset_t vm_kernel_addrperm_ext;
extern void vm_kernel_addrperm_external(
vm_offset_t addr,
vm_offset_t *perm_addr);
extern void vm_kernel_unslide_or_perm_external(
vm_offset_t addr,
vm_offset_t *up_addr);
extern void vm_init_before_launchd(void);
extern thread_t current_thread(void);
extern void thread_reference(
thread_t thread);
extern void thread_deallocate(
thread_t thread);
extern uint64_t thread_tid(thread_t thread);
extern kern_return_t kernel_thread_start(
thread_continue_t continuation,
void *parameter,
thread_t *new_thread);
struct kcdata_item {
uint32_t type;
uint32_t size;
uint64_t flags;
char data[];
};
typedef struct kcdata_item * kcdata_item_t;
enum KCDATA_SUBTYPE_TYPES { KC_ST_CHAR = 1, KC_ST_INT8, KC_ST_UINT8, KC_ST_INT16, KC_ST_UINT16, KC_ST_INT32, KC_ST_UINT32, KC_ST_INT64, KC_ST_UINT64 };
typedef enum KCDATA_SUBTYPE_TYPES kctype_subtype_t;
struct kcdata_subtype_descriptor {
uint8_t kcs_flags;
uint8_t kcs_elem_type;
uint16_t kcs_elem_offset;
uint32_t kcs_elem_size;
char kcs_name[32];
};
typedef struct kcdata_subtype_descriptor * kcdata_subtype_descriptor_t;
static inline uint32_t
kcs_get_elem_size(kcdata_subtype_descriptor_t d)
{
if (d->kcs_flags & 0x1) {
return (uint32_t)((d->kcs_elem_size & 0xffff) * ((d->kcs_elem_size & 0xffff0000)>>16));
}
return d->kcs_elem_size;
}
static inline uint32_t
kcs_get_elem_count(kcdata_subtype_descriptor_t d)
{
if (d->kcs_flags & 0x1)
return (d->kcs_elem_size >> 16) & 0xffff;
return 1;
}
static inline int
kcs_set_elem_size(kcdata_subtype_descriptor_t d, uint32_t size, uint32_t count)
{
if (count > 1) {
if (size > 0xffff || count > 0xffff)
return -1;
d->kcs_elem_size = ((count & 0xffff) << 16 | (size & 0xffff));
}
else
{
d->kcs_elem_size = size;
}
return 0;
}
struct kcdata_type_definition {
uint32_t kct_type_identifier;
uint32_t kct_num_elements;
char kct_name[32];
struct kcdata_subtype_descriptor kct_elements[];
};
struct stack_snapshot_frame32 {
uint32_t lr;
uint32_t sp;
};
struct stack_snapshot_frame64 {
uint64_t lr;
uint64_t sp;
};
struct dyld_uuid_info_32 {
uint32_t imageLoadAddress;
uuid_t imageUUID;
};
struct dyld_uuid_info_64 {
uint64_t imageLoadAddress;
uuid_t imageUUID;
};
struct dyld_uuid_info_64_v2 {
uint64_t imageLoadAddress;
uuid_t imageUUID;
uint64_t imageSlidBaseAddress;
};
struct user32_dyld_uuid_info {
uint32_t imageLoadAddress;
uuid_t imageUUID;
};
struct user64_dyld_uuid_info {
uint64_t imageLoadAddress;
uuid_t imageUUID;
};
enum task_snapshot_flags {
kTaskRsrcFlagged = 0x4,
kTerminatedSnapshot = 0x8,
kPidSuspended = 0x10,
kFrozen = 0x20,
kTaskDarwinBG = 0x40,
kTaskExtDarwinBG = 0x80,
kTaskVisVisible = 0x100,
kTaskVisNonvisible = 0x200,
kTaskIsForeground = 0x400,
kTaskIsBoosted = 0x800,
kTaskIsSuppressed = 0x1000,
kTaskIsTimerThrottled = 0x2000,
kTaskIsImpDonor = 0x4000,
kTaskIsLiveImpDonor = 0x8000,
kTaskIsDirty = 0x10000,
kTaskWqExceededConstrainedThreadLimit = 0x20000,
kTaskWqExceededTotalThreadLimit = 0x40000,
kTaskWqFlagsAvailable = 0x80000,
kTaskUUIDInfoFaultedIn = 0x100000,
kTaskUUIDInfoMissing = 0x200000,
kTaskUUIDInfoTriedFault = 0x400000,
kTaskSharedRegionInfoUnavailable = 0x800000,
};
enum thread_snapshot_flags {
kHasDispatchSerial = 0x4,
kStacksPCOnly = 0x8,
kThreadDarwinBG = 0x10,
kThreadIOPassive = 0x20,
kThreadSuspended = 0x40,
kThreadTruncatedBT = 0x80,
kGlobalForcedIdle = 0x100,
kThreadFaultedBT = 0x200,
kThreadTriedFaultBT = 0x400,
kThreadOnCore = 0x800,
kThreadIdleWorker = 0x1000,
kThreadMain = 0x2000,
};
struct mem_and_io_snapshot {
uint32_t snapshot_magic;
uint32_t free_pages;
uint32_t active_pages;
uint32_t inactive_pages;
uint32_t purgeable_pages;
uint32_t wired_pages;
uint32_t speculative_pages;
uint32_t throttled_pages;
uint32_t filebacked_pages;
uint32_t compressions;
uint32_t decompressions;
uint32_t compressor_size;
int32_t busy_buffer_count;
uint32_t pages_wanted;
uint32_t pages_reclaimed;
uint8_t pages_wanted_reclaimed_valid;
} ;
struct thread_snapshot_v2 {
uint64_t ths_thread_id;
uint64_t ths_wait_event;
uint64_t ths_continuation;
uint64_t ths_total_syscalls;
uint64_t ths_voucher_identifier;
uint64_t ths_dqserialnum;
uint64_t ths_user_time;
uint64_t ths_sys_time;
uint64_t ths_ss_flags;
uint64_t ths_last_run_time;
uint64_t ths_last_made_runnable_time;
uint32_t ths_state;
uint32_t ths_sched_flags;
int16_t ths_base_priority;
int16_t ths_sched_priority;
uint8_t ths_eqos;
uint8_t ths_rqos;
uint8_t ths_rqos_override;
uint8_t ths_io_tier;
} ;
struct thread_snapshot_v3 {
uint64_t ths_thread_id;
uint64_t ths_wait_event;
uint64_t ths_continuation;
uint64_t ths_total_syscalls;
uint64_t ths_voucher_identifier;
uint64_t ths_dqserialnum;
uint64_t ths_user_time;
uint64_t ths_sys_time;
uint64_t ths_ss_flags;
uint64_t ths_last_run_time;
uint64_t ths_last_made_runnable_time;
uint32_t ths_state;
uint32_t ths_sched_flags;
int16_t ths_base_priority;
int16_t ths_sched_priority;
uint8_t ths_eqos;
uint8_t ths_rqos;
uint8_t ths_rqos_override;
uint8_t ths_io_tier;
uint64_t ths_thread_t;
} ;
struct thread_snapshot_v4 {
uint64_t ths_thread_id;
uint64_t ths_wait_event;
uint64_t ths_continuation;
uint64_t ths_total_syscalls;
uint64_t ths_voucher_identifier;
uint64_t ths_dqserialnum;
uint64_t ths_user_time;
uint64_t ths_sys_time;
uint64_t ths_ss_flags;
uint64_t ths_last_run_time;
uint64_t ths_last_made_runnable_time;
uint32_t ths_state;
uint32_t ths_sched_flags;
int16_t ths_base_priority;
int16_t ths_sched_priority;
uint8_t ths_eqos;
uint8_t ths_rqos;
uint8_t ths_rqos_override;
uint8_t ths_io_tier;
uint64_t ths_thread_t;
uint64_t ths_requested_policy;
uint64_t ths_effective_policy;
} ;
struct thread_group_snapshot {
uint64_t tgs_id;
char tgs_name[16];
} ;
enum thread_group_flags {
kThreadGroupEfficient = 0x1,
kThreadGroupUIApp = 0x2
};
struct thread_group_snapshot_v2 {
uint64_t tgs_id;
char tgs_name[16];
uint64_t tgs_flags;
} ;
enum coalition_flags {
kCoalitionTermRequested = 0x1,
kCoalitionTerminated = 0x2,
kCoalitionReaped = 0x4,
kCoalitionPrivileged = 0x8,
};
struct jetsam_coalition_snapshot {
uint64_t jcs_id;
uint64_t jcs_flags;
uint64_t jcs_thread_group;
uint64_t jcs_leader_task_uniqueid;
} ;
struct instrs_cycles_snapshot {
uint64_t ics_instructions;
uint64_t ics_cycles;
} ;
struct thread_delta_snapshot_v2 {
uint64_t tds_thread_id;
uint64_t tds_voucher_identifier;
uint64_t tds_ss_flags;
uint64_t tds_last_made_runnable_time;
uint32_t tds_state;
uint32_t tds_sched_flags;
int16_t tds_base_priority;
int16_t tds_sched_priority;
uint8_t tds_eqos;
uint8_t tds_rqos;
uint8_t tds_rqos_override;
uint8_t tds_io_tier;
} ;
struct io_stats_snapshot
{
uint64_t ss_disk_reads_count;
uint64_t ss_disk_reads_size;
uint64_t ss_disk_writes_count;
uint64_t ss_disk_writes_size;
uint64_t ss_io_priority_count[4];
uint64_t ss_io_priority_size[4];
uint64_t ss_paging_count;
uint64_t ss_paging_size;
uint64_t ss_non_paging_count;
uint64_t ss_non_paging_size;
uint64_t ss_data_count;
uint64_t ss_data_size;
uint64_t ss_metadata_count;
uint64_t ss_metadata_size;
} ;
struct task_snapshot_v2 {
uint64_t ts_unique_pid;
uint64_t ts_ss_flags;
uint64_t ts_user_time_in_terminated_threads;
uint64_t ts_system_time_in_terminated_threads;
uint64_t ts_p_start_sec;
uint64_t ts_task_size;
uint64_t ts_max_resident_size;
uint32_t ts_suspend_count;
uint32_t ts_faults;
uint32_t ts_pageins;
uint32_t ts_cow_faults;
uint32_t ts_was_throttled;
uint32_t ts_did_throttle;
uint32_t ts_latency_qos;
int32_t ts_pid;
char ts_p_comm[32];
} ;
struct task_delta_snapshot_v2 {
uint64_t tds_unique_pid;
uint64_t tds_ss_flags;
uint64_t tds_user_time_in_terminated_threads;
uint64_t tds_system_time_in_terminated_threads;
uint64_t tds_task_size;
uint64_t tds_max_resident_size;
uint32_t tds_suspend_count;
uint32_t tds_faults;
uint32_t tds_pageins;
uint32_t tds_cow_faults;
uint32_t tds_was_throttled;
uint32_t tds_did_throttle;
uint32_t tds_latency_qos;
} ;
struct stackshot_cpu_times {
uint64_t user_usec;
uint64_t system_usec;
} ;
struct stackshot_duration {
uint64_t stackshot_duration;
uint64_t stackshot_duration_outer;
} ;
struct stackshot_fault_stats {
uint32_t sfs_pages_faulted_in;
uint64_t sfs_time_spent_faulting;
uint64_t sfs_system_max_fault_time;
uint8_t sfs_stopped_faulting;
} ;
typedef struct stackshot_thread_waitinfo {
uint64_t owner;
uint64_t waiter;
uint64_t context;
uint8_t wait_type;
}  thread_waitinfo_t;
struct exit_reason_snapshot {
uint32_t ers_namespace;
uint64_t ers_code;
uint64_t ers_flags;
} ;
struct codesigning_exit_reason_info {
uint64_t ceri_virt_addr;
uint64_t ceri_file_offset;
char ceri_pathname[1024];
char ceri_filename[1024];
uint64_t ceri_codesig_modtime_secs;
uint64_t ceri_codesig_modtime_nsecs;
uint64_t ceri_page_modtime_secs;
uint64_t ceri_page_modtime_nsecs;
uint8_t ceri_path_truncated;
uint8_t ceri_object_codesigned;
uint8_t ceri_page_codesig_validated;
uint8_t ceri_page_codesig_tainted;
uint8_t ceri_page_codesig_nx;
uint8_t ceri_page_wpmapped;
uint8_t ceri_page_slid;
uint8_t ceri_page_dirty;
uint32_t ceri_page_shadow_depth;
} ;
typedef struct kcdata_iter {
kcdata_item_t item;
void *end;
} kcdata_iter_t;
static inline
kcdata_iter_t kcdata_iter(void *buffer, unsigned long size) {
kcdata_iter_t iter;
iter.item = (kcdata_item_t) buffer;
iter.end = (void*) (((uintptr_t)buffer) + size);
return iter;
}
static inline
kcdata_iter_t kcdata_iter_unsafe(void *buffer) ;
static inline
kcdata_iter_t kcdata_iter_unsafe(void *buffer) {
kcdata_iter_t iter;
iter.item = (kcdata_item_t) buffer;
iter.end = (void*) (uintptr_t) ~0;
return iter;
}
//static const kcdata_iter_t kcdata_invalid_iter = { .item = 0, .end = 0 };
static inline
int kcdata_iter_valid(kcdata_iter_t iter) {
return
( (uintptr_t)iter.item + sizeof(struct kcdata_item) <= (uintptr_t)iter.end ) &&
( (uintptr_t)iter.item + sizeof(struct kcdata_item) + iter.item->size <= (uintptr_t)iter.end);
}
static inline
kcdata_iter_t kcdata_iter_next(kcdata_iter_t iter) {
iter.item = (kcdata_item_t) (((uintptr_t)iter.item) + sizeof(struct kcdata_item) + (iter.item->size));
return iter;
}
static inline uint32_t
kcdata_iter_type(kcdata_iter_t iter)
{
if ((iter.item->type & ~0xfu) == 0x20u)
return 0x11u;
else
return iter.item->type;
}
static inline uint32_t
kcdata_calc_padding(uint32_t size)
{
return (-size) & 0xf;
}
static inline uint32_t
kcdata_flags_get_padding(uint64_t flags)
{
return flags & 0xf;
}
static inline int
kcdata_iter_is_legacy_item(kcdata_iter_t iter, uint32_t legacy_size)
{
uint32_t legacy_size_padded = legacy_size + kcdata_calc_padding(legacy_size);
return (iter.item->size == legacy_size_padded &&
(iter.item->flags & (0xf | 0x80)) == 0);
}
static inline uint32_t
kcdata_iter_size(kcdata_iter_t iter)
{
uint32_t legacy_size = 0;
switch (kcdata_iter_type(iter)) {
case 0x11u:
case 0x13u:
return iter.item->size;
case 0x906u: {
legacy_size = sizeof(struct thread_snapshot_v2);
if (kcdata_iter_is_legacy_item(iter, legacy_size)) {
return legacy_size;
}
goto not_legacy;
}
case 0x908u: {
legacy_size = sizeof(struct dyld_uuid_info_64);
if (kcdata_iter_is_legacy_item(iter, legacy_size)) {
return legacy_size;
}
goto not_legacy;
}
not_legacy:
default:
if (iter.item->size < kcdata_flags_get_padding(iter.item->flags))
return 0;
else
return iter.item->size - kcdata_flags_get_padding(iter.item->flags);
}
}
static inline uint64_t
kcdata_iter_flags(kcdata_iter_t iter)
{
return iter.item->flags;
}
static inline
void * kcdata_iter_payload(kcdata_iter_t iter) {
return &iter.item->data;
}
static inline
uint32_t kcdata_iter_array_elem_type(kcdata_iter_t iter) {
return (iter.item->flags >> 32) & 4294967295U;
}
static inline
uint32_t kcdata_iter_array_elem_count(kcdata_iter_t iter) {
return (iter.item->flags) & 4294967295U;
}
static inline
uint32_t
kcdata_iter_array_size_switch(kcdata_iter_t iter) {
switch(kcdata_iter_array_elem_type(iter)) {
case 0x30u:
return sizeof(struct dyld_uuid_info_32);
case 0x31u:
return sizeof(struct dyld_uuid_info_64);
case 0x90Au:
case 0x90Cu:
return sizeof(struct stack_snapshot_frame32);
case 0x90Bu:
case 0x90Du:
return sizeof(struct stack_snapshot_frame64);
case 0x907u:
return sizeof(int32_t);
case 0x941u:
return sizeof(struct thread_delta_snapshot_v2);
case 0x81A:
return sizeof(uint64_t);
default:
return 0;
}
}
static inline
int kcdata_iter_array_valid(kcdata_iter_t iter) {
if (!kcdata_iter_valid(iter))
return 0;
if (kcdata_iter_type(iter) != 0x11u)
return 0;
if (kcdata_iter_array_elem_count(iter) == 0)
return iter.item->size == 0;
if (iter.item->type == 0x11u) {
uint32_t elem_size = kcdata_iter_array_size_switch(iter);
if (elem_size == 0)
return 0;
return
kcdata_iter_array_elem_count(iter) <= iter.item->size / elem_size &&
iter.item->size % kcdata_iter_array_elem_count(iter) < 16;
} else {
return
(iter.item->type & 0xf) <= iter.item->size &&
kcdata_iter_array_elem_count(iter) <= iter.item->size - (iter.item->type & 0xf) &&
(iter.item->size - (iter.item->type & 0xf)) % kcdata_iter_array_elem_count(iter) == 0;
}
}
static inline
uint32_t kcdata_iter_array_elem_size(kcdata_iter_t iter) {
if (iter.item->type == 0x11u)
return kcdata_iter_array_size_switch(iter);
if (kcdata_iter_array_elem_count(iter) == 0)
return 0;
return (iter.item->size - (iter.item->type & 0xf)) / kcdata_iter_array_elem_count(iter);
}
static inline
int kcdata_iter_container_valid(kcdata_iter_t iter) {
return
kcdata_iter_valid(iter) &&
kcdata_iter_type(iter) == 0x13u &&
iter.item->size >= sizeof(uint32_t);
}
static inline
uint32_t kcdata_iter_container_type(kcdata_iter_t iter) {
return * (uint32_t *) kcdata_iter_payload(iter);
}
static inline
uint64_t kcdata_iter_container_id(kcdata_iter_t iter) {
return iter.item->flags;
}
static inline
kcdata_iter_t
kcdata_iter_find_type(kcdata_iter_t iter, uint32_t type)
{
for(; kcdata_iter_valid(iter) && iter.item->type != 0xF19158EDu; iter = kcdata_iter_next(iter))
{
if (kcdata_iter_type(iter) == type)
return iter;
}
return kcdata_invalid_iter;
}
static inline
int kcdata_iter_data_with_desc_valid(kcdata_iter_t iter, uint32_t minsize) {
return
kcdata_iter_valid(iter) &&
kcdata_iter_size(iter) >= 32 + minsize &&
((char*)kcdata_iter_payload(iter))[32 -1] == 0;
}
static inline
char *kcdata_iter_string(kcdata_iter_t iter, uint32_t offset) {
if (offset > kcdata_iter_size(iter)) {
return ((void *)0);
}
uint32_t maxlen = kcdata_iter_size(iter) - offset;
char *s = ((char*)kcdata_iter_payload(iter)) + offset;
if (strnlen(s, maxlen) < maxlen) {
return s;
} else {
return ((void *)0);
}
}
static inline void kcdata_iter_get_data_with_desc(kcdata_iter_t iter, char **desc_ptr, void **data_ptr, uint32_t *size_ptr) {
if (desc_ptr)
*desc_ptr = (char *)kcdata_iter_payload(iter);
if (data_ptr)
*data_ptr = (void *)((uintptr_t)kcdata_iter_payload(iter) + 32);
if (size_ptr)
*size_ptr = kcdata_iter_size(iter) - 32;
}
struct thread_snapshot {
uint32_t snapshot_magic;
uint32_t nkern_frames;
uint32_t nuser_frames;
uint64_t wait_event;
uint64_t continuation;
uint64_t thread_id;
uint64_t user_time;
uint64_t system_time;
int32_t state;
int32_t priority;
int32_t sched_pri;
int32_t sched_flags;
char ss_flags;
char ts_qos;
char ts_rqos;
char ts_rqos_override;
char io_tier;
char _reserved[3];
uint64_t disk_reads_count;
uint64_t disk_reads_size;
uint64_t disk_writes_count;
uint64_t disk_writes_size;
uint64_t io_priority_count[4];
uint64_t io_priority_size[4];
uint64_t paging_count;
uint64_t paging_size;
uint64_t non_paging_count;
uint64_t non_paging_size;
uint64_t data_count;
uint64_t data_size;
uint64_t metadata_count;
uint64_t metadata_size;
uint64_t voucher_identifier;
uint64_t total_syscalls;
char pth_name[64];
} ;
struct task_snapshot {
uint32_t snapshot_magic;
int32_t pid;
uint64_t uniqueid;
uint64_t user_time_in_terminated_threads;
uint64_t system_time_in_terminated_threads;
uint8_t shared_cache_identifier[16];
uint64_t shared_cache_slide;
uint32_t nloadinfos;
int suspend_count;
int task_size;
int faults;
int pageins;
int cow_faults;
uint32_t ss_flags;
uint64_t p_start_sec;
uint64_t p_start_usec;
char p_comm[17];
uint32_t was_throttled;
uint32_t did_throttle;
uint32_t latency_qos;
uint64_t disk_reads_count;
uint64_t disk_reads_size;
uint64_t disk_writes_count;
uint64_t disk_writes_size;
uint64_t io_priority_count[4];
uint64_t io_priority_size[4];
uint64_t paging_count;
uint64_t paging_size;
uint64_t non_paging_count;
uint64_t non_paging_size;
uint64_t data_count;
uint64_t data_size;
uint64_t metadata_count;
uint64_t metadata_size;
uint32_t donating_pid_count;
} ;
struct micro_snapshot {
uint32_t snapshot_magic;
uint32_t ms_cpu;
uint64_t ms_time;
uint64_t ms_time_microsecs;
uint8_t ms_flags;
uint16_t ms_opaque_flags;
} ;
struct _dyld_cache_header
{
char magic[16];
uint32_t mappingOffset;
uint32_t mappingCount;
uint32_t imagesOffset;
uint32_t imagesCount;
uint64_t dyldBaseAddress;
uint64_t codeSignatureOffset;
uint64_t codeSignatureSize;
uint64_t slideInfoOffset;
uint64_t slideInfoSize;
uint64_t localSymbolsOffset;
uint64_t localSymbolsSize;
uint8_t uuid[16];
};
enum micro_snapshot_flags {
kInterruptRecord = 0x1,
kTimerArmingRecord = 0x2,
kUserMode = 0x4,
kIORecord = 0x8,
};
enum generic_snapshot_flags {
kUser64_p = 0x1,
kKernel64_p = 0x2
};
enum {
STACKSHOT_GET_DQ = 0x01,
STACKSHOT_SAVE_LOADINFO = 0x02,
STACKSHOT_GET_GLOBAL_MEM_STATS = 0x04,
STACKSHOT_SAVE_KEXT_LOADINFO = 0x08,
STACKSHOT_GET_MICROSTACKSHOT = 0x10,
STACKSHOT_GLOBAL_MICROSTACKSHOT_ENABLE = 0x20,
STACKSHOT_GLOBAL_MICROSTACKSHOT_DISABLE = 0x40,
STACKSHOT_SET_MICROSTACKSHOT_MARK = 0x80,
STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY = 0x100,
STACKSHOT_GET_BOOT_PROFILE = 0x200,
STACKSHOT_SAVE_IMP_DONATION_PIDS = 0x2000,
STACKSHOT_SAVE_IN_KERNEL_BUFFER = 0x4000,
STACKSHOT_RETRIEVE_EXISTING_BUFFER = 0x8000,
STACKSHOT_KCDATA_FORMAT = 0x10000,
STACKSHOT_ENABLE_BT_FAULTING = 0x20000,
STACKSHOT_COLLECT_DELTA_SNAPSHOT = 0x40000,
STACKSHOT_TAILSPIN = 0x80000,
STACKSHOT_TRYLOCK = 0x100000,
STACKSHOT_ENABLE_UUID_FAULTING = 0x200000,
STACKSHOT_FROM_PANIC = 0x400000,
STACKSHOT_NO_IO_STATS = 0x800000,
STACKSHOT_THREAD_WAITINFO = 0x1000000,
STACKSHOT_THREAD_GROUP = 0x2000000,
STACKSHOT_SAVE_JETSAM_COALITIONS = 0x4000000,
STACKSHOT_INSTRS_CYCLES = 0x8000000,
};
boolean_t kern_feature_override(uint32_t fmask);
struct embedded_panic_header {
uint32_t eph_magic;
uint32_t eph_crc;
uint32_t eph_version;
uint64_t eph_panic_flags;
uint32_t eph_panic_log_offset;
uint32_t eph_panic_log_len;
uint32_t eph_stackshot_offset;
uint32_t eph_stackshot_len;
uint32_t eph_other_log_offset;
uint32_t eph_other_log_len;
uint64_t eph_x86_power_state:8,
eph_x86_efi_boot_state:8,
eph_x86_system_state:8,
eph_x86_unused_bits:40;
} ;
struct macos_panic_header {
uint32_t mph_magic;
uint32_t mph_crc;
uint32_t mph_version;
uint32_t mph_padding;
uint64_t mph_panic_flags;
uint32_t mph_panic_log_offset;
uint32_t mph_panic_log_len;
uint32_t mph_stackshot_offset;
uint32_t mph_stackshot_len;
uint32_t mph_other_log_offset;
uint32_t mph_other_log_len;
char mph_data[];
} ;
extern void panic(const char *string, ...) ;
int nullop(void);
int nulldev(void);
int enoioctl(void);
int enosys(void);
int enxio(void);
int eopnotsupp(void);
void *hashinit(int count, int type, u_long *hashmask);
void ovbcopy(const void *from, void *to, size_t len);
int fubyte(user_addr_t addr);
int fuibyte(user_addr_t addr);
int subyte(user_addr_t addr, int byte);
int suibyte(user_addr_t addr, int byte);
long fuword(user_addr_t addr);
long fuiword(user_addr_t addr);
int suword(user_addr_t addr, long word);
int suiword(user_addr_t addr, long word);
int useracc(user_addr_t addr, user_size_t len,int prot);
typedef void (*timeout_fcn_t)(void *);
void bsd_timeout(void (*)(void *), void *arg, struct timespec * ts);
void bsd_untimeout(void (*)(void *), void *arg);
void set_fsblocksize(struct vnode *);
uint64_t tvtoabstime(struct timeval *);
uint64_t tstoabstime(struct timespec *);
void *throttle_info_create(void);
void throttle_info_mount_ref(mount_t mp, void * throttle_info);
void throttle_info_mount_rel(mount_t mp);
void throttle_info_release(void *throttle_info);
void throttle_info_update(void *throttle_info, int flags);
uint32_t throttle_lowpri_io(int sleep_amount);
void throttle_set_thread_io_policy(int policy);
typedef struct __throttle_info_handle *throttle_info_handle_t;
int throttle_info_ref_by_mask(uint64_t throttle_mask, throttle_info_handle_t *throttle_info_handle);
void throttle_info_rel_by_mask(throttle_info_handle_t throttle_info_handle);
void throttle_info_update_by_mask(void *throttle_info_handle, int flags);
void throttle_info_disable_throttle(int devno, boolean_t isfusion);
int throttle_info_io_will_be_throttled(void *throttle_info_handle, int policy);
struct flock {
off_t l_start;
off_t l_len;
pid_t l_pid;
short l_type;
short l_whence;
};
struct flocktimeout {
struct flock fl;
struct timespec timeout;
};
struct radvisory {
off_t ra_offset;
int ra_count;
};
typedef struct user32_fcodeblobs {
user32_addr_t f_cd_hash;
user32_size_t f_hash_size;
user32_addr_t f_cd_buffer;
user32_size_t f_cd_size;
user32_addr_t f_out_size;
int f_arch;
} user32_fcodeblobs_t;
typedef struct user64_fcodeblobs {
user64_addr_t f_cd_hash;
user64_size_t f_hash_size;
user64_addr_t f_cd_buffer;
user64_size_t f_cd_size;
user64_addr_t f_out_size;
int f_arch;
int __padding;
} user64_fcodeblobs_t;
typedef struct user_fcodeblobs {
user_addr_t f_cd_hash;
user_size_t f_hash_size;
user_addr_t f_cd_buffer;
user_size_t f_cd_size;
user_addr_t f_out_size;
int f_arch;
} user_fcodeblobs_t;
typedef struct fsignatures {
off_t fs_file_start;
void *fs_blob_start;
size_t fs_blob_size;
} fsignatures_t;
typedef struct user32_fsignatures {
off_t fs_file_start;
user32_addr_t fs_blob_start;
user32_size_t fs_blob_size;
} user32_fsignatures_t;
typedef struct user_fsignatures {
off_t fs_file_start;
user_addr_t fs_blob_start;
user_size_t fs_blob_size;
} user_fsignatures_t;
typedef struct fchecklv {
off_t lv_file_start;
size_t lv_error_message_size;
void *lv_error_message;
} fchecklv_t;
typedef struct user32_fchecklv {
user32_off_t lv_file_start;
user32_size_t lv_error_message_size;
user32_addr_t lv_error_message;
} user32_fchecklv_t;
typedef struct user_fchecklv {
off_t lv_file_start;
user_size_t lv_error_message_size;
user_addr_t lv_error_message;
} user_fchecklv_t;
typedef struct fstore {
unsigned int fst_flags;
int fst_posmode;
off_t fst_offset;
off_t fst_length;
off_t fst_bytesalloc;
} fstore_t;
typedef struct fpunchhole {
unsigned int fp_flags;
unsigned int reserved;
off_t fp_offset;
off_t fp_length;
} fpunchhole_t;
typedef struct ftrimactivefile {
off_t fta_offset;
off_t fta_length;
} ftrimactivefile_t;
typedef struct fbootstraptransfer {
off_t fbt_offset;
size_t fbt_length;
void *fbt_buffer;
} fbootstraptransfer_t;
typedef struct user32_fbootstraptransfer {
off_t fbt_offset;
user32_size_t fbt_length;
user32_addr_t fbt_buffer;
} user32_fbootstraptransfer_t;
typedef struct user_fbootstraptransfer {
off_t fbt_offset;
user_size_t fbt_length;
user_addr_t fbt_buffer;
} user_fbootstraptransfer_t;
struct log2phys {
unsigned int l2p_flags;
off_t l2p_contigbytes;
off_t l2p_devoffset;
};
struct accessx_descriptor {
unsigned int ad_name_offset;
int ad_flags;
int ad_pad[2];
};
int file_socket(int, socket_t *);
int file_vnode(int, vnode_t *);
int file_vnode_withvid(int, vnode_t *, uint32_t *);
int file_flags(int, int *);
int file_drop(int);
struct ostat {
__uint16_t st_dev;
ino_t st_ino;
mode_t st_mode;
nlink_t st_nlink;
__uint16_t st_uid;
__uint16_t st_gid;
__uint16_t st_rdev;
__int32_t st_size;
struct timespec st_atimespec;
struct timespec st_mtimespec;
struct timespec st_ctimespec;
__int32_t st_blksize;
__int32_t st_blocks;
__uint32_t st_flags;
__uint32_t st_gen;
};
struct stat {
dev_t st_dev;
ino_t st_ino;
mode_t st_mode;
nlink_t st_nlink;
uid_t st_uid;
gid_t st_gid;
dev_t st_rdev;
struct timespec st_atimespec;
struct timespec st_mtimespec;
struct timespec st_ctimespec;
off_t st_size;
blkcnt_t st_blocks;
blksize_t st_blksize;
__uint32_t st_flags;
__uint32_t st_gen;
__int32_t st_lspare;
__int64_t st_qspare[2];
};
struct stat64 { dev_t st_dev; mode_t st_mode; nlink_t st_nlink; __darwin_ino64_t st_ino; uid_t st_uid; gid_t st_gid; dev_t st_rdev; struct timespec st_atimespec; struct timespec st_mtimespec; struct timespec st_ctimespec; struct timespec st_birthtimespec; off_t st_size; blkcnt_t st_blocks; blksize_t st_blksize; __uint32_t st_flags; __uint32_t st_gen; __int32_t st_lspare; __int64_t st_qspare[2]; };
struct buf;
struct proc;
struct tty;
struct uio;
struct vnode;
typedef int open_close_fcn_t(dev_t dev, int flags, int devtype,
struct proc *p);
typedef struct tty *d_devtotty_t(dev_t dev);
typedef void strategy_fcn_t(struct buf *bp);
typedef int ioctl_fcn_t(dev_t dev, u_long cmd, caddr_t data,
int fflag, struct proc *p);
typedef int dump_fcn_t(void);
typedef int psize_fcn_t(dev_t dev);
typedef int read_write_fcn_t(dev_t dev, struct uio *uio, int ioflag);
typedef int stop_fcn_t(struct tty *tp, int rw);
typedef int reset_fcn_t(int uban);
typedef int select_fcn_t(dev_t dev, int which, void * wql, struct proc *p);
typedef int mmap_fcn_t(void);
int enodev(void);
void enodev_strat(void);
struct bdevsw {
open_close_fcn_t *d_open;
open_close_fcn_t *d_close;
strategy_fcn_t *d_strategy;
ioctl_fcn_t *d_ioctl;
dump_fcn_t *d_dump;
psize_fcn_t *d_psize;
int d_type;
};
d_devtotty_t nodevtotty;
read_write_fcn_t nowrite;
struct cdevsw {
open_close_fcn_t *d_open;
open_close_fcn_t *d_close;
read_write_fcn_t *d_read;
read_write_fcn_t *d_write;
ioctl_fcn_t *d_ioctl;
stop_fcn_t *d_stop;
reset_fcn_t *d_reset;
struct tty **d_ttys;
select_fcn_t *d_select;
mmap_fcn_t *d_mmap;
strategy_fcn_t *d_strategy;
void *d_reserved_1;
void *d_reserved_2;
int d_type;
};
int bdevsw_isfree(int);
int bdevsw_add(int, struct bdevsw *);
int bdevsw_remove(int, struct bdevsw *);
int cdevsw_isfree(int);
int cdevsw_add(int, struct cdevsw *);
int cdevsw_add_with_bdev(int index, struct cdevsw * csw, int bdev);
int cdevsw_remove(int, struct cdevsw *);
int isdisk(dev_t, int);
typedef u_int32_t text_encoding_t;
typedef u_int32_t fsobj_type_t;
typedef u_int32_t fsobj_tag_t;
typedef u_int32_t fsfile_type_t;
typedef u_int32_t fsvolid_t;
typedef u_int32_t attrgroup_t;
struct attrlist {
u_short bitmapcount;
u_int16_t reserved;
attrgroup_t commonattr;
attrgroup_t volattr;
attrgroup_t dirattr;
attrgroup_t fileattr;
attrgroup_t forkattr;
};
typedef struct attribute_set {
attrgroup_t commonattr;
attrgroup_t volattr;
attrgroup_t dirattr;
attrgroup_t fileattr;
attrgroup_t forkattr;
} attribute_set_t;
typedef struct attrreference {
int32_t attr_dataoffset;
u_int32_t attr_length;
} attrreference_t;
struct diskextent {
u_int32_t startblock;
u_int32_t blockcount;
};
typedef struct diskextent extentrecord[8];
typedef u_int32_t vol_capabilities_set_t[4];
typedef struct vol_capabilities_attr {
vol_capabilities_set_t capabilities;
vol_capabilities_set_t valid;
} vol_capabilities_attr_t;
typedef struct vol_attributes_attr {
attribute_set_t validattr;
attribute_set_t nativeattr;
} vol_attributes_attr_t;
struct fssearchblock {
struct attrlist *returnattrs;
void *returnbuffer;
size_t returnbuffersize;
u_long maxmatches;
struct timeval timelimit;
void *searchparams1;
size_t sizeofsearchparams1;
void *searchparams2;
size_t sizeofsearchparams2;
struct attrlist searchattrs;
};
struct user64_fssearchblock {
user64_addr_t returnattrs;
user64_addr_t returnbuffer;
user64_size_t returnbuffersize;
user64_ulong_t maxmatches;
struct user64_timeval timelimit;
user64_addr_t searchparams1;
user64_size_t sizeofsearchparams1;
user64_addr_t searchparams2;
user64_size_t sizeofsearchparams2;
struct attrlist searchattrs;
};
struct user32_fssearchblock {
user32_addr_t returnattrs;
user32_addr_t returnbuffer;
user32_size_t returnbuffersize;
user32_ulong_t maxmatches;
struct user32_timeval timelimit;
user32_addr_t searchparams1;
user32_size_t sizeofsearchparams1;
user32_addr_t searchparams2;
user32_size_t sizeofsearchparams2;
struct attrlist searchattrs;
};
struct searchstate {
uint32_t ss_union_flags;
uint32_t ss_union_layer;
u_char ss_fsstate[548];
} ;
struct statfs64 { uint32_t f_bsize; int32_t f_iosize; uint64_t f_blocks; uint64_t f_bfree; uint64_t f_bavail; uint64_t f_files; uint64_t f_ffree; fsid_t f_fsid; uid_t f_owner; uint32_t f_type; uint32_t f_flags; uint32_t f_fssubtype; char f_fstypename[16]; char f_mntonname[1024]; char f_mntfromname[1024]; uint32_t f_reserved[8]; };
struct statfs {
short f_otype;
short f_oflags;
long f_bsize;
long f_iosize;
long f_blocks;
long f_bfree;
long f_bavail;
long f_files;
long f_ffree;
fsid_t f_fsid;
uid_t f_owner;
short f_reserved1;
short f_type;
long f_flags;
long f_reserved2[2];
char f_fstypename[15];
char f_mntonname[90];
char f_mntfromname[90];
char f_reserved3;
long f_reserved4[4];
};
struct vfsstatfs {
uint32_t f_bsize;
size_t f_iosize;
uint64_t f_blocks;
uint64_t f_bfree;
uint64_t f_bavail;
uint64_t f_bused;
uint64_t f_files;
uint64_t f_ffree;
fsid_t f_fsid;
uid_t f_owner;
uint64_t f_flags;
char f_fstypename[16];
char f_mntonname[1024];
char f_mntfromname[1024];
uint32_t f_fssubtype;
void *f_reserved[2];
};
struct vfs_attr {
uint64_t f_supported;
uint64_t f_active;
uint64_t f_objcount;
uint64_t f_filecount;
uint64_t f_dircount;
uint64_t f_maxobjcount;
uint32_t f_bsize;
size_t f_iosize;
uint64_t f_blocks;
uint64_t f_bfree;
uint64_t f_bavail;
uint64_t f_bused;
uint64_t f_files;
uint64_t f_ffree;
fsid_t f_fsid;
uid_t f_owner;
vol_capabilities_attr_t f_capabilities;
vol_attributes_attr_t f_attributes;
struct timespec f_create_time;
struct timespec f_modify_time;
struct timespec f_access_time;
struct timespec f_backup_time;
uint32_t f_fssubtype;
char *f_vol_name;
uint16_t f_signature;
uint16_t f_carbon_fsid;
uuid_t f_uuid;
uint64_t f_quota;
uint64_t f_reserved;
};
struct vfsconf {
uint32_t vfc_reserved1;
char vfc_name[15];
int vfc_typenum;
int vfc_refcount;
int vfc_flags;
uint32_t vfc_reserved2;
uint32_t vfc_reserved3;
};
struct vfsidctl {
int vc_vers;
fsid_t vc_fsid;
void *vc_ptr;
size_t vc_len;
u_int32_t vc_spare[12];
};
struct user_vfsidctl {
int vc_vers;
fsid_t vc_fsid;
user_addr_t vc_ptr ;
user_size_t vc_len;
u_int32_t vc_spare[12];
};
struct user32_vfsidctl {
int vc_vers;
fsid_t vc_fsid;
user32_addr_t vc_ptr;
user32_size_t vc_len;
u_int32_t vc_spare[12];
};
union union_vfsidctl {
struct user32_vfsidctl vc32;
struct user_vfsidctl vc64;
};
struct vfsquery {
u_int32_t vq_flags;
u_int32_t vq_spare[31];
};
struct vfs_server {
int32_t vs_minutes;
u_int8_t vs_server_name[256*3];
};
struct netfs_status {
u_int32_t ns_status;
char ns_mountopts[512];
uint32_t ns_waittime;
uint32_t ns_threadcount;
uint64_t ns_threadids[0];
};
struct vfsioattr {
u_int32_t io_maxreadcnt;
u_int32_t io_maxwritecnt;
u_int32_t io_segreadcnt;
u_int32_t io_segwritecnt;
u_int32_t io_maxsegreadsize;
u_int32_t io_maxsegwritesize;
u_int32_t io_devblocksize;
u_int32_t io_flags;
union {
int64_t io_max_swappin_available;
void *io_reserved[2];
};
};
struct vfs_fsentry {
struct vfsops * vfe_vfsops;
int vfe_vopcnt;
struct vnodeopv_desc ** vfe_opvdescs;
int vfe_fstypenum;
char vfe_fsname[15];
uint32_t vfe_flags;
void * vfe_reserv[2];
};
struct vfsops {
int (*vfs_mount)(struct mount *mp, vnode_t devvp, user_addr_t data, vfs_context_t context);
int (*vfs_start)(struct mount *mp, int flags, vfs_context_t context);
int (*vfs_unmount)(struct mount *mp, int mntflags, vfs_context_t context);
int (*vfs_root)(struct mount *mp, struct vnode **vpp, vfs_context_t context);
int (*vfs_quotactl)(struct mount *mp, int cmds, uid_t uid, caddr_t arg, vfs_context_t context);
int (*vfs_getattr)(struct mount *mp, struct vfs_attr *, vfs_context_t context);
int (*vfs_sync)(struct mount *mp, int waitfor, vfs_context_t context);
int (*vfs_vget)(struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);
int (*vfs_fhtovp)(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp,
vfs_context_t context);
int (*vfs_vptofh)(struct vnode *vp, int *fhlen, unsigned char *fhp, vfs_context_t context);
int (*vfs_init)(struct vfsconf *);
int (*vfs_sysctl)(int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t context);
int (*vfs_setattr)(struct mount *mp, struct vfs_attr *, vfs_context_t context);
int (*vfs_ioctl)(struct mount *mp, u_long command, caddr_t data,
int flags, vfs_context_t context);
int (*vfs_vget_snapdir)(struct mount *mp, struct vnode **vpp, vfs_context_t context);
void *vfs_reserved5;
void *vfs_reserved4;
void *vfs_reserved3;
void *vfs_reserved2;
void *vfs_reserved1;
};
struct fs_snapshot_mount_args {
mount_t sm_mp;
struct componentname *sm_cnp;
};
struct fs_snapshot_revert_args {
struct componentname *sr_cnp;
};
struct fs_snapshot_root_args {
struct componentname *sr_cnp;
};
int vfs_fsadd(struct vfs_fsentry *vfe, vfstable_t *handle);
int vfs_fsremove(vfstable_t handle);
int vfs_iterate(int flags, int (*callout)(struct mount *, void *), void *arg);
int vfs_init_io_attributes(vnode_t devvp, mount_t mp);
uint64_t vfs_flags(mount_t mp);
void vfs_setflags(mount_t mp, uint64_t flags);
void vfs_clearflags(mount_t mp, uint64_t flags);
int vfs_issynchronous(mount_t mp);
int vfs_iswriteupgrade(mount_t mp);
int vfs_isupdate(mount_t mp);
int vfs_isreload(mount_t mp);
int vfs_isforce(mount_t mp);
int vfs_isunmount(mount_t mp);
int vfs_isrdonly(mount_t mp);
int vfs_isrdwr(mount_t mp);
int vfs_authopaque(mount_t mp);
int vfs_authopaqueaccess(mount_t mp);
void vfs_setauthopaque(mount_t mp);
void vfs_setauthopaqueaccess(mount_t mp);
void vfs_clearauthopaque(mount_t mp);
void vfs_clearauthopaqueaccess(mount_t mp);
void vfs_setextendedsecurity(mount_t mp);
void vfs_clearextendedsecurity(mount_t mp);
void vfs_setnoswap(mount_t mp);
void vfs_clearnoswap(mount_t mp);
void vfs_setlocklocal(mount_t mp);
int vfs_authcache_ttl(mount_t mp);
void vfs_setauthcache_ttl(mount_t mp, int ttl);
void vfs_clearauthcache_ttl(mount_t mp);
uint32_t vfs_maxsymlen(mount_t mp);
void vfs_setmaxsymlen(mount_t mp, uint32_t symlen);
void * vfs_fsprivate(mount_t mp);
void vfs_setfsprivate(mount_t mp, void *mntdata);
struct vfsstatfs * vfs_statfs(mount_t mp);
int vfs_update_vfsstat(mount_t mp, vfs_context_t ctx, int eventtype);
int vfs_typenum(mount_t mp);
void vfs_name(mount_t mp, char *buffer);
int vfs_devblocksize(mount_t mp);
void vfs_ioattr(mount_t mp, struct vfsioattr *ioattrp);
void vfs_setioattr(mount_t mp, struct vfsioattr *ioattrp);
int vfs_64bitready(mount_t mp);
int vfs_busy(mount_t mp, int flags);
void vfs_unbusy(mount_t mp);
void vfs_getnewfsid(struct mount *mp);
mount_t vfs_getvfs(fsid_t *fsid);
int vfs_mountedon(struct vnode *vp);
int vfs_unmountbyfsid(fsid_t *fsid, int flags, vfs_context_t ctx);
void vfs_event_signal(fsid_t *fsid, u_int32_t event, intptr_t data);
void vfs_event_init(void);
void vfs_set_root_unmounted_cleanly(void);
enum vtype {
VNON,
VREG, VDIR, VBLK, VCHR, VLNK,
VSOCK, VFIFO, VBAD, VSTR, VCPLX
};
enum vtagtype {
VT_NON,
VT_UFS,
VT_NFS, VT_MFS, VT_MSDOSFS, VT_LFS,
VT_LOFS, VT_FDESC, VT_PORTAL, VT_NULL, VT_UMAP,
VT_KERNFS, VT_PROCFS, VT_AFS, VT_ISOFS, VT_MOCKFS,
VT_HFS, VT_ZFS, VT_DEVFS, VT_WEBDAV, VT_UDF,
VT_AFP, VT_CDDA, VT_CIFS, VT_OTHER, VT_APFS
};
struct componentname {
uint32_t cn_nameiop;
uint32_t cn_flags;
void * cn_reserved1;
void * cn_reserved2;
char *cn_pnbuf;
int cn_pnlen;
char *cn_nameptr;
int cn_namelen;
uint32_t cn_hash;
uint32_t cn_consume;
};
struct vnode_fsparam {
struct mount * vnfs_mp;
enum vtype vnfs_vtype;
const char * vnfs_str;
struct vnode * vnfs_dvp;
void * vnfs_fsnode;
int (**vnfs_vops)(void *);
int vnfs_markroot;
int vnfs_marksystem;
dev_t vnfs_rdev;
off_t vnfs_filesize;
struct componentname * vnfs_cnp;
uint32_t vnfs_flags;
};
struct vnode_attr {
uint64_t va_supported;
uint64_t va_active;
int va_vaflags;
dev_t va_rdev;
uint64_t va_nlink;
uint64_t va_total_size;
uint64_t va_total_alloc;
uint64_t va_data_size;
uint64_t va_data_alloc;
uint32_t va_iosize;
uid_t va_uid;
gid_t va_gid;
mode_t va_mode;
uint32_t va_flags;
struct kauth_acl *va_acl;
struct timespec va_create_time;
struct timespec va_access_time;
struct timespec va_modify_time;
struct timespec va_change_time;
struct timespec va_backup_time;
uint64_t va_fileid;
uint64_t va_linkid;
uint64_t va_parentid;
uint32_t va_fsid;
uint64_t va_filerev;
uint32_t va_gen;
uint32_t va_encoding;
enum vtype va_type;
char * va_name;
guid_t va_uuuid;
guid_t va_guuid;
uint64_t va_nchildren;
uint64_t va_dirlinkcount;
void * va_reserved1;
struct timespec va_addedtime;
uint32_t va_dataprotect_class;
uint32_t va_dataprotect_flags;
uint32_t va_document_id;
uint32_t va_devid;
uint32_t va_objtype;
uint32_t va_objtag;
uint32_t va_user_access;
uint8_t va_finderinfo[32];
uint64_t va_rsrc_length;
uint64_t va_rsrc_alloc;
fsid_t va_fsid64;
uint32_t va_write_gencount;
uint64_t va_private_size;
};
extern enum vtype iftovt_tab[];
extern int vttoif_tab[];
struct vnodeop_desc;
extern int desiredvnodes;
struct vnodeopv_entry_desc {
struct vnodeop_desc *opve_op;
int (*opve_impl)(void *);
};
struct vnodeopv_desc {
int (***opv_desc_vector_p)(void *);
struct vnodeopv_entry_desc *opv_desc_ops;
};
int vn_default_error(void);
struct vnop_generic_args {
struct vnodeop_desc *a_desc;
};
void buf_markaged(buf_t bp);
void buf_markinvalid(buf_t bp);
void buf_markdelayed(buf_t bp);
void buf_markclean(buf_t);
void buf_markeintr(buf_t bp);
void buf_markfua(buf_t bp);
int buf_fua(buf_t bp);
int buf_valid(buf_t bp);
int buf_fromcache(buf_t bp);
void * buf_upl(buf_t bp);
uint32_t buf_uploffset(buf_t bp);
kauth_cred_t buf_rcred(buf_t bp);
kauth_cred_t buf_wcred(buf_t bp);
proc_t buf_proc(buf_t bp);
uint32_t buf_dirtyoff(buf_t bp);
uint32_t buf_dirtyend(buf_t bp);
void buf_setdirtyoff(buf_t bp, uint32_t);
void buf_setdirtyend(buf_t bp, uint32_t);
errno_t buf_error(buf_t bp);
void buf_seterror(buf_t bp, errno_t);
void buf_setflags(buf_t bp, int32_t flags);
void buf_clearflags(buf_t bp, int32_t flags);
int32_t buf_flags(buf_t bp);
void buf_reset(buf_t bp, int32_t flags);
errno_t buf_map(buf_t bp, caddr_t *io_addr);
errno_t buf_unmap(buf_t bp);
void buf_setdrvdata(buf_t bp, void *drvdata);
void * buf_drvdata(buf_t bp);
void buf_setfsprivate(buf_t bp, void *fsprivate);
void * buf_fsprivate(buf_t bp);
daddr64_t buf_blkno(buf_t bp);
daddr64_t buf_lblkno(buf_t bp);
void buf_setblkno(buf_t bp, daddr64_t blkno);
void buf_setlblkno(buf_t bp, daddr64_t lblkno);
uint32_t buf_count(buf_t bp);
uint32_t buf_size(buf_t bp);
uint32_t buf_resid(buf_t bp);
void buf_setcount(buf_t bp, uint32_t bcount);
void buf_setsize(buf_t bp, uint32_t);
void buf_setresid(buf_t bp, uint32_t resid);
void buf_setdataptr(buf_t bp, uintptr_t data);
uintptr_t buf_dataptr(buf_t bp);
vnode_t buf_vnode(buf_t bp);
void buf_setvnode(buf_t bp, vnode_t vp);
dev_t buf_device(buf_t bp);
errno_t buf_setdevice(buf_t bp, vnode_t vp);
errno_t buf_strategy(vnode_t devvp, void *ap);
errno_t buf_invalblkno(vnode_t vp, daddr64_t lblkno, int flags);
void * buf_callback(buf_t bp);
errno_t buf_setcallback(buf_t bp, void (*callback)(buf_t, void *), void *transaction);
errno_t buf_setupl(buf_t bp, upl_t upl, uint32_t offset);
buf_t buf_clone(buf_t bp, int io_offset, int io_size, void (*iodone)(buf_t, void *), void *arg);
buf_t buf_create_shadow(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg);
int buf_shadow(buf_t bp);
buf_t buf_alloc(vnode_t vp);
void buf_free(buf_t bp);
int buf_invalidateblks(vnode_t vp, int flags, int slpflag, int slptimeo);
void buf_flushdirtyblks(vnode_t vp, int wait, int flags, const char *msg);
void buf_iterate(vnode_t vp, int (*callout)(buf_t, void *), int flags, void *arg);
void buf_clear(buf_t bp);
errno_t buf_bawrite(buf_t bp);
errno_t buf_bdwrite(buf_t bp);
errno_t buf_bwrite(buf_t bp);
void buf_biodone(buf_t bp);
errno_t buf_biowait(buf_t bp);
void buf_brelse(buf_t bp);
errno_t buf_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp);
errno_t buf_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp);
errno_t buf_meta_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp);
errno_t buf_meta_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp);
u_int minphys(buf_t bp);
int physio(void (*f_strategy)(buf_t), buf_t bp, dev_t dev, int flags, u_int (*f_minphys)(buf_t), struct uio *uio, int blocksize);
buf_t buf_getblk(vnode_t vp, daddr64_t blkno, int size, int slpflag, int slptimeo, int operation);
buf_t buf_geteblk(int size);
void buf_clear_redundancy_flags(buf_t bp, uint32_t flags);
uint32_t buf_redundancy_flags(buf_t bp);
void buf_set_redundancy_flags(buf_t bp, uint32_t flags);
bufattr_t buf_attr(buf_t bp);
void buf_markstatic(buf_t bp);
int buf_static(buf_t bp);
extern struct vnodeop_desc vnop_default_desc;
extern struct vnodeop_desc vnop_lookup_desc;
extern struct vnodeop_desc vnop_create_desc;
extern struct vnodeop_desc vnop_whiteout_desc;
extern struct vnodeop_desc vnop_mknod_desc;
extern struct vnodeop_desc vnop_open_desc;
extern struct vnodeop_desc vnop_close_desc;
extern struct vnodeop_desc vnop_access_desc;
extern struct vnodeop_desc vnop_getattr_desc;
extern struct vnodeop_desc vnop_setattr_desc;
extern struct vnodeop_desc vnop_read_desc;
extern struct vnodeop_desc vnop_write_desc;
extern struct vnodeop_desc vnop_ioctl_desc;
extern struct vnodeop_desc vnop_select_desc;
extern struct vnodeop_desc vnop_exchange_desc;
extern struct vnodeop_desc vnop_revoke_desc;
extern struct vnodeop_desc vnop_mmap_desc;
extern struct vnodeop_desc vnop_mnomap_desc;
extern struct vnodeop_desc vnop_fsync_desc;
extern struct vnodeop_desc vnop_remove_desc;
extern struct vnodeop_desc vnop_link_desc;
extern struct vnodeop_desc vnop_rename_desc;
extern struct vnodeop_desc vnop_renamex_desc;
extern struct vnodeop_desc vnop_mkdir_desc;
extern struct vnodeop_desc vnop_rmdir_desc;
extern struct vnodeop_desc vnop_symlink_desc;
extern struct vnodeop_desc vnop_readdir_desc;
extern struct vnodeop_desc vnop_readdirattr_desc;
extern struct vnodeop_desc vnop_getattrlistbulk_desc;
extern struct vnodeop_desc vnop_readlink_desc;
extern struct vnodeop_desc vnop_inactive_desc;
extern struct vnodeop_desc vnop_reclaim_desc;
extern struct vnodeop_desc vnop_print_desc;
extern struct vnodeop_desc vnop_pathconf_desc;
extern struct vnodeop_desc vnop_advlock_desc;
extern struct vnodeop_desc vnop_truncate_desc;
extern struct vnodeop_desc vnop_allocate_desc;
extern struct vnodeop_desc vnop_pagein_desc;
extern struct vnodeop_desc vnop_pageout_desc;
extern struct vnodeop_desc vnop_searchfs_desc;
extern struct vnodeop_desc vnop_copyfile_desc;
extern struct vnodeop_desc vnop_clonefile_desc;
extern struct vnodeop_desc vnop_blktooff_desc;
extern struct vnodeop_desc vnop_offtoblk_desc;
extern struct vnodeop_desc vnop_blockmap_desc;
extern struct vnodeop_desc vnop_strategy_desc;
extern struct vnodeop_desc vnop_bwrite_desc;
struct vnop_lookup_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
vfs_context_t a_context;
};
struct vnop_create_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
};
struct vnop_whiteout_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
struct componentname *a_cnp;
int a_flags;
vfs_context_t a_context;
};
struct vnop_mknod_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
};
struct vnop_open_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_mode;
vfs_context_t a_context;
};
struct vnop_close_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_fflag;
vfs_context_t a_context;
};
struct vnop_access_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_action;
vfs_context_t a_context;
};
struct vnop_getattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
};
struct vnop_setattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
};
struct vnop_read_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct uio *a_uio;
int a_ioflag;
vfs_context_t a_context;
};
extern errno_t VNOP_READ(vnode_t vp, struct uio *uio, int, vfs_context_t ctx);
struct vnop_write_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct uio *a_uio;
int a_ioflag;
vfs_context_t a_context;
};
extern errno_t VNOP_WRITE(vnode_t vp, struct uio *uio, int ioflag, vfs_context_t ctx);
struct vnop_ioctl_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
u_long a_command;
caddr_t a_data;
int a_fflag;
vfs_context_t a_context;
};
extern errno_t VNOP_IOCTL(vnode_t vp, u_long command, caddr_t data, int fflag, vfs_context_t ctx);
struct vnop_select_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_which;
int a_fflags;
void *a_wql;
vfs_context_t a_context;
};
struct vnop_exchange_args {
struct vnodeop_desc *a_desc;
vnode_t a_fvp;
vnode_t a_tvp;
int a_options;
vfs_context_t a_context;
};
struct vnop_revoke_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_flags;
vfs_context_t a_context;
};
struct vnop_mmap_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_fflags;
vfs_context_t a_context;
};
struct vnop_mnomap_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
vfs_context_t a_context;
};
struct vnop_fsync_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_waitfor;
vfs_context_t a_context;
};
extern errno_t VNOP_FSYNC(vnode_t vp, int waitfor, vfs_context_t ctx);
struct vnop_remove_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t a_vp;
struct componentname *a_cnp;
int a_flags;
vfs_context_t a_context;
};
struct vnop_link_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
vnode_t a_tdvp;
struct componentname *a_cnp;
vfs_context_t a_context;
};
struct vnop_rename_args {
struct vnodeop_desc *a_desc;
vnode_t a_fdvp;
vnode_t a_fvp;
struct componentname *a_fcnp;
vnode_t a_tdvp;
vnode_t a_tvp;
struct componentname *a_tcnp;
vfs_context_t a_context;
};
typedef unsigned int vfs_rename_flags_t;
enum {
VFS_RENAME_SECLUDE = 0x00000001,
VFS_RENAME_SWAP = 0x00000002,
VFS_RENAME_EXCL = 0x00000004,
VFS_RENAME_FLAGS_MASK = (VFS_RENAME_SECLUDE | VFS_RENAME_SWAP
| VFS_RENAME_EXCL),
};
struct vnop_renamex_args {
struct vnodeop_desc *a_desc;
vnode_t a_fdvp;
vnode_t a_fvp;
struct componentname *a_fcnp;
vnode_t a_tdvp;
vnode_t a_tvp;
struct componentname *a_tcnp;
struct vnode_attr *a_vap;
vfs_rename_flags_t a_flags;
vfs_context_t a_context;
};
struct vnop_mkdir_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
struct vnode_attr *a_vap;
vfs_context_t a_context;
};
struct vnop_rmdir_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t a_vp;
struct componentname *a_cnp;
vfs_context_t a_context;
};
struct vnop_symlink_args {
struct vnodeop_desc *a_desc;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
struct vnode_attr *a_vap;
char *a_target;
vfs_context_t a_context;
};
struct vnop_readdir_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct uio *a_uio;
int a_flags;
int *a_eofflag;
int *a_numdirent;
vfs_context_t a_context;
};
struct vnop_readdirattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct attrlist *a_alist;
struct uio *a_uio;
uint32_t a_maxcount;
uint32_t a_options;
uint32_t *a_newstate;
int *a_eofflag;
uint32_t *a_actualcount;
vfs_context_t a_context;
};
struct vnop_getattrlistbulk_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct attrlist *a_alist;
struct vnode_attr *a_vap;
struct uio *a_uio;
void *a_private;
uint64_t a_options;
int32_t *a_eofflag;
int32_t *a_actualcount;
vfs_context_t a_context;
};
struct vnop_readlink_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
struct uio *a_uio;
vfs_context_t a_context;
};
struct vnop_inactive_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
vfs_context_t a_context;
};
struct vnop_reclaim_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
vfs_context_t a_context;
};
struct vnop_pathconf_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
int a_name;
int32_t *a_retval;
vfs_context_t a_context;
};
struct vnop_advlock_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
caddr_t a_id;
int a_op;
struct flock *a_fl;
int a_flags;
vfs_context_t a_context;
struct timespec *a_timeout;
};
struct vnop_allocate_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
off_t a_length;
u_int32_t a_flags;
off_t *a_bytesallocated;
off_t a_offset;
vfs_context_t a_context;
};
struct vnop_pagein_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
upl_t a_pl;
upl_offset_t a_pl_offset;
off_t a_f_offset;
size_t a_size;
int a_flags;
vfs_context_t a_context;
};
struct vnop_pageout_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
upl_t a_pl;
upl_offset_t a_pl_offset;
off_t a_f_offset;
size_t a_size;
int a_flags;
vfs_context_t a_context;
};
struct vnop_searchfs_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
void *a_searchparams1;
void *a_searchparams2;
struct attrlist *a_searchattrs;
uint32_t a_maxmatches;
struct timeval *a_timelimit;
struct attrlist *a_returnattrs;
uint32_t *a_nummatches;
uint32_t a_scriptcode;
uint32_t a_options;
struct uio *a_uio;
struct searchstate *a_searchstate;
vfs_context_t a_context;
};
struct vnop_copyfile_args {
struct vnodeop_desc *a_desc;
vnode_t a_fvp;
vnode_t a_tdvp;
vnode_t a_tvp;
struct componentname *a_tcnp;
int a_mode;
int a_flags;
vfs_context_t a_context;
};
typedef enum dir_clone_authorizer_op {
OP_AUTHORIZE = 0,
OP_VATTR_SETUP = 1,
OP_VATTR_CLEANUP = 2
} dir_clone_authorizer_op_t;
struct vnop_clonefile_args {
struct vnodeop_desc *a_desc;
vnode_t a_fvp;
vnode_t a_dvp;
vnode_t *a_vpp;
struct componentname *a_cnp;
struct vnode_attr *a_vap;
uint32_t a_flags;
vfs_context_t a_context;
int (*a_dir_clone_authorizer)(
struct vnode_attr *vap,
kauth_action_t action,
struct vnode_attr *dvap,
vnode_t sdvp,
mount_t mp,
dir_clone_authorizer_op_t vattr_op,
uint32_t flags,
vfs_context_t ctx,
void *reserved);
void *a_reserved;
};
struct vnop_getxattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
const char * a_name;
uio_t a_uio;
size_t *a_size;
int a_options;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_getxattr_desc;
extern errno_t VNOP_GETXATTR(vnode_t vp, const char *name, uio_t uio, size_t *size, int options, vfs_context_t ctx);
struct vnop_setxattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
const char * a_name;
uio_t a_uio;
int a_options;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_setxattr_desc;
extern errno_t VNOP_SETXATTR(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t ctx);
struct vnop_removexattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
const char * a_name;
int a_options;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_removexattr_desc;
struct vnop_listxattr_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
uio_t a_uio;
size_t *a_size;
int a_options;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_listxattr_desc;
struct vnop_blktooff_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
daddr64_t a_lblkno;
off_t *a_offset;
};
struct vnop_offtoblk_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
off_t a_offset;
daddr64_t *a_lblkno;
};
struct vnop_blockmap_args {
struct vnodeop_desc *a_desc;
vnode_t a_vp;
off_t a_foffset;
size_t a_size;
daddr64_t *a_bpn;
size_t *a_run;
void *a_poff;
int a_flags;
vfs_context_t a_context;
};
struct vnop_strategy_args {
struct vnodeop_desc *a_desc;
struct buf *a_bp;
};
extern errno_t VNOP_STRATEGY(struct buf *bp);
struct vnop_bwrite_args {
struct vnodeop_desc *a_desc;
buf_t a_bp;
};
extern errno_t VNOP_BWRITE(buf_t bp);
struct vnop_kqfilt_add_args {
struct vnodeop_desc *a_desc;
struct vnode *a_vp;
struct knote *a_kn;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_kqfilt_add_desc;
struct vnop_kqfilt_remove_args {
struct vnodeop_desc *a_desc;
struct vnode *a_vp;
uintptr_t a_ident;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_kqfilt_remove_desc;
struct label;
struct vnop_setlabel_args {
struct vnodeop_desc *a_desc;
struct vnode *a_vp;
struct label *a_vl;
vfs_context_t a_context;
};
extern struct vnodeop_desc vnop_setlabel_desc;
errno_t vnode_create(uint32_t flavor, uint32_t size, void *data, vnode_t *vpp);
int vnode_addfsref(vnode_t vp);
int vnode_removefsref(vnode_t vp);
int vnode_hasdirtyblks(vnode_t vp);
int vnode_hascleanblks(vnode_t vp);
int vnode_waitforwrites(vnode_t vp, int output_target, int slpflag, int slptimeout, const char *msg);
void vnode_startwrite(vnode_t vp);
void vnode_writedone(vnode_t vp);
enum vtype vnode_vtype(vnode_t vp);
uint32_t vnode_vid(vnode_t vp);
mount_t vnode_mountedhere(vnode_t vp);
mount_t vnode_mount(vnode_t vp);
dev_t vnode_specrdev(vnode_t vp);
void * vnode_fsnode(vnode_t vp);
void vnode_clearfsnode(vnode_t vp);
int vnode_isvroot(vnode_t vp);
int vnode_issystem(vnode_t vp);
int vnode_ismount(vnode_t vp);
int vnode_isreg(vnode_t vp);
int vnode_isdir(vnode_t vp);
int vnode_islnk(vnode_t vp);
int vnode_isfifo(vnode_t vp);
int vnode_isblk(vnode_t vp);
int vnode_ischr(vnode_t vp);
int vnode_isswap(vnode_t vp);
int vnode_isnamedstream(vnode_t vp);
int vnode_ismountedon(vnode_t vp);
void vnode_setmountedon(vnode_t vp);
void vnode_clearmountedon(vnode_t vp);
int vnode_isrecycled(vnode_t vp);
int vnode_isnocache(vnode_t vp);
int vnode_israge(vnode_t vp);
int vnode_needssnapshots(vnode_t vp);
void vnode_setnocache(vnode_t vp);
void vnode_clearnocache(vnode_t vp);
int vnode_isnoreadahead(vnode_t vp);
void vnode_setnoreadahead(vnode_t vp);
void vnode_clearnoreadahead(vnode_t vp);
int vnode_isfastdevicecandidate(vnode_t vp);
void vnode_setfastdevicecandidate(vnode_t vp);
void vnode_clearfastdevicecandidate(vnode_t vp);
int vnode_isautocandidate(vnode_t vp);
void vnode_setautocandidate(vnode_t vp);
void vnode_clearautocandidate(vnode_t vp);
void vnode_settag(vnode_t vp, int tag);
int vnode_tag(vnode_t vp);
int vnode_getattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx);
int vnode_setattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx);
vnode_t vfs_rootvnode(void);
void vnode_uncache_credentials(vnode_t vp);
void vnode_setmultipath(vnode_t vp);
uint32_t vnode_vfsmaxsymlen(vnode_t vp);
int vnode_vfsisrdonly(vnode_t vp);
int vnode_vfstypenum(vnode_t vp);
void vnode_vfsname(vnode_t vp, char *buf);
int vnode_vfs64bitready(vnode_t vp);
int vfs_context_get_special_port(vfs_context_t, int, ipc_port_t *);
int vfs_context_set_special_port(vfs_context_t, int, ipc_port_t);
proc_t vfs_context_proc(vfs_context_t ctx);
kauth_cred_t vfs_context_ucred(vfs_context_t ctx);
int vfs_context_pid(vfs_context_t ctx);
int vfs_context_issignal(vfs_context_t ctx, sigset_t mask);
int vfs_context_suser(vfs_context_t ctx);
int vfs_context_is64bit(vfs_context_t ctx);
vfs_context_t vfs_context_create(vfs_context_t ctx);
int vfs_context_rele(vfs_context_t ctx);
vfs_context_t vfs_context_current(void);
int vflush(struct mount *mp, struct vnode *skipvp, int flags);
int vnode_get(vnode_t);
int vnode_getwithvid(vnode_t, uint32_t);
int vnode_getwithref(vnode_t vp);
int vnode_put(vnode_t vp);
int vnode_ref(vnode_t vp);
void vnode_rele(vnode_t vp);
int vnode_isinuse(vnode_t vp, int refcnt);
int vnode_recycle(vnode_t vp);
void vnode_update_identity(vnode_t vp, vnode_t dvp, const char *name, int name_len, uint32_t name_hashval, int flags);
int vn_bwrite(struct vnop_bwrite_args *ap);
int vnode_authorize(vnode_t vp, vnode_t dvp, kauth_action_t action, vfs_context_t ctx);
int vnode_authattr(vnode_t vp, struct vnode_attr *vap, kauth_action_t *actionp, vfs_context_t ctx);
int vnode_authattr_new(vnode_t dvp, struct vnode_attr *vap, int noauth, vfs_context_t ctx);
errno_t vnode_close(vnode_t vp, int flags, vfs_context_t ctx);
int vn_getpath(struct vnode *vp, char *pathbuf, int *len);
int vnode_notify(vnode_t vp, uint32_t events, struct vnode_attr *vap);
int vfs_get_notify_attributes(struct vnode_attr *vap);
errno_t vnode_lookup(const char *path, int flags, vnode_t *vpp, vfs_context_t ctx);
errno_t vnode_open(const char *path, int fmode, int cmode, int flags, vnode_t *vpp, vfs_context_t ctx);
int vnode_iterate(struct mount *mp, int flags, int (*callout)(struct vnode *, void *), void *arg);
int vn_revoke(vnode_t vp, int flags, vfs_context_t ctx);
int cache_lookup(vnode_t dvp, vnode_t *vpp, struct componentname *cnp);
void cache_enter(vnode_t dvp, vnode_t vp, struct componentname *cnp);
void cache_purge(vnode_t vp);
void cache_purge_negatives(vnode_t vp);
const char *vfs_addname(const char *name, uint32_t len, uint32_t nc_hash, uint32_t flags);
int vfs_removename(const char *name);
int vcount(vnode_t vp);
int vn_path_package_check(vnode_t vp, char *path, int pathlen, int *component);
int vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, int len, off_t offset, enum uio_seg segflg, int ioflg, kauth_cred_t cred, int *aresid, proc_t p);
const char *vnode_getname(vnode_t vp);
void vnode_putname(const char *name);
vnode_t vnode_getparent(vnode_t vp);
int vnode_setdirty(vnode_t vp);
int vnode_cleardirty(vnode_t vp);
int vnode_isdirty(vnode_t vp);
errno_t vfs_setup_vattr_from_attrlist(struct attrlist *alp, struct vnode_attr *vap, enum vtype obj_vtype, ssize_t *attr_fixed_sizep, vfs_context_t ctx);
errno_t vfs_attr_pack(vnode_t vp, uio_t uio, struct attrlist *alp, uint64_t options, struct vnode_attr *vap, void *fndesc, vfs_context_t ctx);
struct dirent {
ino_t d_ino;
__uint16_t d_reclen;
__uint8_t d_type;
__uint8_t d_namlen;
char d_name[255 + 1];
};
struct direntry { __uint64_t d_ino; __uint64_t d_seekoff; __uint16_t d_reclen; __uint16_t d_namlen; __uint8_t d_type; char d_name[1024]; };
extern int nop_create(struct vnop_create_args *ap);
extern int err_create(struct vnop_create_args *ap);
extern int nop_whiteout(struct vnop_whiteout_args *ap);
extern int err_whiteout(struct vnop_whiteout_args *ap);
extern int nop_mknod(struct vnop_mknod_args *ap);
extern int err_mknod(struct vnop_mknod_args *ap);
extern int nop_open(struct vnop_open_args *ap);
extern int err_open(struct vnop_open_args *ap);
extern int nop_close(struct vnop_close_args *ap);
extern int err_close(struct vnop_close_args *ap);
extern int nop_access(struct vnop_access_args *ap);
extern int err_access(struct vnop_access_args *ap);
extern int nop_getattr(struct vnop_getattr_args *ap);
extern int err_getattr(struct vnop_getattr_args *ap);
extern int nop_setattr(struct vnop_setattr_args *ap);
extern int err_setattr(struct vnop_setattr_args *ap);
extern int nop_read(struct vnop_read_args *ap);
extern int err_read(struct vnop_read_args *ap);
extern int nop_write(struct vnop_write_args *ap);
extern int err_write(struct vnop_write_args *ap);
extern int nop_ioctl(struct vnop_ioctl_args *ap);
extern int err_ioctl(struct vnop_ioctl_args *ap);
extern int nop_select(struct vnop_select_args *ap);
extern int err_select(struct vnop_select_args *ap);
extern int nop_exchange(struct vnop_exchange_args *ap);
extern int err_exchange(struct vnop_exchange_args *ap);
extern int nop_revoke(struct vnop_revoke_args *ap);
extern int err_revoke(struct vnop_revoke_args *ap);
extern int nop_mmap(struct vnop_mmap_args *ap);
extern int err_mmap(struct vnop_mmap_args *ap);
extern int nop_fsync(struct vnop_fsync_args *ap);
extern int err_fsync(struct vnop_fsync_args *ap);
extern int nop_remove(struct vnop_remove_args *ap);
extern int err_remove(struct vnop_remove_args *ap);
extern int nop_link(struct vnop_link_args *ap);
extern int err_link(struct vnop_link_args *ap);
extern int nop_rename(struct vnop_rename_args *ap);
extern int err_rename(struct vnop_rename_args *ap);
extern int nop_mkdir(struct vnop_mkdir_args *ap);
extern int err_mkdir(struct vnop_mkdir_args *ap);
extern int nop_rmdir(struct vnop_rmdir_args *ap);
extern int err_rmdir(struct vnop_rmdir_args *ap);
extern int nop_symlink(struct vnop_symlink_args *ap);
extern int err_symlink(struct vnop_symlink_args *ap);
extern int nop_readdir(struct vnop_readdir_args *ap);
extern int err_readdir(struct vnop_readdir_args *ap);
extern int nop_readdirattr(struct vnop_readdirattr_args *ap);
extern int err_readdirattr(struct vnop_readdirattr_args *ap);
extern int nop_readlink(struct vnop_readlink_args *ap);
extern int err_readlink(struct vnop_readlink_args *ap);
extern int nop_inactive(struct vnop_inactive_args *ap);
extern int err_inactive(struct vnop_inactive_args *ap);
extern int nop_reclaim(struct vnop_reclaim_args *ap);
extern int err_reclaim(struct vnop_reclaim_args *ap);
extern int nop_strategy(struct vnop_strategy_args *ap);
extern int err_strategy(struct vnop_strategy_args *ap);
extern int nop_pathconf(struct vnop_pathconf_args *ap);
extern int err_pathconf(struct vnop_pathconf_args *ap);
extern int nop_advlock(struct vnop_advlock_args *ap);
extern int err_advlock(struct vnop_advlock_args *ap);
extern int nop_allocate(struct vnop_allocate_args *ap);
extern int err_allocate(struct vnop_allocate_args *ap);
extern int nop_bwrite(struct vnop_bwrite_args *ap);
extern int err_bwrite(struct vnop_bwrite_args *ap);
extern int nop_pagein(struct vnop_pagein_args *ap);
extern int err_pagein(struct vnop_pagein_args *ap);
extern int nop_pageout(struct vnop_pageout_args *ap);
extern int err_pageout(struct vnop_pageout_args *ap);
extern int nop_searchfs(struct vnop_searchfs_args *ap);
extern int err_searchfs(struct vnop_searchfs_args *ap);
extern int nop_copyfile(struct vnop_copyfile_args *ap);
extern int err_copyfile(struct vnop_copyfile_args *ap);
extern int nop_blktooff(struct vnop_blktooff_args *ap);
extern int err_blktooff(struct vnop_blktooff_args *ap);
extern int nop_offtoblk(struct vnop_offtoblk_args *ap);
extern int err_offtoblk(struct vnop_offtoblk_args *ap);
extern int nop_blockmap(struct vnop_blockmap_args *ap);
extern int err_blockmap(struct vnop_blockmap_args *ap);
enum {
CSMAGIC_REQUIREMENT = 0xfade0c00,
CSMAGIC_REQUIREMENTS = 0xfade0c01,
CSMAGIC_CODEDIRECTORY = 0xfade0c02,
CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0,
CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02,
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171,
CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1,
CSMAGIC_BLOBWRAPPER = 0xfade0b01,
CS_SUPPORTSSCATTER = 0x20100,
CS_SUPPORTSTEAMID = 0x20200,
CS_SUPPORTSCODELIMIT64 = 0x20300,
CS_SUPPORTSEXECSEG = 0x20400,
CSSLOT_CODEDIRECTORY = 0,
CSSLOT_INFOSLOT = 1,
CSSLOT_REQUIREMENTS = 2,
CSSLOT_RESOURCEDIR = 3,
CSSLOT_APPLICATION = 4,
CSSLOT_ENTITLEMENTS = 5,
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000,
CSSLOT_ALTERNATE_CODEDIRECTORY_MAX = 5,
CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX,
CSSLOT_SIGNATURESLOT = 0x10000,
CSTYPE_INDEX_REQUIREMENTS = 0x00000002,
CSTYPE_INDEX_ENTITLEMENTS = 0x00000005,
CS_HASHTYPE_SHA1 = 1,
CS_HASHTYPE_SHA256 = 2,
CS_HASHTYPE_SHA256_TRUNCATED = 3,
CS_HASHTYPE_SHA384 = 4,
CS_SHA1_LEN = 20,
CS_SHA256_LEN = 32,
CS_SHA256_TRUNCATED_LEN = 20,
CS_CDHASH_LEN = 20,
CS_HASH_MAX_SIZE = 48,
CS_SIGNER_TYPE_UNKNOWN = 0,
CS_SIGNER_TYPE_LEGACYVPN = 5,
};
typedef struct __CodeDirectory {
uint32_t magic;
uint32_t length;
uint32_t version;
uint32_t flags;
uint32_t hashOffset;
uint32_t identOffset;
uint32_t nSpecialSlots;
uint32_t nCodeSlots;
uint32_t codeLimit;
uint8_t hashSize;
uint8_t hashType;
uint8_t platform;
uint8_t pageSize;
uint32_t spare2;
char end_earliest[0];
uint32_t scatterOffset;
char end_withScatter[0];
uint32_t teamOffset;
char end_withTeam[0];
uint32_t spare3;
uint64_t codeLimit64;
char end_withCodeLimit64[0];
uint64_t execSegBase;
uint64_t execSegLimit;
uint64_t execSegFlags;
char end_withExecSeg[0];
} CS_CodeDirectory
;
typedef struct __BlobIndex {
uint32_t type;
uint32_t offset;
} CS_BlobIndex
;
typedef struct __SC_SuperBlob {
uint32_t magic;
uint32_t length;
uint32_t count;
CS_BlobIndex index[];
} CS_SuperBlob
;
typedef struct __SC_GenericBlob {
uint32_t magic;
uint32_t length;
char data[];
} CS_GenericBlob
;
typedef struct __SC_Scatter {
uint32_t count;
uint32_t base;
uint64_t targetOffset;
uint64_t spare;
} SC_Scatter
;
struct thread_group;
typedef struct thread_group *thread_group_t;
extern task_t current_task(void);
extern void task_reference(task_t task);
extern task_t kernel_task;
extern void task_deallocate(
task_t task);
extern void task_name_deallocate(
task_name_t task_name);
extern void task_inspect_deallocate(
task_inspect_t task_inspect);
extern void task_suspension_token_deallocate(
task_suspension_token_t token);
extern void extmod_statistics_incr_task_for_pid(task_t target);
extern void extmod_statistics_incr_thread_set_state(thread_t target);
extern void extmod_statistics_incr_thread_create(task_t target);
struct mach_timebase_info {
uint32_t numer;
uint32_t denom;
};
typedef struct mach_timebase_info *mach_timebase_info_t;
typedef struct mach_timebase_info mach_timebase_info_data_t;
uint64_t mach_absolute_time(void);

uint64_t mach_approximate_time(void);
   
uint64_t mach_continuous_time(void);
   
uint64_t mach_continuous_approximate_time(void);
typedef unsigned long clock_sec_t;
typedef unsigned int clock_usec_t, clock_nsec_t;
extern void clock_get_calendar_microtime(
clock_sec_t *secs,
clock_usec_t *microsecs);
extern void clock_get_calendar_absolute_and_microtime(
clock_sec_t *secs,
clock_usec_t *microsecs,
uint64_t *abstime);
extern void clock_get_calendar_nanotime(
clock_sec_t *secs,
clock_nsec_t *nanosecs);
extern void clock_get_system_microtime(
clock_sec_t *secs,
clock_usec_t *microsecs);
extern void clock_get_system_nanotime(
clock_sec_t *secs,
clock_nsec_t *nanosecs);
extern void clock_timebase_info(
mach_timebase_info_t info);
extern void clock_get_uptime(
uint64_t *result);
extern void clock_interval_to_deadline(
uint32_t interval,
uint32_t scale_factor,
uint64_t *result);
extern void clock_interval_to_absolutetime_interval(
uint32_t interval,
uint32_t scale_factor,
uint64_t *result);
extern void clock_absolutetime_interval_to_deadline(
uint64_t abstime,
uint64_t *result);
extern void clock_continuoustime_interval_to_deadline(
uint64_t abstime,
uint64_t *result);
extern void clock_delay_until(
uint64_t deadline);
extern void absolutetime_to_nanoseconds(
uint64_t abstime,
uint64_t *result);
extern void nanoseconds_to_absolutetime(
uint64_t nanoseconds,
uint64_t *result);
extern uint64_t absolutetime_to_continuoustime(
uint64_t abstime);
extern uint64_t continuoustime_to_absolutetime(
uint64_t conttime);
extern uint64_t mach_absolutetime_asleep;
extern uint64_t mach_absolutetime_last_sleep;
struct thread_call;
typedef struct thread_call *thread_call_t;
typedef void *thread_call_param_t;
typedef void (*thread_call_func_t)(
thread_call_param_t param0,
thread_call_param_t param1);
typedef enum {
THREAD_CALL_PRIORITY_HIGH = 0,
THREAD_CALL_PRIORITY_KERNEL = 1,
THREAD_CALL_PRIORITY_USER = 2,
THREAD_CALL_PRIORITY_LOW = 3,
THREAD_CALL_PRIORITY_KERNEL_HIGH = 4
} thread_call_priority_t;
enum {
THREAD_CALL_OPTIONS_ONCE = 0x00000001,
};
typedef uint32_t thread_call_options_t;
extern boolean_t thread_call_enter(
thread_call_t call);
extern boolean_t thread_call_enter1(
thread_call_t call,
thread_call_param_t param1);
extern boolean_t thread_call_enter_delayed(
thread_call_t call,
uint64_t deadline);
extern boolean_t thread_call_enter1_delayed(
thread_call_t call,
thread_call_param_t param1,
uint64_t deadline);
extern boolean_t thread_call_cancel(
thread_call_t call);
extern boolean_t thread_call_cancel_wait(
thread_call_t call);
extern thread_call_t thread_call_allocate(
thread_call_func_t func,
thread_call_param_t param0);
extern thread_call_t thread_call_allocate_with_priority(
thread_call_func_t func,
thread_call_param_t param0,
thread_call_priority_t pri);
extern thread_call_t thread_call_allocate_with_options(
thread_call_func_t func,
thread_call_param_t param0,
thread_call_priority_t pri,
thread_call_options_t options);
extern boolean_t thread_call_free(
thread_call_t call);
boolean_t thread_call_isactive(
thread_call_t call);
extern host_t host_self(void);
extern host_priv_t host_priv_self(void);
extern host_security_t host_security_self(void);
extern void pset_deallocate(
processor_set_t pset);
extern void pset_reference(
processor_set_t pset);
uint32_t backtrace(uintptr_t *bt, uint32_t max_frames)
;
uint32_t backtrace_frame(uintptr_t *bt, uint32_t max_frames, void *start_frame)
;
uint32_t backtrace_interrupted(uintptr_t *bt, uint32_t max_frames);
int backtrace_user(uintptr_t *bt, uint32_t max_frames, uint32_t *frames_out,
_Bool *user_64_out);
int backtrace_thread_user(void *thread, uintptr_t *bt, uint32_t max_frames,
uint32_t *frames_out, _Bool *user_64_out);
typedef uint64_t kpc_config_t;
typedef void (*kpc_pm_handler_t)(boolean_t);
struct cpu_data;
extern boolean_t kpc_register_cpu(struct cpu_data *cpu_data);
extern void kpc_unregister_cpu(struct cpu_data *cpu_data);
extern void kpc_init(void);
extern void kpc_common_init(void);
extern void kpc_arch_init(void);
extern void kpc_thread_init(void);
extern uint32_t kpc_get_classes(void);
extern uint32_t kpc_get_running(void);
extern int kpc_get_pmu_version(void);
extern int kpc_set_running(uint32_t classes);
extern int kpc_get_cpu_counters(boolean_t all_cpus, uint32_t classes,
int *curcpu, uint64_t *buf);
extern int kpc_get_shadow_counters( boolean_t all_cpus, uint32_t classes,
int *curcpu, uint64_t *buf );
extern int kpc_get_curthread_counters(uint32_t *inoutcount, uint64_t *buf);
extern uint32_t kpc_get_counter_count(uint32_t classes);
extern uint32_t kpc_get_config_count(uint32_t classes);
extern uint32_t kpc_get_thread_counting(void);
extern int kpc_set_thread_counting(uint32_t classes);
extern int kpc_get_config(uint32_t classes, kpc_config_t *current_config);
extern int kpc_set_config(uint32_t classes, kpc_config_t *new_config);
extern int kpc_get_period(uint32_t classes, uint64_t *period);
extern int kpc_set_period(uint32_t classes, uint64_t *period);
extern int kpc_get_actionid(uint32_t classes, uint32_t *actionid);
extern int kpc_set_actionid(uint32_t classes, uint32_t *actionid);
extern void kpc_thread_create(thread_t thread);
extern void kpc_thread_destroy(thread_t thread);
extern uint64_t *kpc_counterbuf_alloc(void);
extern void kpc_counterbuf_free(uint64_t*);
extern int kpc_threads_counting;
extern void kpc_thread_ast_handler( thread_t thread );
extern int kpc_force_all_ctrs( task_t task, int val );
extern int kpc_get_force_all_ctrs( void );
extern int kpc_force_all_ctrs_arch( task_t task, int val );
extern int kpc_set_sw_inc( uint32_t mask );
extern int kpc_get_whitelist_disabled( void );
extern int kpc_disable_whitelist( int val );
extern boolean_t kpc_register_pm_handler(void (*handler)(boolean_t));
extern boolean_t kpc_reserve_pm_counters(uint64_t pmc_mask, kpc_pm_handler_t handler,
boolean_t custom_config);
extern void kpc_release_pm_counters(void);
extern void kpc_pm_acknowledge(boolean_t available_to_pm);
extern boolean_t kpc_multiple_clients(void);
extern boolean_t kpc_controls_fixed_counters(void);
extern boolean_t kpc_controls_counter(uint32_t ctr);
extern void kpc_idle(void);
extern void kpc_idle_exit(void);
extern uint32_t kpc_actionid[(32)];
struct kpc_config_remote {
uint32_t classes;
kpc_config_t *configv;
uint64_t pmc_mask;
};
struct kpc_running_remote {
uint32_t classes;
uint64_t cfg_target_mask;
uint64_t cfg_state_mask;
};
struct kpc_get_counters_remote {
uint32_t classes;
uint32_t nb_counters;
uint32_t buf_stride;
uint64_t *buf;
};
extern int kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf);
extern int kpc_get_curcpu_counters(uint32_t classes, int *curcpu, uint64_t *buf);
extern int kpc_get_fixed_counters(uint64_t *counterv);
extern int kpc_get_configurable_counters(uint64_t *counterv, uint64_t pmc_mask);
extern boolean_t kpc_is_running_fixed(void);
extern boolean_t kpc_is_running_configurable(uint64_t pmc_mask);
extern uint32_t kpc_fixed_count(void);
extern uint32_t kpc_configurable_count(void);
extern uint32_t kpc_fixed_config_count(void);
extern uint32_t kpc_configurable_config_count(uint64_t pmc_mask);
extern uint32_t kpc_rawpmu_config_count(void);
extern int kpc_get_fixed_config(kpc_config_t *configv);
extern int kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask);
extern int kpc_get_rawpmu_config(kpc_config_t *configv);
extern uint64_t kpc_fixed_max(void);
extern uint64_t kpc_configurable_max(void);
extern int kpc_set_config_arch(struct kpc_config_remote *mp_config);
extern int kpc_set_period_arch(struct kpc_config_remote *mp_config);
extern void kpc_sample_kperf(uint32_t actionid);
extern int kpc_set_running_arch(struct kpc_running_remote *mp_config);
extern uint8_t kpc_popcount(uint64_t value);
extern uint64_t kpc_get_configurable_pmc_mask(uint32_t classes);
struct kpc_driver
{
uint32_t (*get_classes)(void);
uint32_t (*get_running)(void);
int (*set_running)(uint32_t classes);
int (*get_cpu_counters)(boolean_t all_cpus, uint32_t classes,
int *curcpu, uint64_t *buf);
int (*get_curthread_counters)(uint32_t *inoutcount, uint64_t *buf);
uint32_t (*get_counter_count)(uint32_t classes);
uint32_t (*get_config_count)(uint32_t classes);
int (*get_config)(uint32_t classes, kpc_config_t *current_config);
int (*set_config)(uint32_t classes, kpc_config_t *new_config);
int (*get_period)(uint32_t classes, uint64_t *period);
int (*set_period)(uint32_t classes, uint64_t *period);
};
extern _Bool mt_debug;
extern  uint64_t mt_pmis;
extern  uint64_t mt_retrograde;
void mt_fixed_counts(uint64_t *counts);
void mt_cur_thread_fixed_counts(uint64_t *counts);
void mt_cur_task_fixed_counts(uint64_t *counts);
uint64_t mt_cur_cpu_instrs(void);
uint64_t mt_cur_cpu_cycles(void);
uint64_t mt_cur_thread_instrs(void);
uint64_t mt_cur_thread_cycles(void);
void kext_alloc_init(void);
kern_return_t kext_alloc(vm_offset_t *addr, vm_size_t size, boolean_t fixed);
void kext_free(vm_offset_t addr, vm_size_t size);
typedef void (*mig_stub_routine_t) (mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
typedef mig_stub_routine_t mig_routine_t;
typedef mig_routine_t (*mig_server_routine_t) (mach_msg_header_t *InHeadP);
typedef kern_return_t (*mig_impl_routine_t)(void);
typedef mach_msg_type_descriptor_t routine_arg_descriptor;
typedef mach_msg_type_descriptor_t *routine_arg_descriptor_t;
typedef mach_msg_type_descriptor_t *mig_routine_arg_descriptor_t;
struct routine_descriptor {
mig_impl_routine_t impl_routine;
mig_stub_routine_t stub_routine;
unsigned int argc;
unsigned int descr_count;
routine_arg_descriptor_t
arg_descr;
unsigned int max_reply_msg;
};
typedef struct routine_descriptor *routine_descriptor_t;
typedef struct routine_descriptor mig_routine_descriptor;
typedef mig_routine_descriptor *mig_routine_descriptor_t;
typedef struct mig_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
mach_msg_size_t maxsize;
vm_address_t reserved;
mig_routine_descriptor
routine[1];
} *mig_subsystem_t;
typedef struct mig_symtab {
char *ms_routine_name;
int ms_routine_number;
void (*ms_routine)(void);
} mig_symtab_t;
extern mach_port_t mig_get_reply_port(void);
extern void mig_dealloc_reply_port(mach_port_t reply_port);
extern void mig_put_reply_port(mach_port_t reply_port);
extern int mig_strncpy(char *dest, const char *src, int len);
extern int mig_strncpy_zerofill(char *dest, const char *src, int len);
extern void mig_allocate(vm_address_t *, vm_size_t);
extern void mig_deallocate(vm_address_t, vm_size_t);
extern mach_msg_return_t mach_msg_send_from_kernel_proper(
mach_msg_header_t *msg,
mach_msg_size_t send_size);
extern mach_msg_return_t
mach_msg_rpc_from_kernel_proper(
mach_msg_header_t *msg,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size);
extern mach_msg_return_t mach_msg_send_from_kernel_with_options(
mach_msg_header_t *msg,
mach_msg_size_t send_size,
mach_msg_option_t option,
mach_msg_timeout_t timeout_val);
struct work_interval;
struct kern_work_interval_args {
uint64_t work_interval_id;
uint64_t start;
uint64_t finish;
uint64_t deadline;
uint64_t next_start;
uint32_t notify_flags;
uint32_t create_flags;
uint16_t urgency;
};
struct kern_work_interval_create_args {
uint64_t wica_id;
uint32_t wica_port;
uint32_t wica_create_flags;
};
extern kern_return_t
kern_work_interval_create(thread_t thread, struct kern_work_interval_create_args *create_params);
extern kern_return_t
kern_work_interval_destroy(thread_t thread, uint64_t work_interval_id);
extern kern_return_t
kern_work_interval_join(thread_t thread, mach_port_name_t port_name);
extern kern_return_t
kern_work_interval_notify(thread_t thread, struct kern_work_interval_args* kwi_args);
typedef enum {
HV_DEBUG_STATE
} hv_volatile_state_t;
typedef enum {
HV_TASK_TRAP = 0,
HV_THREAD_TRAP = 1
} hv_trap_type_t;
typedef kern_return_t (*hv_trap_t) (void *target, uint64_t arg);
typedef struct {
const hv_trap_t *traps;
unsigned trap_count;
} hv_trap_table_t;
typedef struct {
void (*dispatch)(void *vcpu);
void (*preempt)(void *vcpu);
void (*suspend)(void);
void (*thread_destroy)(void *vcpu);
void (*task_destroy)(void *vm);
void (*volatile_state)(void *vcpu, int state);
void (*memory_pressure)(void);
} hv_callbacks_t;
extern hv_callbacks_t hv_callbacks;
extern int hv_support_available;
extern void hv_support_init(void);
extern int hv_get_support(void);
extern void hv_set_task_target(void *target);
extern void hv_set_thread_target(void *target);
extern void *hv_get_task_target(void);
extern void *hv_get_thread_target(void);
extern int hv_get_volatile_state(hv_volatile_state_t state);
extern kern_return_t hv_set_traps(hv_trap_type_t trap_type,
const hv_trap_t *traps, unsigned trap_count);
extern void hv_release_traps(hv_trap_type_t trap_type);
extern kern_return_t hv_set_callbacks(hv_callbacks_t callbacks);
extern void hv_release_callbacks(void);
extern void hv_suspend(void);
extern kern_return_t hv_task_trap(uint64_t index, uint64_t arg);
extern kern_return_t hv_thread_trap(uint64_t index, uint64_t arg);
typedef enum thread_snapshot_wait_flags {
kThreadWaitNone = 0x00,
kThreadWaitKernelMutex = 0x01,
kThreadWaitPortReceive = 0x02,
kThreadWaitPortSetReceive = 0x03,
kThreadWaitPortSend = 0x04,
kThreadWaitPortSendInTransit = 0x05,
kThreadWaitSemaphore = 0x06,
kThreadWaitKernelRWLockRead = 0x07,
kThreadWaitKernelRWLockWrite = 0x08,
kThreadWaitKernelRWLockUpgrade = 0x09,
kThreadWaitUserLock = 0x0a,
kThreadWaitPThreadMutex = 0x0b,
kThreadWaitPThreadRWLockRead = 0x0c,
kThreadWaitPThreadRWLockWrite = 0x0d,
kThreadWaitPThreadCondVar = 0x0e,
kThreadWaitParkedWorkQueue = 0x0f,
kThreadWaitWorkloopSyncWait = 0x10,
}  block_hint_t;
extern wait_result_t thread_block(
thread_continue_t continuation);
extern wait_result_t thread_block_parameter(
thread_continue_t continuation,
void *parameter);
extern wait_result_t assert_wait(
event_t event,
wait_interrupt_t interruptible);
extern wait_result_t assert_wait_timeout(
event_t event,
wait_interrupt_t interruptible,
uint32_t interval,
uint32_t scale_factor);
extern wait_result_t assert_wait_timeout_with_leeway(
event_t event,
wait_interrupt_t interruptible,
wait_timeout_urgency_t urgency,
uint32_t interval,
uint32_t leeway,
uint32_t scale_factor);
extern wait_result_t assert_wait_deadline(
event_t event,
wait_interrupt_t interruptible,
uint64_t deadline);
extern wait_result_t assert_wait_deadline_with_leeway(
event_t event,
wait_interrupt_t interruptible,
wait_timeout_urgency_t urgency,
uint64_t deadline,
uint64_t leeway);
extern kern_return_t thread_wakeup_prim(
event_t event,
boolean_t one_thread,
wait_result_t result);
extern kern_return_t thread_wakeup_thread(event_t event, thread_t thread);
extern boolean_t preemption_enabled(void);
typedef void * kcdata_descriptor_t;
uint32_t kcdata_estimate_required_buffer_size(uint32_t num_items, uint32_t payload_size);
uint64_t kcdata_memory_get_used_bytes(kcdata_descriptor_t kcd);
kern_return_t kcdata_memcpy(kcdata_descriptor_t data, mach_vm_address_t dst_addr, void * src_addr, uint32_t size);
kern_return_t kcdata_get_memory_addr(kcdata_descriptor_t data, uint32_t type, uint32_t size, mach_vm_address_t * user_addr);
kern_return_t kcdata_get_memory_addr_for_array(
kcdata_descriptor_t data, uint32_t type_of_element, uint32_t size_of_element, uint32_t count, mach_vm_address_t * user_addr);
struct ecc_event {
uint8_t id;
uint8_t count;
uint64_t data[8] ;
};
extern void Assert(
const char *file,
int line,
const char *expression) ;
extern int kext_assertions_enable;
typedef uint32_t sfi_class_id_t;
typedef void (*IOInterruptHandler)(void *target, void *refCon,
void *nub, int source);
enum {
kBootDriverTypeInvalid = 0,
kBootDriverTypeKEXT = 1,
kBootDriverTypeMKEXT = 2
};
enum {
kEfiReservedMemoryType = 0,
kEfiLoaderCode = 1,
kEfiLoaderData = 2,
kEfiBootServicesCode = 3,
kEfiBootServicesData = 4,
kEfiRuntimeServicesCode = 5,
kEfiRuntimeServicesData = 6,
kEfiConventionalMemory = 7,
kEfiUnusableMemory = 8,
kEfiACPIReclaimMemory = 9,
kEfiACPIMemoryNVS = 10,
kEfiMemoryMappedIO = 11,
kEfiMemoryMappedIOPortSpace = 12,
kEfiPalCode = 13,
kEfiMaxMemoryType = 14
};
typedef struct EfiMemoryRange {
uint32_t Type;
uint32_t Pad;
uint64_t PhysicalStart;
uint64_t VirtualStart;
uint64_t NumberOfPages;
uint64_t Attribute;
} EfiMemoryRange;
struct Boot_VideoV1 {
uint32_t v_baseAddr;
uint32_t v_display;
uint32_t v_rowBytes;
uint32_t v_width;
uint32_t v_height;
uint32_t v_depth;
};
typedef struct Boot_VideoV1 Boot_VideoV1;
struct Boot_Video {
uint32_t v_display;
uint32_t v_rowBytes;
uint32_t v_width;
uint32_t v_height;
uint32_t v_depth;
uint32_t v_resv[7];
uint64_t v_baseAddr;
};
typedef struct Boot_Video Boot_Video;
struct boot_icon_element {
unsigned int width;
unsigned int height;
int y_offset_from_center;
unsigned int data_size;
unsigned int __reserved1[4];
unsigned char data[0];
};
typedef struct boot_icon_element boot_icon_element;
typedef struct boot_args {
uint16_t Revision;
uint16_t Version;
uint8_t efiMode;
uint8_t debugMode;
uint16_t flags;
char CommandLine[1024];
uint32_t MemoryMap;
uint32_t MemoryMapSize;
uint32_t MemoryMapDescriptorSize;
uint32_t MemoryMapDescriptorVersion;
Boot_VideoV1 VideoV1;
uint32_t deviceTreeP;
uint32_t deviceTreeLength;
uint32_t kaddr;
uint32_t ksize;
uint32_t efiRuntimeServicesPageStart;
uint32_t efiRuntimeServicesPageCount;
uint64_t efiRuntimeServicesVirtualPageStart;
uint32_t efiSystemTable;
uint32_t kslide;
uint32_t performanceDataStart;
uint32_t performanceDataSize;
uint32_t keyStoreDataStart;
uint32_t keyStoreDataSize;
uint64_t bootMemStart;
uint64_t bootMemSize;
uint64_t PhysicalMemorySize;
uint64_t FSBFrequency;
uint64_t pciConfigSpaceBaseAddress;
uint32_t pciConfigSpaceStartBusNumber;
uint32_t pciConfigSpaceEndBusNumber;
uint32_t csrActiveConfig;
uint32_t csrCapabilities;
uint32_t boot_SMC_plimit;
uint16_t bootProgressMeterStart;
uint16_t bootProgressMeterEnd;
Boot_Video Video;
uint32_t apfsDataStart;
uint32_t apfsDataSize;
uint32_t __reserved4[710];
} boot_args;
extern char assert_boot_args_size_is_4096[sizeof(boot_args) == 4096 ? 1 : -1];
typedef void *cpu_id_t;
void PE_enter_debugger(
const char *cause);
void PE_init_platform(
boolean_t vm_initialized,
void *args);
uint32_t PE_get_random_seed(
unsigned char * dst_random_seed,
uint32_t request_size);
uint32_t PE_i_can_has_debugger(
uint32_t *);
uint32_t PE_get_offset_into_panic_region(
char *location);
void PE_init_panicheader(
void);
void PE_update_panicheader_nestedpanic(
void);
void PE_init_kprintf(
boolean_t vm_initialized);
extern int32_t gPESerialBaud;
extern uint8_t gPlatformECID[8];
extern uint32_t gPlatformMemoryID;
unsigned int PE_init_taproot(vm_offset_t *taddr);
extern void (*PE_kputc)(char c);
void PE_init_printf(
boolean_t vm_initialized);
extern void (*PE_putc)(char c);
void PE_init_iokit(
void);
struct clock_frequency_info_t {
unsigned long bus_clock_rate_hz;
unsigned long cpu_clock_rate_hz;
unsigned long dec_clock_rate_hz;
unsigned long bus_clock_rate_num;
unsigned long bus_clock_rate_den;
unsigned long bus_to_cpu_rate_num;
unsigned long bus_to_cpu_rate_den;
unsigned long bus_to_dec_rate_num;
unsigned long bus_to_dec_rate_den;
unsigned long timebase_frequency_hz;
unsigned long timebase_frequency_num;
unsigned long timebase_frequency_den;
unsigned long long bus_frequency_hz;
unsigned long long bus_frequency_min_hz;
unsigned long long bus_frequency_max_hz;
unsigned long long cpu_frequency_hz;
unsigned long long cpu_frequency_min_hz;
unsigned long long cpu_frequency_max_hz;
unsigned long long prf_frequency_hz;
unsigned long long prf_frequency_min_hz;
unsigned long long prf_frequency_max_hz;
unsigned long long mem_frequency_hz;
unsigned long long mem_frequency_min_hz;
unsigned long long mem_frequency_max_hz;
unsigned long long fix_frequency_hz;
};
typedef struct clock_frequency_info_t clock_frequency_info_t;
extern clock_frequency_info_t gPEClockFrequencyInfo;
struct timebase_freq_t {
unsigned long timebase_num;
unsigned long timebase_den;
};
typedef void (*timebase_callback_func)(struct timebase_freq_t *timebase_freq);
void PE_register_timebase_callback(timebase_callback_func callback);
void PE_call_timebase_callback(void);
void PE_install_interrupt_handler(
void *nub, int source,
void *target, IOInterruptHandler handler, void *refCon);
void kprintf(const char *fmt, ...) ;
void init_display_putc(unsigned char *baseaddr, int rowbytes, int height);
void display_putc(char c);
enum {
kPEReadTOD,
kPEWriteTOD
};
extern int (*PE_read_write_time_of_day)(
unsigned int options,
long * secs);
enum {
kPEWaitForInput = 0x00000001,
kPERawInput = 0x00000002
};
extern int (*PE_poll_input)(
unsigned int options,
char * c);
extern int (*PE_write_IIC)(
unsigned char addr,
unsigned char reg,
unsigned char data);
enum {
kDebugTypeNone = 0,
kDebugTypeDisplay = 1,
kDebugTypeSerial = 2
};
enum {
kPEScaleFactorUnknown = 0,
kPEScaleFactor1x = 1,
kPEScaleFactor2x = 2
};
struct PE_Video {
unsigned long v_baseAddr;
unsigned long v_rowBytes;
unsigned long v_width;
unsigned long v_height;
unsigned long v_depth;
unsigned long v_display;
char v_pixelFormat[64];
unsigned long v_offset;
unsigned long v_length;
unsigned char v_rotate;
unsigned char v_scale;
char reserved1[2];
long reserved2;
};
typedef struct PE_Video PE_Video;
extern void initialize_screen(PE_Video *, unsigned int);
extern void dim_screen(void);
extern int PE_current_console(
PE_Video *info);
extern void PE_create_console(
void);
extern int PE_initialize_console(
PE_Video *newInfo,
int op);
extern void PE_display_icon( unsigned int flags,
const char * name );
typedef struct PE_state {
boolean_t initialized;
PE_Video video;
void *deviceTreeHead;
void *bootArgs;
} PE_state_t;
extern PE_state_t PE_state;
extern char * PE_boot_args(
void);
extern boolean_t PE_parse_boot_argn(
const char *arg_string,
void *arg_ptr,
int max_arg);
extern boolean_t PE_get_default(
const char *property_name,
void *property_ptr,
unsigned int max_property);
enum {
kPEOptionKey = 0x3a,
kPECommandKey = 0x37,
kPEControlKey = 0x36,
kPEShiftKey = 0x38
};
extern boolean_t PE_get_hotkey(
unsigned char key);
extern kern_return_t PE_cpu_start(
cpu_id_t target,
vm_offset_t start_paddr,
vm_offset_t arg_paddr);
extern void PE_cpu_halt(
cpu_id_t target);
extern void PE_cpu_signal(
cpu_id_t source,
cpu_id_t target);
extern void PE_cpu_signal_deferred(
cpu_id_t source,
cpu_id_t target);
extern void PE_cpu_signal_cancel(
cpu_id_t source,
cpu_id_t target);
extern void PE_cpu_machine_init(
cpu_id_t target,
boolean_t bootb);
extern void PE_cpu_machine_quiesce(
cpu_id_t target);
extern void pe_init_debug(void);
extern boolean_t PE_imgsrc_mount_supported(void);
boolean_t ml_get_interrupts_enabled(void);
boolean_t ml_set_interrupts_enabled(boolean_t enable);
boolean_t ml_at_interrupt_context(void);
void bzero_phys(
addr64_t phys_address,
uint32_t length);
vm_offset_t ml_stack_remaining(void);
typedef unsigned spl_t;
typedef uint32_t ast_t;
extern void ast_taken_kernel(void);
extern void ast_taken_user(void);
extern void ast_check(processor_t processor);
extern ast_t *ast_pending(void);
extern void ast_on(ast_t reasons);
extern void ast_off(ast_t reasons);
extern ast_t ast_consume(ast_t reasons);
extern ast_t ast_peek(ast_t reasons);
extern void ast_context(thread_t thread);
extern void ast_propagate(thread_t thread);
extern void kevent_ast(thread_t thread, uint16_t bits);
extern void act_set_astkevent(thread_t thread, uint16_t bits);
struct ledger_info {
char li_name[32];
int64_t li_id;
int64_t li_entries;
};
struct ledger_template_info {
char lti_name[32];
char lti_group[32];
char lti_units[32];
};
struct ledger_entry_info {
int64_t lei_balance;
int64_t lei_credit;
int64_t lei_debit;
uint64_t lei_limit;
uint64_t lei_refill_period;
uint64_t lei_last_refill;
};
struct ledger_limit_args {
char lla_name[32];
uint64_t lla_limit;
uint64_t lla_refill_period;
};
extern void sfi_init(void);
extern void sfi_early_init(void);
extern sfi_class_id_t sfi_get_ledger_alias_for_class(sfi_class_id_t class_id);
//extern int sfi_ledger_entry_add(ledger_template_t template, sfi_class_id_t class_id);
kern_return_t sfi_set_window(uint64_t window_usecs);
kern_return_t sfi_window_cancel(void);
kern_return_t sfi_get_window(uint64_t *window_usecs);
kern_return_t sfi_set_class_offtime(sfi_class_id_t class_id, uint64_t offtime_usecs);
kern_return_t sfi_class_offtime_cancel(sfi_class_id_t class_id);
kern_return_t sfi_get_class_offtime(sfi_class_id_t class_id, uint64_t *offtime_usecs);
struct queue_entry {
struct queue_entry *next;
struct queue_entry *prev;
};
typedef struct queue_entry *queue_t;
typedef struct queue_entry queue_head_t;
typedef struct queue_entry queue_chain_t;
typedef struct queue_entry *queue_entry_t;
static  void
enqueue_head(
queue_t que,
queue_entry_t elt)
{
queue_entry_t old_head;
do { } while (0);
old_head = que->next;
elt->next = old_head;
elt->prev = que;
old_head->prev = elt;
que->next = elt;
}
static  void
enqueue_tail(
queue_t que,
queue_entry_t elt)
{
queue_entry_t old_tail;
do { } while (0);
old_tail = que->prev;
elt->next = que;
elt->prev = old_tail;
old_tail->next = elt;
que->prev = elt;
}
static  queue_entry_t
dequeue_head(
queue_t que)
{
queue_entry_t elt = (queue_entry_t) 0;
queue_entry_t new_head;
if (que->next != que) {
elt = que->next;
do { } while (0);
new_head = elt->next;
new_head->prev = que;
que->next = new_head;
do { } while(0);
}
return (elt);
}
static  queue_entry_t
dequeue_tail(
queue_t que)
{
queue_entry_t elt = (queue_entry_t) 0;
queue_entry_t new_tail;
if (que->prev != que) {
elt = que->prev;
do { } while (0);
new_tail = elt->prev;
new_tail->next = que;
que->prev = new_tail;
do { } while(0);
}
return (elt);
}
static  void
remqueue(
queue_entry_t elt)
{
queue_entry_t next_elt, prev_elt;
do { } while (0);
next_elt = elt->next;
prev_elt = elt->prev;
next_elt->prev = prev_elt;
prev_elt->next = next_elt;
do { } while(0);
}
static  void
insque(
queue_entry_t entry,
queue_entry_t pred)
{
queue_entry_t successor;
do { } while (0);
successor = pred->next;
entry->next = successor;
entry->prev = pred;
successor->prev = entry;
pred->next = entry;
}
static  void
remque(
queue_entry_t elt)
{
queue_entry_t next_elt, prev_elt;
do { } while (0);
next_elt = elt->next;
prev_elt = elt->prev;
next_elt->prev = prev_elt;
prev_elt->next = next_elt;
do { } while(0);
}
static  void
re_queue_head(queue_t que, queue_entry_t elt)
{
queue_entry_t n_elt, p_elt;
do { } while (0);
do { } while (0);
n_elt = elt->next;
p_elt = elt->prev;
n_elt->prev = p_elt;
p_elt->next = n_elt;
n_elt = que->next;
elt->next = n_elt;
elt->prev = que;
n_elt->prev = elt;
que->next = elt;
}
static  void
re_queue_tail(queue_t que, queue_entry_t elt)
{
queue_entry_t n_elt, p_elt;
do { } while (0);
do { } while (0);
n_elt = elt->next;
p_elt = elt->prev;
n_elt->prev = p_elt;
p_elt->next = n_elt;
p_elt = que->prev;
elt->next = que;
elt->prev = p_elt;
p_elt->next = elt;
que->prev = elt;
}
static  void
movqueue(queue_t _old, queue_t _new)
{
queue_entry_t next_elt, prev_elt;
do { } while (0);
if ((((_old)) == (((_old)->next)))) {
do { (_new)->next = (_new); (_new)->prev = (_new);} while (0);
return;
}
next_elt = _old->next;
prev_elt = _old->prev;
_new->next = next_elt;
_new->prev = prev_elt;
next_elt->prev = _new;
prev_elt->next = _new;
do { (_old)->next = (_old); (_old)->prev = (_old);} while (0);
}
extern void *kalloc(vm_size_t size) ;
extern void *kalloc_noblock(vm_size_t size) ;
extern void kfree(void *data,
vm_size_t size);
typedef unsigned int uint;
inline static _Bool
bit_clear_if_set(uint64_t bitmap, int bit)
{
_Bool bit_is_set = ((_Bool)((bitmap) & (1ULL << (bit))));
((bitmap) &= ~(1ULL << (bit)));
return bit_is_set;
}
inline static _Bool
bit_set_if_clear(uint64_t bitmap, int bit)
{
_Bool bit_is_set = ((_Bool)((bitmap) & (1ULL << (bit))));
((bitmap) |= (1ULL << (bit)));
return !bit_is_set;
}
inline static int
bit_first(uint64_t bitmap)
{
return (bitmap == 0) ? -1 : 63 - __builtin_clzll(bitmap);
}
inline static int
__bit_next(uint64_t bitmap, int previous_bit)
{
uint64_t mask = previous_bit ? ((1ULL << (previous_bit)) - 1) : ~0ULL;
return bit_first(bitmap & mask);
}
inline static int
bit_next(uint64_t bitmap, int previous_bit)
{
if (previous_bit == 0) {
return -1;
} else {
return __bit_next(bitmap, previous_bit);
}
}
inline static int
lsb_first(uint64_t bitmap)
{
return __builtin_ffsll(bitmap) - 1;
}
inline static int
lsb_next(uint64_t bitmap, int previous_bit)
{
uint64_t mask = ((1ULL << (previous_bit + 1)) - 1);
return lsb_first(bitmap & ~mask);
}
inline static int
bit_count(uint64_t x)
{
return __builtin_popcountll(x);
}
inline static int
bit_floor(uint64_t n)
{
return bit_first(n);
}
inline static int
bit_ceiling(uint64_t n)
{
if (n == 0) {
return -1;
}
return bit_first(n - 1) + 1;
}
typedef  uint64_t bitmap_t;
inline static _Bool
atomic_bit_set(bitmap_t *map, int n, int mem_order)
{
bitmap_t prev;
prev = __c11_atomic_fetch_or(map, (1ULL << (n)), mem_order);
return ((_Bool)((prev) & (1ULL << (n))));
}
inline static _Bool
atomic_bit_clear(bitmap_t *map, int n, int mem_order)
{
bitmap_t prev;
prev = __c11_atomic_fetch_and(map, ~(1ULL << (n)), mem_order);
return ((_Bool)((prev) & (1ULL << (n))));
}
inline static bitmap_t *
bitmap_zero(bitmap_t *map, uint nbits)
{
return (bitmap_t *)memset((void *)map, 0, (size_t)((((uint)(nbits) + 63) >> 6) << 3));
}
inline static bitmap_t *
bitmap_full(bitmap_t *map, uint nbits)
{
return (bitmap_t *)memset((void *)map, ~0, (size_t)((((uint)(nbits) + 63) >> 6) << 3));
}
inline static bitmap_t *
bitmap_alloc(uint nbits)
{
((void)0);
bitmap_t *map = (bitmap_t *)kalloc((size_t)((((uint)(nbits) + 63) >> 6) << 3));
if (map) {
bitmap_zero(map, nbits);
}
return map;
}
inline static void
bitmap_free(bitmap_t *map, uint nbits)
{
((void)0);
kfree(map, (size_t)((((uint)(nbits) + 63) >> 6) << 3));
}
inline static void
bitmap_set(bitmap_t *map, uint n)
{
((map[((((uint64_t)((n))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1))]) |= (1ULL << (((((uint64_t)((n))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)))));
}
inline static void
bitmap_clear(bitmap_t *map, uint n)
{
((map[((((uint64_t)((n))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1))]) &= ~(1ULL << (((((uint64_t)((n))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)))));
}
inline static _Bool
atomic_bitmap_set(bitmap_t *map, uint n, int mem_order)
{
return atomic_bit_set(&map[((((uint64_t)((n))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1))], ((((uint64_t)((n))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)), mem_order);
}
inline static _Bool
atomic_bitmap_clear(bitmap_t *map, uint n, int mem_order)
{
return atomic_bit_clear(&map[((((uint64_t)((n))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1))], ((((uint64_t)((n))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)), mem_order);
}
inline static _Bool
bitmap_test(bitmap_t *map, uint n)
{
return ((_Bool)((map[((((uint64_t)((n))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1))]) & (1ULL << (((((uint64_t)((n))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1))))));
}
inline static int
bitmap_first(bitmap_t *map, uint nbits)
{
for (int i = (int)((((uint64_t)((nbits - 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1)); i >= 0; i--) {
if (map[i] == 0) {
continue;
}
return (i << 6) + bit_first(map[i]);
}
return -1;
}
inline static int
bitmap_and_not_mask_first(bitmap_t *map, bitmap_t *mask, uint nbits)
{
for (int i = (int)((((uint64_t)((nbits - 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1)); i >= 0; i--) {
if ((map[i] & ~mask[i]) == 0) {
continue;
}
return (i << 6) + bit_first(map[i] & ~mask[i]);
}
return -1;
}
inline static int
bitmap_lsb_first(bitmap_t *map, uint nbits)
{
for (uint i = 0; i <= ((((uint64_t)((nbits - 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1)); i++) {
if (map[i] == 0) {
continue;
}
return (int)((i << 6) + (uint32_t)lsb_first(map[i]));
}
return -1;
}
inline static int
bitmap_next(bitmap_t *map, uint prev)
{
if (prev == 0) {
return -1;
}
int64_t i = ((((uint64_t)((prev - 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1));
int res = __bit_next(map[i], ((((uint64_t)((prev))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)));
if (res >= 0) {
return (int)(res + (i << 6));
}
for (i = i - 1; i >= 0; i--) {
if (map[i] == 0) {
continue;
}
return (int)((i << 6) + bit_first(map[i]));
}
return -1;
}
inline static int
bitmap_lsb_next(bitmap_t *map, uint nbits, uint prev)
{
if ((prev + 1) >= nbits) {
return -1;
}
uint64_t i = ((((uint64_t)((prev + 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1));
uint b = ((((uint64_t)(((prev + 1)))) >> ((0))) & ((1ULL << ((5) - (0) + 1)) - 1)) - 1;
int32_t res = lsb_next((uint64_t)map[i], (int)b);
if (res >= 0) {
return (int)((uint64_t)res + (i << 6));
}
for (i = i + 1; i <= ((((uint64_t)((nbits - 1))) >> ((6))) & ((1ULL << ((63) - (6) + 1)) - 1)); i++) {
if (map[i] == 0) {
continue;
}
return (int)((i << 6) + (uint64_t)lsb_first(map[i]));
}
return -1;
}
static  uint64_t
multi_overflow(uint64_t a, uint64_t b)
{
__uint128_t prod;
prod = (__uint128_t)a * (__uint128_t)b;
return (uint64_t) (prod >> 64);
}
struct bt_params {
double rate;
uint64_t base_local_ts;
uint64_t base_remote_ts;
};
static inline uint64_t
mach_bridge_compute_timestamp(uint64_t local_ts_ns, struct bt_params *params)
{
if (!params || params->rate == 0.0) {
return 0;
}
int64_t remote_ts = 0;
int64_t rate_prod = 0;
rate_prod = (int64_t)(params->rate * (double)((int64_t)local_ts_ns - (int64_t)params->base_local_ts));
if (__os_warn_unused(__builtin_add_overflow(((int64_t)params->base_remote_ts), (rate_prod), (&remote_ts)))) {
return 0;
}
return (uint64_t)remote_ts;
}
uint64_t mach_bridge_remote_time(uint64_t);
extern volatile boolean_t telemetry_needs_record;
extern void telemetry_init(void);
extern void compute_telemetry(void *);
extern void telemetry_ast(thread_t thread, uint32_t reasons);
extern int telemetry_gather(user_addr_t buffer, uint32_t *length, boolean_t mark);
extern void telemetry_mark_curthread(boolean_t interrupted_userspace);
extern void telemetry_task_ctl(task_t task, uint32_t reason, int enable_disable);
extern void telemetry_task_ctl_locked(task_t task, uint32_t reason, int enable_disable);
extern void telemetry_global_ctl(int enable_disable);
extern int telemetry_timer_event(uint64_t deadline, uint64_t interval, uint64_t leeway);
extern void bootprofile_init(void);
extern void bootprofile_wake_from_sleep(void);
extern void bootprofile_get(void **buffer, uint32_t *length);
extern int bootprofile_gather(user_addr_t buffer, uint32_t *length);
typedef struct {
uint32_t gpu_id;
uint32_t gpu_max_domains;
} gpu_descriptor;
typedef gpu_descriptor *gpu_descriptor_t;
void gpu_describe(gpu_descriptor_t);
uint64_t gpu_accumulate_time(uint32_t scope, uint32_t gpu_id, uint32_t gpu_domain, uint64_t gpu_accumulated_ns, uint64_t gpu_tstamp_ns);
uint64_t io_rate_update(
uint64_t io_rate_flags,
uint64_t read_ops_delta,
uint64_t write_ops_delta,
uint64_t read_bytes_delta,
uint64_t write_bytes_delta);
typedef uint64_t (*io_rate_update_callback_t) (uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
void io_rate_update_register(io_rate_update_callback_t);
void gpu_submission_telemetry(
uint64_t gpu_ncmds_total,
uint64_t gpu_noutstanding,
uint64_t gpu_busy_ns_total,
uint64_t gpu_cycles,
uint64_t gpu_telemetry_valid_flags,
uint64_t gpu_telemetry_misc);
typedef uint64_t (*gpu_set_fceiling_t) (uint32_t gpu_fceiling_ratio, uint64_t gpu_fceiling_param);
void gpu_fceiling_cb_register(gpu_set_fceiling_t);
typedef __uint8_t sa_family_t;
struct timeval;
struct sockaddr;
struct sockaddr_dl;
struct kern_event_msg;
struct kev_msg;
struct ifnet_demux_desc;
enum {
IFNET_FAMILY_ANY = 0,
IFNET_FAMILY_LOOPBACK = 1,
IFNET_FAMILY_ETHERNET = 2,
IFNET_FAMILY_SLIP = 3,
IFNET_FAMILY_TUN = 4,
IFNET_FAMILY_VLAN = 5,
IFNET_FAMILY_PPP = 6,
IFNET_FAMILY_PVC = 7,
IFNET_FAMILY_DISC = 8,
IFNET_FAMILY_MDECAP = 9,
IFNET_FAMILY_GIF = 10,
IFNET_FAMILY_FAITH = 11,
IFNET_FAMILY_STF = 12,
IFNET_FAMILY_FIREWIRE = 13,
IFNET_FAMILY_BOND = 14,
IFNET_FAMILY_CELLULAR = 15
};
typedef u_int32_t ifnet_family_t;
enum {
BPF_MODE_DISABLED = 0,
BPF_MODE_INPUT = 1,
BPF_MODE_OUTPUT = 2,
BPF_MODE_INPUT_OUTPUT = 3
};
typedef u_int32_t bpf_tap_mode;
typedef u_int32_t protocol_family_t;
enum {
IFNET_CSUM_IP = 0x00000001,
IFNET_CSUM_TCP = 0x00000002,
IFNET_CSUM_UDP = 0x00000004,
IFNET_CSUM_FRAGMENT = 0x00000008,
IFNET_IP_FRAGMENT = 0x00000010,
IFNET_CSUM_TCPIPV6 = 0x00000020,
IFNET_CSUM_UDPIPV6 = 0x00000040,
IFNET_IPV6_FRAGMENT = 0x00000080,
IFNET_VLAN_TAGGING = 0x00010000,
IFNET_VLAN_MTU = 0x00020000,
IFNET_MULTIPAGES = 0x00100000,
IFNET_TSO_IPV4 = 0x00200000,
IFNET_TSO_IPV6 = 0x00400000,
IFNET_TX_STATUS = 0x00800000,
IFNET_HW_TIMESTAMP = 0x01000000,
IFNET_SW_TIMESTAMP = 0x02000000
};
typedef u_int32_t ifnet_offload_t;
typedef errno_t (*bpf_packet_func)(ifnet_t interface, mbuf_t data);
typedef errno_t (*ifnet_output_func)(ifnet_t interface, mbuf_t data);
typedef errno_t (*ifnet_ioctl_func)(ifnet_t interface, unsigned long cmd,
void *data);
typedef errno_t (*ifnet_set_bpf_tap)(ifnet_t interface, bpf_tap_mode mode,
bpf_packet_func callback);
typedef void (*ifnet_detached_func)(ifnet_t interface);
typedef errno_t (*ifnet_demux_func)(ifnet_t interface, mbuf_t packet,
char *frame_header, protocol_family_t *protocol_family);
typedef void (*ifnet_event_func)(ifnet_t interface, const struct kev_msg *msg);
typedef errno_t (*ifnet_framer_func)(ifnet_t interface, mbuf_t *packet,
const struct sockaddr *dest, const char *dest_linkaddr,
const char *frame_type
);
typedef errno_t (*ifnet_add_proto_func)(ifnet_t interface,
protocol_family_t protocol_family,
const struct ifnet_demux_desc *demux_array, u_int32_t demux_count);
typedef errno_t (*ifnet_del_proto_func)(ifnet_t interface,
protocol_family_t protocol_family);
typedef errno_t (*ifnet_check_multi)(ifnet_t interface,
const struct sockaddr *mcast);
typedef errno_t (*proto_media_input)(ifnet_t ifp, protocol_family_t protocol,
mbuf_t packet, char *header);
typedef errno_t (*proto_media_input_v2)(ifnet_t ifp, protocol_family_t protocol,
mbuf_t packet);
typedef errno_t (*proto_media_preout)(ifnet_t ifp, protocol_family_t protocol,
mbuf_t *packet, const struct sockaddr *dest, void *route, char *frame_type,
char *link_layer_dest);
typedef void (*proto_media_event)(ifnet_t ifp, protocol_family_t protocol,
const struct kev_msg *event);
typedef errno_t (*proto_media_ioctl)(ifnet_t ifp, protocol_family_t protocol,
unsigned long command, void *argument);
typedef errno_t (*proto_media_detached)(ifnet_t ifp, protocol_family_t protocol);
typedef errno_t (*proto_media_resolve_multi)(ifnet_t ifp,
const struct sockaddr *proto_addr, struct sockaddr_dl *out_ll,
size_t ll_len);
typedef errno_t (*proto_media_send_arp)(ifnet_t ifp, u_short arpop,
const struct sockaddr_dl *sender_hw, const struct sockaddr *sender_proto,
const struct sockaddr_dl *target_hw, const struct sockaddr *target_proto);
struct ifnet_stat_increment_param {
u_int32_t packets_in;
u_int32_t bytes_in;
u_int32_t errors_in;
u_int32_t packets_out;
u_int32_t bytes_out;
u_int32_t errors_out;
u_int32_t collisions;
u_int32_t dropped;
};
struct ifnet_init_params {
const void *uniqueid;
u_int32_t uniqueid_len;
const char *name;
u_int32_t unit;
ifnet_family_t family;
u_int32_t type;
ifnet_output_func output;
ifnet_demux_func demux;
ifnet_add_proto_func add_proto;
ifnet_del_proto_func del_proto;
ifnet_check_multi check_multi;
ifnet_framer_func framer;
void *softc;
ifnet_ioctl_func ioctl;
ifnet_set_bpf_tap set_bpf_tap;
ifnet_detached_func detach;
ifnet_event_func event;
const void *broadcast_addr;
u_int32_t broadcast_len;
};
struct ifnet_stats_param {
u_int64_t packets_in;
u_int64_t bytes_in;
u_int64_t multicasts_in;
u_int64_t errors_in;
u_int64_t packets_out;
u_int64_t bytes_out;
u_int64_t multicasts_out;
u_int64_t errors_out;
u_int64_t collisions;
u_int64_t dropped;
u_int64_t no_protocol;
};
struct ifnet_demux_desc {
u_int32_t type;
void *data;
u_int32_t datalen;
};
struct ifnet_attach_proto_param {
struct ifnet_demux_desc *demux_array;
u_int32_t demux_count;
proto_media_input input;
proto_media_preout pre_output;
proto_media_event event;
proto_media_ioctl ioctl;
proto_media_detached detached;
proto_media_resolve_multi resolve;
proto_media_send_arp send_arp;
};
struct ifnet_attach_proto_param_v2 {
struct ifnet_demux_desc *demux_array;
u_int32_t demux_count;
proto_media_input_v2 input;
proto_media_preout pre_output;
proto_media_event event;
proto_media_ioctl ioctl;
proto_media_detached detached;
proto_media_resolve_multi resolve;
proto_media_send_arp send_arp;
};
extern errno_t ifnet_allocate(const struct ifnet_init_params *init,
ifnet_t *interface);
extern errno_t ifnet_reference(ifnet_t interface);
extern errno_t ifnet_release(ifnet_t interface);
extern errno_t ifnet_attach(ifnet_t interface,
const struct sockaddr_dl *ll_addr);
extern errno_t ifnet_detach(ifnet_t interface);
extern errno_t ifnet_interface_family_find(const char *module_string, ifnet_family_t *family_id);
extern void *ifnet_softc(ifnet_t interface);
extern const char *ifnet_name(ifnet_t interface);
extern ifnet_family_t ifnet_family(ifnet_t interface);
extern u_int32_t ifnet_unit(ifnet_t interface);
extern u_int32_t ifnet_index(ifnet_t interface);
extern errno_t ifnet_set_flags(ifnet_t interface, u_int16_t new_flags,
u_int16_t mask);
extern u_int16_t ifnet_flags(ifnet_t interface);
extern errno_t ifnet_set_capabilities_supported(ifnet_t interface, u_int32_t new_caps,
u_int32_t mask);
extern u_int32_t ifnet_capabilities_supported(ifnet_t interface);
extern errno_t ifnet_set_capabilities_enabled(ifnet_t interface, u_int32_t new_caps,
u_int32_t mask);
extern u_int32_t ifnet_capabilities_enabled(ifnet_t interface);
extern errno_t ifnet_set_offload(ifnet_t interface, ifnet_offload_t offload);
extern ifnet_offload_t ifnet_offload(ifnet_t interface);
extern errno_t ifnet_set_tso_mtu(ifnet_t interface, sa_family_t family,
u_int32_t mtuLen);
extern errno_t ifnet_get_tso_mtu(ifnet_t interface, sa_family_t family,
u_int32_t *mtuLen);
enum {
IFNET_WAKE_ON_MAGIC_PACKET = 0x01
};
extern errno_t ifnet_set_wake_flags(ifnet_t interface, u_int32_t properties, u_int32_t mask);
extern u_int32_t ifnet_get_wake_flags(ifnet_t interface);
extern errno_t ifnet_set_link_mib_data(ifnet_t interface, void *mibData,
u_int32_t mibLen);
extern errno_t ifnet_get_link_mib_data(ifnet_t interface, void *mibData,
u_int32_t *mibLen);
extern u_int32_t ifnet_get_link_mib_data_length(ifnet_t interface);
extern errno_t ifnet_attach_protocol(ifnet_t interface,
protocol_family_t protocol_family,
const struct ifnet_attach_proto_param *proto_details);
extern errno_t ifnet_attach_protocol_v2(ifnet_t interface,
protocol_family_t protocol_family,
const struct ifnet_attach_proto_param_v2 *proto_details);
extern errno_t ifnet_detach_protocol(ifnet_t interface,
protocol_family_t protocol_family);
extern errno_t ifnet_output(ifnet_t interface,
protocol_family_t protocol_family, mbuf_t packet, void *route,
const struct sockaddr *dest);
extern errno_t ifnet_output_raw(ifnet_t interface,
protocol_family_t protocol_family, mbuf_t packet);
extern errno_t ifnet_input(ifnet_t interface, mbuf_t first_packet,
const struct ifnet_stat_increment_param *stats);
extern errno_t ifnet_ioctl(ifnet_t interface, protocol_family_t protocol,
unsigned long ioctl_code, void *ioctl_arg);
extern errno_t ifnet_event(ifnet_t interface, struct kern_event_msg *event_ptr);
extern errno_t ifnet_set_mtu(ifnet_t interface, u_int32_t mtu);
extern u_int32_t ifnet_mtu(ifnet_t interface);
extern u_int8_t ifnet_type(ifnet_t interface);
extern errno_t ifnet_set_addrlen(ifnet_t interface, u_int8_t addrlen);
extern u_int8_t ifnet_addrlen(ifnet_t interface);
extern errno_t ifnet_set_hdrlen(ifnet_t interface, u_int8_t hdrlen);
extern u_int8_t ifnet_hdrlen(ifnet_t interface);
extern errno_t ifnet_set_metric(ifnet_t interface, u_int32_t metric);
extern u_int32_t ifnet_metric(ifnet_t interface);
extern errno_t ifnet_set_baudrate(ifnet_t interface, u_int64_t baudrate);
extern u_int64_t ifnet_baudrate(ifnet_t interface);
extern errno_t ifnet_stat_increment(ifnet_t interface,
const struct ifnet_stat_increment_param *counts);
extern errno_t ifnet_stat_increment_in(ifnet_t interface,
u_int32_t packets_in, u_int32_t bytes_in, u_int32_t errors_in);
extern errno_t ifnet_stat_increment_out(ifnet_t interface,
u_int32_t packets_out, u_int32_t bytes_out, u_int32_t errors_out);
extern errno_t ifnet_set_stat(ifnet_t interface,
const struct ifnet_stats_param *stats);
extern errno_t ifnet_stat(ifnet_t interface,
struct ifnet_stats_param *out_stats);
extern errno_t ifnet_set_promiscuous(ifnet_t interface, int on);
extern errno_t ifnet_touch_lastchange(ifnet_t interface);
extern errno_t ifnet_lastchange(ifnet_t interface, struct timeval *last_change);
extern errno_t ifnet_get_address_list(ifnet_t interface, ifaddr_t **addresses);
extern errno_t ifnet_get_address_list_family(ifnet_t interface,
ifaddr_t **addresses, sa_family_t family);
extern void ifnet_free_address_list(ifaddr_t *addresses);
extern errno_t ifnet_set_lladdr(ifnet_t interface, const void *lladdr,
size_t lladdr_len);
extern errno_t ifnet_lladdr_copy_bytes(ifnet_t interface, void *lladdr,
size_t length);
extern errno_t ifnet_llbroadcast_copy_bytes(ifnet_t interface, void *addr,
size_t bufferlen, size_t *out_len);
extern errno_t ifnet_resolve_multicast(ifnet_t ifp,
const struct sockaddr *proto_addr, struct sockaddr *ll_addr, size_t ll_len);
extern errno_t ifnet_add_multicast(ifnet_t interface,
const struct sockaddr *maddr, ifmultiaddr_t *multicast);
extern errno_t ifnet_remove_multicast(ifmultiaddr_t multicast);
extern errno_t ifnet_get_multicast_list(ifnet_t interface,
ifmultiaddr_t **addresses);
extern void ifnet_free_multicast_list(ifmultiaddr_t *multicasts);
extern errno_t ifnet_find_by_name(const char *ifname, ifnet_t *interface);
extern errno_t ifnet_list_get(ifnet_family_t family, ifnet_t **interfaces,
u_int32_t *count);
extern void ifnet_list_free(ifnet_t *interfaces);
extern errno_t ifaddr_reference(ifaddr_t ifaddr);
extern errno_t ifaddr_release(ifaddr_t ifaddr);
extern errno_t ifaddr_address(ifaddr_t ifaddr, struct sockaddr *out_addr,
u_int32_t addr_size);
extern sa_family_t ifaddr_address_family(ifaddr_t ifaddr);
extern errno_t ifaddr_dstaddress(ifaddr_t ifaddr, struct sockaddr *out_dstaddr,
u_int32_t dstaddr_size);
extern errno_t ifaddr_netmask(ifaddr_t ifaddr, struct sockaddr *out_netmask,
u_int32_t netmask_size);
extern ifnet_t ifaddr_ifnet(ifaddr_t ifaddr);
extern ifaddr_t ifaddr_withaddr(const struct sockaddr *address);
extern ifaddr_t ifaddr_withdstaddr(const struct sockaddr *destination);
extern ifaddr_t ifaddr_withnet(const struct sockaddr *net);
extern ifaddr_t ifaddr_withroute(int flags, const struct sockaddr *destination,
const struct sockaddr *gateway);
extern ifaddr_t ifaddr_findbestforaddr(const struct sockaddr *addr,
ifnet_t interface);
extern errno_t ifmaddr_reference(ifmultiaddr_t ifmaddr);
extern errno_t ifmaddr_release(ifmultiaddr_t ifmaddr);
extern errno_t ifmaddr_address(ifmultiaddr_t ifmaddr,
struct sockaddr *out_multicast, u_int32_t addr_size);
extern errno_t ifmaddr_lladdress(ifmultiaddr_t ifmaddr,
struct sockaddr *out_link_layer_multicast, u_int32_t addr_size);
extern ifnet_t ifmaddr_ifnet(ifmultiaddr_t ifmaddr);
enum {
BPF_TAP_DISABLE,
BPF_TAP_INPUT,
BPF_TAP_OUTPUT,
BPF_TAP_INPUT_OUTPUT
};
struct sockaddr_ndrv
{
unsigned char snd_len;
unsigned char snd_family;
unsigned char snd_name[IFNAMSIZ];
};
struct ndrv_demux_desc
{
u_int16_t type;
u_int16_t length;
union
{
u_int16_t ether_type;
u_int8_t sap[3];
u_int8_t snap[5];
u_int8_t other[28];
} data;
};
struct ndrv_protocol_desc
{
u_int32_t version;
u_int32_t protocol_family;
u_int32_t demux_count;
struct ndrv_demux_desc *demux_list;
};
struct utun_stats_param {
u_int64_t utsp_packets;
u_int64_t utsp_bytes;
u_int64_t utsp_errors;
};
struct net_event_data {
u_int32_t if_family;
u_int32_t if_unit;
char if_name[16];
};
struct timeval32
{
__int32_t tv_sec;
__int32_t tv_usec;
};
struct if_data {
u_char ifi_type;
u_char ifi_typelen;
u_char ifi_physical;
u_char ifi_addrlen;
u_char ifi_hdrlen;
u_char ifi_recvquota;
u_char ifi_xmitquota;
u_char ifi_unused1;
u_int32_t ifi_mtu;
u_int32_t ifi_metric;
u_int32_t ifi_baudrate;
u_int32_t ifi_ipackets;
u_int32_t ifi_ierrors;
u_int32_t ifi_opackets;
u_int32_t ifi_oerrors;
u_int32_t ifi_collisions;
u_int32_t ifi_ibytes;
u_int32_t ifi_obytes;
u_int32_t ifi_imcasts;
u_int32_t ifi_omcasts;
u_int32_t ifi_iqdrops;
u_int32_t ifi_noproto;
u_int32_t ifi_recvtiming;
u_int32_t ifi_xmittiming;
struct timeval32 ifi_lastchange;
u_int32_t ifi_unused2;
u_int32_t ifi_hwassist;
u_int32_t ifi_reserved1;
u_int32_t ifi_reserved2;
};
struct if_data64 {
u_char ifi_type;
u_char ifi_typelen;
u_char ifi_physical;
u_char ifi_addrlen;
u_char ifi_hdrlen;
u_char ifi_recvquota;
u_char ifi_xmitquota;
u_char ifi_unused1;
u_int32_t ifi_mtu;
u_int32_t ifi_metric;
u_int64_t ifi_baudrate;
u_int64_t ifi_ipackets;
u_int64_t ifi_ierrors;
u_int64_t ifi_opackets;
u_int64_t ifi_oerrors;
u_int64_t ifi_collisions;
u_int64_t ifi_ibytes;
u_int64_t ifi_obytes;
u_int64_t ifi_imcasts;
u_int64_t ifi_omcasts;
u_int64_t ifi_iqdrops;
u_int64_t ifi_noproto;
u_int32_t ifi_recvtiming;
u_int32_t ifi_xmittiming;
struct timeval32 ifi_lastchange;
};
struct ifqueue {
void *ifq_head;
void *ifq_tail;
int ifq_len;
int ifq_maxlen;
int ifq_drops;
};
typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
struct bpf_program {
u_int bf_len;
struct bpf_insn *bf_insns;
};
struct bpf_stat {
u_int bs_recv;
u_int bs_drop;
};
struct bpf_version {
u_short bv_major;
u_short bv_minor;
};
struct bpf_hdr {
struct timeval32 bh_tstamp;
bpf_u_int32 bh_caplen;
bpf_u_int32 bh_datalen;
u_short bh_hdrlen;
};
struct bpf_insn {
u_short code;
u_char jt;
u_char jf;
bpf_u_int32 k;
};
struct bpf_dltlist {
u_int32_t bfl_len;
union {
u_int32_t *bflu_list;
u_int64_t bflu_pad;
} bfl_u;
};
typedef errno_t (*bpf_send_func)(ifnet_t interface, u_int32_t data_link_type,
mbuf_t packet);
typedef errno_t (*bpf_tap_func)(ifnet_t interface, u_int32_t data_link_type,
bpf_tap_mode direction);
extern void bpfattach(ifnet_t interface, u_int data_link_type,
u_int header_length);
extern errno_t bpf_attach(ifnet_t interface, u_int32_t data_link_type,
u_int32_t header_length, bpf_send_func send, bpf_tap_func tap);
extern void bpf_tap_in(ifnet_t interface, u_int32_t dlt, mbuf_t packet,
void *header, size_t header_len);
extern void bpf_tap_out(ifnet_t interface, u_int32_t dlt, mbuf_t packet,
void *header, size_t header_len);
typedef __darwin_socklen_t socklen_t;
typedef __uint32_t sae_associd_t;
typedef __uint32_t sae_connid_t;
typedef struct sa_endpoints {
unsigned int sae_srcif;
const struct sockaddr *sae_srcaddr;
socklen_t sae_srcaddrlen;
const struct sockaddr *sae_dstaddr;
socklen_t sae_dstaddrlen;
} sa_endpoints_t;
struct linger {
int l_onoff;
int l_linger;
};
struct so_np_extensions {
u_int32_t npx_flags;
u_int32_t npx_mask;
};
struct sockaddr {
__uint8_t sa_len;
sa_family_t sa_family;
char sa_data[14];
};
struct sockproto {
__uint16_t sp_family;
__uint16_t sp_protocol;
};
struct sockaddr_storage {
__uint8_t ss_len;
sa_family_t ss_family;
char __ss_pad1[((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t))];
__int64_t __ss_align;
char __ss_pad2[(128 - sizeof(__uint8_t) - sizeof(sa_family_t) - ((sizeof(__int64_t)) - sizeof(__uint8_t) - sizeof(sa_family_t)) - (sizeof(__int64_t)))];
};
struct msghdr {
void *msg_name;
socklen_t msg_namelen;
struct iovec *msg_iov;
int msg_iovlen;
void *msg_control;
socklen_t msg_controllen;
int msg_flags;
};
struct cmsghdr {
socklen_t cmsg_len;
int cmsg_level;
int cmsg_type;
};
struct sf_hdtr {
struct iovec *headers;
int hdr_cnt;
struct iovec *trailers;
int trl_cnt;
};
struct user_sf_hdtr {
user_addr_t headers;
int hdr_cnt;
user_addr_t trailers;
int trl_cnt;
};
struct user64_sf_hdtr {
user64_addr_t headers;
int hdr_cnt;
user64_addr_t trailers;
int trl_cnt;
};
struct user32_sf_hdtr {
user32_addr_t headers;
int hdr_cnt;
user32_addr_t trailers;
int trl_cnt;
};
struct timeval;
typedef void (*sock_upcall)(socket_t so, void *cookie, int waitf);
extern errno_t sock_accept(socket_t so, struct sockaddr *from, int fromlen,
int flags, sock_upcall callback, void *cookie, socket_t *new_so);
extern errno_t sock_bind(socket_t so, const struct sockaddr *to);
extern errno_t sock_connect(socket_t so, const struct sockaddr *to, int flags);
extern errno_t sock_getpeername(socket_t so, struct sockaddr *peername,
int peernamelen);
extern errno_t sock_getsockname(socket_t so, struct sockaddr *sockname,
int socknamelen);
extern errno_t sock_getsockopt(socket_t so, int level, int optname,
void *optval, int *optlen);
extern errno_t sock_ioctl(socket_t so, unsigned long request, void *argp);
extern errno_t sock_setsockopt(socket_t so, int level, int optname,
const void *optval, int optlen);
extern errno_t sock_listen(socket_t so, int backlog);
extern errno_t sock_receive(socket_t so, struct msghdr *msg, int flags,
size_t *recvdlen);
extern errno_t sock_receivembuf(socket_t so, struct msghdr *msg, mbuf_t *data,
int flags, size_t *recvlen);
extern errno_t sock_send(socket_t so, const struct msghdr *msg, int flags,
size_t *sentlen);
extern errno_t sock_sendmbuf(socket_t so, const struct msghdr *msg, mbuf_t data,
int flags, size_t *sentlen);
extern errno_t sock_shutdown(socket_t so, int how);
extern errno_t sock_socket(int domain, int type, int protocol,
sock_upcall callback, void *cookie, socket_t *new_so);
extern void sock_close(socket_t so);
extern errno_t sock_setpriv(socket_t so, int on);
extern int sock_isconnected(socket_t so);
extern int sock_isnonblocking(socket_t so);
extern errno_t sock_gettype(socket_t so, int *domain, int *type, int *protocol);
struct rt_metrics {
u_int32_t rmx_locks;
u_int32_t rmx_mtu;
u_int32_t rmx_hopcount;
int32_t rmx_expire;
u_int32_t rmx_recvpipe;
u_int32_t rmx_sendpipe;
u_int32_t rmx_ssthresh;
u_int32_t rmx_rtt;
u_int32_t rmx_rttvar;
u_int32_t rmx_pksent;
u_int32_t rmx_state;
u_int32_t rmx_filler[3];
};
struct rtstat {
short rts_badredirect;
short rts_dynamic;
short rts_newgateway;
short rts_unreach;
short rts_wildcard;
short rts_badrtgwroute;
};
struct rt_msghdr {
u_short rtm_msglen;
u_char rtm_version;
u_char rtm_type;
u_short rtm_index;
int rtm_flags;
int rtm_addrs;
pid_t rtm_pid;
int rtm_seq;
int rtm_errno;
int rtm_use;
u_int32_t rtm_inits;
struct rt_metrics rtm_rmx;
};
struct rt_msghdr2 {
u_short rtm_msglen;
u_char rtm_version;
u_char rtm_type;
u_short rtm_index;
int rtm_flags;
int rtm_addrs;
int32_t rtm_refcnt;
int rtm_parentflags;
int rtm_reserved;
int rtm_use;
u_int32_t rtm_inits;
struct rt_metrics rtm_rmx;
};
struct rt_addrinfo {
int rti_addrs;
struct sockaddr *rti_info[8];
};
extern int ether_family_init(void);
errno_t ether_demux(ifnet_t interface, mbuf_t packet, char* header,
protocol_family_t *protocol);
errno_t ether_add_proto(ifnet_t interface, protocol_family_t protocol,
const struct ifnet_demux_desc *demux_list, u_int32_t demux_count);
errno_t ether_del_proto(ifnet_t interface, protocol_family_t protocol);
errno_t ether_frameout(ifnet_t interface, mbuf_t *packet,
const struct sockaddr *dest, const char *dest_lladdr,
const char *frame_type);
errno_t ether_ioctl(ifnet_t interface, u_int32_t command, void* data);
errno_t ether_check_multi(ifnet_t ifp, const struct sockaddr *multicast);
struct llc {
u_int8_t llc_dsap;
u_int8_t llc_ssap;
union {
struct {
u_int8_t control;
u_int8_t format_id;
u_int8_t class_id;
u_int8_t window_x2;
} type_u;
struct {
u_int8_t num_snd_x2;
u_int8_t num_rcv_x2;
} type_i;
struct {
u_int8_t control;
u_int8_t num_rcv_x2;
} type_s;
struct {
u_int8_t control;
u_int8_t frmr_rej_pdu0;
u_int8_t frmr_rej_pdu1;
u_int8_t frmr_control;
u_int8_t frmr_control_ext;
u_int8_t frmr_cause;
} type_frmr;
struct {
u_int8_t control;
u_int8_t org_code[3];
u_int16_t ether_type;
} type_snap ;
struct {
u_int8_t control;
u_int8_t control_ext;
} type_raw;
} llc_un;
} ;
struct frmrinfo {
u_int8_t frmr_rej_pdu0;
u_int8_t frmr_rej_pdu1;
u_int8_t frmr_control;
u_int8_t frmr_control_ext;
u_int8_t frmr_cause;
} ;
extern errno_t proto_input(protocol_family_t protocol, mbuf_t packet);
extern errno_t proto_inject(protocol_family_t protocol, mbuf_t packet);
typedef errno_t (*proto_plumb_handler)(ifnet_t ifp, protocol_family_t protocol);
typedef void (*proto_unplumb_handler)(ifnet_t ifp, protocol_family_t protocol);
extern errno_t proto_register_plumber(protocol_family_t proto_fam,
ifnet_family_t if_fam, proto_plumb_handler plumb,
proto_unplumb_handler unplumb);
extern void proto_unregister_plumber(protocol_family_t proto_fam,
ifnet_family_t if_fam);
struct if_clonereq {
int ifcr_total;
int ifcr_count;
char *ifcr_buffer;
};
struct if_msghdr {
unsigned short ifm_msglen;
unsigned char ifm_version;
unsigned char ifm_type;
int ifm_addrs;
int ifm_flags;
unsigned short ifm_index;
struct if_data ifm_data;
};
struct ifa_msghdr {
unsigned short ifam_msglen;
unsigned char ifam_version;
unsigned char ifam_type;
int ifam_addrs;
int ifam_flags;
unsigned short ifam_index;
int ifam_metric;
};
struct ifma_msghdr {
unsigned short ifmam_msglen;
unsigned char ifmam_version;
unsigned char ifmam_type;
int ifmam_addrs;
int ifmam_flags;
unsigned short ifmam_index;
};
struct if_msghdr2 {
u_short ifm_msglen;
u_char ifm_version;
u_char ifm_type;
int ifm_addrs;
int ifm_flags;
u_short ifm_index;
int ifm_snd_len;
int ifm_snd_maxlen;
int ifm_snd_drops;
int ifm_timer;
struct if_data64 ifm_data;
};
struct ifma_msghdr2 {
u_short ifmam_msglen;
u_char ifmam_version;
u_char ifmam_type;
int ifmam_addrs;
int ifmam_flags;
u_short ifmam_index;
int32_t ifmam_refcount;
};
struct ifdevmtu {
int ifdm_current;
int ifdm_min;
int ifdm_max;
};
struct ifkpi {
unsigned int ifk_module_id;
unsigned int ifk_type;
union {
void *ifk_ptr;
int ifk_value;
u_int64_t ifk_ptr64;
} ifk_data;
};
struct ifreq {
char ifr_name[16];
union {
struct sockaddr ifru_addr;
struct sockaddr ifru_dstaddr;
struct sockaddr ifru_broadaddr;
short ifru_flags;
int ifru_metric;
int ifru_mtu;
int ifru_phys;
int ifru_media;
int ifru_intval;
caddr_t ifru_data;
struct ifdevmtu ifru_devmtu;
struct ifkpi ifru_kpi;
u_int32_t ifru_wake_flags;
u_int32_t ifru_route_refcnt;
int ifru_cap[2];
u_int32_t ifru_functional_type;
} ifr_ifru;
};
struct ifaliasreq {
char ifra_name[16];
struct sockaddr ifra_addr;
struct sockaddr ifra_broadaddr;
struct sockaddr ifra_mask;
};
struct rslvmulti_req {
struct sockaddr *sa;
struct sockaddr **llsa;
};
struct ifdrv {
char ifd_name[16];
unsigned long ifd_cmd;
size_t ifd_len;
void *ifd_data;
};
struct ifstat {
char ifs_name[16];
char ascii[800 + 1];
};
struct kev_dl_proto_data {
struct net_event_data link_data;
u_int32_t proto_family;
u_int32_t proto_remaining_count;
};
struct sadb_msg {
u_int8_t sadb_msg_version;
u_int8_t sadb_msg_type;
u_int8_t sadb_msg_errno;
u_int8_t sadb_msg_satype;
u_int16_t sadb_msg_len;
u_int16_t sadb_msg_reserved;
u_int32_t sadb_msg_seq;
u_int32_t sadb_msg_pid;
};
struct sadb_ext {
u_int16_t sadb_ext_len;
u_int16_t sadb_ext_type;
};
struct sadb_sa {
u_int16_t sadb_sa_len;
u_int16_t sadb_sa_exttype;
u_int32_t sadb_sa_spi;
u_int8_t sadb_sa_replay;
u_int8_t sadb_sa_state;
u_int8_t sadb_sa_auth;
u_int8_t sadb_sa_encrypt;
u_int32_t sadb_sa_flags;
};
struct sadb_lifetime {
u_int16_t sadb_lifetime_len;
u_int16_t sadb_lifetime_exttype;
u_int32_t sadb_lifetime_allocations;
u_int64_t sadb_lifetime_bytes;
u_int64_t sadb_lifetime_addtime;
u_int64_t sadb_lifetime_usetime;
};
struct sadb_address {
u_int16_t sadb_address_len;
u_int16_t sadb_address_exttype;
u_int8_t sadb_address_proto;
u_int8_t sadb_address_prefixlen;
u_int16_t sadb_address_reserved;
};
struct sadb_key {
u_int16_t sadb_key_len;
u_int16_t sadb_key_exttype;
u_int16_t sadb_key_bits;
u_int16_t sadb_key_reserved;
};
struct sadb_ident {
u_int16_t sadb_ident_len;
u_int16_t sadb_ident_exttype;
u_int16_t sadb_ident_type;
u_int16_t sadb_ident_reserved;
u_int64_t sadb_ident_id;
};
struct sadb_sens {
u_int16_t sadb_sens_len;
u_int16_t sadb_sens_exttype;
u_int32_t sadb_sens_dpd;
u_int8_t sadb_sens_sens_level;
u_int8_t sadb_sens_sens_len;
u_int8_t sadb_sens_integ_level;
u_int8_t sadb_sens_integ_len;
u_int32_t sadb_sens_reserved;
};
struct sadb_prop {
u_int16_t sadb_prop_len;
u_int16_t sadb_prop_exttype;
u_int8_t sadb_prop_replay;
u_int8_t sadb_prop_reserved[3];
};
struct sadb_comb {
u_int8_t sadb_comb_auth;
u_int8_t sadb_comb_encrypt;
u_int16_t sadb_comb_flags;
u_int16_t sadb_comb_auth_minbits;
u_int16_t sadb_comb_auth_maxbits;
u_int16_t sadb_comb_encrypt_minbits;
u_int16_t sadb_comb_encrypt_maxbits;
u_int32_t sadb_comb_reserved;
u_int32_t sadb_comb_soft_allocations;
u_int32_t sadb_comb_hard_allocations;
u_int64_t sadb_comb_soft_bytes;
u_int64_t sadb_comb_hard_bytes;
u_int64_t sadb_comb_soft_addtime;
u_int64_t sadb_comb_hard_addtime;
u_int64_t sadb_comb_soft_usetime;
u_int64_t sadb_comb_hard_usetime;
};
struct sadb_supported {
u_int16_t sadb_supported_len;
u_int16_t sadb_supported_exttype;
u_int32_t sadb_supported_reserved;
};
struct sadb_alg {
u_int8_t sadb_alg_id;
u_int8_t sadb_alg_ivlen;
u_int16_t sadb_alg_minbits;
u_int16_t sadb_alg_maxbits;
u_int16_t sadb_alg_reserved;
};
struct sadb_spirange {
u_int16_t sadb_spirange_len;
u_int16_t sadb_spirange_exttype;
u_int32_t sadb_spirange_min;
u_int32_t sadb_spirange_max;
u_int32_t sadb_spirange_reserved;
};
struct sadb_x_kmprivate {
u_int16_t sadb_x_kmprivate_len;
u_int16_t sadb_x_kmprivate_exttype;
u_int32_t sadb_x_kmprivate_reserved;
};
struct sadb_x_sa2 {
u_int16_t sadb_x_sa2_len;
u_int16_t sadb_x_sa2_exttype;
u_int8_t sadb_x_sa2_mode;
union {
u_int8_t sadb_x_sa2_reserved1;
};
union {
u_int16_t sadb_x_sa2_reserved2;
};
u_int32_t sadb_x_sa2_sequence;
u_int32_t sadb_x_sa2_reqid;
};
struct sadb_x_policy {
u_int16_t sadb_x_policy_len;
u_int16_t sadb_x_policy_exttype;
u_int16_t sadb_x_policy_type;
u_int8_t sadb_x_policy_dir;
u_int8_t sadb_x_policy_reserved;
u_int32_t sadb_x_policy_id;
u_int32_t sadb_x_policy_reserved2;
};
struct sadb_x_ipsecrequest {
u_int16_t sadb_x_ipsecrequest_len;
u_int16_t sadb_x_ipsecrequest_proto;
u_int8_t sadb_x_ipsecrequest_mode;
u_int8_t sadb_x_ipsecrequest_level;
u_int16_t sadb_x_ipsecrequest_reqid;
};
struct sadb_session_id {
u_int16_t sadb_session_id_len;
u_int16_t sadb_session_id_exttype;
u_int64_t sadb_session_id_v[2];
} ;
struct sastat {
u_int32_t spi;
u_int32_t created;
struct sadb_lifetime lft_c;
};
struct sadb_sastat {
u_int16_t sadb_sastat_len;
u_int16_t sadb_sastat_exttype;
u_int32_t sadb_sastat_dir;
u_int32_t sadb_sastat_reserved;
u_int32_t sadb_sastat_list_len;
} ;
struct ifmibdata {
char ifmd_name[16];
unsigned int ifmd_pcount;
unsigned int ifmd_flags;
unsigned int ifmd_snd_len;
unsigned int ifmd_snd_maxlen;
unsigned int ifmd_snd_drops;
unsigned int ifmd_filler[4];
struct if_data64 ifmd_data;
};
struct ifs_iso_8802_3 {
u_int32_t dot3StatsAlignmentErrors;
u_int32_t dot3StatsFCSErrors;
u_int32_t dot3StatsSingleCollisionFrames;
u_int32_t dot3StatsMultipleCollisionFrames;
u_int32_t dot3StatsSQETestErrors;
u_int32_t dot3StatsDeferredTransmissions;
u_int32_t dot3StatsLateCollisions;
u_int32_t dot3StatsExcessiveCollisions;
u_int32_t dot3StatsInternalMacTransmitErrors;
u_int32_t dot3StatsCarrierSenseErrors;
u_int32_t dot3StatsFrameTooLongs;
u_int32_t dot3StatsInternalMacReceiveErrors;
u_int32_t dot3StatsEtherChipSet;
u_int32_t dot3StatsMissedFrames;
u_int32_t dot3StatsCollFrequencies[16];
u_int32_t dot3Compliance;
};
enum dot3Vendors {
dot3VendorAMD = 1,
dot3VendorIntel = 2,
dot3VendorNational = 4,
dot3VendorFujitsu = 5,
dot3VendorDigital = 6,
dot3VendorWesternDigital = 7
};
enum {
dot3ChipSetAMD7990 = 1,
dot3ChipSetAMD79900 = 2,
dot3ChipSetAMD79C940 = 3
};
enum {
dot3ChipSetIntel82586 = 1,
dot3ChipSetIntel82596 = 2,
dot3ChipSetIntel82557 = 3
};
enum {
dot3ChipSetNational8390 = 1,
dot3ChipSetNationalSonic = 2
};
enum {
dot3ChipSetFujitsu86950 = 1
};
enum {
dot3ChipSetDigitalDC21040 = 1,
dot3ChipSetDigitalDC21140 = 2,
dot3ChipSetDigitalDC21041 = 3,
dot3ChipSetDigitalDC21140A = 4,
dot3ChipSetDigitalDC21142 = 5
};
enum {
dot3ChipSetWesternDigital83C690 = 1,
dot3ChipSetWesternDigital83C790 = 2
};
struct if_family_id {
u_int32_t iffmid_len;
u_int32_t iffmid_id;
char iffmid_str[1];
};
struct ether_header {
u_char ether_dhost[6];
u_char ether_shost[6];
u_short ether_type;
};
struct ether_addr {
u_char octet[6];
};
struct ifmedia_description {
int ifmt_word;
const char *ifmt_string;
};
struct sockaddr_dl {
u_char sdl_len;
u_char sdl_family;
u_short sdl_index;
u_char sdl_type;
u_char sdl_nlen;
u_char sdl_alen;
u_char sdl_slen;
char sdl_data[12];
};
struct in_addr {
in_addr_t s_addr;
};
struct sockaddr_in {
__uint8_t sin_len;
sa_family_t sin_family;
in_port_t sin_port;
struct in_addr sin_addr;
char sin_zero[8];
};
struct ip_opts {
struct in_addr ip_dst;
char ip_opts[40];
};
struct ip_mreq {
struct in_addr imr_multiaddr;
struct in_addr imr_interface;
};
struct ip_mreqn {
struct in_addr imr_multiaddr;
struct in_addr imr_address;
int imr_ifindex;
};
struct ip_mreq_source {
struct in_addr imr_multiaddr;
struct in_addr imr_sourceaddr;
struct in_addr imr_interface;
};
struct group_req {
uint32_t gr_interface;
struct sockaddr_storage gr_group;
};
struct group_source_req {
uint32_t gsr_interface;
struct sockaddr_storage gsr_group;
struct sockaddr_storage gsr_source;
};
struct __msfilterreq {
uint32_t msfr_ifindex;
uint32_t msfr_fmode;
uint32_t msfr_nsrcs;
uint32_t __msfr_align;
struct sockaddr_storage msfr_group;
struct sockaddr_storage *msfr_srcs;
};
struct sockaddr;
struct in_pktinfo {
unsigned int ipi_ifindex;
struct in_addr ipi_spec_dst;
struct in_addr ipi_addr;
};
struct in6_addr {
union {
__uint8_t __u6_addr8[16];
__uint16_t __u6_addr16[8];
__uint32_t __u6_addr32[4];
} __u6_addr;
};
struct sockaddr_in6 {
__uint8_t sin6_len;
sa_family_t sin6_family;
in_port_t sin6_port;
__uint32_t sin6_flowinfo;
struct in6_addr sin6_addr;
__uint32_t sin6_scope_id;
};
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;
extern const struct in6_addr in6addr_nodelocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allrouters;
extern const struct in6_addr in6addr_linklocal_allv2routers;
struct ipv6_mreq {
struct in6_addr ipv6mr_multiaddr;
unsigned int ipv6mr_interface;
};
struct in6_pktinfo {
struct in6_addr ipi6_addr;
unsigned int ipi6_ifindex;
};
struct ip6_mtuinfo {
struct sockaddr_in6 ip6m_addr;
uint32_t ip6m_mtu;
};
extern int inet_aton(const char *, struct in_addr *);
extern const char *inet_ntop(int, const void *, char *, socklen_t);
struct arphdr {
u_short ar_hrd;
u_short ar_pro;
u_char ar_hln;
u_char ar_pln;
u_short ar_op;
};
struct arpreq {
struct sockaddr arp_pa;
struct sockaddr arp_ha;
int arp_flags;
};
struct arpstat {
uint32_t txrequests;
uint32_t txreplies;
uint32_t txannounces;
uint32_t rxrequests;
uint32_t rxreplies;
uint32_t received;
uint32_t txconflicts;
uint32_t invalidreqs;
uint32_t reqnobufs;
uint32_t dropped;
uint32_t purged;
uint32_t timeouts;
uint32_t dupips;
uint32_t inuse;
uint32_t txurequests;
uint32_t held;
};
struct kev_msg;
typedef errno_t (*iff_input_func)(void *cookie, ifnet_t interface,
protocol_family_t protocol, mbuf_t *data, char **frame_ptr);
typedef errno_t (*iff_output_func)(void *cookie, ifnet_t interface,
protocol_family_t protocol, mbuf_t *data);
typedef void (*iff_event_func)(void *cookie, ifnet_t interface,
protocol_family_t protocol, const struct kev_msg *event_msg);
typedef errno_t (*iff_ioctl_func)(void *cookie, ifnet_t interface,
protocol_family_t protocol, unsigned long ioctl_cmd, void *ioctl_arg);
typedef void (*iff_detached_func)(void *cookie, ifnet_t interface);
struct iff_filter {
void *iff_cookie;
const char *iff_name;
protocol_family_t iff_protocol;
iff_input_func iff_input;
iff_output_func iff_output;
iff_event_func iff_event;
iff_ioctl_func iff_ioctl;
iff_detached_func iff_detached;
};
extern errno_t iflt_attach(ifnet_t interface, const struct iff_filter *filter,
interface_filter_t *filter_ref);
extern void iflt_detach(interface_filter_t filter_ref);
typedef void (*net_init_func_ptr)(void);
errno_t net_init_add(net_init_func_ptr init_func);
struct so_nke {
unsigned int nke_handle;
unsigned int nke_where;
int nke_flags;
u_int32_t reserved[4];
};
typedef int __darwin_nl_item;
typedef int __darwin_wctrans_t;
typedef __uint32_t __darwin_wctype_t;
typedef __darwin_va_list va_list;
typedef __darwin_off_t fpos_t;
struct __sbuf {
unsigned char *_base;
int _size;
};
struct __sFILEX;
typedef struct __sFILE {
unsigned char *_p;
int _r;
int _w;
short _flags;
short _file;
struct __sbuf _bf;
int _lbfsize;
void *_cookie;
int (*  _close)(void *);
int (*  _read) (void *, char *, int);
fpos_t (*  _seek) (void *, fpos_t, int);
int (*  _write)(void *, const char *, int);
struct __sbuf _ub;
struct __sFILEX *_extra;
int _ur;
unsigned char _ubuf[3];
unsigned char _nbuf[1];
struct __sbuf _lb;
int _blksize;
fpos_t _offset;
} FILE;
extern FILE *__stdinp;
extern FILE *__stdoutp;
extern FILE *__stderrp;
void clearerr(FILE *);
int fclose(FILE *);
int feof(FILE *);
int ferror(FILE *);
int fflush(FILE *);
int fgetc(FILE *);
int fgetpos(FILE *, fpos_t *);
char *fgets(char *, int, FILE *);
FILE *fopen(const char * __filename, const char * __mode) ;
int fprintf(FILE *, const char *, ...) ;
int fputc(int, FILE *);
int fputs(const char *, FILE *) ;
size_t fread(void * __ptr, size_t __size, size_t __nitems, FILE * __stream);
FILE *freopen(const char *, const char *,
FILE *) ;
int fscanf(FILE *, const char *, ...) ;
int fseek(FILE *, long, int);
int fsetpos(FILE *, const fpos_t *);
long ftell(FILE *);
size_t fwrite(const void * __ptr, size_t __size, size_t __nitems, FILE * __stream) ;
int getc(FILE *);
int getchar(void);
char *gets(char *);
void perror(const char *);
int printf(const char *, ...) ;
int putc(int, FILE *);
int putchar(int);
int puts(const char *);
int remove(const char *);
int rename (const char *__old, const char *__new);
void rewind(FILE *);
int scanf(const char *, ...) ;
void setbuf(FILE *, char *);
int setvbuf(FILE *, char *, int, size_t);
int sprintf(char *, const char *, ...)  ;
int sscanf(const char *, const char *, ...) ;
FILE *tmpfile(void);


char *tmpnam(char *);
int ungetc(int, FILE *);
int vfprintf(FILE *, const char *, va_list) ;
int vprintf(const char *, va_list) ;
int vsprintf(char *, const char *, va_list)  ;
char *ctermid(char *);
FILE *fdopen(int, const char *) ;
int fileno(FILE *);
int pclose(FILE *) ;
FILE *popen(const char *, const char *) ;
int __srget(FILE *);
int __svfscanf(FILE *, const char *, va_list) ;
int __swbuf(int, FILE *);
inline  int __sputc(int _c, FILE *_p) {
if (--_p->_w >= 0 || (_p->_w >= _p->_lbfsize && (char)_c != '\n'))
return (*_p->_p++ = _c);
else
return (__swbuf(_c, _p));
}
void flockfile(FILE *);
int ftrylockfile(FILE *);
void funlockfile(FILE *);
int getc_unlocked(FILE *);
int getchar_unlocked(void);
int putc_unlocked(int, FILE *);
int putchar_unlocked(int);
int getw(FILE *);
int putw(int, FILE *);


char *tempnam(const char *__dir, const char *__prefix) ;
int fseeko(FILE * __stream, off_t __offset, int __whence);
off_t ftello(FILE * __stream);
int snprintf(char * __str, size_t __size, const char *  ...) ;
int vfscanf(FILE * __stream, const char *  va_list) ;
int vscanf(const char *  va_list) ;
int vsnprintf(char * __str, size_t __size, const char *  va_list) ;
int vsscanf(const char * __str, const char *  va_list) ;
int dprintf(int, const char *, ...)  ;
int vdprintf(int, const char *, va_list)  ;
ssize_t getdelim(char ** __linep, size_t * __linecapp, int __delimiter, FILE * __stream) ;
ssize_t getline(char ** __linep, size_t * __linecapp, FILE * __stream) ;
FILE *fmemopen(void * __buf, size_t __size, const char * __mode)    ;
FILE *open_memstream(char **__bufp, size_t *__sizep)    ;
extern const int sys_nerr;
extern const char *const sys_errlist[];
int asprintf(char **, const char *, ...) ;
char *ctermid_r(char *);
char *fgetln(FILE *, size_t *);
const char *fmtcheck(const char *, const char *);
int fpurge(FILE *);
void setbuffer(FILE *, char *, int);
int setlinebuf(FILE *);
int vasprintf(char **, const char *, va_list) ;
FILE *zopen(const char *, const char *, int);
FILE *funopen(const void *,
int (* )(void *, char *, int),
int (* )(void *, const char *, int),
fpos_t (* )(void *, fpos_t, int),
int (* )(void *));
extern int __sprintf_chk (char *, int, size_t,
const char *, ...);
extern int __snprintf_chk (char *, size_t, int, size_t,
const char *, ...);
extern int __vsprintf_chk (char *, int, size_t,
const char *, va_list);
extern int __vsnprintf_chk (char *, size_t, int, size_t,
const char *, va_list);
struct auditpipe_ioctl_preselect {
au_id_t aip_auid;
au_mask_t aip_mask;
};
struct pfkeystat {
u_quad_t out_total;
u_quad_t out_bytes;
u_quad_t out_msgtype[256];
u_quad_t out_invlen;
u_quad_t out_invver;
u_quad_t out_invmsgtype;
u_quad_t out_tooshort;
u_quad_t out_nomem;
u_quad_t out_dupext;
u_quad_t out_invexttype;
u_quad_t out_invsatype;
u_quad_t out_invaddr;
u_quad_t in_total;
u_quad_t in_bytes;
u_quad_t in_msgtype[256];
u_quad_t in_msgtarget[3];
u_quad_t in_nomem;
u_quad_t sockerr;
};
typedef uint32_t bank_action_t;
struct proc_persona_info {
uint64_t unique_pid;
int32_t pid;
uint32_t flags;
uint32_t pidversion;
uint32_t persona_id;
uint32_t uid;
uint32_t gid;
uint8_t macho_uuid[16];
};
struct persona_token {
struct proc_persona_info originator;
struct proc_persona_info proximate;
};
typedef uint32_t atm_action_t;
typedef uint64_t atm_guard_t;
typedef uint64_t aid_t;
typedef uint64_t subaid_t;
typedef uint64_t mailbox_offset_t;
typedef uint64_t atm_aid_t;
typedef uint32_t atm_subaid32_t;
typedef uint64_t mach_atm_subaid_t;
typedef uint64_t atm_mailbox_offset_t;
typedef mach_port_t atm_memory_descriptor_t;
typedef atm_memory_descriptor_t *atm_memory_descriptor_array_t;
typedef uint64_t *atm_memory_size_array_t;
//typedef __typeof__(((int*)0)-((int*)0)) ptrdiff_t;
typedef int wchar_t;
static inline uint16_t get_es(void)
{
uint16_t es;
;
return es;
}
static inline void set_es(uint16_t es)
{
;
}
static inline uint16_t get_ds(void)
{
uint16_t ds;
;
return ds;
}
static inline void set_ds(uint16_t ds)
{
;
}
static inline uint16_t get_fs(void)
{
uint16_t fs;
;
return fs;
}
static inline void set_fs(uint16_t fs)
{
;
}
static inline uint16_t get_gs(void)
{
uint16_t gs;
;
return gs;
}
static inline void set_gs(uint16_t gs)
{
;
}
static inline uint16_t get_ss(void)
{
uint16_t ss;
;
return ss;
}
static inline void set_ss(uint16_t ss)
{
;
}
static inline uintptr_t get_cr0(void)
{
uintptr_t cr0;
;
return(cr0);
}
static inline void set_cr0(uintptr_t value)
{
;
}
static inline uintptr_t get_cr2(void)
{
uintptr_t cr2;
;
return(cr2);
}
static inline uintptr_t get_cr3_raw(void)
{
uintptr_t cr3;
;
return(cr3);
}
static inline void set_cr3_raw(uintptr_t value)
{
;
}
static inline uintptr_t get_cr3_base(void)
{
uintptr_t cr3;
;
return(cr3 & ~(0xFFFULL));
}
static inline void set_cr3_composed(uintptr_t base, uint16_t pcid, uint64_t preserve)
{
;
}
static inline uintptr_t get_cr4(void)
{
uintptr_t cr4;
;
return(cr4);
}
static inline void set_cr4(uintptr_t value)
{
;
}
static inline uintptr_t x86_get_flags(void)
{
uintptr_t erflags;
;
return erflags;
}
static inline void clear_ts(void)
{
;
}
static inline unsigned short get_tr(void)
{
unsigned short seg;
;
return(seg);
}
static inline void set_tr(unsigned int seg)
{
;
}
static inline unsigned short sldt(void)
{
unsigned short seg;
;
return(seg);
}
static inline void lldt(unsigned int seg)
{
;
}
static inline void lgdt(uintptr_t *desc)
{
;
}
static inline void lidt(uintptr_t *desc)
{
;
}
static inline void swapgs(void)
{
;
}
static inline void hlt(void)
{
;
}
static inline void wbinvd(void)
{
;
}
static inline void invlpg(uintptr_t addr)
{
;
}
static inline void clac(void)
{
;
}
static inline void stac(void)
{
;
}
static inline uint64_t rdpmc64(uint32_t pmc)
{
uint32_t lo=0, hi=0;
;
return (((uint64_t)hi) << 32) | ((uint64_t)lo);
}
static inline uint64_t rdmsr64(uint32_t msr)
{
uint32_t lo=0, hi=0;
;
return (((uint64_t)hi) << 32) | ((uint64_t)lo);
}
static inline void wrmsr64(uint32_t msr, uint64_t val)
{
;
}
static inline uint64_t rdtsc64(void)
{
uint64_t lo, hi;
;
return ((hi) << 32) | (lo);
}
static inline uint64_t rdtscp64(uint32_t *aux)
{
uint64_t lo, hi;
__asm__ volatile("rdtscp; mov %%ecx, %1"
: "=a" (lo), "=d" (hi), "=m" (*aux)
:
: "ecx");
return ((hi) << 32) | (lo);
}
extern int rdmsr_carefully(uint32_t msr, uint32_t *lo, uint32_t *hi);
typedef enum { eax, ebx, ecx, edx } cpuid_register_t;
static inline void
cpuid(uint32_t *data)
{
__asm__ volatile ("cpuid"
: "=a" (data[eax]),
"=b" (data[ebx]),
"=c" (data[ecx]),
"=d" (data[edx])
: "a" (data[eax]),
"b" (data[ebx]),
"c" (data[ecx]),
"d" (data[edx]));
}
static inline void
do_cpuid(uint32_t selector, uint32_t *data)
{
__asm__ volatile ("cpuid"
: "=a" (data[0]),
"=b" (data[1]),
"=c" (data[2]),
"=d" (data[3])
: "a"(selector),
"b" (0),
"c" (0),
"d" (0));
}
typedef enum { Lnone, L1I, L1D, L2U, L3U, LCACHE_MAX } cache_type_t ;
typedef struct {
unsigned char value;
cache_type_t type;
unsigned int size;
unsigned int linesize;
const char *description;
} cpuid_cache_desc_t;
typedef struct {
uint32_t linesize_min;
uint32_t linesize_max;
uint32_t extensions;
uint32_t sub_Cstates;
} cpuid_mwait_leaf_t;
typedef struct {
boolean_t sensor;
boolean_t dynamic_acceleration;
boolean_t invariant_APIC_timer;
boolean_t core_power_limits;
boolean_t fine_grain_clock_mod;
boolean_t package_thermal_intr;
uint32_t thresholds;
boolean_t ACNT_MCNT;
boolean_t hardware_feedback;
boolean_t energy_policy;
} cpuid_thermal_leaf_t;
typedef struct {
uint32_t extended_state[4];
} cpuid_xsave_leaf_t;
typedef struct {
uint8_t version;
uint8_t number;
uint8_t width;
uint8_t events_number;
uint32_t events;
uint8_t fixed_number;
uint8_t fixed_width;
} cpuid_arch_perf_leaf_t;
typedef struct {
uint32_t numerator;
uint32_t denominator;
} cpuid_tsc_leaf_t;
typedef struct {
char cpuid_vendor[16];
char cpuid_brand_string[48];
const char *cpuid_model_string;
cpu_type_t cpuid_type;
uint8_t cpuid_family;
uint8_t cpuid_model;
uint8_t cpuid_extmodel;
uint8_t cpuid_extfamily;
uint8_t cpuid_stepping;
uint64_t cpuid_features;
uint64_t cpuid_extfeatures;
uint32_t cpuid_signature;
uint8_t cpuid_brand;
uint8_t cpuid_processor_flag;
uint32_t cache_size[LCACHE_MAX];
uint32_t cache_linesize;
uint8_t cache_info[64];
uint32_t cpuid_cores_per_package;
uint32_t cpuid_logical_per_package;
uint32_t cache_sharing[LCACHE_MAX];
uint32_t cache_partitions[LCACHE_MAX];
cpu_type_t cpuid_cpu_type;
cpu_subtype_t cpuid_cpu_subtype;
cpuid_mwait_leaf_t cpuid_mwait_leaf;
cpuid_thermal_leaf_t cpuid_thermal_leaf;
cpuid_arch_perf_leaf_t cpuid_arch_perf_leaf;
uint32_t unused[4];
uint32_t cpuid_cache_linesize;
uint32_t cpuid_cache_L2_associativity;
uint32_t cpuid_cache_size;
uint32_t cpuid_address_bits_physical;
uint32_t cpuid_address_bits_virtual;
uint32_t cpuid_microcode_version;
uint32_t cpuid_tlb[2][2][2];
uint32_t cpuid_stlb;
uint32_t core_count;
uint32_t thread_count;
uint32_t cpuid_max_basic;
uint32_t cpuid_max_ext;
uint32_t cpuid_cpufamily;
cpuid_mwait_leaf_t *cpuid_mwait_leafp;
cpuid_thermal_leaf_t *cpuid_thermal_leafp;
cpuid_arch_perf_leaf_t *cpuid_arch_perf_leafp;
cpuid_xsave_leaf_t *cpuid_xsave_leafp;
uint64_t cpuid_leaf7_features;
cpuid_tsc_leaf_t cpuid_tsc_leaf;
cpuid_xsave_leaf_t cpuid_xsave_leaf[2];
} i386_cpu_info_t;
extern cpu_type_t cpuid_cputype(void);
extern cpu_subtype_t cpuid_cpusubtype(void);
extern void cpuid_cpu_display(const char *);
extern void cpuid_feature_display(const char *);
extern void cpuid_extfeature_display(const char *);
extern char * cpuid_get_feature_names(uint64_t, char *, unsigned);
extern char * cpuid_get_extfeature_names(uint64_t, char *, unsigned);
extern char * cpuid_get_leaf7_feature_names(uint64_t, char *, unsigned);
extern uint64_t cpuid_features(void);
extern uint64_t cpuid_extfeatures(void);
extern uint64_t cpuid_leaf7_features(void);
extern uint32_t cpuid_family(void);
extern uint32_t cpuid_cpufamily(void);
extern i386_cpu_info_t *cpuid_info(void);
extern void cpuid_set_info(void);
int host_vmxon(boolean_t exclusive);
void host_vmxoff(void);
typedef struct ipc_info_space {
natural_t iis_genno_mask;
natural_t iis_table_size;
natural_t iis_table_next;
natural_t iis_tree_size;
natural_t iis_tree_small;
natural_t iis_tree_hash;
} ipc_info_space_t;
typedef struct ipc_info_space_basic {
natural_t iisb_genno_mask;
natural_t iisb_table_size;
natural_t iisb_table_next;
natural_t iisb_table_inuse;
natural_t iisb_reserved[2];
} ipc_info_space_basic_t;
typedef struct ipc_info_name {
mach_port_name_t iin_name;
integer_t iin_collision;
mach_port_type_t iin_type;
mach_port_urefs_t iin_urefs;
natural_t iin_object;
natural_t iin_next;
natural_t iin_hash;
} ipc_info_name_t;
typedef ipc_info_name_t *ipc_info_name_array_t;
typedef struct ipc_info_tree_name {
ipc_info_name_t iitn_name;
mach_port_name_t iitn_lchild;
mach_port_name_t iitn_rchild;
} ipc_info_tree_name_t;
typedef ipc_info_tree_name_t *ipc_info_tree_name_array_t;
typedef struct mach_vm_info_region {
mach_vm_offset_t vir_start;
mach_vm_offset_t vir_end;
mach_vm_offset_t vir_object;
memory_object_offset_t vir_offset;
boolean_t vir_needs_copy;
vm_prot_t vir_protection;
vm_prot_t vir_max_protection;
vm_inherit_t vir_inheritance;
natural_t vir_wired_count;
natural_t vir_user_wired_count;
} mach_vm_info_region_t;
typedef struct vm_info_region_64 {
natural_t vir_start;
natural_t vir_end;
natural_t vir_object;
memory_object_offset_t vir_offset;
boolean_t vir_needs_copy;
vm_prot_t vir_protection;
vm_prot_t vir_max_protection;
vm_inherit_t vir_inheritance;
natural_t vir_wired_count;
natural_t vir_user_wired_count;
} vm_info_region_64_t;
typedef struct vm_info_region {
natural_t vir_start;
natural_t vir_end;
natural_t vir_object;
natural_t vir_offset;
boolean_t vir_needs_copy;
vm_prot_t vir_protection;
vm_prot_t vir_max_protection;
vm_inherit_t vir_inheritance;
natural_t vir_wired_count;
natural_t vir_user_wired_count;
} vm_info_region_t;
typedef struct vm_info_object {
natural_t vio_object;
natural_t vio_size;
unsigned int vio_ref_count;
unsigned int vio_resident_page_count;
unsigned int vio_absent_count;
natural_t vio_copy;
natural_t vio_shadow;
natural_t vio_shadow_offset;
natural_t vio_paging_offset;
memory_object_copy_strategy_t vio_copy_strategy;
vm_offset_t vio_last_alloc;
unsigned int vio_paging_in_progress;
boolean_t vio_pager_created;
boolean_t vio_pager_initialized;
boolean_t vio_pager_ready;
boolean_t vio_can_persist;
boolean_t vio_internal;
boolean_t vio_temporary;
boolean_t vio_alive;
boolean_t vio_purgable;
boolean_t vio_purgable_volatile;
} vm_info_object_t;
typedef vm_info_object_t *vm_info_object_array_t;
typedef struct zone_name {
char zn_name[80];
} zone_name_t;
typedef zone_name_t *zone_name_array_t;
typedef struct zone_info {
integer_t zi_count;
vm_size_t zi_cur_size;
vm_size_t zi_max_size;
vm_size_t zi_elem_size;
vm_size_t zi_alloc_size;
integer_t zi_pageable;
integer_t zi_sleepable;
integer_t zi_exhaustible;
integer_t zi_collectable;
} zone_info_t;
typedef zone_info_t *zone_info_array_t;
typedef struct mach_zone_name {
char mzn_name[80];
} mach_zone_name_t;
typedef mach_zone_name_t *mach_zone_name_array_t;
typedef struct mach_zone_info_data {
uint64_t mzi_count;
uint64_t mzi_cur_size;
uint64_t mzi_max_size;
uint64_t mzi_elem_size;
uint64_t mzi_alloc_size;
uint64_t mzi_sum_size;
uint64_t mzi_exhaustible;
uint64_t mzi_collectable;
} mach_zone_info_t;
typedef mach_zone_info_t *mach_zone_info_array_t;
typedef struct task_zone_info_data {
uint64_t tzi_count;
uint64_t tzi_cur_size;
uint64_t tzi_max_size;
uint64_t tzi_elem_size;
uint64_t tzi_alloc_size;
uint64_t tzi_sum_size;
uint64_t tzi_exhaustible;
uint64_t tzi_collectable;
uint64_t tzi_caller_acct;
uint64_t tzi_task_alloc;
uint64_t tzi_task_free;
} task_zone_info_t;
typedef task_zone_info_t *task_zone_info_array_t;
typedef struct mach_memory_info {
uint64_t flags;
uint64_t site;
uint64_t size;
uint64_t free;
uint64_t largest;
uint64_t collectable_bytes;
uint64_t mapped;
uint64_t peak;
uint16_t tag;
uint16_t zone;
uint16_t _resvA[2];
uint64_t _resv[3];
char name[80];
} mach_memory_info_t;
typedef mach_memory_info_t *mach_memory_info_array_t;
typedef vm_offset_t *page_address_array_t;
typedef struct hash_info_bucket {
natural_t hib_count;
} hash_info_bucket_t;
typedef hash_info_bucket_t *hash_info_bucket_array_t;
typedef struct lockgroup_info {
char lockgroup_name[64];
uint64_t lockgroup_attr;
uint64_t lock_spin_cnt;
uint64_t lock_spin_util_cnt;
uint64_t lock_spin_held_cnt;
uint64_t lock_spin_miss_cnt;
uint64_t lock_spin_held_max;
uint64_t lock_spin_held_cum;
uint64_t lock_mtx_cnt;
uint64_t lock_mtx_util_cnt;
uint64_t lock_mtx_held_cnt;
uint64_t lock_mtx_miss_cnt;
uint64_t lock_mtx_wait_cnt;
uint64_t lock_mtx_held_max;
uint64_t lock_mtx_held_cum;
uint64_t lock_mtx_wait_max;
uint64_t lock_mtx_wait_cum;
uint64_t lock_rw_cnt;
uint64_t lock_rw_util_cnt;
uint64_t lock_rw_held_cnt;
uint64_t lock_rw_miss_cnt;
uint64_t lock_rw_wait_cnt;
uint64_t lock_rw_held_max;
uint64_t lock_rw_held_cum;
uint64_t lock_rw_wait_max;
uint64_t lock_rw_wait_cum;
} lockgroup_info_t;
typedef lockgroup_info_t *lockgroup_info_array_t;
typedef char symtab_name_t[32];
struct mach_core_details
{
uint64_t gzip_offset;
uint64_t gzip_length;
char core_name[16];
};
struct mach_core_fileheader
{
uint64_t signature;
uint64_t log_offset;
uint64_t log_length;
uint64_t num_files;
struct mach_core_details files[16];
};
static 
uint16_t
OSReadSwapInt16(
const volatile void * base,
uintptr_t byteOffset
)
{
uint16_t result;
result = *(volatile uint16_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt16(result);
}
static 
uint32_t
OSReadSwapInt32(
const volatile void * base,
uintptr_t byteOffset
)
{
uint32_t result;
result = *(volatile uint32_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt32(result);
}
static 
uint64_t
OSReadSwapInt64(
const volatile void * base,
uintptr_t byteOffset
)
{
uint64_t result;
result = *(volatile uint64_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt64(result);
}
static 
void
OSWriteSwapInt16(
volatile void * base,
uintptr_t byteOffset,
uint16_t data
)
{
*(volatile uint16_t *)((uintptr_t)base + byteOffset) = _OSSwapInt16(data);
}
static 
void
OSWriteSwapInt32(
volatile void * base,
uintptr_t byteOffset,
uint32_t data
)
{
*(volatile uint32_t *)((uintptr_t)base + byteOffset) = _OSSwapInt32(data);
}
static 
void
OSWriteSwapInt64(
volatile void * base,
uintptr_t byteOffset,
uint64_t data
)
{
*(volatile uint64_t *)((uintptr_t)base + byteOffset) = _OSSwapInt64(data);
}
enum {
OSUnknownByteOrder,
OSLittleEndian,
OSBigEndian
};
static 
int32_t
OSHostByteOrder(void) {
return OSLittleEndian;
}
static 
uint16_t
_OSReadInt16(
const volatile void * base,
uintptr_t byteOffset
)
{
return *(volatile uint16_t *)((uintptr_t)base + byteOffset);
}
static 
uint32_t
_OSReadInt32(
const volatile void * base,
uintptr_t byteOffset
)
{
return *(volatile uint32_t *)((uintptr_t)base + byteOffset);
}
static 
uint64_t
_OSReadInt64(
const volatile void * base,
uintptr_t byteOffset
)
{
return *(volatile uint64_t *)((uintptr_t)base + byteOffset);
}
static 
void
_OSWriteInt16(
volatile void * base,
uintptr_t byteOffset,
uint16_t data
)
{
*(volatile uint16_t *)((uintptr_t)base + byteOffset) = data;
}
static 
void
_OSWriteInt32(
volatile void * base,
uintptr_t byteOffset,
uint32_t data
)
{
*(volatile uint32_t *)((uintptr_t)base + byteOffset) = data;
}
static 
void
_OSWriteInt64(
volatile void * base,
uintptr_t byteOffset,
uint64_t data
)
{
*(volatile uint64_t *)((uintptr_t)base + byteOffset) = data;
}
typedef struct {
unsigned char mig_vers;
unsigned char if_vers;
unsigned char reserved1;
unsigned char mig_encoding;
unsigned char int_rep;
unsigned char char_rep;
unsigned char float_rep;
unsigned char reserved2;
} NDR_record_t;
extern NDR_record_t NDR_record;
typedef mach_port_t notify_port_t;
typedef struct {
mach_msg_header_t not_header;
NDR_record_t NDR;
mach_port_name_t not_port;
mach_msg_format_0_trailer_t trailer;
} mach_port_deleted_notification_t;
typedef struct {
mach_msg_header_t not_header;
NDR_record_t NDR;
mach_port_name_t not_port;
mach_msg_format_0_trailer_t trailer;
} mach_send_possible_notification_t;
typedef struct {
mach_msg_header_t not_header;
mach_msg_body_t not_body;
mach_msg_port_descriptor_t not_port;
mach_msg_format_0_trailer_t trailer;
} mach_port_destroyed_notification_t;
typedef struct {
mach_msg_header_t not_header;
NDR_record_t NDR;
mach_msg_type_number_t not_count;
mach_msg_format_0_trailer_t trailer;
} mach_no_senders_notification_t;
typedef struct {
mach_msg_header_t not_header;
mach_msg_format_0_trailer_t trailer;
} mach_send_once_notification_t;
typedef struct {
mach_msg_header_t not_header;
NDR_record_t NDR;
mach_port_name_t not_port;
mach_msg_format_0_trailer_t trailer;
} mach_dead_name_notification_t;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} mig_reply_error_t;
static  void
__NDR_convert__mig_reply_error_t( mig_reply_error_t *x)
{
}
extern int mig_strncpy_zerofill(char *dest, const char *src, int len) ;
extern
kern_return_t host_info
(
host_t host,
host_flavor_t flavor,
host_info_t host_info_out,
mach_msg_type_number_t *host_info_outCnt
);
extern
kern_return_t host_kernel_version
(
host_t host,
kernel_version_t kernel_version
);
extern
kern_return_t host_page_size
(
host_t host,
vm_size_t *out_page_size
);
extern
kern_return_t mach_memory_object_memory_entry
(
host_t host,
boolean_t internal,
vm_size_t size,
vm_prot_t permission,
memory_object_t pager,
mach_port_t *entry_handle
);
extern
kern_return_t host_processor_info
(
host_t host,
processor_flavor_t flavor,
natural_t *out_processor_count,
processor_info_array_t *out_processor_info,
mach_msg_type_number_t *out_processor_infoCnt
);
extern
kern_return_t host_get_io_master
(
host_t host,
io_master_t *io_master
);
extern
kern_return_t host_get_clock_service
(
host_t host,
clock_id_t clock_id,
clock_serv_t *clock_serv
);
extern
kern_return_t kmod_get_info
(
host_t host,
kmod_args_t *modules,
mach_msg_type_number_t *modulesCnt
);
extern
kern_return_t host_virtual_physical_table_info
(
host_t host,
hash_info_bucket_array_t *info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t processor_set_default
(
host_t host,
processor_set_name_t *default_set
);
extern
kern_return_t processor_set_create
(
host_t host,
processor_set_t *new_set,
processor_set_name_t *new_name
);
extern
kern_return_t mach_memory_object_memory_entry_64
(
host_t host,
boolean_t internal,
memory_object_size_t size,
vm_prot_t permission,
memory_object_t pager,
mach_port_t *entry_handle
);
extern
kern_return_t host_statistics
(
host_t host_priv,
host_flavor_t flavor,
host_info_t host_info_out,
mach_msg_type_number_t *host_info_outCnt
);
extern
kern_return_t host_request_notification
(
host_t host,
host_flavor_t notify_type,
mach_port_t notify_port
);
extern
kern_return_t host_lockgroup_info
(
host_t host,
lockgroup_info_array_t *lockgroup_info,
mach_msg_type_number_t *lockgroup_infoCnt
);
extern
kern_return_t host_statistics64
(
host_t host_priv,
host_flavor_t flavor,
host_info64_t host_info64_out,
mach_msg_type_number_t *host_info64_outCnt
);
extern
kern_return_t mach_zone_info
(
host_priv_t host,
mach_zone_name_array_t *names,
mach_msg_type_number_t *namesCnt,
mach_zone_info_array_t *info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t mach_zone_force_gc
(
host_t host
);
extern
kern_return_t host_create_mach_voucher
(
host_t host,
mach_voucher_attr_raw_recipe_array_t recipes,
mach_msg_type_number_t recipesCnt,
ipc_voucher_t *voucher
);
extern
kern_return_t host_register_mach_voucher_attr_manager
(
host_t host,
mach_voucher_attr_manager_t attr_manager,
mach_voucher_attr_value_handle_t default_value,
mach_voucher_attr_key_t *new_key,
ipc_voucher_attr_control_t *new_attr_control
);
extern
kern_return_t host_register_well_known_mach_voucher_attr_manager
(
host_t host,
mach_voucher_attr_manager_t attr_manager,
mach_voucher_attr_value_handle_t default_value,
mach_voucher_attr_key_t key,
ipc_voucher_attr_control_t *new_attr_control
);
extern
kern_return_t host_set_atm_diagnostic_flag
(
host_priv_t host_priv,
uint32_t diagnostic_flag
);
extern
kern_return_t mach_memory_info
(
host_priv_t host,
mach_zone_name_array_t *names,
mach_msg_type_number_t *namesCnt,
mach_zone_info_array_t *info,
mach_msg_type_number_t *infoCnt,
mach_memory_info_array_t *memory_info,
mach_msg_type_number_t *memory_infoCnt
);
extern
kern_return_t host_set_multiuser_config_flags
(
host_priv_t host_priv,
uint32_t multiuser_flags
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
host_flavor_t flavor;
mach_msg_type_number_t host_info_outCnt;
} __Request__host_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_kernel_version_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_page_size_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t pager;
NDR_record_t NDR;
boolean_t internal;
vm_size_t size;
vm_prot_t permission;
} __Request__mach_memory_object_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
processor_flavor_t flavor;
} __Request__host_processor_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_get_io_master_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
clock_id_t clock_id;
} __Request__host_get_clock_service_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__kmod_get_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_virtual_physical_table_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_default_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_create_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t pager;
NDR_record_t NDR;
boolean_t internal;
memory_object_size_t size;
vm_prot_t permission;
} __Request__mach_memory_object_memory_entry_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
host_flavor_t flavor;
mach_msg_type_number_t host_info_outCnt;
} __Request__host_statistics_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t notify_port;
NDR_record_t NDR;
host_flavor_t notify_type;
} __Request__host_request_notification_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_lockgroup_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
host_flavor_t flavor;
mach_msg_type_number_t host_info64_outCnt;
} __Request__host_statistics64_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_zone_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_zone_force_gc_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t recipesCnt;
uint8_t recipes[5120];
} __Request__host_create_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t attr_manager;
NDR_record_t NDR;
mach_voucher_attr_value_handle_t default_value;
} __Request__host_register_mach_voucher_attr_manager_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t attr_manager;
NDR_record_t NDR;
mach_voucher_attr_value_handle_t default_value;
mach_voucher_attr_key_t key;
} __Request__host_register_well_known_mach_voucher_attr_manager_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t diagnostic_flag;
} __Request__host_set_atm_diagnostic_flag_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_memory_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t multiuser_flags;
} __Request__host_set_multiuser_config_flags_t ;
union __RequestUnion__mach_host_subsystem {
__Request__host_info_t Request_host_info;
__Request__host_kernel_version_t Request_host_kernel_version;
__Request__host_page_size_t Request_host_page_size;
__Request__mach_memory_object_memory_entry_t Request_mach_memory_object_memory_entry;
__Request__host_processor_info_t Request_host_processor_info;
__Request__host_get_io_master_t Request_host_get_io_master;
__Request__host_get_clock_service_t Request_host_get_clock_service;
__Request__kmod_get_info_t Request_kmod_get_info;
__Request__host_virtual_physical_table_info_t Request_host_virtual_physical_table_info;
__Request__processor_set_default_t Request_processor_set_default;
__Request__processor_set_create_t Request_processor_set_create;
__Request__mach_memory_object_memory_entry_64_t Request_mach_memory_object_memory_entry_64;
__Request__host_statistics_t Request_host_statistics;
__Request__host_request_notification_t Request_host_request_notification;
__Request__host_lockgroup_info_t Request_host_lockgroup_info;
__Request__host_statistics64_t Request_host_statistics64;
__Request__mach_zone_info_t Request_mach_zone_info;
__Request__mach_zone_force_gc_t Request_mach_zone_force_gc;
__Request__host_create_mach_voucher_t Request_host_create_mach_voucher;
__Request__host_register_mach_voucher_attr_manager_t Request_host_register_mach_voucher_attr_manager;
__Request__host_register_well_known_mach_voucher_attr_manager_t Request_host_register_well_known_mach_voucher_attr_manager;
__Request__host_set_atm_diagnostic_flag_t Request_host_set_atm_diagnostic_flag;
__Request__mach_memory_info_t Request_mach_memory_info;
__Request__host_set_multiuser_config_flags_t Request_host_set_multiuser_config_flags;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t host_info_outCnt;
integer_t host_info_out[68];
} __Reply__host_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t kernel_versionOffset;
mach_msg_type_number_t kernel_versionCnt;
char kernel_version[512];
} __Reply__host_kernel_version_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_size_t out_page_size;
} __Reply__host_page_size_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t entry_handle;
} __Reply__mach_memory_object_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t out_processor_info;
NDR_record_t NDR;
natural_t out_processor_count;
mach_msg_type_number_t out_processor_infoCnt;
} __Reply__host_processor_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t io_master;
} __Reply__host_get_io_master_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t clock_serv;
} __Reply__host_get_clock_service_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t modules;
NDR_record_t NDR;
mach_msg_type_number_t modulesCnt;
} __Reply__kmod_get_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t info;
NDR_record_t NDR;
mach_msg_type_number_t infoCnt;
} __Reply__host_virtual_physical_table_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t default_set;
} __Reply__processor_set_default_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_set;
mach_msg_port_descriptor_t new_name;
} __Reply__processor_set_create_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t entry_handle;
} __Reply__mach_memory_object_memory_entry_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t host_info_outCnt;
integer_t host_info_out[68];
} __Reply__host_statistics_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_request_notification_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t lockgroup_info;
NDR_record_t NDR;
mach_msg_type_number_t lockgroup_infoCnt;
} __Reply__host_lockgroup_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t host_info64_outCnt;
integer_t host_info64_out[256];
} __Reply__host_statistics64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t names;
mach_msg_ool_descriptor_t info;
NDR_record_t NDR;
mach_msg_type_number_t namesCnt;
mach_msg_type_number_t infoCnt;
} __Reply__mach_zone_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_zone_force_gc_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Reply__host_create_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_attr_control;
NDR_record_t NDR;
mach_voucher_attr_key_t new_key;
} __Reply__host_register_mach_voucher_attr_manager_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_attr_control;
} __Reply__host_register_well_known_mach_voucher_attr_manager_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_set_atm_diagnostic_flag_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t names;
mach_msg_ool_descriptor_t info;
mach_msg_ool_descriptor_t memory_info;
NDR_record_t NDR;
mach_msg_type_number_t namesCnt;
mach_msg_type_number_t infoCnt;
mach_msg_type_number_t memory_infoCnt;
} __Reply__mach_memory_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_set_multiuser_config_flags_t ;
union __ReplyUnion__mach_host_subsystem {
__Reply__host_info_t Reply_host_info;
__Reply__host_kernel_version_t Reply_host_kernel_version;
__Reply__host_page_size_t Reply_host_page_size;
__Reply__mach_memory_object_memory_entry_t Reply_mach_memory_object_memory_entry;
__Reply__host_processor_info_t Reply_host_processor_info;
__Reply__host_get_io_master_t Reply_host_get_io_master;
__Reply__host_get_clock_service_t Reply_host_get_clock_service;
__Reply__kmod_get_info_t Reply_kmod_get_info;
__Reply__host_virtual_physical_table_info_t Reply_host_virtual_physical_table_info;
__Reply__processor_set_default_t Reply_processor_set_default;
__Reply__processor_set_create_t Reply_processor_set_create;
__Reply__mach_memory_object_memory_entry_64_t Reply_mach_memory_object_memory_entry_64;
__Reply__host_statistics_t Reply_host_statistics;
__Reply__host_request_notification_t Reply_host_request_notification;
__Reply__host_lockgroup_info_t Reply_host_lockgroup_info;
__Reply__host_statistics64_t Reply_host_statistics64;
__Reply__mach_zone_info_t Reply_mach_zone_info;
__Reply__mach_zone_force_gc_t Reply_mach_zone_force_gc;
__Reply__host_create_mach_voucher_t Reply_host_create_mach_voucher;
__Reply__host_register_mach_voucher_attr_manager_t Reply_host_register_mach_voucher_attr_manager;
__Reply__host_register_well_known_mach_voucher_attr_manager_t Reply_host_register_well_known_mach_voucher_attr_manager;
__Reply__host_set_atm_diagnostic_flag_t Reply_host_set_atm_diagnostic_flag;
__Reply__mach_memory_info_t Reply_mach_memory_info;
__Reply__host_set_multiuser_config_flags_t Reply_host_set_multiuser_config_flags;
};
extern
kern_return_t mach_port_names
(
ipc_space_t task,
mach_port_name_array_t *names,
mach_msg_type_number_t *namesCnt,
mach_port_type_array_t *types,
mach_msg_type_number_t *typesCnt
);
extern
kern_return_t mach_port_type
(
ipc_space_t task,
mach_port_name_t name,
mach_port_type_t *ptype
);
extern
kern_return_t mach_port_rename
(
ipc_space_t task,
mach_port_name_t old_name,
mach_port_name_t new_name
);
extern
kern_return_t mach_port_allocate_name
(
ipc_space_t task,
mach_port_right_t right,
mach_port_name_t name
);
extern
kern_return_t mach_port_allocate
(
ipc_space_t task,
mach_port_right_t right,
mach_port_name_t *name
);
extern
kern_return_t mach_port_destroy
(
ipc_space_t task,
mach_port_name_t name
);
extern
kern_return_t mach_port_deallocate
(
ipc_space_t task,
mach_port_name_t name
);
extern
kern_return_t mach_port_get_refs
(
ipc_space_t task,
mach_port_name_t name,
mach_port_right_t right,
mach_port_urefs_t *refs
);
extern
kern_return_t mach_port_mod_refs
(
ipc_space_t task,
mach_port_name_t name,
mach_port_right_t right,
mach_port_delta_t delta
);
extern
kern_return_t mach_port_peek
(
ipc_space_t task,
mach_port_name_t name,
mach_msg_trailer_type_t trailer_type,
mach_port_seqno_t *request_seqnop,
mach_msg_size_t *msg_sizep,
mach_msg_id_t *msg_idp,
mach_msg_trailer_info_t trailer_infop,
mach_msg_type_number_t *trailer_infopCnt
);
extern
kern_return_t mach_port_set_mscount
(
ipc_space_t task,
mach_port_name_t name,
mach_port_mscount_t mscount
);
extern
kern_return_t mach_port_get_set_status
(
ipc_space_inspect_t task,
mach_port_name_t name,
mach_port_name_array_t *members,
mach_msg_type_number_t *membersCnt
);
extern
kern_return_t mach_port_move_member
(
ipc_space_t task,
mach_port_name_t member,
mach_port_name_t after
);
extern
kern_return_t mach_port_request_notification
(
ipc_space_t task,
mach_port_name_t name,
mach_msg_id_t msgid,
mach_port_mscount_t sync,
mach_port_t notify,
mach_msg_type_name_t notifyPoly,
mach_port_t *previous
);
extern
kern_return_t mach_port_insert_right
(
ipc_space_t task,
mach_port_name_t name,
mach_port_t poly,
mach_msg_type_name_t polyPoly
);
extern
kern_return_t mach_port_extract_right
(
ipc_space_t task,
mach_port_name_t name,
mach_msg_type_name_t msgt_name,
mach_port_t *poly,
mach_msg_type_name_t *polyPoly
);
extern
kern_return_t mach_port_set_seqno
(
ipc_space_t task,
mach_port_name_t name,
mach_port_seqno_t seqno
);
extern
kern_return_t mach_port_get_attributes
(
ipc_space_inspect_t task,
mach_port_name_t name,
mach_port_flavor_t flavor,
mach_port_info_t port_info_out,
mach_msg_type_number_t *port_info_outCnt
);
extern
kern_return_t mach_port_set_attributes
(
ipc_space_t task,
mach_port_name_t name,
mach_port_flavor_t flavor,
mach_port_info_t port_info,
mach_msg_type_number_t port_infoCnt
);
extern
kern_return_t mach_port_allocate_qos
(
ipc_space_t task,
mach_port_right_t right,
mach_port_qos_t *qos,
mach_port_name_t *name
);
extern
kern_return_t mach_port_allocate_full
(
ipc_space_t task,
mach_port_right_t right,
mach_port_t proto,
mach_port_qos_t *qos,
mach_port_name_t *name
);
extern
kern_return_t task_set_port_space
(
ipc_space_t task,
int table_entries
);
extern
kern_return_t mach_port_get_srights
(
ipc_space_t task,
mach_port_name_t name,
mach_port_rights_t *srights
);
extern
kern_return_t mach_port_space_info
(
ipc_space_inspect_t task,
ipc_info_space_t *space_info,
ipc_info_name_array_t *table_info,
mach_msg_type_number_t *table_infoCnt,
ipc_info_tree_name_array_t *tree_info,
mach_msg_type_number_t *tree_infoCnt
);
extern
kern_return_t mach_port_dnrequest_info
(
ipc_space_t task,
mach_port_name_t name,
unsigned *dnr_total,
unsigned *dnr_used
);
extern
kern_return_t mach_port_kernel_object
(
ipc_space_inspect_t task,
mach_port_name_t name,
unsigned *object_type,
unsigned *object_addr
);
extern
kern_return_t mach_port_insert_member
(
ipc_space_t task,
mach_port_name_t name,
mach_port_name_t pset
);
extern
kern_return_t mach_port_extract_member
(
ipc_space_t task,
mach_port_name_t name,
mach_port_name_t pset
);
extern
kern_return_t mach_port_get_context
(
ipc_space_inspect_t task,
mach_port_name_t name,
mach_vm_address_t *context
);
extern
kern_return_t mach_port_set_context
(
ipc_space_t task,
mach_port_name_t name,
mach_vm_address_t context
);
extern
kern_return_t mach_port_kobject
(
ipc_space_inspect_t task,
mach_port_name_t name,
natural_t *object_type,
mach_vm_address_t *object_addr
);
extern
kern_return_t mach_port_construct
(
ipc_space_t task,
mach_port_options_ptr_t options,
uint64_t context,
mach_port_name_t *name
);
extern
kern_return_t mach_port_destruct
(
ipc_space_t task,
mach_port_name_t name,
mach_port_delta_t srdelta,
uint64_t guard
);
extern
kern_return_t mach_port_guard
(
ipc_space_t task,
mach_port_name_t name,
uint64_t guard,
boolean_t strict
);
extern
kern_return_t mach_port_unguard
(
ipc_space_t task,
mach_port_name_t name,
uint64_t guard
);
extern
kern_return_t mach_port_space_basic_info
(
ipc_space_inspect_t task,
ipc_info_space_basic_t *basic_info
);
typedef struct {
mach_msg_header_t Head;
} __Request__mach_port_names_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_type_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t old_name;
mach_port_name_t new_name;
} __Request__mach_port_rename_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_right_t right;
mach_port_name_t name;
} __Request__mach_port_allocate_name_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_right_t right;
} __Request__mach_port_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_right_t right;
} __Request__mach_port_get_refs_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_right_t right;
mach_port_delta_t delta;
} __Request__mach_port_mod_refs_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_msg_trailer_type_t trailer_type;
mach_port_seqno_t request_seqnop;
mach_msg_type_number_t trailer_infopCnt;
} __Request__mach_port_peek_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_mscount_t mscount;
} __Request__mach_port_set_mscount_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_get_set_status_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t member;
mach_port_name_t after;
} __Request__mach_port_move_member_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t notify;
NDR_record_t NDR;
mach_port_name_t name;
mach_msg_id_t msgid;
mach_port_mscount_t sync;
} __Request__mach_port_request_notification_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t poly;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_insert_right_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_msg_type_name_t msgt_name;
} __Request__mach_port_extract_right_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_seqno_t seqno;
} __Request__mach_port_set_seqno_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_flavor_t flavor;
mach_msg_type_number_t port_info_outCnt;
} __Request__mach_port_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_flavor_t flavor;
mach_msg_type_number_t port_infoCnt;
integer_t port_info[17];
} __Request__mach_port_set_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_right_t right;
mach_port_qos_t qos;
} __Request__mach_port_allocate_qos_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t proto;
NDR_record_t NDR;
mach_port_right_t right;
mach_port_qos_t qos;
mach_port_name_t name;
} __Request__mach_port_allocate_full_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int table_entries;
} __Request__task_set_port_space_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_get_srights_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_port_space_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_dnrequest_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_kernel_object_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_name_t pset;
} __Request__mach_port_insert_member_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_name_t pset;
} __Request__mach_port_extract_member_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_get_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_vm_address_t context;
} __Request__mach_port_set_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_port_kobject_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t options;
NDR_record_t NDR;
uint64_t context;
} __Request__mach_port_construct_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
mach_port_delta_t srdelta;
uint64_t guard;
} __Request__mach_port_destruct_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
uint64_t guard;
boolean_t strict;
} __Request__mach_port_guard_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
uint64_t guard;
} __Request__mach_port_unguard_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_port_space_basic_info_t ;
union __RequestUnion__mach_port_subsystem {
__Request__mach_port_names_t Request_mach_port_names;
__Request__mach_port_type_t Request_mach_port_type;
__Request__mach_port_rename_t Request_mach_port_rename;
__Request__mach_port_allocate_name_t Request_mach_port_allocate_name;
__Request__mach_port_allocate_t Request_mach_port_allocate;
__Request__mach_port_destroy_t Request_mach_port_destroy;
__Request__mach_port_deallocate_t Request_mach_port_deallocate;
__Request__mach_port_get_refs_t Request_mach_port_get_refs;
__Request__mach_port_mod_refs_t Request_mach_port_mod_refs;
__Request__mach_port_peek_t Request_mach_port_peek;
__Request__mach_port_set_mscount_t Request_mach_port_set_mscount;
__Request__mach_port_get_set_status_t Request_mach_port_get_set_status;
__Request__mach_port_move_member_t Request_mach_port_move_member;
__Request__mach_port_request_notification_t Request_mach_port_request_notification;
__Request__mach_port_insert_right_t Request_mach_port_insert_right;
__Request__mach_port_extract_right_t Request_mach_port_extract_right;
__Request__mach_port_set_seqno_t Request_mach_port_set_seqno;
__Request__mach_port_get_attributes_t Request_mach_port_get_attributes;
__Request__mach_port_set_attributes_t Request_mach_port_set_attributes;
__Request__mach_port_allocate_qos_t Request_mach_port_allocate_qos;
__Request__mach_port_allocate_full_t Request_mach_port_allocate_full;
__Request__task_set_port_space_t Request_task_set_port_space;
__Request__mach_port_get_srights_t Request_mach_port_get_srights;
__Request__mach_port_space_info_t Request_mach_port_space_info;
__Request__mach_port_dnrequest_info_t Request_mach_port_dnrequest_info;
__Request__mach_port_kernel_object_t Request_mach_port_kernel_object;
__Request__mach_port_insert_member_t Request_mach_port_insert_member;
__Request__mach_port_extract_member_t Request_mach_port_extract_member;
__Request__mach_port_get_context_t Request_mach_port_get_context;
__Request__mach_port_set_context_t Request_mach_port_set_context;
__Request__mach_port_kobject_t Request_mach_port_kobject;
__Request__mach_port_construct_t Request_mach_port_construct;
__Request__mach_port_destruct_t Request_mach_port_destruct;
__Request__mach_port_guard_t Request_mach_port_guard;
__Request__mach_port_unguard_t Request_mach_port_unguard;
__Request__mach_port_space_basic_info_t Request_mach_port_space_basic_info;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t names;
mach_msg_ool_descriptor_t types;
NDR_record_t NDR;
mach_msg_type_number_t namesCnt;
mach_msg_type_number_t typesCnt;
} __Reply__mach_port_names_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_type_t ptype;
} __Reply__mach_port_type_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_rename_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_allocate_name_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_name_t name;
} __Reply__mach_port_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_urefs_t refs;
} __Reply__mach_port_get_refs_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_mod_refs_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_seqno_t request_seqnop;
mach_msg_size_t msg_sizep;
mach_msg_id_t msg_idp;
mach_msg_type_number_t trailer_infopCnt;
char trailer_infop[68];
} __Reply__mach_port_peek_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_set_mscount_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t members;
NDR_record_t NDR;
mach_msg_type_number_t membersCnt;
} __Reply__mach_port_get_set_status_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_move_member_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t previous;
} __Reply__mach_port_request_notification_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_insert_right_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t poly;
} __Reply__mach_port_extract_right_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_set_seqno_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t port_info_outCnt;
integer_t port_info_out[17];
} __Reply__mach_port_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_set_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_qos_t qos;
mach_port_name_t name;
} __Reply__mach_port_allocate_qos_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_qos_t qos;
mach_port_name_t name;
} __Reply__mach_port_allocate_full_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_port_space_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_rights_t srights;
} __Reply__mach_port_get_srights_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t table_info;
mach_msg_ool_descriptor_t tree_info;
NDR_record_t NDR;
ipc_info_space_t space_info;
mach_msg_type_number_t table_infoCnt;
mach_msg_type_number_t tree_infoCnt;
} __Reply__mach_port_space_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
unsigned dnr_total;
unsigned dnr_used;
} __Reply__mach_port_dnrequest_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
unsigned object_type;
unsigned object_addr;
} __Reply__mach_port_kernel_object_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_insert_member_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_extract_member_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t context;
} __Reply__mach_port_get_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_set_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
natural_t object_type;
mach_vm_address_t object_addr;
} __Reply__mach_port_kobject_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_port_name_t name;
} __Reply__mach_port_construct_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_destruct_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_guard_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_port_unguard_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
ipc_info_space_basic_t basic_info;
} __Reply__mach_port_space_basic_info_t ;
union __ReplyUnion__mach_port_subsystem {
__Reply__mach_port_names_t Reply_mach_port_names;
__Reply__mach_port_type_t Reply_mach_port_type;
__Reply__mach_port_rename_t Reply_mach_port_rename;
__Reply__mach_port_allocate_name_t Reply_mach_port_allocate_name;
__Reply__mach_port_allocate_t Reply_mach_port_allocate;
__Reply__mach_port_destroy_t Reply_mach_port_destroy;
__Reply__mach_port_deallocate_t Reply_mach_port_deallocate;
__Reply__mach_port_get_refs_t Reply_mach_port_get_refs;
__Reply__mach_port_mod_refs_t Reply_mach_port_mod_refs;
__Reply__mach_port_peek_t Reply_mach_port_peek;
__Reply__mach_port_set_mscount_t Reply_mach_port_set_mscount;
__Reply__mach_port_get_set_status_t Reply_mach_port_get_set_status;
__Reply__mach_port_move_member_t Reply_mach_port_move_member;
__Reply__mach_port_request_notification_t Reply_mach_port_request_notification;
__Reply__mach_port_insert_right_t Reply_mach_port_insert_right;
__Reply__mach_port_extract_right_t Reply_mach_port_extract_right;
__Reply__mach_port_set_seqno_t Reply_mach_port_set_seqno;
__Reply__mach_port_get_attributes_t Reply_mach_port_get_attributes;
__Reply__mach_port_set_attributes_t Reply_mach_port_set_attributes;
__Reply__mach_port_allocate_qos_t Reply_mach_port_allocate_qos;
__Reply__mach_port_allocate_full_t Reply_mach_port_allocate_full;
__Reply__task_set_port_space_t Reply_task_set_port_space;
__Reply__mach_port_get_srights_t Reply_mach_port_get_srights;
__Reply__mach_port_space_info_t Reply_mach_port_space_info;
__Reply__mach_port_dnrequest_info_t Reply_mach_port_dnrequest_info;
__Reply__mach_port_kernel_object_t Reply_mach_port_kernel_object;
__Reply__mach_port_insert_member_t Reply_mach_port_insert_member;
__Reply__mach_port_extract_member_t Reply_mach_port_extract_member;
__Reply__mach_port_get_context_t Reply_mach_port_get_context;
__Reply__mach_port_set_context_t Reply_mach_port_set_context;
__Reply__mach_port_kobject_t Reply_mach_port_kobject;
__Reply__mach_port_construct_t Reply_mach_port_construct;
__Reply__mach_port_destruct_t Reply_mach_port_destruct;
__Reply__mach_port_guard_t Reply_mach_port_guard;
__Reply__mach_port_unguard_t Reply_mach_port_unguard;
__Reply__mach_port_space_basic_info_t Reply_mach_port_space_basic_info;
};
extern
kern_return_t clock_get_time
(
clock_serv_t clock_serv,
mach_timespec_t *cur_time
);
extern
kern_return_t clock_get_attributes
(
clock_serv_t clock_serv,
clock_flavor_t flavor,
clock_attr_t clock_attr,
mach_msg_type_number_t *clock_attrCnt
);
extern
kern_return_t clock_alarm
(
clock_serv_t clock_serv,
alarm_type_t alarm_type,
mach_timespec_t alarm_time,
clock_reply_t alarm_port
);
typedef struct {
mach_msg_header_t Head;
} __Request__clock_get_time_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
clock_flavor_t flavor;
mach_msg_type_number_t clock_attrCnt;
} __Request__clock_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t alarm_port;
NDR_record_t NDR;
alarm_type_t alarm_type;
mach_timespec_t alarm_time;
} __Request__clock_alarm_t ;
union __RequestUnion__clock_subsystem {
__Request__clock_get_time_t Request_clock_get_time;
__Request__clock_get_attributes_t Request_clock_get_attributes;
__Request__clock_alarm_t Request_clock_alarm;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_timespec_t cur_time;
} __Reply__clock_get_time_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t clock_attrCnt;
int clock_attr[1];
} __Reply__clock_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__clock_alarm_t ;
union __ReplyUnion__clock_subsystem {
__Reply__clock_get_time_t Reply_clock_get_time;
__Reply__clock_get_attributes_t Reply_clock_get_attributes;
__Reply__clock_alarm_t Reply_clock_alarm;
};
extern
kern_return_t clock_set_time
(
clock_ctrl_t clock_ctrl,
mach_timespec_t new_time
);
extern
kern_return_t clock_set_attributes
(
clock_ctrl_t clock_ctrl,
clock_flavor_t flavor,
clock_attr_t clock_attr,
mach_msg_type_number_t clock_attrCnt
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_timespec_t new_time;
} __Request__clock_set_time_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
clock_flavor_t flavor;
mach_msg_type_number_t clock_attrCnt;
int clock_attr[1];
} __Request__clock_set_attributes_t ;
union __RequestUnion__clock_priv_subsystem {
__Request__clock_set_time_t Request_clock_set_time;
__Request__clock_set_attributes_t Request_clock_set_attributes;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__clock_set_time_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__clock_set_attributes_t ;
union __ReplyUnion__clock_priv_subsystem {
__Reply__clock_set_time_t Reply_clock_set_time;
__Reply__clock_set_attributes_t Reply_clock_set_attributes;
};
extern
kern_return_t clock_alarm_reply
(
clock_reply_t alarm_port,
kern_return_t alarm_code,
alarm_type_t alarm_type,
mach_timespec_t alarm_time
);
extern
boolean_t clock_reply_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t clock_reply_server_routine(
mach_msg_header_t *InHeadP);
extern const struct clock_reply_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} clock_reply_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t alarm_code;
alarm_type_t alarm_type;
mach_timespec_t alarm_time;
} __Request__clock_alarm_reply_t ;
union __RequestUnion__clock_reply_subsystem {
__Request__clock_alarm_reply_t Request_clock_alarm_reply;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__clock_alarm_reply_t ;
union __ReplyUnion__clock_reply_subsystem {
__Reply__clock_alarm_reply_t Reply_clock_alarm_reply;
};
extern
kern_return_t catch_exception_raise
(
mach_port_t exception_port,
mach_port_t thread,
mach_port_t task,
exception_type_t exception,
exception_data_t code,
mach_msg_type_number_t codeCnt
);
extern
kern_return_t catch_exception_raise_state
(
mach_port_t exception_port,
exception_type_t exception,
const exception_data_t code,
mach_msg_type_number_t codeCnt,
int *flavor,
const thread_state_t old_state,
mach_msg_type_number_t old_stateCnt,
thread_state_t new_state,
mach_msg_type_number_t *new_stateCnt
);
extern
kern_return_t catch_exception_raise_state_identity
(
mach_port_t exception_port,
mach_port_t thread,
mach_port_t task,
exception_type_t exception,
exception_data_t code,
mach_msg_type_number_t codeCnt,
int *flavor,
thread_state_t old_state,
mach_msg_type_number_t old_stateCnt,
thread_state_t new_state,
mach_msg_type_number_t *new_stateCnt
);
extern
boolean_t exc_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t exc_server_routine(
mach_msg_header_t *InHeadP);
extern const struct catch_exc_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[3];
} catch_exc_subsystem;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t thread;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
integer_t code[2];
} __Request__exception_raise_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
integer_t code[2];
int flavor;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Request__exception_raise_state_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t thread;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
integer_t code[2];
int flavor;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Request__exception_raise_state_identity_t ;
union __RequestUnion__catch_exc_subsystem {
__Request__exception_raise_t Request_exception_raise;
__Request__exception_raise_state_t Request_exception_raise_state;
__Request__exception_raise_state_identity_t Request_exception_raise_state_identity;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__exception_raise_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Reply__exception_raise_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Reply__exception_raise_state_identity_t ;
union __ReplyUnion__catch_exc_subsystem {
__Reply__exception_raise_t Reply_exception_raise;
__Reply__exception_raise_state_t Reply_exception_raise_state;
__Reply__exception_raise_state_identity_t Reply_exception_raise_state_identity;
};
extern
kern_return_t host_get_boot_info
(
host_priv_t host_priv,
kernel_boot_info_t boot_info
);
extern
kern_return_t host_reboot
(
host_priv_t host_priv,
int options
);
extern
kern_return_t host_priv_statistics
(
host_priv_t host_priv,
host_flavor_t flavor,
host_info_t host_info_out,
mach_msg_type_number_t *host_info_outCnt
);
extern
kern_return_t host_default_memory_manager
(
host_priv_t host_priv,
memory_object_default_t *default_manager,
memory_object_cluster_size_t cluster_size
);
extern
kern_return_t vm_wire
(
host_priv_t host_priv,
vm_map_t task,
vm_address_t address,
vm_size_t size,
vm_prot_t desired_access
);
extern
kern_return_t thread_wire
(
host_priv_t host_priv,
thread_act_t thread,
boolean_t wired
);
extern
kern_return_t vm_allocate_cpm
(
host_priv_t host_priv,
vm_map_t task,
vm_address_t *address,
vm_size_t size,
int flags
);
extern
kern_return_t host_processors
(
host_priv_t host_priv,
processor_array_t *out_processor_list,
mach_msg_type_number_t *out_processor_listCnt
);
extern
kern_return_t host_get_clock_control
(
host_priv_t host_priv,
clock_id_t clock_id,
clock_ctrl_t *clock_ctrl
);
extern
kern_return_t kmod_create
(
host_priv_t host_priv,
vm_address_t info,
kmod_t *module
);
extern
kern_return_t kmod_destroy
(
host_priv_t host_priv,
kmod_t module
);
extern
kern_return_t kmod_control
(
host_priv_t host_priv,
kmod_t module,
kmod_control_flavor_t flavor,
kmod_args_t *data,
mach_msg_type_number_t *dataCnt
);
extern
kern_return_t host_get_special_port
(
host_priv_t host_priv,
int node,
int which,
mach_port_t *port
);
extern
kern_return_t host_set_special_port
(
host_priv_t host_priv,
int which,
mach_port_t port
);
extern
kern_return_t host_set_exception_ports
(
host_priv_t host_priv,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor
);
extern
kern_return_t host_get_exception_ports
(
host_priv_t host_priv,
exception_mask_t exception_mask,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlers,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t host_swap_exception_ports
(
host_priv_t host_priv,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlerss,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t mach_vm_wire
(
host_priv_t host_priv,
vm_map_t task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_prot_t desired_access
);
extern
kern_return_t host_processor_sets
(
host_priv_t host_priv,
processor_set_name_array_t *processor_sets,
mach_msg_type_number_t *processor_setsCnt
);
extern
kern_return_t host_processor_set_priv
(
host_priv_t host_priv,
processor_set_name_t set_name,
processor_set_t *set
);
extern
kern_return_t host_set_UNDServer
(
host_priv_t host,
UNDServerRef server
);
extern
kern_return_t host_get_UNDServer
(
host_priv_t host,
UNDServerRef *server
);
extern
kern_return_t kext_request
(
host_priv_t host_priv,
uint32_t user_log_flags,
vm_offset_t request_data,
mach_msg_type_number_t request_dataCnt,
vm_offset_t *response_data,
mach_msg_type_number_t *response_dataCnt,
vm_offset_t *log_data,
mach_msg_type_number_t *log_dataCnt,
kern_return_t *op_result
);
typedef struct {
mach_msg_header_t Head;
} __Request__host_get_boot_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int options;
} __Request__host_reboot_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
host_flavor_t flavor;
mach_msg_type_number_t host_info_outCnt;
} __Request__host_priv_statistics_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t default_manager;
NDR_record_t NDR;
memory_object_cluster_size_t cluster_size;
} __Request__host_default_memory_manager_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_prot_t desired_access;
} __Request__vm_wire_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t thread;
NDR_record_t NDR;
boolean_t wired;
} __Request__thread_wire_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
int flags;
} __Request__vm_allocate_cpm_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_processors_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
clock_id_t clock_id;
} __Request__host_get_clock_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t info;
} __Request__kmod_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kmod_t module;
} __Request__kmod_destroy_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
kmod_t module;
kmod_control_flavor_t flavor;
mach_msg_type_number_t dataCnt;
} __Request__kmod_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int node;
int which;
} __Request__host_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t port;
NDR_record_t NDR;
int which;
} __Request__host_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__host_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
exception_mask_t exception_mask;
} __Request__host_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__host_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
vm_prot_t desired_access;
} __Request__mach_vm_wire_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_processor_sets_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t set_name;
} __Request__host_processor_set_priv_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t server;
} __Request__host_set_UNDServer_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__host_get_UNDServer_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t request_data;
NDR_record_t NDR;
uint32_t user_log_flags;
mach_msg_type_number_t request_dataCnt;
} __Request__kext_request_t ;
union __RequestUnion__host_priv_subsystem {
__Request__host_get_boot_info_t Request_host_get_boot_info;
__Request__host_reboot_t Request_host_reboot;
__Request__host_priv_statistics_t Request_host_priv_statistics;
__Request__host_default_memory_manager_t Request_host_default_memory_manager;
__Request__vm_wire_t Request_vm_wire;
__Request__thread_wire_t Request_thread_wire;
__Request__vm_allocate_cpm_t Request_vm_allocate_cpm;
__Request__host_processors_t Request_host_processors;
__Request__host_get_clock_control_t Request_host_get_clock_control;
__Request__kmod_create_t Request_kmod_create;
__Request__kmod_destroy_t Request_kmod_destroy;
__Request__kmod_control_t Request_kmod_control;
__Request__host_get_special_port_t Request_host_get_special_port;
__Request__host_set_special_port_t Request_host_set_special_port;
__Request__host_set_exception_ports_t Request_host_set_exception_ports;
__Request__host_get_exception_ports_t Request_host_get_exception_ports;
__Request__host_swap_exception_ports_t Request_host_swap_exception_ports;
__Request__mach_vm_wire_t Request_mach_vm_wire;
__Request__host_processor_sets_t Request_host_processor_sets;
__Request__host_processor_set_priv_t Request_host_processor_set_priv;
__Request__host_set_UNDServer_t Request_host_set_UNDServer;
__Request__host_get_UNDServer_t Request_host_get_UNDServer;
__Request__kext_request_t Request_kext_request;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t boot_infoOffset;
mach_msg_type_number_t boot_infoCnt;
char boot_info[4096];
} __Reply__host_get_boot_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_reboot_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t host_info_outCnt;
integer_t host_info_out[68];
} __Reply__host_priv_statistics_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t default_manager;
} __Reply__host_default_memory_manager_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_wire_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_wire_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
} __Reply__vm_allocate_cpm_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t out_processor_list;
NDR_record_t NDR;
mach_msg_type_number_t out_processor_listCnt;
} __Reply__host_processors_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t clock_ctrl;
} __Reply__host_get_clock_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
kmod_t module;
} __Reply__kmod_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__kmod_destroy_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
mach_msg_type_number_t dataCnt;
} __Reply__kmod_control_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t port;
} __Reply__host_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlers[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__host_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlerss[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__host_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_wire_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t processor_sets;
NDR_record_t NDR;
mach_msg_type_number_t processor_setsCnt;
} __Reply__host_processor_sets_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t set;
} __Reply__host_processor_set_priv_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_set_UNDServer_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t server;
} __Reply__host_get_UNDServer_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t response_data;
mach_msg_ool_descriptor_t log_data;
NDR_record_t NDR;
mach_msg_type_number_t response_dataCnt;
mach_msg_type_number_t log_dataCnt;
kern_return_t op_result;
} __Reply__kext_request_t ;
union __ReplyUnion__host_priv_subsystem {
__Reply__host_get_boot_info_t Reply_host_get_boot_info;
__Reply__host_reboot_t Reply_host_reboot;
__Reply__host_priv_statistics_t Reply_host_priv_statistics;
__Reply__host_default_memory_manager_t Reply_host_default_memory_manager;
__Reply__vm_wire_t Reply_vm_wire;
__Reply__thread_wire_t Reply_thread_wire;
__Reply__vm_allocate_cpm_t Reply_vm_allocate_cpm;
__Reply__host_processors_t Reply_host_processors;
__Reply__host_get_clock_control_t Reply_host_get_clock_control;
__Reply__kmod_create_t Reply_kmod_create;
__Reply__kmod_destroy_t Reply_kmod_destroy;
__Reply__kmod_control_t Reply_kmod_control;
__Reply__host_get_special_port_t Reply_host_get_special_port;
__Reply__host_set_special_port_t Reply_host_set_special_port;
__Reply__host_set_exception_ports_t Reply_host_set_exception_ports;
__Reply__host_get_exception_ports_t Reply_host_get_exception_ports;
__Reply__host_swap_exception_ports_t Reply_host_swap_exception_ports;
__Reply__mach_vm_wire_t Reply_mach_vm_wire;
__Reply__host_processor_sets_t Reply_host_processor_sets;
__Reply__host_processor_set_priv_t Reply_host_processor_set_priv;
__Reply__host_set_UNDServer_t Reply_host_set_UNDServer;
__Reply__host_get_UNDServer_t Reply_host_get_UNDServer;
__Reply__kext_request_t Reply_kext_request;
};
extern
kern_return_t host_security_create_task_token
(
host_security_t host_security,
task_t parent_task,
security_token_t sec_token,
audit_token_t audit_token,
host_t host,
ledger_array_t ledgers,
mach_msg_type_number_t ledgersCnt,
boolean_t inherit_memory,
task_t *child_task
);
extern
kern_return_t host_security_set_task_token
(
host_security_t host_security,
task_t target_task,
security_token_t sec_token,
audit_token_t audit_token,
host_t host
);
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t parent_task;
mach_msg_port_descriptor_t host;
mach_msg_ool_ports_descriptor_t ledgers;
NDR_record_t NDR;
security_token_t sec_token;
audit_token_t audit_token;
mach_msg_type_number_t ledgersCnt;
boolean_t inherit_memory;
} __Request__host_security_create_task_token_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t target_task;
mach_msg_port_descriptor_t host;
NDR_record_t NDR;
security_token_t sec_token;
audit_token_t audit_token;
} __Request__host_security_set_task_token_t ;
union __RequestUnion__host_security_subsystem {
__Request__host_security_create_task_token_t Request_host_security_create_task_token;
__Request__host_security_set_task_token_t Request_host_security_set_task_token;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t child_task;
} __Reply__host_security_create_task_token_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__host_security_set_task_token_t ;
union __ReplyUnion__host_security_subsystem {
__Reply__host_security_create_task_token_t Reply_host_security_create_task_token;
__Reply__host_security_set_task_token_t Reply_host_security_set_task_token;
};
extern
kern_return_t lock_acquire
(
lock_set_t lock_set,
int lock_id
);
extern
kern_return_t lock_release
(
lock_set_t lock_set,
int lock_id
);
extern
kern_return_t lock_try
(
lock_set_t lock_set,
int lock_id
);
extern
kern_return_t lock_make_stable
(
lock_set_t lock_set,
int lock_id
);
extern
kern_return_t lock_handoff
(
lock_set_t lock_set,
int lock_id
);
extern
kern_return_t lock_handoff_accept
(
lock_set_t lock_set,
int lock_id
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_acquire_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_release_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_try_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_make_stable_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_handoff_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int lock_id;
} __Request__lock_handoff_accept_t ;
union __RequestUnion__lock_set_subsystem {
__Request__lock_acquire_t Request_lock_acquire;
__Request__lock_release_t Request_lock_release;
__Request__lock_try_t Request_lock_try;
__Request__lock_make_stable_t Request_lock_make_stable;
__Request__lock_handoff_t Request_lock_handoff;
__Request__lock_handoff_accept_t Request_lock_handoff_accept;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_acquire_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_release_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_try_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_make_stable_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_handoff_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_handoff_accept_t ;
union __ReplyUnion__lock_set_subsystem {
__Reply__lock_acquire_t Reply_lock_acquire;
__Reply__lock_release_t Reply_lock_release;
__Reply__lock_try_t Reply_lock_try;
__Reply__lock_make_stable_t Reply_lock_make_stable;
__Reply__lock_handoff_t Reply_lock_handoff;
__Reply__lock_handoff_accept_t Reply_lock_handoff_accept;
};
extern
kern_return_t catch_mach_exception_raise
(
mach_port_t exception_port,
mach_port_t thread,
mach_port_t task,
exception_type_t exception,
mach_exception_data_t code,
mach_msg_type_number_t codeCnt
);
extern
kern_return_t catch_mach_exception_raise_state
(
mach_port_t exception_port,
exception_type_t exception,
const mach_exception_data_t code,
mach_msg_type_number_t codeCnt,
int *flavor,
const thread_state_t old_state,
mach_msg_type_number_t old_stateCnt,
thread_state_t new_state,
mach_msg_type_number_t *new_stateCnt
);
extern
kern_return_t catch_mach_exception_raise_state_identity
(
mach_port_t exception_port,
mach_port_t thread,
mach_port_t task,
exception_type_t exception,
mach_exception_data_t code,
mach_msg_type_number_t codeCnt,
int *flavor,
thread_state_t old_state,
mach_msg_type_number_t old_stateCnt,
thread_state_t new_state,
mach_msg_type_number_t *new_stateCnt
);
extern
boolean_t mach_exc_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t mach_exc_server_routine(
mach_msg_header_t *InHeadP);
extern const struct catch_mach_exc_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[3];
} catch_mach_exc_subsystem;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t thread;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
int64_t code[2];
} __Request__mach_exception_raise_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
int64_t code[2];
int flavor;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Request__mach_exception_raise_state_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t thread;
mach_msg_port_descriptor_t task;
NDR_record_t NDR;
exception_type_t exception;
mach_msg_type_number_t codeCnt;
int64_t code[2];
int flavor;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Request__mach_exception_raise_state_identity_t ;
union __RequestUnion__catch_mach_exc_subsystem {
__Request__mach_exception_raise_t Request_mach_exception_raise;
__Request__mach_exception_raise_state_t Request_mach_exception_raise_state;
__Request__mach_exception_raise_state_identity_t Request_mach_exception_raise_state_identity;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_exception_raise_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Reply__mach_exception_raise_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Reply__mach_exception_raise_state_identity_t ;
union __ReplyUnion__catch_mach_exc_subsystem {
__Reply__mach_exception_raise_t Reply_mach_exception_raise;
__Reply__mach_exception_raise_state_t Reply_mach_exception_raise_state;
__Reply__mach_exception_raise_state_identity_t Reply_mach_exception_raise_state_identity;
};
extern
kern_return_t do_mach_notify_port_deleted
(
mach_port_t notify,
mach_port_name_t name
);
extern
kern_return_t do_mach_notify_port_destroyed
(
mach_port_t notify,
mach_port_t rights
);
extern
kern_return_t do_mach_notify_no_senders
(
mach_port_t notify,
mach_port_mscount_t mscount
);
extern
kern_return_t do_mach_notify_send_once
(
mach_port_t notify
);
extern
kern_return_t do_mach_notify_dead_name
(
mach_port_t notify,
mach_port_name_t name
);
extern
boolean_t notify_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t notify_server_routine(
mach_msg_header_t *InHeadP);
extern const struct do_notify_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[9];
} do_notify_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_notify_port_deleted_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t rights;
} __Request__mach_notify_port_destroyed_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_mscount_t mscount;
} __Request__mach_notify_no_senders_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_notify_send_once_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t name;
} __Request__mach_notify_dead_name_t ;
union __RequestUnion__do_notify_subsystem {
__Request__mach_notify_port_deleted_t Request_mach_notify_port_deleted;
__Request__mach_notify_port_destroyed_t Request_mach_notify_port_destroyed;
__Request__mach_notify_no_senders_t Request_mach_notify_no_senders;
__Request__mach_notify_send_once_t Request_mach_notify_send_once;
__Request__mach_notify_dead_name_t Request_mach_notify_dead_name;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_notify_port_deleted_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_notify_port_destroyed_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_notify_no_senders_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_notify_send_once_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_notify_dead_name_t ;
union __ReplyUnion__do_notify_subsystem {
__Reply__mach_notify_port_deleted_t Reply_mach_notify_port_deleted;
__Reply__mach_notify_port_destroyed_t Reply_mach_notify_port_destroyed;
__Reply__mach_notify_no_senders_t Reply_mach_notify_no_senders;
__Reply__mach_notify_send_once_t Reply_mach_notify_send_once;
__Reply__mach_notify_dead_name_t Reply_mach_notify_dead_name;
};
extern
kern_return_t processor_start
(
processor_t processor
);
extern
kern_return_t processor_exit
(
processor_t processor
);
extern
kern_return_t processor_info
(
processor_t processor,
processor_flavor_t flavor,
host_t *host,
processor_info_t processor_info_out,
mach_msg_type_number_t *processor_info_outCnt
);
extern
kern_return_t processor_control
(
processor_t processor,
processor_info_t processor_cmd,
mach_msg_type_number_t processor_cmdCnt
);
extern
kern_return_t processor_assign
(
processor_t processor,
processor_set_t new_set,
boolean_t wait
);
extern
kern_return_t processor_get_assignment
(
processor_t processor,
processor_set_name_t *assigned_set
);
typedef struct {
mach_msg_header_t Head;
} __Request__processor_start_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_exit_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
processor_flavor_t flavor;
mach_msg_type_number_t processor_info_outCnt;
} __Request__processor_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t processor_cmdCnt;
integer_t processor_cmd[12];
} __Request__processor_control_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_set;
NDR_record_t NDR;
boolean_t wait;
} __Request__processor_assign_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_get_assignment_t ;
union __RequestUnion__processor_subsystem {
__Request__processor_start_t Request_processor_start;
__Request__processor_exit_t Request_processor_exit;
__Request__processor_info_t Request_processor_info;
__Request__processor_control_t Request_processor_control;
__Request__processor_assign_t Request_processor_assign;
__Request__processor_get_assignment_t Request_processor_get_assignment;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_start_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_exit_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t host;
NDR_record_t NDR;
mach_msg_type_number_t processor_info_outCnt;
integer_t processor_info_out[12];
} __Reply__processor_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_assign_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t assigned_set;
} __Reply__processor_get_assignment_t ;
union __ReplyUnion__processor_subsystem {
__Reply__processor_start_t Reply_processor_start;
__Reply__processor_exit_t Reply_processor_exit;
__Reply__processor_info_t Reply_processor_info;
__Reply__processor_control_t Reply_processor_control;
__Reply__processor_assign_t Reply_processor_assign;
__Reply__processor_get_assignment_t Reply_processor_get_assignment;
};
extern
kern_return_t processor_set_statistics
(
processor_set_name_t pset,
processor_set_flavor_t flavor,
processor_set_info_t info_out,
mach_msg_type_number_t *info_outCnt
);
extern
kern_return_t processor_set_destroy
(
processor_set_t set
);
extern
kern_return_t processor_set_max_priority
(
processor_set_t processor_set,
int max_priority,
boolean_t change_threads
);
extern
kern_return_t processor_set_policy_enable
(
processor_set_t processor_set,
int policy
);
extern
kern_return_t processor_set_policy_disable
(
processor_set_t processor_set,
int policy,
boolean_t change_threads
);
extern
kern_return_t processor_set_tasks
(
processor_set_t processor_set,
task_array_t *task_list,
mach_msg_type_number_t *task_listCnt
);
extern
kern_return_t processor_set_threads
(
processor_set_t processor_set,
thread_act_array_t *thread_list,
mach_msg_type_number_t *thread_listCnt
);
extern
kern_return_t processor_set_policy_control
(
processor_set_t pset,
processor_set_flavor_t flavor,
processor_set_info_t policy_info,
mach_msg_type_number_t policy_infoCnt,
boolean_t change
);
extern
kern_return_t processor_set_stack_usage
(
processor_set_t pset,
unsigned *ltotal,
vm_size_t *space,
vm_size_t *resident,
vm_size_t *maxusage,
vm_offset_t *maxstack
);
extern
kern_return_t processor_set_info
(
processor_set_name_t set_name,
int flavor,
host_t *host,
processor_set_info_t info_out,
mach_msg_type_number_t *info_outCnt
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
processor_set_flavor_t flavor;
mach_msg_type_number_t info_outCnt;
} __Request__processor_set_statistics_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int max_priority;
boolean_t change_threads;
} __Request__processor_set_max_priority_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int policy;
} __Request__processor_set_policy_enable_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int policy;
boolean_t change_threads;
} __Request__processor_set_policy_disable_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_tasks_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_threads_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
processor_set_flavor_t flavor;
mach_msg_type_number_t policy_infoCnt;
integer_t policy_info[5];
boolean_t change;
} __Request__processor_set_policy_control_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__processor_set_stack_usage_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int flavor;
mach_msg_type_number_t info_outCnt;
} __Request__processor_set_info_t ;
union __RequestUnion__processor_set_subsystem {
__Request__processor_set_statistics_t Request_processor_set_statistics;
__Request__processor_set_destroy_t Request_processor_set_destroy;
__Request__processor_set_max_priority_t Request_processor_set_max_priority;
__Request__processor_set_policy_enable_t Request_processor_set_policy_enable;
__Request__processor_set_policy_disable_t Request_processor_set_policy_disable;
__Request__processor_set_tasks_t Request_processor_set_tasks;
__Request__processor_set_threads_t Request_processor_set_threads;
__Request__processor_set_policy_control_t Request_processor_set_policy_control;
__Request__processor_set_stack_usage_t Request_processor_set_stack_usage;
__Request__processor_set_info_t Request_processor_set_info;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t info_outCnt;
integer_t info_out[5];
} __Reply__processor_set_statistics_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_set_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_set_max_priority_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_set_policy_enable_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_set_policy_disable_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t task_list;
NDR_record_t NDR;
mach_msg_type_number_t task_listCnt;
} __Reply__processor_set_tasks_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t thread_list;
NDR_record_t NDR;
mach_msg_type_number_t thread_listCnt;
} __Reply__processor_set_threads_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__processor_set_policy_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
unsigned ltotal;
vm_size_t space;
vm_size_t resident;
vm_size_t maxusage;
vm_offset_t maxstack;
} __Reply__processor_set_stack_usage_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t host;
NDR_record_t NDR;
mach_msg_type_number_t info_outCnt;
integer_t info_out[5];
} __Reply__processor_set_info_t ;
union __ReplyUnion__processor_set_subsystem {
__Reply__processor_set_statistics_t Reply_processor_set_statistics;
__Reply__processor_set_destroy_t Reply_processor_set_destroy;
__Reply__processor_set_max_priority_t Reply_processor_set_max_priority;
__Reply__processor_set_policy_enable_t Reply_processor_set_policy_enable;
__Reply__processor_set_policy_disable_t Reply_processor_set_policy_disable;
__Reply__processor_set_tasks_t Reply_processor_set_tasks;
__Reply__processor_set_threads_t Reply_processor_set_threads;
__Reply__processor_set_policy_control_t Reply_processor_set_policy_control;
__Reply__processor_set_stack_usage_t Reply_processor_set_stack_usage;
__Reply__processor_set_info_t Reply_processor_set_info;
};
typedef int sync_policy_t;
extern kern_return_t semaphore_signal (semaphore_t semaphore);
extern kern_return_t semaphore_signal_all (semaphore_t semaphore);
extern kern_return_t semaphore_wait (semaphore_t semaphore);
extern kern_return_t semaphore_wait_deadline (semaphore_t semaphore,
uint64_t deadline);
extern kern_return_t semaphore_wait_noblock (semaphore_t semaphore);
extern
kern_return_t task_create
(
task_t target_task,
ledger_array_t ledgers,
mach_msg_type_number_t ledgersCnt,
boolean_t inherit_memory,
task_t *child_task
);
extern
kern_return_t task_terminate
(
task_t target_task
);
extern
kern_return_t task_threads
(
task_inspect_t target_task,
thread_act_array_t *act_list,
mach_msg_type_number_t *act_listCnt
);
extern
kern_return_t mach_ports_register
(
task_t target_task,
mach_port_array_t init_port_set,
mach_msg_type_number_t init_port_setCnt
);
extern
kern_return_t mach_ports_lookup
(
task_t target_task,
mach_port_array_t *init_port_set,
mach_msg_type_number_t *init_port_setCnt
);
extern
kern_return_t task_info
(
task_name_t target_task,
task_flavor_t flavor,
task_info_t task_info_out,
mach_msg_type_number_t *task_info_outCnt
);
extern
kern_return_t task_set_info
(
task_t target_task,
task_flavor_t flavor,
task_info_t task_info_in,
mach_msg_type_number_t task_info_inCnt
);
extern
kern_return_t task_suspend
(
task_t target_task
);
extern
kern_return_t task_resume
(
task_t target_task
);
extern
kern_return_t task_get_special_port
(
task_inspect_t task,
int which_port,
mach_port_t *special_port
);
extern
kern_return_t task_set_special_port
(
task_t task,
int which_port,
mach_port_t special_port
);
extern
kern_return_t thread_create
(
task_t parent_task,
thread_act_t *child_act
);
extern
kern_return_t thread_create_running
(
task_t parent_task,
thread_state_flavor_t flavor,
thread_state_t new_state,
mach_msg_type_number_t new_stateCnt,
thread_act_t *child_act
);
extern
kern_return_t task_set_exception_ports
(
task_t task,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor
);
extern
kern_return_t task_get_exception_ports
(
task_inspect_t task,
exception_mask_t exception_mask,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlers,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t task_swap_exception_ports
(
task_t task,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlerss,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t lock_set_create
(
task_t task,
lock_set_t *new_lock_set,
int n_ulocks,
int policy
);
extern
kern_return_t lock_set_destroy
(
task_t task,
lock_set_t lock_set
);
extern
kern_return_t semaphore_create
(
task_t task,
semaphore_t *semaphore,
int policy,
int value
);
extern
kern_return_t semaphore_destroy
(
task_t task,
semaphore_t semaphore
);
extern
kern_return_t task_policy_set
(
task_t task,
task_policy_flavor_t flavor,
task_policy_t policy_info,
mach_msg_type_number_t policy_infoCnt
);
extern
kern_return_t task_policy_get
(
task_t task,
task_policy_flavor_t flavor,
task_policy_t policy_info,
mach_msg_type_number_t *policy_infoCnt,
boolean_t *get_default
);
extern
kern_return_t task_sample
(
task_t task,
mach_port_t reply
);
extern
kern_return_t task_policy
(
task_t task,
policy_t policy,
policy_base_t base,
mach_msg_type_number_t baseCnt,
boolean_t set_limit,
boolean_t change
);
extern
kern_return_t task_set_emulation
(
task_t target_port,
vm_address_t routine_entry_pt,
int routine_number
);
extern
kern_return_t task_get_emulation_vector
(
task_t task,
int *vector_start,
emulation_vector_t *emulation_vector,
mach_msg_type_number_t *emulation_vectorCnt
);
extern
kern_return_t task_set_emulation_vector
(
task_t task,
int vector_start,
emulation_vector_t emulation_vector,
mach_msg_type_number_t emulation_vectorCnt
);
extern
kern_return_t task_set_ras_pc
(
task_t target_task,
vm_address_t basepc,
vm_address_t boundspc
);
extern
kern_return_t task_zone_info
(
task_t target_task,
mach_zone_name_array_t *names,
mach_msg_type_number_t *namesCnt,
task_zone_info_array_t *info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t task_assign
(
task_t task,
processor_set_t new_set,
boolean_t assign_threads
);
extern
kern_return_t task_assign_default
(
task_t task,
boolean_t assign_threads
);
extern
kern_return_t task_get_assignment
(
task_t task,
processor_set_name_t *assigned_set
);
extern
kern_return_t task_set_policy
(
task_t task,
processor_set_t pset,
policy_t policy,
policy_base_t base,
mach_msg_type_number_t baseCnt,
policy_limit_t limit,
mach_msg_type_number_t limitCnt,
boolean_t change
);
extern
kern_return_t task_get_state
(
task_t task,
thread_state_flavor_t flavor,
thread_state_t old_state,
mach_msg_type_number_t *old_stateCnt
);
extern
kern_return_t task_set_state
(
task_t task,
thread_state_flavor_t flavor,
thread_state_t new_state,
mach_msg_type_number_t new_stateCnt
);
extern
kern_return_t task_set_phys_footprint_limit
(
task_t task,
int new_limit,
int *old_limit
);
extern
kern_return_t task_suspend2
(
task_t target_task,
task_suspension_token_t *suspend_token
);
extern
kern_return_t task_resume2
(
task_suspension_token_t suspend_token
);
extern
kern_return_t task_purgable_info
(
task_t task,
task_purgable_info_t *stats
);
extern
kern_return_t task_get_mach_voucher
(
task_t task,
mach_voucher_selector_t which,
ipc_voucher_t *voucher
);
extern
kern_return_t task_set_mach_voucher
(
task_t task,
ipc_voucher_t voucher
);
extern
kern_return_t task_swap_mach_voucher
(
task_t task,
ipc_voucher_t new_voucher,
ipc_voucher_t *old_voucher
);
extern
kern_return_t task_generate_corpse
(
task_t task,
mach_port_t *corpse_task_port
);
extern
kern_return_t task_map_corpse_info
(
task_t task,
task_t corspe_task,
vm_address_t *kcd_addr_begin,
uint32_t *kcd_size
);
extern
kern_return_t task_register_dyld_image_infos
(
task_t task,
dyld_kernel_image_info_array_t dyld_images,
mach_msg_type_number_t dyld_imagesCnt
);
extern
kern_return_t task_unregister_dyld_image_infos
(
task_t task,
dyld_kernel_image_info_array_t dyld_images,
mach_msg_type_number_t dyld_imagesCnt
);
extern
kern_return_t task_get_dyld_image_infos
(
task_inspect_t task,
dyld_kernel_image_info_array_t *dyld_images,
mach_msg_type_number_t *dyld_imagesCnt
);
extern
kern_return_t task_register_dyld_shared_cache_image_info
(
task_t task,
dyld_kernel_image_info_t dyld_cache_image,
boolean_t no_cache,
boolean_t private_cache
);
extern
kern_return_t task_register_dyld_set_dyld_state
(
task_t task,
uint8_t dyld_state
);
extern
kern_return_t task_register_dyld_get_process_state
(
task_t task,
dyld_kernel_process_info_t *dyld_process_state
);
extern
kern_return_t task_map_corpse_info_64
(
task_t task,
task_t corspe_task,
mach_vm_address_t *kcd_addr_begin,
mach_vm_size_t *kcd_size
);
extern
kern_return_t task_inspect
(
task_inspect_t task,
task_inspect_flavor_t flavor,
task_inspect_info_t info_out,
mach_msg_type_number_t *info_outCnt
);
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t ledgers;
NDR_record_t NDR;
mach_msg_type_number_t ledgersCnt;
boolean_t inherit_memory;
} __Request__task_create_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_terminate_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_threads_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t init_port_set;
NDR_record_t NDR;
mach_msg_type_number_t init_port_setCnt;
} __Request__mach_ports_register_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__mach_ports_lookup_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
task_flavor_t flavor;
mach_msg_type_number_t task_info_outCnt;
} __Request__task_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
task_flavor_t flavor;
mach_msg_type_number_t task_info_inCnt;
integer_t task_info_in[52];
} __Request__task_set_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_suspend_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_resume_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int which_port;
} __Request__task_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t special_port;
NDR_record_t NDR;
int which_port;
} __Request__task_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_state_flavor_t flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Request__thread_create_running_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__task_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
exception_mask_t exception_mask;
} __Request__task_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__task_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int n_ulocks;
int policy;
} __Request__lock_set_create_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t lock_set;
} __Request__lock_set_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int policy;
int value;
} __Request__semaphore_create_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t semaphore;
} __Request__semaphore_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
task_policy_flavor_t flavor;
mach_msg_type_number_t policy_infoCnt;
integer_t policy_info[16];
} __Request__task_policy_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
task_policy_flavor_t flavor;
mach_msg_type_number_t policy_infoCnt;
boolean_t get_default;
} __Request__task_policy_get_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t reply;
} __Request__task_sample_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
policy_t policy;
mach_msg_type_number_t baseCnt;
integer_t base[5];
boolean_t set_limit;
boolean_t change;
} __Request__task_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t routine_entry_pt;
int routine_number;
} __Request__task_set_emulation_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_get_emulation_vector_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t emulation_vector;
NDR_record_t NDR;
int vector_start;
mach_msg_type_number_t emulation_vectorCnt;
} __Request__task_set_emulation_vector_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t basepc;
vm_address_t boundspc;
} __Request__task_set_ras_pc_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_zone_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_set;
NDR_record_t NDR;
boolean_t assign_threads;
} __Request__task_assign_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
boolean_t assign_threads;
} __Request__task_assign_default_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_get_assignment_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t pset;
NDR_record_t NDR;
policy_t policy;
mach_msg_type_number_t baseCnt;
integer_t base[5];
mach_msg_type_number_t limitCnt;
integer_t limit[1];
boolean_t change;
} __Request__task_set_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_state_flavor_t flavor;
mach_msg_type_number_t old_stateCnt;
} __Request__task_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_state_flavor_t flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Request__task_set_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int new_limit;
} __Request__task_set_phys_footprint_limit_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_suspend2_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_resume2_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_purgable_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_voucher_selector_t which;
} __Request__task_get_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Request__task_set_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_voucher;
mach_msg_port_descriptor_t old_voucher;
} __Request__task_swap_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_generate_corpse_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t corspe_task;
} __Request__task_map_corpse_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t dyld_images;
NDR_record_t NDR;
mach_msg_type_number_t dyld_imagesCnt;
} __Request__task_register_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t dyld_images;
NDR_record_t NDR;
mach_msg_type_number_t dyld_imagesCnt;
} __Request__task_unregister_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_get_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
dyld_kernel_image_info_t dyld_cache_image;
boolean_t no_cache;
boolean_t private_cache;
} __Request__task_register_dyld_shared_cache_image_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint8_t dyld_state;
char dyld_statePad[3];
} __Request__task_register_dyld_set_dyld_state_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__task_register_dyld_get_process_state_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t corspe_task;
} __Request__task_map_corpse_info_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
task_inspect_flavor_t flavor;
mach_msg_type_number_t info_outCnt;
} __Request__task_inspect_t ;
union __RequestUnion__task_subsystem {
__Request__task_create_t Request_task_create;
__Request__task_terminate_t Request_task_terminate;
__Request__task_threads_t Request_task_threads;
__Request__mach_ports_register_t Request_mach_ports_register;
__Request__mach_ports_lookup_t Request_mach_ports_lookup;
__Request__task_info_t Request_task_info;
__Request__task_set_info_t Request_task_set_info;
__Request__task_suspend_t Request_task_suspend;
__Request__task_resume_t Request_task_resume;
__Request__task_get_special_port_t Request_task_get_special_port;
__Request__task_set_special_port_t Request_task_set_special_port;
__Request__thread_create_t Request_thread_create;
__Request__thread_create_running_t Request_thread_create_running;
__Request__task_set_exception_ports_t Request_task_set_exception_ports;
__Request__task_get_exception_ports_t Request_task_get_exception_ports;
__Request__task_swap_exception_ports_t Request_task_swap_exception_ports;
__Request__lock_set_create_t Request_lock_set_create;
__Request__lock_set_destroy_t Request_lock_set_destroy;
__Request__semaphore_create_t Request_semaphore_create;
__Request__semaphore_destroy_t Request_semaphore_destroy;
__Request__task_policy_set_t Request_task_policy_set;
__Request__task_policy_get_t Request_task_policy_get;
__Request__task_sample_t Request_task_sample;
__Request__task_policy_t Request_task_policy;
__Request__task_set_emulation_t Request_task_set_emulation;
__Request__task_get_emulation_vector_t Request_task_get_emulation_vector;
__Request__task_set_emulation_vector_t Request_task_set_emulation_vector;
__Request__task_set_ras_pc_t Request_task_set_ras_pc;
__Request__task_zone_info_t Request_task_zone_info;
__Request__task_assign_t Request_task_assign;
__Request__task_assign_default_t Request_task_assign_default;
__Request__task_get_assignment_t Request_task_get_assignment;
__Request__task_set_policy_t Request_task_set_policy;
__Request__task_get_state_t Request_task_get_state;
__Request__task_set_state_t Request_task_set_state;
__Request__task_set_phys_footprint_limit_t Request_task_set_phys_footprint_limit;
__Request__task_suspend2_t Request_task_suspend2;
__Request__task_resume2_t Request_task_resume2;
__Request__task_purgable_info_t Request_task_purgable_info;
__Request__task_get_mach_voucher_t Request_task_get_mach_voucher;
__Request__task_set_mach_voucher_t Request_task_set_mach_voucher;
__Request__task_swap_mach_voucher_t Request_task_swap_mach_voucher;
__Request__task_generate_corpse_t Request_task_generate_corpse;
__Request__task_map_corpse_info_t Request_task_map_corpse_info;
__Request__task_register_dyld_image_infos_t Request_task_register_dyld_image_infos;
__Request__task_unregister_dyld_image_infos_t Request_task_unregister_dyld_image_infos;
__Request__task_get_dyld_image_infos_t Request_task_get_dyld_image_infos;
__Request__task_register_dyld_shared_cache_image_info_t Request_task_register_dyld_shared_cache_image_info;
__Request__task_register_dyld_set_dyld_state_t Request_task_register_dyld_set_dyld_state;
__Request__task_register_dyld_get_process_state_t Request_task_register_dyld_get_process_state;
__Request__task_map_corpse_info_64_t Request_task_map_corpse_info_64;
__Request__task_inspect_t Request_task_inspect;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t child_task;
} __Reply__task_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_terminate_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t act_list;
NDR_record_t NDR;
mach_msg_type_number_t act_listCnt;
} __Reply__task_threads_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_ports_register_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_ports_descriptor_t init_port_set;
NDR_record_t NDR;
mach_msg_type_number_t init_port_setCnt;
} __Reply__mach_ports_lookup_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t task_info_outCnt;
integer_t task_info_out[52];
} __Reply__task_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_suspend_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_resume_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t special_port;
} __Reply__task_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t child_act;
} __Reply__thread_create_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t child_act;
} __Reply__thread_create_running_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlers[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__task_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlerss[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__task_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_lock_set;
} __Reply__lock_set_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lock_set_destroy_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t semaphore;
} __Reply__semaphore_create_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__semaphore_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_policy_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t policy_infoCnt;
integer_t policy_info[16];
boolean_t get_default;
} __Reply__task_policy_get_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_sample_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_emulation_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t emulation_vector;
NDR_record_t NDR;
int vector_start;
mach_msg_type_number_t emulation_vectorCnt;
} __Reply__task_get_emulation_vector_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_emulation_vector_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_ras_pc_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t names;
mach_msg_ool_descriptor_t info;
NDR_record_t NDR;
mach_msg_type_number_t namesCnt;
mach_msg_type_number_t infoCnt;
} __Reply__task_zone_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_assign_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_assign_default_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t assigned_set;
} __Reply__task_get_assignment_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Reply__task_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int old_limit;
} __Reply__task_set_phys_footprint_limit_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t suspend_token;
} __Reply__task_suspend2_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_resume2_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
task_purgable_info_t stats;
} __Reply__task_purgable_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Reply__task_get_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_set_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_voucher;
} __Reply__task_swap_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t corpse_task_port;
} __Reply__task_generate_corpse_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t kcd_addr_begin;
uint32_t kcd_size;
} __Reply__task_map_corpse_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_register_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_unregister_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t dyld_images;
NDR_record_t NDR;
mach_msg_type_number_t dyld_imagesCnt;
} __Reply__task_get_dyld_image_infos_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_register_dyld_shared_cache_image_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_register_dyld_set_dyld_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
dyld_kernel_process_info_t dyld_process_state;
} __Reply__task_register_dyld_get_process_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t kcd_addr_begin;
mach_vm_size_t kcd_size;
} __Reply__task_map_corpse_info_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t info_outCnt;
integer_t info_out[4];
} __Reply__task_inspect_t ;
union __ReplyUnion__task_subsystem {
__Reply__task_create_t Reply_task_create;
__Reply__task_terminate_t Reply_task_terminate;
__Reply__task_threads_t Reply_task_threads;
__Reply__mach_ports_register_t Reply_mach_ports_register;
__Reply__mach_ports_lookup_t Reply_mach_ports_lookup;
__Reply__task_info_t Reply_task_info;
__Reply__task_set_info_t Reply_task_set_info;
__Reply__task_suspend_t Reply_task_suspend;
__Reply__task_resume_t Reply_task_resume;
__Reply__task_get_special_port_t Reply_task_get_special_port;
__Reply__task_set_special_port_t Reply_task_set_special_port;
__Reply__thread_create_t Reply_thread_create;
__Reply__thread_create_running_t Reply_thread_create_running;
__Reply__task_set_exception_ports_t Reply_task_set_exception_ports;
__Reply__task_get_exception_ports_t Reply_task_get_exception_ports;
__Reply__task_swap_exception_ports_t Reply_task_swap_exception_ports;
__Reply__lock_set_create_t Reply_lock_set_create;
__Reply__lock_set_destroy_t Reply_lock_set_destroy;
__Reply__semaphore_create_t Reply_semaphore_create;
__Reply__semaphore_destroy_t Reply_semaphore_destroy;
__Reply__task_policy_set_t Reply_task_policy_set;
__Reply__task_policy_get_t Reply_task_policy_get;
__Reply__task_sample_t Reply_task_sample;
__Reply__task_policy_t Reply_task_policy;
__Reply__task_set_emulation_t Reply_task_set_emulation;
__Reply__task_get_emulation_vector_t Reply_task_get_emulation_vector;
__Reply__task_set_emulation_vector_t Reply_task_set_emulation_vector;
__Reply__task_set_ras_pc_t Reply_task_set_ras_pc;
__Reply__task_zone_info_t Reply_task_zone_info;
__Reply__task_assign_t Reply_task_assign;
__Reply__task_assign_default_t Reply_task_assign_default;
__Reply__task_get_assignment_t Reply_task_get_assignment;
__Reply__task_set_policy_t Reply_task_set_policy;
__Reply__task_get_state_t Reply_task_get_state;
__Reply__task_set_state_t Reply_task_set_state;
__Reply__task_set_phys_footprint_limit_t Reply_task_set_phys_footprint_limit;
__Reply__task_suspend2_t Reply_task_suspend2;
__Reply__task_resume2_t Reply_task_resume2;
__Reply__task_purgable_info_t Reply_task_purgable_info;
__Reply__task_get_mach_voucher_t Reply_task_get_mach_voucher;
__Reply__task_set_mach_voucher_t Reply_task_set_mach_voucher;
__Reply__task_swap_mach_voucher_t Reply_task_swap_mach_voucher;
__Reply__task_generate_corpse_t Reply_task_generate_corpse;
__Reply__task_map_corpse_info_t Reply_task_map_corpse_info;
__Reply__task_register_dyld_image_infos_t Reply_task_register_dyld_image_infos;
__Reply__task_unregister_dyld_image_infos_t Reply_task_unregister_dyld_image_infos;
__Reply__task_get_dyld_image_infos_t Reply_task_get_dyld_image_infos;
__Reply__task_register_dyld_shared_cache_image_info_t Reply_task_register_dyld_shared_cache_image_info;
__Reply__task_register_dyld_set_dyld_state_t Reply_task_register_dyld_set_dyld_state;
__Reply__task_register_dyld_get_process_state_t Reply_task_register_dyld_get_process_state;
__Reply__task_map_corpse_info_64_t Reply_task_map_corpse_info_64;
__Reply__task_inspect_t Reply_task_inspect;
};
extern
kern_return_t thread_terminate
(
thread_act_t target_act
);
extern
kern_return_t act_get_state
(
thread_act_t target_act,
int flavor,
thread_state_t old_state,
mach_msg_type_number_t *old_stateCnt
);
extern
kern_return_t act_set_state
(
thread_act_t target_act,
int flavor,
thread_state_t new_state,
mach_msg_type_number_t new_stateCnt
);
extern
kern_return_t thread_get_state
(
thread_act_t target_act,
thread_state_flavor_t flavor,
thread_state_t old_state,
mach_msg_type_number_t *old_stateCnt
);
extern
kern_return_t thread_set_state
(
thread_act_t target_act,
thread_state_flavor_t flavor,
thread_state_t new_state,
mach_msg_type_number_t new_stateCnt
);
extern
kern_return_t thread_suspend
(
thread_act_t target_act
);
extern
kern_return_t thread_resume
(
thread_act_t target_act
);
extern
kern_return_t thread_abort
(
thread_act_t target_act
);
extern
kern_return_t thread_abort_safely
(
thread_act_t target_act
);
extern
kern_return_t thread_depress_abort
(
thread_act_t thread
);
extern
kern_return_t thread_get_special_port
(
thread_act_t thr_act,
int which_port,
mach_port_t *special_port
);
extern
kern_return_t thread_set_special_port
(
thread_act_t thr_act,
int which_port,
mach_port_t special_port
);
extern
kern_return_t thread_info
(
thread_inspect_t target_act,
thread_flavor_t flavor,
thread_info_t thread_info_out,
mach_msg_type_number_t *thread_info_outCnt
);
extern
kern_return_t thread_set_exception_ports
(
thread_act_t thread,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor
);
extern
kern_return_t thread_get_exception_ports
(
thread_inspect_t thread,
exception_mask_t exception_mask,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlers,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t thread_swap_exception_ports
(
thread_act_t thread,
exception_mask_t exception_mask,
mach_port_t new_port,
exception_behavior_t behavior,
thread_state_flavor_t new_flavor,
exception_mask_array_t masks,
mach_msg_type_number_t *masksCnt,
exception_handler_array_t old_handlers,
exception_behavior_array_t old_behaviors,
exception_flavor_array_t old_flavors
);
extern
kern_return_t thread_policy
(
thread_act_t thr_act,
policy_t policy,
policy_base_t base,
mach_msg_type_number_t baseCnt,
boolean_t set_limit
);
extern
kern_return_t thread_policy_set
(
thread_act_t thread,
thread_policy_flavor_t flavor,
thread_policy_t policy_info,
mach_msg_type_number_t policy_infoCnt
);
extern
kern_return_t thread_policy_get
(
thread_inspect_t thread,
thread_policy_flavor_t flavor,
thread_policy_t policy_info,
mach_msg_type_number_t *policy_infoCnt,
boolean_t *get_default
);
extern
kern_return_t thread_sample
(
thread_act_t thread,
mach_port_t reply
);
extern
kern_return_t etap_trace_thread
(
thread_act_t target_act,
boolean_t trace_status
);
extern
kern_return_t thread_assign
(
thread_act_t thread,
processor_set_t new_set
);
extern
kern_return_t thread_assign_default
(
thread_act_t thread
);
extern
kern_return_t thread_get_assignment
(
thread_act_t thread,
processor_set_name_t *assigned_set
);
extern
kern_return_t thread_set_policy
(
thread_act_t thr_act,
processor_set_t pset,
policy_t policy,
policy_base_t base,
mach_msg_type_number_t baseCnt,
policy_limit_t limit,
mach_msg_type_number_t limitCnt
);
extern
kern_return_t thread_get_mach_voucher
(
thread_act_t thr_act,
mach_voucher_selector_t which,
ipc_voucher_t *voucher
);
extern
kern_return_t thread_set_mach_voucher
(
thread_act_t thr_act,
ipc_voucher_t voucher
);
extern
kern_return_t thread_swap_mach_voucher
(
thread_act_t thr_act,
ipc_voucher_t new_voucher,
ipc_voucher_t *old_voucher
);
typedef struct {
mach_msg_header_t Head;
} __Request__thread_terminate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int flavor;
mach_msg_type_number_t old_stateCnt;
} __Request__act_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Request__act_set_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_state_flavor_t flavor;
mach_msg_type_number_t old_stateCnt;
} __Request__thread_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_state_flavor_t flavor;
mach_msg_type_number_t new_stateCnt;
natural_t new_state[614];
} __Request__thread_set_state_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_suspend_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_resume_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_abort_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_abort_safely_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_depress_abort_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int which_port;
} __Request__thread_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t special_port;
NDR_record_t NDR;
int which_port;
} __Request__thread_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_flavor_t flavor;
mach_msg_type_number_t thread_info_outCnt;
} __Request__thread_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__thread_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
exception_mask_t exception_mask;
} __Request__thread_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_port;
NDR_record_t NDR;
exception_mask_t exception_mask;
exception_behavior_t behavior;
thread_state_flavor_t new_flavor;
} __Request__thread_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
policy_t policy;
mach_msg_type_number_t baseCnt;
integer_t base[5];
boolean_t set_limit;
} __Request__thread_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_policy_flavor_t flavor;
mach_msg_type_number_t policy_infoCnt;
integer_t policy_info[16];
} __Request__thread_policy_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
thread_policy_flavor_t flavor;
mach_msg_type_number_t policy_infoCnt;
boolean_t get_default;
} __Request__thread_policy_get_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t reply;
} __Request__thread_sample_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
boolean_t trace_status;
} __Request__etap_trace_thread_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_set;
} __Request__thread_assign_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_assign_default_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__thread_get_assignment_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t pset;
NDR_record_t NDR;
policy_t policy;
mach_msg_type_number_t baseCnt;
integer_t base[5];
mach_msg_type_number_t limitCnt;
integer_t limit[1];
} __Request__thread_set_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_voucher_selector_t which;
} __Request__thread_get_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Request__thread_set_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_voucher;
mach_msg_port_descriptor_t old_voucher;
} __Request__thread_swap_mach_voucher_t ;
union __RequestUnion__thread_act_subsystem {
__Request__thread_terminate_t Request_thread_terminate;
__Request__act_get_state_t Request_act_get_state;
__Request__act_set_state_t Request_act_set_state;
__Request__thread_get_state_t Request_thread_get_state;
__Request__thread_set_state_t Request_thread_set_state;
__Request__thread_suspend_t Request_thread_suspend;
__Request__thread_resume_t Request_thread_resume;
__Request__thread_abort_t Request_thread_abort;
__Request__thread_abort_safely_t Request_thread_abort_safely;
__Request__thread_depress_abort_t Request_thread_depress_abort;
__Request__thread_get_special_port_t Request_thread_get_special_port;
__Request__thread_set_special_port_t Request_thread_set_special_port;
__Request__thread_info_t Request_thread_info;
__Request__thread_set_exception_ports_t Request_thread_set_exception_ports;
__Request__thread_get_exception_ports_t Request_thread_get_exception_ports;
__Request__thread_swap_exception_ports_t Request_thread_swap_exception_ports;
__Request__thread_policy_t Request_thread_policy;
__Request__thread_policy_set_t Request_thread_policy_set;
__Request__thread_policy_get_t Request_thread_policy_get;
__Request__thread_sample_t Request_thread_sample;
__Request__etap_trace_thread_t Request_etap_trace_thread;
__Request__thread_assign_t Request_thread_assign;
__Request__thread_assign_default_t Request_thread_assign_default;
__Request__thread_get_assignment_t Request_thread_get_assignment;
__Request__thread_set_policy_t Request_thread_set_policy;
__Request__thread_get_mach_voucher_t Request_thread_get_mach_voucher;
__Request__thread_set_mach_voucher_t Request_thread_set_mach_voucher;
__Request__thread_swap_mach_voucher_t Request_thread_swap_mach_voucher;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_terminate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Reply__act_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__act_set_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t old_stateCnt;
natural_t old_state[614];
} __Reply__thread_get_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_set_state_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_suspend_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_resume_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_abort_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_abort_safely_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_depress_abort_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t special_port;
} __Reply__thread_get_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_set_special_port_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t thread_info_outCnt;
integer_t thread_info_out[32];
} __Reply__thread_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_set_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlers[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__thread_get_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_handlers[32];
NDR_record_t NDR;
mach_msg_type_number_t masksCnt;
exception_mask_t masks[32];
exception_behavior_t old_behaviors[32];
thread_state_flavor_t old_flavors[32];
} __Reply__thread_swap_exception_ports_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_policy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_policy_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t policy_infoCnt;
integer_t policy_info[16];
boolean_t get_default;
} __Reply__thread_policy_get_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_sample_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__etap_trace_thread_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_assign_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_assign_default_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t assigned_set;
} __Reply__thread_get_assignment_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_set_policy_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Reply__thread_get_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__thread_set_mach_voucher_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t old_voucher;
} __Reply__thread_swap_mach_voucher_t ;
union __ReplyUnion__thread_act_subsystem {
__Reply__thread_terminate_t Reply_thread_terminate;
__Reply__act_get_state_t Reply_act_get_state;
__Reply__act_set_state_t Reply_act_set_state;
__Reply__thread_get_state_t Reply_thread_get_state;
__Reply__thread_set_state_t Reply_thread_set_state;
__Reply__thread_suspend_t Reply_thread_suspend;
__Reply__thread_resume_t Reply_thread_resume;
__Reply__thread_abort_t Reply_thread_abort;
__Reply__thread_abort_safely_t Reply_thread_abort_safely;
__Reply__thread_depress_abort_t Reply_thread_depress_abort;
__Reply__thread_get_special_port_t Reply_thread_get_special_port;
__Reply__thread_set_special_port_t Reply_thread_set_special_port;
__Reply__thread_info_t Reply_thread_info;
__Reply__thread_set_exception_ports_t Reply_thread_set_exception_ports;
__Reply__thread_get_exception_ports_t Reply_thread_get_exception_ports;
__Reply__thread_swap_exception_ports_t Reply_thread_swap_exception_ports;
__Reply__thread_policy_t Reply_thread_policy;
__Reply__thread_policy_set_t Reply_thread_policy_set;
__Reply__thread_policy_get_t Reply_thread_policy_get;
__Reply__thread_sample_t Reply_thread_sample;
__Reply__etap_trace_thread_t Reply_etap_trace_thread;
__Reply__thread_assign_t Reply_thread_assign;
__Reply__thread_assign_default_t Reply_thread_assign_default;
__Reply__thread_get_assignment_t Reply_thread_get_assignment;
__Reply__thread_set_policy_t Reply_thread_set_policy;
__Reply__thread_get_mach_voucher_t Reply_thread_get_mach_voucher;
__Reply__thread_set_mach_voucher_t Reply_thread_set_mach_voucher;
__Reply__thread_swap_mach_voucher_t Reply_thread_swap_mach_voucher;
};
extern
kern_return_t vm_region
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t *size,
vm_region_flavor_t flavor,
vm_region_info_t info,
mach_msg_type_number_t *infoCnt,
mach_port_t *object_name
);
extern
kern_return_t vm_allocate
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t size,
int flags
);
extern
kern_return_t vm_deallocate
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size
);
extern
kern_return_t vm_protect
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
boolean_t set_maximum,
vm_prot_t new_protection
);
extern
kern_return_t vm_inherit
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_inherit_t new_inheritance
);
extern
kern_return_t vm_read
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_offset_t *data,
mach_msg_type_number_t *dataCnt
);
extern
kern_return_t vm_read_list
(
vm_map_t target_task,
vm_read_entry_t data_list,
natural_t count
);
extern
kern_return_t vm_write
(
vm_map_t target_task,
vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);
extern
kern_return_t vm_copy
(
vm_map_t target_task,
vm_address_t source_address,
vm_size_t size,
vm_address_t dest_address
);
extern
kern_return_t vm_read_overwrite
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_address_t data,
vm_size_t *outsize
);
extern
kern_return_t vm_msync
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_sync_t sync_flags
);
extern
kern_return_t vm_behavior_set
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_behavior_t new_behavior
);
extern
kern_return_t vm_map
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t size,
vm_address_t mask,
int flags,
mem_entry_name_port_t object,
vm_offset_t offset,
boolean_t copy,
vm_prot_t cur_protection,
vm_prot_t max_protection,
vm_inherit_t inheritance
);
extern
kern_return_t vm_machine_attribute
(
vm_map_t target_task,
vm_address_t address,
vm_size_t size,
vm_machine_attribute_t attribute,
vm_machine_attribute_val_t *value
);
extern
kern_return_t vm_remap
(
vm_map_t target_task,
vm_address_t *target_address,
vm_size_t size,
vm_address_t mask,
int flags,
vm_map_t src_task,
vm_address_t src_address,
boolean_t copy,
vm_prot_t *cur_protection,
vm_prot_t *max_protection,
vm_inherit_t inheritance
);
extern
kern_return_t task_wire
(
vm_map_t target_task,
boolean_t must_wire
);
extern
kern_return_t mach_make_memory_entry
(
vm_map_t target_task,
vm_size_t *size,
vm_offset_t offset,
vm_prot_t permission,
mem_entry_name_port_t *object_handle,
mem_entry_name_port_t parent_entry
);
extern
kern_return_t vm_map_page_query
(
vm_map_t target_map,
vm_offset_t offset,
integer_t *disposition,
integer_t *ref_count
);
extern
kern_return_t mach_vm_region_info
(
vm_map_t task,
vm_address_t address,
vm_info_region_t *region,
vm_info_object_array_t *objects,
mach_msg_type_number_t *objectsCnt
);
extern
kern_return_t vm_mapped_pages_info
(
vm_map_t task,
page_address_array_t *pages,
mach_msg_type_number_t *pagesCnt
);
extern
kern_return_t vm_region_recurse
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t *size,
natural_t *nesting_depth,
vm_region_recurse_info_t info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t vm_region_recurse_64
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t *size,
natural_t *nesting_depth,
vm_region_recurse_info_t info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t mach_vm_region_info_64
(
vm_map_t task,
vm_address_t address,
vm_info_region_64_t *region,
vm_info_object_array_t *objects,
mach_msg_type_number_t *objectsCnt
);
extern
kern_return_t vm_region_64
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t *size,
vm_region_flavor_t flavor,
vm_region_info_t info,
mach_msg_type_number_t *infoCnt,
mach_port_t *object_name
);
extern
kern_return_t mach_make_memory_entry_64
(
vm_map_t target_task,
memory_object_size_t *size,
memory_object_offset_t offset,
vm_prot_t permission,
mach_port_t *object_handle,
mem_entry_name_port_t parent_entry
);
extern
kern_return_t vm_map_64
(
vm_map_t target_task,
vm_address_t *address,
vm_size_t size,
vm_address_t mask,
int flags,
mem_entry_name_port_t object,
memory_object_offset_t offset,
boolean_t copy,
vm_prot_t cur_protection,
vm_prot_t max_protection,
vm_inherit_t inheritance
);
extern
kern_return_t vm_purgable_control
(
vm_map_t target_task,
vm_address_t address,
vm_purgable_t control,
int *state
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_region_flavor_t flavor;
mach_msg_type_number_t infoCnt;
} __Request__vm_region_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
int flags;
} __Request__vm_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
} __Request__vm_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
boolean_t set_maximum;
vm_prot_t new_protection;
} __Request__vm_protect_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_inherit_t new_inheritance;
} __Request__vm_inherit_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
} __Request__vm_read_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_read_entry_t data_list;
natural_t count;
} __Request__vm_read_list_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
vm_address_t address;
mach_msg_type_number_t dataCnt;
} __Request__vm_write_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t source_address;
vm_size_t size;
vm_address_t dest_address;
} __Request__vm_copy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_address_t data;
} __Request__vm_read_overwrite_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_sync_t sync_flags;
} __Request__vm_msync_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_behavior_t new_behavior;
} __Request__vm_behavior_set_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_address_t mask;
int flags;
vm_offset_t offset;
boolean_t copy;
vm_prot_t cur_protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
} __Request__vm_map_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_machine_attribute_t attribute;
vm_machine_attribute_val_t value;
} __Request__vm_machine_attribute_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t src_task;
NDR_record_t NDR;
vm_address_t target_address;
vm_size_t size;
vm_address_t mask;
int flags;
vm_address_t src_address;
boolean_t copy;
vm_inherit_t inheritance;
} __Request__vm_remap_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
boolean_t must_wire;
} __Request__task_wire_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t parent_entry;
NDR_record_t NDR;
vm_size_t size;
vm_offset_t offset;
vm_prot_t permission;
} __Request__mach_make_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_offset_t offset;
} __Request__vm_map_page_query_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
} __Request__mach_vm_region_info_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__vm_mapped_pages_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
} __Request__vm_region_recurse_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
} __Request__vm_region_recurse_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
} __Request__mach_vm_region_info_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_region_flavor_t flavor;
mach_msg_type_number_t infoCnt;
} __Request__vm_region_64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t parent_entry;
NDR_record_t NDR;
memory_object_size_t size;
memory_object_offset_t offset;
vm_prot_t permission;
} __Request__mach_make_memory_entry_64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
vm_address_t mask;
int flags;
memory_object_offset_t offset;
boolean_t copy;
vm_prot_t cur_protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
} __Request__vm_map_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_address_t address;
vm_purgable_t control;
int state;
} __Request__vm_purgable_control_t ;
union __RequestUnion__vm_map_subsystem {
__Request__vm_region_t Request_vm_region;
__Request__vm_allocate_t Request_vm_allocate;
__Request__vm_deallocate_t Request_vm_deallocate;
__Request__vm_protect_t Request_vm_protect;
__Request__vm_inherit_t Request_vm_inherit;
__Request__vm_read_t Request_vm_read;
__Request__vm_read_list_t Request_vm_read_list;
__Request__vm_write_t Request_vm_write;
__Request__vm_copy_t Request_vm_copy;
__Request__vm_read_overwrite_t Request_vm_read_overwrite;
__Request__vm_msync_t Request_vm_msync;
__Request__vm_behavior_set_t Request_vm_behavior_set;
__Request__vm_map_t Request_vm_map;
__Request__vm_machine_attribute_t Request_vm_machine_attribute;
__Request__vm_remap_t Request_vm_remap;
__Request__task_wire_t Request_task_wire;
__Request__mach_make_memory_entry_t Request_mach_make_memory_entry;
__Request__vm_map_page_query_t Request_vm_map_page_query;
__Request__mach_vm_region_info_t Request_mach_vm_region_info;
__Request__vm_mapped_pages_info_t Request_vm_mapped_pages_info;
__Request__vm_region_recurse_t Request_vm_region_recurse;
__Request__vm_region_recurse_64_t Request_vm_region_recurse_64;
__Request__mach_vm_region_info_64_t Request_mach_vm_region_info_64;
__Request__vm_region_64_t Request_vm_region_64;
__Request__mach_make_memory_entry_64_t Request_mach_make_memory_entry_64;
__Request__vm_map_64_t Request_vm_map_64;
__Request__vm_purgable_control_t Request_vm_purgable_control;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_name;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
mach_msg_type_number_t infoCnt;
int info[10];
} __Reply__vm_region_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
} __Reply__vm_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_protect_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_inherit_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
mach_msg_type_number_t dataCnt;
} __Reply__vm_read_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_read_entry_t data_list;
} __Reply__vm_read_list_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_write_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_copy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_size_t outsize;
} __Reply__vm_read_overwrite_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_msync_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__vm_behavior_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
} __Reply__vm_map_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_machine_attribute_val_t value;
} __Reply__vm_machine_attribute_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t target_address;
vm_prot_t cur_protection;
vm_prot_t max_protection;
} __Reply__vm_remap_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__task_wire_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_handle;
NDR_record_t NDR;
vm_size_t size;
} __Reply__mach_make_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
integer_t disposition;
integer_t ref_count;
} __Reply__vm_map_page_query_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t objects;
NDR_record_t NDR;
vm_info_region_t region;
mach_msg_type_number_t objectsCnt;
} __Reply__mach_vm_region_info_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t pages;
NDR_record_t NDR;
mach_msg_type_number_t pagesCnt;
} __Reply__vm_mapped_pages_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
vm_size_t size;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
int info[19];
} __Reply__vm_region_recurse_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
vm_size_t size;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
int info[19];
} __Reply__vm_region_recurse_64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t objects;
NDR_record_t NDR;
vm_info_region_64_t region;
mach_msg_type_number_t objectsCnt;
} __Reply__mach_vm_region_info_64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_name;
NDR_record_t NDR;
vm_address_t address;
vm_size_t size;
mach_msg_type_number_t infoCnt;
int info[10];
} __Reply__vm_region_64_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_handle;
NDR_record_t NDR;
memory_object_size_t size;
} __Reply__mach_make_memory_entry_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_address_t address;
} __Reply__vm_map_64_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int state;
} __Reply__vm_purgable_control_t ;
union __ReplyUnion__vm_map_subsystem {
__Reply__vm_region_t Reply_vm_region;
__Reply__vm_allocate_t Reply_vm_allocate;
__Reply__vm_deallocate_t Reply_vm_deallocate;
__Reply__vm_protect_t Reply_vm_protect;
__Reply__vm_inherit_t Reply_vm_inherit;
__Reply__vm_read_t Reply_vm_read;
__Reply__vm_read_list_t Reply_vm_read_list;
__Reply__vm_write_t Reply_vm_write;
__Reply__vm_copy_t Reply_vm_copy;
__Reply__vm_read_overwrite_t Reply_vm_read_overwrite;
__Reply__vm_msync_t Reply_vm_msync;
__Reply__vm_behavior_set_t Reply_vm_behavior_set;
__Reply__vm_map_t Reply_vm_map;
__Reply__vm_machine_attribute_t Reply_vm_machine_attribute;
__Reply__vm_remap_t Reply_vm_remap;
__Reply__task_wire_t Reply_task_wire;
__Reply__mach_make_memory_entry_t Reply_mach_make_memory_entry;
__Reply__vm_map_page_query_t Reply_vm_map_page_query;
__Reply__mach_vm_region_info_t Reply_mach_vm_region_info;
__Reply__vm_mapped_pages_info_t Reply_vm_mapped_pages_info;
__Reply__vm_region_recurse_t Reply_vm_region_recurse;
__Reply__vm_region_recurse_64_t Reply_vm_region_recurse_64;
__Reply__mach_vm_region_info_64_t Reply_mach_vm_region_info_64;
__Reply__vm_region_64_t Reply_vm_region_64;
__Reply__mach_make_memory_entry_64_t Reply_mach_make_memory_entry_64;
__Reply__vm_map_64_t Reply_vm_map_64;
__Reply__vm_purgable_control_t Reply_vm_purgable_control;
};
extern void _doprnt( const char *format, va_list *arg,
void (*lputc)(char), int radix );
typedef kern_return_t mach_error_t;
typedef mach_error_t (* mach_error_fn_t)( void );
typedef kern_return_t IOReturn;
typedef unsigned int UInt;
typedef signed int SInt;
typedef unsigned char UInt8;
typedef unsigned short UInt16;
typedef unsigned int UInt32;
typedef unsigned long long UInt64;
typedef struct  UnsignedWide {
UInt32 lo;
UInt32 hi;
} UnsignedWide ;
typedef signed char SInt8;
typedef signed short SInt16;
typedef signed int SInt32;
typedef signed long long SInt64;
typedef SInt32 OSStatus;
typedef UInt64 AbsoluteTime;
typedef UInt32 OptionBits ;
typedef _Bool Boolean;
typedef UInt32 IOOptionBits;
typedef SInt32 IOFixed;
typedef UInt32 IOVersion;
typedef UInt32 IOItemCount;
typedef UInt32 IOCacheMode;
typedef UInt32 IOByteCount32;
typedef UInt64 IOByteCount64;
typedef UInt32 IOPhysicalAddress32;
typedef UInt64 IOPhysicalAddress64;
typedef UInt32 IOPhysicalLength32;
typedef UInt64 IOPhysicalLength64;
typedef mach_vm_address_t IOVirtualAddress;
typedef IOByteCount32 IOByteCount;
typedef IOVirtualAddress IOLogicalAddress;
typedef IOPhysicalAddress32 IOPhysicalAddress;
typedef IOPhysicalLength32 IOPhysicalLength;
typedef struct
{
IOPhysicalAddress address;
IOByteCount length;
} IOPhysicalRange;
typedef struct
{
IOVirtualAddress address;
IOByteCount length;
} IOVirtualRange;
typedef IOVirtualRange IOAddressRange;
typedef struct {
int value;
const char *name;
} IONamedValue;
typedef unsigned int IOAlignment;
typedef struct OSObject * io_object_t;
typedef char * io_buf_ptr_t;
typedef char io_name_t[128];
typedef char io_string_t[512];
typedef char io_string_inband_t[4096];
typedef char io_struct_inband_t[4096];
typedef uint64_t io_user_scalar_t;
typedef uint64_t io_user_reference_t;
typedef int io_scalar_inband_t[16];
typedef natural_t io_async_ref_t[8];
typedef io_user_scalar_t io_scalar_inband64_t[16];
typedef io_user_reference_t io_async_ref64_t[8];
typedef io_object_t io_connect_t;
typedef io_object_t io_enumerator_t;
typedef io_object_t io_iterator_t;
typedef io_object_t io_registry_entry_t;
typedef io_object_t io_service_t;
enum {
kIODefaultMemoryType = 0
};
enum {
kIODefaultCache = 0,
kIOInhibitCache = 1,
kIOWriteThruCache = 2,
kIOCopybackCache = 3,
kIOWriteCombineCache = 4,
kIOCopybackInnerCache = 5,
kIOPostedWrite = 6
};
enum {
kIOMapAnywhere = 0x00000001,
kIOMapCacheMask = 0x00000700,
kIOMapCacheShift = 8,
kIOMapDefaultCache = kIODefaultCache << kIOMapCacheShift,
kIOMapInhibitCache = kIOInhibitCache << kIOMapCacheShift,
kIOMapWriteThruCache = kIOWriteThruCache << kIOMapCacheShift,
kIOMapCopybackCache = kIOCopybackCache << kIOMapCacheShift,
kIOMapWriteCombineCache = kIOWriteCombineCache << kIOMapCacheShift,
kIOMapCopybackInnerCache = kIOCopybackInnerCache << kIOMapCacheShift,
kIOMapPostedWrite = kIOPostedWrite << kIOMapCacheShift,
kIOMapUserOptionsMask = 0x00000fff,
kIOMapReadOnly = 0x00001000,
kIOMapStatic = 0x01000000,
kIOMapReference = 0x02000000,
kIOMapUnique = 0x04000000,
kIOMapPrefault = 0x10000000,
kIOMapOverwrite = 0x20000000
};
enum {
kNanosecondScale = 1,
kMicrosecondScale = 1000,
kMillisecondScale = 1000 * 1000,
kSecondScale = 1000 * 1000 * 1000,
kTickScale = (kSecondScale / 100)
};
enum {
kIOConnectMethodVarOutputSize = -3
};
typedef kern_return_t OSReturn;
extern lck_grp_t *IOLockGroup;
typedef struct _IOLock IOLock;
IOLock * IOLockAlloc( void );
void IOLockFree( IOLock * lock);
lck_mtx_t * IOLockGetMachLock( IOLock * lock);
void IOLockLock( IOLock * lock);
boolean_t IOLockTryLock( IOLock * lock);
void IOLockUnlock( IOLock * lock);
int IOLockSleep( IOLock * lock, void *event, UInt32 interType) ;
int IOLockSleepDeadline( IOLock * lock, void *event,
AbsoluteTime deadline, UInt32 interType) ;
void IOLockWakeup(IOLock * lock, void *event, _Bool oneThread) ;
typedef enum {
kIOLockStateUnlocked = 0,
kIOLockStateLocked = 1
} IOLockState;
void IOLockInitWithState( IOLock * lock, IOLockState state);
static  void IOTakeLock( IOLock * lock) { IOLockLock(lock); }
static  boolean_t IOTryLock( IOLock * lock) { return(IOLockTryLock(lock)); }
static  void IOUnlock( IOLock * lock) { IOLockUnlock(lock); }
typedef struct _IORecursiveLock IORecursiveLock;
IORecursiveLock * IORecursiveLockAlloc( void );
void IORecursiveLockFree( IORecursiveLock * lock);
lck_mtx_t * IORecursiveLockGetMachLock( IORecursiveLock * lock);
void IORecursiveLockLock( IORecursiveLock * lock);
boolean_t IORecursiveLockTryLock( IORecursiveLock * lock);
void IORecursiveLockUnlock( IORecursiveLock * lock);
boolean_t IORecursiveLockHaveLock( const IORecursiveLock * lock);
extern int IORecursiveLockSleep( IORecursiveLock *_lock,
void *event, UInt32 interType);
extern int IORecursiveLockSleepDeadline( IORecursiveLock * _lock, void *event,
AbsoluteTime deadline, UInt32 interType);
extern void IORecursiveLockWakeup( IORecursiveLock *_lock,
void *event, _Bool oneThread);
typedef struct _IORWLock IORWLock;
IORWLock * IORWLockAlloc( void );
void IORWLockFree( IORWLock * lock);
lck_rw_t * IORWLockGetMachLock( IORWLock * lock);
void IORWLockRead(IORWLock * lock);
void IORWLockWrite( IORWLock * lock);
void IORWLockUnlock( IORWLock * lock);
static  void IOReadLock( IORWLock * lock) { IORWLockRead(lock); }
static  void IOWriteLock( IORWLock * lock) { IORWLockWrite(lock); }
static  void IORWUnlock( IORWLock * lock) { IORWLockUnlock(lock); }
typedef struct _IOSimpleLock IOSimpleLock;
IOSimpleLock * IOSimpleLockAlloc( void );
void IOSimpleLockFree( IOSimpleLock * lock );
lck_spin_t * IOSimpleLockGetMachLock( IOSimpleLock * lock);
void IOSimpleLockInit( IOSimpleLock * lock );
void IOSimpleLockLock( IOSimpleLock * lock );
boolean_t IOSimpleLockTryLock( IOSimpleLock * lock );
void IOSimpleLockUnlock( IOSimpleLock * lock );
typedef boolean_t IOInterruptState;
static 
IOInterruptState IOSimpleLockLockDisableInterrupt( IOSimpleLock * lock )
{
IOInterruptState state = ml_set_interrupts_enabled( 0 );
IOSimpleLockLock( lock );
return( state );
}
static 
void IOSimpleLockUnlockEnableInterrupt( IOSimpleLock * lock,
IOInterruptState state )
{
IOSimpleLockUnlock( lock );
ml_set_interrupts_enabled( state );
}
extern Boolean OSCompareAndSwap64(
UInt64 oldValue,
UInt64 newValue,
volatile UInt64 * address);
extern SInt64 OSAddAtomic64(
SInt64 theAmount,
volatile SInt64 * address);
inline static SInt64 OSIncrementAtomic64(volatile SInt64 * address)
{
return (OSAddAtomic64(1LL, ((volatile SInt64*)(address))));
}
inline static SInt64 OSDecrementAtomic64(volatile SInt64 * address)
{
return (OSAddAtomic64(-1LL, ((volatile SInt64*)(address))));
}
extern Boolean OSCompareAndSwap(
UInt32 oldValue,
UInt32 newValue,
volatile UInt32 * address);
extern Boolean OSCompareAndSwapPtr(
void * oldValue,
void * newValue,
void * volatile * address);
extern SInt32 OSAddAtomic(
SInt32 amount,
volatile SInt32 * address);
extern SInt16 OSAddAtomic16(
SInt32 amount,
volatile SInt16 * address);
extern SInt8 OSAddAtomic8(
SInt32 amount,
volatile SInt8 * address);
extern SInt32 OSIncrementAtomic(volatile SInt32 * address);
extern SInt16 OSIncrementAtomic16(volatile SInt16 * address);
extern SInt8 OSIncrementAtomic8(volatile SInt8 * address);
extern SInt32 OSDecrementAtomic(volatile SInt32 * address);
extern SInt16 OSDecrementAtomic16(volatile SInt16 * address);
extern SInt8 OSDecrementAtomic8(volatile SInt8 * address);
extern UInt32 OSBitAndAtomic(
UInt32 mask,
volatile UInt32 * address);
extern UInt16 OSBitAndAtomic16(
UInt32 mask,
volatile UInt16 * address);
extern UInt8 OSBitAndAtomic8(
UInt32 mask,
volatile UInt8 * address);
extern UInt32 OSBitOrAtomic(
UInt32 mask,
volatile UInt32 * address);
extern UInt16 OSBitOrAtomic16(
UInt32 mask,
volatile UInt16 * address);
extern UInt8 OSBitOrAtomic8(
UInt32 mask,
volatile UInt8 * address);
extern UInt32 OSBitXorAtomic(
UInt32 mask,
volatile UInt32 * address);
extern UInt16 OSBitXorAtomic16(
UInt32 mask,
volatile UInt16 * address);
extern UInt8 OSBitXorAtomic8(
UInt32 mask,
volatile UInt8 * address);
extern Boolean OSTestAndSet(
UInt32 bit,
volatile UInt8 * startAddress);
extern Boolean OSTestAndClear(
UInt32 bit,
volatile UInt8 * startAddress);
typedef SInt32 OSSpinLock;
static  void OSSynchronizeIO(void)
{
}
typedef thread_t IOThread;
typedef void (*IOThreadFunc)(void *argument);
void * IOMalloc(vm_size_t size) ;
void IOFree(void * address, vm_size_t size);
void * IOMallocAligned(vm_size_t size, vm_offset_t alignment) ;
void IOFreeAligned(void * address, vm_size_t size);
void * IOMallocContiguous(vm_size_t size, vm_size_t alignment,
IOPhysicalAddress * physicalAddress)  ;
void IOFreeContiguous(void * address, vm_size_t size) ;
void * IOMallocPageable(vm_size_t size, vm_size_t alignment) ;
void IOFreePageable(void * address, vm_size_t size);
UInt8 IOMappedRead8(IOPhysicalAddress address);
UInt16 IOMappedRead16(IOPhysicalAddress address);
UInt32 IOMappedRead32(IOPhysicalAddress address);
UInt64 IOMappedRead64(IOPhysicalAddress address);
void IOMappedWrite8(IOPhysicalAddress address, UInt8 value);
void IOMappedWrite16(IOPhysicalAddress address, UInt16 value);
void IOMappedWrite32(IOPhysicalAddress address, UInt32 value);
void IOMappedWrite64(IOPhysicalAddress address, UInt64 value);
IOReturn IOSetProcessorCacheMode( task_t task, IOVirtualAddress address,
IOByteCount length, IOOptionBits cacheMode ) ;
IOReturn IOFlushProcessorCache( task_t task, IOVirtualAddress address,
IOByteCount length );
IOThread IOCreateThread(IOThreadFunc function, void *argument) ;
void IOExitThread(void) ;
void IOSleep(unsigned milliseconds);
void IOSleepWithLeeway(unsigned intervalMilliseconds, unsigned leewayMilliseconds);
void IODelay(unsigned microseconds);
void IOPause(unsigned nanoseconds);
void IOLog(const char *format, ...)
;
void IOLogv(const char *format, va_list ap)
;
const char *IOFindNameForValue(int value,
const IONamedValue *namedValueArray);
IOReturn IOFindValueForName(const char *string,
const IONamedValue *regValueArray,
int *value);
void Debugger(const char * reason);
struct OSDictionary *
IOBSDNameMatching( const char * name );
struct OSDictionary *
IOOFPathMatching( const char * path, char * buf, int maxLen ) ;
IOAlignment IOSizeToAlignment(unsigned int size);
unsigned int IOAlignmentToSize(IOAlignment align);
static inline IOFixed IOFixedMultiply(IOFixed a, IOFixed b)
{
return (IOFixed)((((SInt64) a) * ((SInt64) b)) >> 16);
}
static inline IOFixed IOFixedDivide(IOFixed a, IOFixed b)
{
return (IOFixed)((((SInt64) a) << 16) / ((SInt64) b));
}
void IOGetTime( mach_timespec_t * clock_time) ;
enum {
kIODTNVRAMImageSize = 0x2000,
kIODTNVRAMXPRAMSize = 0x0100,
kIODTNVRAMNameRegistrySize = 0x0400
};
enum {
kOFVariableTypeBoolean = 1,
kOFVariableTypeNumber,
kOFVariableTypeString,
kOFVariableTypeData
};
enum {
kOFVariablePermRootOnly = 0,
kOFVariablePermUserRead,
kOFVariablePermUserWrite,
kOFVariablePermKernelOnly
};
extern OSBoolean * const & kOSBooleanTrue;
extern OSBoolean * const & kOSBooleanFalse;
enum { kOSStringNoCopy = 0x00000001 };
OSObject *
OSUnserializeBinary(const void *buffer, size_t bufferSize);
typedef _Bool (*OSSerializerCallback)(void * target, void * ref,
OSSerialize * serializer);
extern "C++" OSObject * OSUnserializeXML(
const char * buffer,
OSString ** errorString = 0);
extern "C++" OSObject * OSUnserializeXML(
const char * buffer,
size_t bufferSize,
OSString ** errorString = 0);
extern "C++" OSObject *
OSUnserializeBinary(const char *buffer, size_t bufferSize, OSString **errorString);
extern OSObject* OSUnserialize(const char *buffer, OSString **errorString = 0);
extern const OSSymbol * gIONameKey;
extern const OSSymbol * gIOLocationKey;
extern const OSSymbol * gIORegistryEntryIDKey;
extern const OSSymbol * gIORegistryEntryPropertyKeysKey;
typedef void (*IORegistryEntryApplierFunction)(IORegistryEntry * entry,
void * context);
enum {
kIORegistryIterateRecursively = 0x00000001,
kIORegistryIterateParents = 0x00000002,
};
extern const IORegistryPlane * gIODTPlane;
extern const OSSymbol * gIODTPHandleKey;
extern const OSSymbol * gIODTCompatibleKey;
extern const OSSymbol * gIODTTypeKey;
extern const OSSymbol * gIODTModelKey;
extern const OSSymbol * gIODTTargetTypeKey;
extern const OSSymbol * gIODTAAPLInterruptsKey;
extern const OSSymbol * gIODTDefaultInterruptController;
extern const OSSymbol * gIODTNWInterruptMappingKey;
IORegistryEntry * IODeviceTreeAlloc( void * dtTop );
_Bool IODTMatchNubWithKeys( IORegistryEntry * nub,
const char * keys );
_Bool IODTCompareNubName( const IORegistryEntry * regEntry,
OSString * name, OSString ** matchingName );
enum {
kIODTRecursive = 0x00000001,
kIODTExclusive = 0x00000002
};
OSCollectionIterator * IODTFindMatchingEntries( IORegistryEntry * from,
IOOptionBits options, const char * keys );
typedef SInt32 (*IODTCompareAddressCellFunc)
(UInt32 cellCount, UInt32 left[], UInt32 right[]);
typedef void (*IODTNVLocationFunc)
(IORegistryEntry * entry,
UInt8 * busNum, UInt8 * deviceNum, UInt8 * functionNum );
void IODTSetResolving( IORegistryEntry * regEntry,
IODTCompareAddressCellFunc compareFunc,
IODTNVLocationFunc locationFunc );
void IODTGetCellCounts( IORegistryEntry * regEntry,
UInt32 * sizeCount, UInt32 * addressCount);
_Bool IODTResolveAddressCell( IORegistryEntry * regEntry,
UInt32 cellsIn[],
IOPhysicalAddress * phys, IOPhysicalLength * len );
OSArray * IODTResolveAddressing( IORegistryEntry * regEntry,
const char * addressPropertyName,
IODeviceMemory * parent );
struct IONVRAMDescriptor {
unsigned int format:4;
unsigned int marker:1;
unsigned int bridgeCount:3;
unsigned int busNum:2;
unsigned int bridgeDevices:6 * 5;
unsigned int functionNum:3;
unsigned int deviceNum:5;
} ;
IOReturn IODTMakeNVDescriptor( IORegistryEntry * regEntry,
IONVRAMDescriptor * hdr );
OSData * IODTFindSlotName( IORegistryEntry * regEntry, UInt32 deviceNumber );
const OSSymbol * IODTInterruptControllerName(
IORegistryEntry * regEntry );
_Bool IODTMapInterrupts( IORegistryEntry * regEntry );
enum {
kIODTInterruptShared = 0x00000001
};
IOReturn IODTGetInterruptOptions( IORegistryEntry * regEntry, int source, IOOptionBits * options );
IOReturn IONDRVLibrariesInitialize( IOService * provider );
typedef enum {
kCoprocessorVersionNone = 0x00000000,
kCoprocessorVersion1 = 0x00010000,
kCoprocessorVersion2 = 0x00020000,
} coprocessor_type_t;
extern boolean_t PEGetMachineName( char * name, int maxLength );
extern boolean_t PEGetModelName( char * name, int maxLength );
extern int PEGetPlatformEpoch( void );
enum {
kPEHaltCPU,
kPERestartCPU,
kPEHangCPU,
kPEUPSDelayHaltCPU,
kPEPanicRestartCPU,
kPEPanicSync,
kPEPagingOff,
kPEPanicBegin,
kPEPanicEnd,
kPEPanicDiskShutdown
};
extern int (*PE_halt_restart)(unsigned int type);
extern int PEHaltRestart(unsigned int type);
extern UInt32 PESavePanicInfo(UInt8 *buffer, UInt32 length);
extern void PESavePanicInfoAction(void *buffer, UInt32 offset, UInt32 length);
extern long PEGetGMTTimeOfDay( void );
extern void PESetGMTTimeOfDay( long secs );
extern void PEGetUTCTimeOfDay( clock_sec_t * secs, clock_usec_t * usecs );
extern void PESetUTCTimeOfDay( clock_sec_t secs, clock_usec_t usecs );
extern boolean_t PEWriteNVRAMBooleanProperty(const char *symbol, boolean_t value);
extern boolean_t PEWriteNVRAMProperty(const char *symbol, const void *value, const unsigned int len);
extern boolean_t PEReadNVRAMProperty(const char *symbol, void *value, unsigned int *len);
extern boolean_t PERemoveNVRAMProperty(const char *symbol);
extern coprocessor_type_t PEGetCoprocessorVersion( void );
ppnum_t IOMapperIOVMAlloc(unsigned pages);
void IOMapperIOVMFree(ppnum_t addr, unsigned pages);
ppnum_t IOMapperInsertPage(ppnum_t addr, unsigned offset, ppnum_t page);
typedef UInt32 IOMessage;
enum
{
kIODirectionNone = 0x0,
kIODirectionIn = 0x1,
kIODirectionOut = 0x2,
kIODirectionOutIn = kIODirectionOut | kIODirectionIn,
kIODirectionInOut = kIODirectionIn | kIODirectionOut,
kIODirectionPrepareToPhys32 = 0x00000004,
kIODirectionPrepareNoFault = 0x00000008,
kIODirectionPrepareReserved1 = 0x00000010,
kIODirectionPrepareNonCoherent = 0x00000020,
kIODirectionCompleteWithError = 0x00000040,
kIODirectionCompleteWithDataValid = 0x00000080,
};
typedef IOOptionBits IODirection;
enum {
kIOMemoryDirectionMask = 0x00000007,
kIOMemoryTypeVirtual = 0x00000010,
kIOMemoryTypePhysical = 0x00000020,
kIOMemoryTypeUPL = 0x00000030,
kIOMemoryTypePersistentMD = 0x00000040,
kIOMemoryTypeUIO = 0x00000050,
kIOMemoryTypeVirtual64 = kIOMemoryTypeVirtual,
kIOMemoryTypePhysical64 = kIOMemoryTypePhysical,
kIOMemoryTypeMask = 0x000000f0,
kIOMemoryAsReference = 0x00000100,
kIOMemoryBufferPageable = 0x00000400,
kIOMemoryMapperNone = 0x00000800,
kIOMemoryHostOnly = 0x00001000,
kIOMemoryPersistent = 0x00010000,
kIOMemoryRemote = 0x00040000,
kIOMemoryThreadSafe = 0x00100000,
kIOMemoryClearEncrypt = 0x00200000,
kIOMemoryUseReserve = 0x00800000,
};
enum
{
kIOMemoryPurgeableKeepCurrent = 1,
kIOMemoryPurgeableNonVolatile = 2,
kIOMemoryPurgeableVolatile = 3,
kIOMemoryPurgeableEmpty = 4,
kIOMemoryPurgeableVolatileGroup0 = (0 << 8),
kIOMemoryPurgeableVolatileGroup1 = (1 << 8),
kIOMemoryPurgeableVolatileGroup2 = (2 << 8),
kIOMemoryPurgeableVolatileGroup3 = (3 << 8),
kIOMemoryPurgeableVolatileGroup4 = (4 << 8),
kIOMemoryPurgeableVolatileGroup5 = (5 << 8),
kIOMemoryPurgeableVolatileGroup6 = (6 << 8),
kIOMemoryPurgeableVolatileGroup7 = (7 << 8),
kIOMemoryPurgeableVolatileBehaviorFifo = (0 << 6),
kIOMemoryPurgeableVolatileBehaviorLifo = (1 << 6),
kIOMemoryPurgeableVolatileOrderingObsolete = (1 << 5),
kIOMemoryPurgeableVolatileOrderingNormal = (0 << 5),
kIOMemoryPurgeableFaultOnAccess = (0x2 << 12),
};
enum
{
kIOMemoryIncoherentIOFlush = 1,
kIOMemoryIncoherentIOStore = 2,
kIOMemoryClearEncrypted = 50,
kIOMemorySetEncrypted = 51,
};
struct IODMAMapSpecification
{
uint64_t alignment;
IOService * device;
uint32_t options;
uint8_t numAddressBits;
uint8_t resvA[3];
uint32_t resvB[4];
};
struct IODMAMapPageList
{
uint32_t pageOffset;
uint32_t pageListCount;
const upl_page_info_t * pageList;
};
enum
{
kIODMAMapReadAccess = 0x00000001,
kIODMAMapWriteAccess = 0x00000002,
kIODMAMapPhysicallyContiguous = 0x00000010,
kIODMAMapDeviceMemory = 0x00000020,
kIODMAMapPagingPath = 0x00000040,
kIODMAMapIdentityMap = 0x00000080,
kIODMAMapPageListFullyOccupied = 0x00000100,
kIODMAMapFixedAddress = 0x00000200,
};
enum
{
kIOPreparationIDUnprepared = 0,
kIOPreparationIDUnsupported = 1,
kIOPreparationIDAlwaysPrepared = 2,
};
/*
mach_vm_address_t IOMemoryMap::getAddress()
{
return (getVirtualAddress());
}
mach_vm_size_t IOMemoryMap::getSize()
{
return (getLength());
}
*/
typedef uint16_t IOReportCategories;
typedef uint8_t IOReportFormat;
enum {
kIOReportInvalidFormat = 0,
kIOReportFormatSimple = 1,
kIOReportFormatState = 2,
kIOReportFormatHistogram = 3,
kIOReportFormatSimpleArray = 4
};
typedef struct {
int64_t simple_value;
uint64_t reserved1;
uint64_t reserved2;
uint64_t reserved3;
}  IOSimpleReportValues;
typedef struct {
int64_t simple_values[4];
}  IOSimpleArrayReportValues;
typedef struct {
uint64_t state_id;
uint64_t intransitions;
uint64_t upticks;
uint64_t last_intransition;
}  IOStateReportValues;
typedef struct {
uint64_t bucket_hits;
int64_t bucket_min;
int64_t bucket_max;
int64_t bucket_sum;
}  IOHistogramReportValues;
typedef uint32_t IOReportConfigureAction;
enum {
kIOReportEnable = 0x01,
kIOReportGetDimensions = 0x02,
kIOReportDisable = 0x00,
kIOReportNotifyHubOnChange = 0x10,
kIOReportTraceOnChange = 0x20
};
typedef uint32_t IOReportUpdateAction;
enum {
kIOReportCopyChannelData = 1,
kIOReportTraceChannelData = 2
};
typedef struct {
uint8_t report_format;
uint8_t reserved;
uint16_t categories;
uint16_t nelements;
int16_t element_idx;
}  IOReportChannelType;
typedef struct {
uint64_t channel_id;
IOReportChannelType channel_type;
} IOReportChannel;
typedef struct {
uint32_t nchannels;
IOReportChannel channels[];
} IOReportChannelList;
typedef struct {
uint64_t provider_id;
IOReportChannel channel;
} IOReportInterest;
typedef struct {
uint32_t ninterests;
IOReportInterest interests[];
} IOReportInterestList;
typedef struct {
uint64_t v[4];
}  IOReportElementValues;
typedef struct {
uint64_t provider_id;
uint64_t channel_id;
IOReportChannelType channel_type;
uint64_t timestamp;
IOReportElementValues values;
}  IOReportElement;
typedef uint64_t IOReportUnit;
typedef uint64_t IOReportUnits;
typedef uint8_t IOReportQuantity;
typedef uint64_t IOReportScaleFactor;
enum {
kIOReportQuantityUndefined = 0,
kIOReportQuantityTime = 1,
kIOReportQuantityPower = 2,
kIOReportQuantityEnergy = 3,
kIOReportQuantityCurrent = 4,
kIOReportQuantityVoltage = 5,
kIOReportQuantityCapacitance = 6,
kIOReportQuantityInductance = 7,
kIOReportQuantityFrequency = 8,
kIOReportQuantityData = 9,
kIOReportQuantityTemperature = 10,
kIOReportQuantityEventCount = 100,
kIOReportQuantityPacketCount = 101,
kIOReportQuantityCPUInstrs = 102
};
typedef struct _IODataQueueMemory IODataQueueMemory;
struct _notifyMsg {
mach_msg_header_t h;
};
typedef struct _IODataQueueEntry{
UInt32 size;
UInt8 data[4];
} IODataQueueEntry;
typedef struct _IODataQueueMemory {
UInt32 queueSize;
volatile UInt32 head;
volatile UInt32 tail;
IODataQueueEntry queue[1];
} IODataQueueMemory;
typedef struct _IODataQueueAppendix {
UInt32 version;
mach_msg_header_t msgh;
} IODataQueueAppendix;
enum {
kFirstIOKitNotificationType = 100,
kIOServicePublishNotificationType = 100,
kIOServiceMatchedNotificationType = 101,
kIOServiceTerminatedNotificationType = 102,
kIOAsyncCompletionNotificationType = 150,
kIOServiceMessageNotificationType = 160,
kLastIOKitNotificationType = 199,
kIOKitNoticationTypeMask = 0x00000FFF,
kIOKitNoticationTypeSizeAdjShift = 30,
kIOKitNoticationMsgSizeMask = 3,
};
enum {
kOSNotificationMessageID = 53,
kOSAsyncCompleteMessageID = 57,
kMaxAsyncArgs = 16
};
enum {
kIOAsyncReservedIndex = 0,
kIOAsyncReservedCount,
kIOAsyncCalloutFuncIndex = kIOAsyncReservedCount,
kIOAsyncCalloutRefconIndex,
kIOAsyncCalloutCount,
kIOMatchingCalloutFuncIndex = kIOAsyncReservedCount,
kIOMatchingCalloutRefconIndex,
kIOMatchingCalloutCount,
kIOInterestCalloutFuncIndex = kIOAsyncReservedCount,
kIOInterestCalloutRefconIndex,
kIOInterestCalloutServiceIndex,
kIOInterestCalloutCount
};
enum {
kOSAsyncRef64Count = 8,
kOSAsyncRef64Size = kOSAsyncRef64Count * ((int) sizeof(io_user_reference_t))
};
typedef io_user_reference_t OSAsyncReference64[kOSAsyncRef64Count];
struct OSNotificationHeader64 {
mach_msg_size_t size;
natural_t type;
OSAsyncReference64 reference;
unsigned char content[];
};
struct IOServiceInterestContent64 {
natural_t messageType;
io_user_reference_t messageArgument[1];
};
enum {
kOSAsyncRefCount = 8,
kOSAsyncRefSize = 32
};
typedef natural_t OSAsyncReference[kOSAsyncRefCount];
struct OSNotificationHeader {
mach_msg_size_t size;
natural_t type;
OSAsyncReference reference;
unsigned char content[];
};
struct IOServiceInterestContent {
natural_t messageType;
void * messageArgument[1];
};
struct IOAsyncCompletionContent {
IOReturn result;
void * args[] ;
};
typedef struct OSNotificationHeader OSNotificationHeader;
typedef struct IOServiceInterestContent IOServiceInterestContent;
typedef struct IOAsyncCompletionContent IOAsyncCompletionContent;
enum {
kIOLogAttach = 0x00000001ULL,
kIOLogProbe = 0x00000002ULL,
kIOLogStart = 0x00000004ULL,
kIOLogRegister = 0x00000008ULL,
kIOLogMatch = 0x00000010ULL,
kIOLogConfig = 0x00000020ULL,
kIOLogYield = 0x00000040ULL,
kIOLogPower = 0x00000080ULL,
kIOLogMapping = 0x00000100ULL,
kIOLogCatalogue = 0x00000200ULL,
kIOLogTracePower = 0x00000400ULL,
kIOLogDebugPower = 0x00000800ULL,
kIOLogServiceTree = 0x00001000ULL,
kIOLogDTree = 0x00002000ULL,
kIOLogMemory = 0x00004000ULL,
kIOLogKextMemory = 0x00008000ULL,
kOSLogRegistryMods = 0x00010000ULL,
kIOLogPMRootDomain = 0x00020000ULL,
kOSRegistryModsMode = 0x00040000ULL,
kIOLogHibernate = 0x00100000ULL,
kIOStatistics = 0x04000000ULL,
kIOSleepWakeWdogOff = 0x40000000ULL,
kIOKextSpinDump = 0x80000000ULL,
kIONoFreeObjects = 0x00100000ULL,
kIOTracking = 0x00400000ULL,
kIOWaitQuietPanics = 0x00800000ULL,
kIOWaitQuietBeforeRoot = 0x01000000ULL,
kIOTrackingBoot = 0x02000000ULL,
_kIODebugTopFlag = 0x8000000000000000ULL
};
enum {
kIOKitDebugUserOptions = 0
| kIOLogAttach
| kIOLogProbe
| kIOLogStart
| kIOLogRegister
| kIOLogMatch
| kIOLogConfig
| kIOLogYield
| kIOLogPower
| kIOLogMapping
| kIOLogCatalogue
| kIOLogTracePower
| kIOLogDebugPower
| kOSLogRegistryMods
| kIOLogPMRootDomain
| kOSRegistryModsMode
| kIOLogHibernate
| kIOSleepWakeWdogOff
| kIOKextSpinDump
| kIOWaitQuietPanics
};
enum {
kIOTraceInterrupts = 0x00000001ULL,
kIOTraceWorkLoops = 0x00000002ULL,
kIOTraceEventSources = 0x00000004ULL,
kIOTraceIntEventSource = 0x00000008ULL,
kIOTraceCommandGates = 0x00000010ULL,
kIOTraceTimers = 0x00000020ULL,
kIOTracePowerMgmt = 0x00000400ULL,
kIOTraceIOService = 0x00080000ULL,
kIOTraceCompatBootArgs = kIOTraceIOService | kIOTracePowerMgmt
};
extern SInt64 gIOKitDebug;
extern SInt64 gIOKitTrace;
extern void IOPrintPlane(
const struct IORegistryPlane * plane
);
extern void OSPrintMemory( void );
enum
{
kIOKitDiagnosticsClientType = 0x99000002
};
struct IOKitDiagnosticsParameters
{
size_t size;
uint64_t value;
uint32_t options;
uint32_t tag;
uint32_t zsize;
uint32_t reserved[8];
};
typedef struct IOKitDiagnosticsParameters IOKitDiagnosticsParameters;
enum
{
kIOTrackingCallSiteBTs = 16,
};
struct IOTrackingCallSiteInfo
{
uint32_t count;
pid_t addressPID;
mach_vm_address_t address;
mach_vm_size_t size[2];
pid_t btPID;
mach_vm_address_t bt[2][kIOTrackingCallSiteBTs];
};
enum
{
kIOTrackingExcludeNames = 0x00000001,
};
enum
{
kIOTrackingGetTracking = 0x00000001,
kIOTrackingGetMappings = 0x00000002,
kIOTrackingResetTracking = 0x00000003,
kIOTrackingStartCapture = 0x00000004,
kIOTrackingStopCapture = 0x00000005,
kIOTrackingSetMinCaptureSize = 0x00000006,
kIOTrackingLeaks = 0x00000007,
kIOTrackingInvalid = 0xFFFFFFFE,
};
enum {
kIOPMMaxPowerStates = 10,
IOPMMaxPowerStates = kIOPMMaxPowerStates
};
typedef unsigned long IOPMPowerFlags;
enum {
kIOPMPowerOn = 0x00000002,
kIOPMDeviceUsable = 0x00008000,
kIOPMLowPower = 0x00010000,
kIOPMPreventIdleSleep = 0x00000040,
kIOPMSleepCapability = 0x00000004,
kIOPMRestartCapability = 0x00000080,
kIOPMSleep = 0x00000001,
kIOPMRestart = 0x00000080,
kIOPMInitialDeviceState = 0x00000100,
kIOPMRootDomainState = 0x00000200
};
enum {
kIOPMClockNormal = 0x0004,
kIOPMClockRunning = 0x0008,
kIOPMPreventSystemSleep = 0x0010,
kIOPMDoze = 0x0400,
kIOPMChildClamp = 0x0080,
kIOPMChildClamp2 = 0x0200,
kIOPMNotPowerManaged = 0x0800
};
enum {
kIOPMMaxPerformance = 0x4000,
kIOPMPassThrough = 0x0100,
kIOPMAuxPowerOn = 0x0020,
kIOPMNotAttainable = 0x0001,
kIOPMContextRetained = 0x2000,
kIOPMConfigRetained = 0x1000,
kIOPMStaticPowerValid = 0x0800,
kIOPMSoftSleep = 0x0400,
kIOPMCapabilitiesMask = kIOPMPowerOn | kIOPMDeviceUsable |
kIOPMMaxPerformance | kIOPMContextRetained |
kIOPMConfigRetained | kIOPMSleepCapability |
kIOPMRestartCapability
};
enum {
IOPMNotAttainable = kIOPMNotAttainable,
IOPMPowerOn = kIOPMPowerOn,
IOPMClockNormal = kIOPMClockNormal,
IOPMClockRunning = kIOPMClockRunning,
IOPMAuxPowerOn = kIOPMAuxPowerOn,
IOPMDeviceUsable = kIOPMDeviceUsable,
IOPMMaxPerformance = kIOPMMaxPerformance,
IOPMContextRetained = kIOPMContextRetained,
IOPMConfigRetained = kIOPMConfigRetained,
IOPMNotPowerManaged = kIOPMNotPowerManaged,
IOPMSoftSleep = kIOPMSoftSleep
};
enum {
kIOPMNextHigherState = 1,
kIOPMHighestState = 2,
kIOPMNextLowerState = 3,
kIOPMLowestState = 4
};
enum {
IOPMNextHigherState = kIOPMNextHigherState,
IOPMHighestState = kIOPMHighestState,
IOPMNextLowerState = kIOPMNextLowerState,
IOPMLowestState = kIOPMLowestState
};
enum {
kIOPMBroadcastAggressiveness = 1,
kIOPMUnidleDevice
};
enum {
kIOPMUnknown = 0xFFFF
};
enum {
kIOPMDriverAssertionCPUBit = 0x01,
kIOPMDriverAssertionUSBExternalDeviceBit = 0x04,
kIOPMDriverAssertionBluetoothHIDDevicePairedBit = 0x08,
kIOPMDriverAssertionExternalMediaMountedBit = 0x10,
kIOPMDriverAssertionReservedBit5 = 0x20,
kIOPMDriverAssertionPreventDisplaySleepBit = 0x40,
kIOPMDriverAssertionReservedBit7 = 0x80,
kIOPMDriverAssertionMagicPacketWakeEnabledBit = 0x100,
kIOPMDriverAssertionNetworkKeepAliveActiveBit = 0x200
};
enum {
kClamshellStateBit = (1 << 0),
kClamshellSleepBit = (1 << 1)
};
enum {
kInflowForciblyEnabledBit = (1 << 0)
};
enum {
kIOPMSleepNow = (1<<0),
kIOPMAllowSleep = (1<<1),
kIOPMPreventSleep = (1<<2),
kIOPMPowerButton = (1<<3),
kIOPMClamshellClosed = (1<<4),
kIOPMPowerEmergency = (1<<5),
kIOPMDisableClamshell = (1<<6),
kIOPMEnableClamshell = (1<<7),
kIOPMProcessorSpeedChange = (1<<8),
kIOPMOverTemp = (1<<9),
kIOPMClamshellOpened = (1<<10),
kIOPMDWOverTemp = (1<<11)
};
enum {
kIOPMNoErr = 0,
kIOPMAckImplied = 0,
kIOPMWillAckLater = 1,
kIOPMBadSpecification = 4,
kIOPMNoSuchState = 5,
kIOPMCannotRaisePower = 6,
kIOPMParameterError = 7,
kIOPMNotYetInitialized = 8,
IOPMNoErr = kIOPMNoErr,
IOPMAckImplied = kIOPMAckImplied,
IOPMWillAckLater = kIOPMWillAckLater,
IOPMBadSpecification = kIOPMBadSpecification,
IOPMNoSuchState = kIOPMNoSuchState,
IOPMCannotRaisePower = kIOPMCannotRaisePower,
IOPMParameterError = kIOPMParameterError,
IOPMNotYetInitialized = kIOPMNotYetInitialized
};
enum {
kIOPMPSLocationLeft = 1001,
kIOPMPSLocationRight = 1002
};
enum {
kIOPMUndefinedValue = 0,
kIOPMPoorValue = 1,
kIOPMFairValue = 2,
kIOPMGoodValue = 3
};
enum {
kIOPSFamilyCodeDisconnected = 0,
kIOPSFamilyCodeUnsupported = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((0)&0xfff)<<14)|0x2c7),
kIOPSFamilyCodeFirewire = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((2)&0xfff)<<14)|0),
kIOPSFamilyCodeUSBHost = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|0),
kIOPSFamilyCodeUSBHostSuspended = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|1),
kIOPSFamilyCodeUSBDevice = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|2),
kIOPSFamilyCodeUSBAdapter = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|3),
kIOPSFamilyCodeUSBChargingPortDedicated = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|4),
kIOPSFamilyCodeUSBChargingPortDownstream = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|5),
kIOPSFamilyCodeUSBChargingPort = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|6),
kIOPSFamilyCodeUSBUnknown = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((1)&0xfff)<<14)|7),
kIOPSFamilyCodeAC = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((9)&0xfff)<<14)|0),
kIOPSFamilyCodeExternal = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((9)&0xfff)<<14)|1),
kIOPSFamilyCodeExternal2 = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((9)&0xfff)<<14)|2),
kIOPSFamilyCodeExternal3 = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((9)&0xfff)<<14)|3),
kIOPSFamilyCodeExternal4 = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((9)&0xfff)<<14)|4),
};
enum {
kIOPMThermalLevelNormal = 0,
kIOPMThermalLevelDanger = 5,
kIOPMThermalLevelCritical = 10,
kIOPMThermalLevelWarning = 100,
kIOPMThermalLevelTrap = 110,
kIOPMThermalLevelUnknown = 255,
};
struct IOPMCalendarStruct {
UInt32 year;
UInt8 month;
UInt8 day;
UInt8 hour;
UInt8 minute;
UInt8 second;
UInt8 selector;
};
typedef struct IOPMCalendarStruct IOPMCalendarStruct;
enum {
kPMGeneralAggressiveness = 0,
kPMMinutesToDim,
kPMMinutesToSpinDown,
kPMMinutesToSleep,
kPMEthernetWakeOnLANSettings,
kPMSetProcessorSpeed,
kPMPowerSource,
kPMMotionSensor,
kPMLastAggressivenessType
};
enum {
kIOPMInternalPower = 1,
kIOPMExternalPower
};
enum {
kIOBatteryInstalled = (1 << 2),
kIOBatteryCharge = (1 << 1),
kIOBatteryChargerConnect = (1 << 0)
};
enum {
kIOPMACInstalled = kIOBatteryChargerConnect,
kIOPMBatteryCharging = kIOBatteryCharge,
kIOPMBatteryInstalled = kIOBatteryInstalled,
kIOPMUPSInstalled = (1<<3),
kIOPMBatteryAtWarn = (1<<4),
kIOPMBatteryDepleted = (1<<5),
kIOPMACnoChargeCapability = (1<<6),
kIOPMRawLowBattery = (1<<7),
kIOPMForceLowSpeed = (1<<8),
kIOPMClosedClamshell = (1<<9),
kIOPMClamshellStateOnWake = (1<<10)
};
struct IOPowerStateChangeNotification {
void * powerRef;
unsigned long returnValue;
unsigned long stateNumber;
IOPMPowerFlags stateFlags;
};
typedef struct IOPowerStateChangeNotification IOPowerStateChangeNotification;
typedef IOPowerStateChangeNotification sleepWakeNote;
struct IOPMSystemCapabilityChangeParameters {
uint32_t notifyRef;
uint32_t maxWaitForReply;
uint32_t changeFlags;
uint32_t __reserved1;
uint32_t fromCapabilities;
uint32_t toCapabilities;
uint32_t __reserved2[4];
};
enum {
kIOPMSystemCapabilityWillChange = 0x01,
kIOPMSystemCapabilityDidChange = 0x02
};
enum {
kIOPMSystemCapabilityCPU = 0x01,
kIOPMSystemCapabilityGraphics = 0x02,
kIOPMSystemCapabilityAudio = 0x04,
kIOPMSystemCapabilityNetwork = 0x08
};
struct IOPMPowerState
{
unsigned long version;
IOPMPowerFlags capabilityFlags;
IOPMPowerFlags outputPowerCharacter;
IOPMPowerFlags inputPowerRequirement;
unsigned long staticPower;
unsigned long stateOrder;
unsigned long powerToAttain;
unsigned long timeToAttain;
unsigned long settleUpTime;
unsigned long timeToLower;
unsigned long settleDownTime;
unsigned long powerDomainBudget;
};
typedef struct IOPMPowerState IOPMPowerState;
enum {
kIOPMPowerStateVersion1 = 1,
kIOPMPowerStateVersion2 = 2
};
extern "C" {
}
enum {
kIODefaultProbeScore = 0
};
enum {
kIOServiceInactiveState = 0x00000001,
kIOServiceRegisteredState = 0x00000002,
kIOServiceMatchedState = 0x00000004,
kIOServiceFirstPublishState = 0x00000008,
kIOServiceFirstMatchState = 0x00000010
};
enum {
kIOServiceExclusive = 0x00000001,
kIOServiceRequired = 0x00000001,
kIOServiceTerminate = 0x00000004,
kIOServiceSynchronous = 0x00000002,
kIOServiceAsynchronous = 0x00000008
};
enum {
kIOServiceSeize = 0x00000001,
kIOServiceFamilyOpenOptions = 0xffff0000
};
enum {
kIOServiceFamilyCloseOptions = 0xffff0000
};
typedef void * IONotificationRef;
extern const IORegistryPlane * gIOServicePlane;
extern const IORegistryPlane * gIOPowerPlane;
extern const OSSymbol * gIOResourcesKey;
extern const OSSymbol * gIOResourceMatchKey;
extern const OSSymbol * gIOResourceMatchedKey;
extern const OSSymbol * gIOProviderClassKey;
extern const OSSymbol * gIONameMatchKey;
extern const OSSymbol * gIONameMatchedKey;
extern const OSSymbol * gIOPropertyMatchKey;
extern const OSSymbol * gIOLocationMatchKey;
extern const OSSymbol * gIOParentMatchKey;
extern const OSSymbol * gIOPathMatchKey;
extern const OSSymbol * gIOMatchCategoryKey;
extern const OSSymbol * gIODefaultMatchCategoryKey;
extern const OSSymbol * gIOMatchedServiceCountKey;
extern const OSSymbol * gIOUserClientClassKey;
extern const OSSymbol * gIOKitDebugKey;
extern const OSSymbol * gIOServiceKey;
extern const OSSymbol * gIOCommandPoolSizeKey;
extern const OSSymbol * gIOPublishNotification;
extern const OSSymbol * gIOFirstPublishNotification;
extern const OSSymbol * gIOMatchedNotification;
extern const OSSymbol * gIOFirstMatchNotification;
extern const OSSymbol * gIOTerminatedNotification;
extern const OSSymbol * gIOWillTerminateNotification;
extern const OSSymbol * gIOGeneralInterest;
extern const OSSymbol * gIOBusyInterest;
extern const OSSymbol * gIOOpenInterest;
extern const OSSymbol * gIOAppPowerStateInterest;
extern const OSSymbol * gIOPriorityPowerStateInterest;
extern const OSSymbol * gIOConsoleSecurityInterest;
extern const OSSymbol * gIODeviceMemoryKey;
extern const OSSymbol * gIOInterruptControllersKey;
extern const OSSymbol * gIOInterruptSpecifiersKey;
extern const OSSymbol * gIOBSDKey;
extern const OSSymbol * gIOBSDNameKey;
extern const OSSymbol * gIOBSDMajorKey;
extern const OSSymbol * gIOBSDMinorKey;
extern const OSSymbol * gIOBSDUnitKey;
extern SInt32 IOServiceOrdering( const OSMetaClassBase * inObj1, const OSMetaClassBase * inObj2, void * ref );
typedef void (*IOInterruptAction)( OSObject * target, void * refCon,
IOService * nub, int source );
typedef _Bool (*IOServiceNotificationHandler)( void * target, void * refCon,
IOService * newService );
typedef _Bool (*IOServiceMatchingNotificationHandler)( void * target, void * refCon,
IOService * newService,
IONotifier * notifier );
typedef IOReturn (*IOServiceInterestHandler)( void * target, void * refCon,
UInt32 messageType, IOService * provider,
void * messageArgument, vm_size_t argSize );
typedef void (*IOServiceApplierFunction)(IOService * service, void * context);
typedef void (*OSObjectApplierFunction)(OSObject * object, void * context);
struct IOInterruptAccountingData;
struct IOInterruptAccountingReporter;
struct IOInterruptAccountingData;
enum {
kIOUCTypeMask = 0x0000000f,
kIOUCScalarIScalarO = 0,
kIOUCScalarIStructO = 2,
kIOUCStructIStructO = 3,
kIOUCScalarIStructI = 4,
kIOUCForegroundOnly = 0x00000010,
};
enum {
kIOUCVariableStructureSize = 0xffffffff
};
/*
typedef IOReturn (IOService::*IOMethod)(void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
typedef IOReturn (IOService::*IOAsyncMethod)(OSAsyncReference asyncRef,
void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
typedef IOReturn (IOService::*IOTrap)(void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
*/
typedef IOReturn (*IOMethod)(void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
typedef IOReturn (*IOAsyncMethod)(OSAsyncReference asyncRef,
void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
typedef IOReturn (*IOTrap)(void * p1, void * p2, void * p3,
void * p4, void * p5, void * p6 );
struct IOExternalMethod {
IOService * object;
IOMethod func;
IOOptionBits flags;
IOByteCount count0;
IOByteCount count1;
};
struct IOExternalAsyncMethod {
IOService * object;
IOAsyncMethod func;
IOOptionBits flags;
IOByteCount count0;
IOByteCount count1;
};
struct IOExternalTrap {
IOService * object;
IOTrap func;
};
enum {
kIOUserNotifyMaxMessageSize = 64
};
enum {
kIOUserNotifyOptionCanDrop = 0x1
};
enum {
kIOExternalMethodScalarInputCountMax = 16,
kIOExternalMethodScalarOutputCountMax = 16,
};
struct IOExternalMethodArguments
{
uint32_t version;
uint32_t selector;
mach_port_t asyncWakePort;
io_user_reference_t * asyncReference;
uint32_t asyncReferenceCount;
const uint64_t * scalarInput;
uint32_t scalarInputCount;
const void * structureInput;
uint32_t structureInputSize;
IOMemoryDescriptor * structureInputDescriptor;
uint64_t * scalarOutput;
uint32_t scalarOutputCount;
void * structureOutput;
uint32_t structureOutputSize;
IOMemoryDescriptor * structureOutputDescriptor;
uint32_t structureOutputDescriptorSize;
uint32_t __reservedA;
OSObject ** structureVariableOutputData;
uint32_t __reserved[30];
};
typedef IOReturn (*IOExternalMethodAction)(OSObject * target, void * reference,
IOExternalMethodArguments * arguments);
struct IOExternalMethodDispatch
{
IOExternalMethodAction function;
uint32_t checkScalarInputCount;
uint32_t checkStructureInputSize;
uint32_t checkScalarOutputCount;
uint32_t checkStructureOutputSize;
};
enum {
kIOExternalMethodArgumentsCurrentVersion = 2
};
typedef struct IOI2CRequest IOI2CRequest;
typedef struct IOI2CBuffer IOI2CBuffer;
typedef void (*IOI2CRequestCompletion) (IOI2CRequest * request);
enum {
kIOI2CNoTransactionType = 0,
kIOI2CSimpleTransactionType = 1,
kIOI2CDDCciReplyTransactionType = 2,
kIOI2CCombinedTransactionType = 3,
kIOI2CDisplayPortNativeTransactionType = 4
};
enum {
kIOI2CUseSubAddressCommFlag = 0x00000002
};
struct IOI2CRequest
{
IOOptionBits sendTransactionType;
IOOptionBits replyTransactionType;
uint32_t sendAddress;
uint32_t replyAddress;
uint8_t sendSubAddress;
uint8_t replySubAddress;
uint8_t __reservedA[2];
uint64_t minReplyDelay;
IOReturn result;
IOOptionBits commFlags;
uint32_t __padA;
uint32_t sendBytes;
uint32_t __reservedB[2];
uint32_t __padB;
uint32_t replyBytes;
IOI2CRequestCompletion completion;
vm_address_t sendBuffer;
vm_address_t replyBuffer;
uint32_t __reservedC[10];
};
enum {
kIOI2CBusTypeI2C = 1,
kIOI2CBusTypeDisplayPort = 2
};
struct IOI2CBusTiming
{
AbsoluteTime bitTimeout;
AbsoluteTime byteTimeout;
AbsoluteTime acknowledgeTimeout;
AbsoluteTime startTimeout;
AbsoluteTime holdTime;
AbsoluteTime riseFallTime;
UInt32 __reservedA[8];
};
typedef struct IOI2CBusTiming IOI2CBusTiming;
enum {
kIOI2CBusNumberMask = 0x000000ff
};
IOReturn IOFBGetI2CInterfaceCount( io_service_t framebuffer, IOItemCount * count );
IOReturn IOFBCopyI2CInterfaceForBus( io_service_t framebuffer, IOOptionBits bus, io_service_t * interface );
typedef struct IOI2CConnect * IOI2CConnectRef;
typedef void * CFTypeRef
IOReturn IOI2CCopyInterfaceForID( CFTypeRef identifier, io_service_t * interface );
IOReturn IOI2CInterfaceOpen( io_service_t interface, IOOptionBits options,
IOI2CConnectRef * connect );
IOReturn IOI2CInterfaceClose( IOI2CConnectRef connect, IOOptionBits options );
IOReturn IOI2CSendRequest( IOI2CConnectRef connect, IOOptionBits options,
IOI2CRequest * request );
enum
{
kIODMAMapOptionMapped = 0x00000000,
kIODMAMapOptionBypassed = 0x00000001,
kIODMAMapOptionNonCoherent = 0x00000002,
kIODMAMapOptionUnmapped = 0x00000003,
kIODMAMapOptionTypeMask = 0x0000000f,
kIODMAMapOptionNoCacheStore = 0x00000010,
kIODMAMapOptionOnChip = 0x00000020,
kIODMAMapOptionIterateOnly = 0x00000040
};
/*
IOReturn IODMACommand::
weakWithSpecification(IODMACommand **newCommand,
SegmentFunction outSegFunc,
UInt8 numAddressBits,
UInt64 maxSegmentSize,
MappingOptions mapType,
UInt64 maxTransferSize,
UInt32 alignment,
IOMapper *mapper,
void *refCon)
{
if (!newCommand)
return (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((0)&0xfff)<<14)|0x2c2);
IODMACommand *self = (IODMACommand *)
OSMetaClass::allocClassWithName("IODMACommand");
if (!self)
return (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((0)&0xfff)<<14)|0x2c7);
IOReturn ret;
_Bool inited = self->
initWithSpecification(outSegFunc,
numAddressBits, maxSegmentSize, mapType,
maxTransferSize, alignment, mapper, refCon);
if (inited)
ret = 0;
else {
self->release();
self = 0;
ret = (((signed)((((unsigned)(0x38))&0x3f)<<26))|(((0)&0xfff)<<14)|0x2bc);
}
*newCommand = self;
return ret;
};
*/
typedef struct {
uint32_t base_bucket_width;
uint32_t scale_flag;
uint32_t segment_idx;
uint32_t segment_bucket_count;
}  IOHistogramSegmentConfig;
typedef struct {
uint64_t samples;
uint64_t mean;
uint64_t variance;
uint64_t reserved;
}  IONormDistReportValues;
enum {
kIOMemoryPhysicallyContiguous = 0x00000010,
kIOMemoryPageable = 0x00000020,
kIOMemoryPurgeable = 0x00000040,
kIOMemoryHostPhysicallyContiguous = 0x00000080,
kIOMemorySharingTypeMask = 0x000f0000,
kIOMemoryUnshared = 0x00000000,
kIOMemoryKernelUserShared = 0x00010000,
kIOBufferDescriptorMemoryFlags = kIOMemoryDirectionMask
| kIOMemoryThreadSafe
| kIOMemoryClearEncrypt
| kIOMemoryMapperNone
| kIOMemoryUseReserve
};
enum {
kIOCatalogAddDrivers = 1,
kIOCatalogAddDriversNoMatch,
kIOCatalogRemoveDrivers,
kIOCatalogRemoveDriversNoMatch,
kIOCatalogStartMatching,
kIOCatalogRemoveKernelLinker,
kIOCatalogKextdActive,
kIOCatalogKextdFinishedLaunching,
kIOCatalogResetDrivers,
kIOCatalogResetDriversNoMatch
};
enum {
kIOCatalogGetContents = 1,
kIOCatalogGetModuleDemandList = 2,
kIOCatalogGetCacheMissList = 3,
kIOCatalogGetROMMkextList = 4
};
enum {
kIOCatalogResetDefault = 1
};
enum {
kIOCatalogModuleUnload = 1,
kIOCatalogModuleTerminate,
kIOCatalogServiceTerminate
};
extern const OSSymbol * gIOClassKey;
extern const OSSymbol * gIOProbeScoreKey;
extern IOCatalogue * gIOCatalogue;
typedef struct {
uint16_t curr_state;
uint64_t update_ts;
IOReportElement elem[];
} IOStateReportInfo;
typedef struct {
int bucketWidth;
IOReportElement elem[];
} IOHistReportInfo;
extern unsigned int kdebug_enable;
extern void kernel_debug(
uint32_t debugid,
uintptr_t arg1,
uintptr_t arg2,
uintptr_t arg3,
uintptr_t arg4,
uintptr_t arg5);
extern void kernel_debug1(
uint32_t debugid,
uintptr_t arg1,
uintptr_t arg2,
uintptr_t arg3,
uintptr_t arg4,
uintptr_t arg5);
extern void kernel_debug_filtered(
uint32_t debugid,
uintptr_t arg1,
uintptr_t arg2,
uintptr_t arg3,
uintptr_t arg4);
extern void kernel_debug_early(
uint32_t debugid,
uintptr_t arg1,
uintptr_t arg2,
uintptr_t arg3,
uintptr_t arg4);
static inline void
IOTimeStampStartConstant(unsigned int csc,
uintptr_t a = 0, uintptr_t b = 0,
uintptr_t c = 0, uintptr_t d = 0)
{
do { if ((kdebug_enable & ~(1U << 3))) { kernel_debug((((uint32_t)csc) | 1), (uintptr_t)(a), (uintptr_t)(b), (uintptr_t)(c), (uintptr_t)(d),(uintptr_t)(0)); } } while (0);
}
static inline void
IOTimeStampEndConstant(uintptr_t csc,
uintptr_t a = 0, uintptr_t b = 0,
uintptr_t c = 0, uintptr_t d = 0)
{
do { if ((kdebug_enable & ~(1U << 3))) { kernel_debug((((uint32_t)csc) | 2), (uintptr_t)(a), (uintptr_t)(b), (uintptr_t)(c), (uintptr_t)(d),(uintptr_t)(0)); } } while (0);
}
static inline void
IOTimeStampConstant(uintptr_t csc,
uintptr_t a = 0, uintptr_t b = 0,
uintptr_t c = 0, uintptr_t d = 0)
{
do { if ((kdebug_enable & ~(1U << 3))) { kernel_debug((((uint32_t)csc) | 0), (uintptr_t)(a), (uintptr_t)(b), (uintptr_t)(c), (uintptr_t)(d),(uintptr_t)(0)); } } while (0);
}
typedef struct _IODataQueueEntry IODataQueueEntry;
typedef void (*RTC_tick_handler)( IOService * );
struct IOInterruptVector {
volatile char interruptActive;
volatile char interruptDisabledSoft;
volatile char interruptDisabledHard;
volatile char interruptRegistered;
IOLock * interruptLock;
IOService * nub;
int source;
void * target;
IOInterruptHandler handler;
void * refCon;
IOSharedInterruptController *sharedController;
};
typedef struct IOInterruptVector IOInterruptVector;
typedef int32_t IOInterruptVectorNumber;
enum
{
kIOTimerEventSourceOptionsPriorityMask = 0x000000ff,
kIOTimerEventSourceOptionsPriorityHigh = 0x00000000,
kIOTimerEventSourceOptionsPriorityKernelHigh = 0x00000001,
kIOTimerEventSourceOptionsPriorityKernel = 0x00000002,
kIOTimerEventSourceOptionsPriorityUser = 0x00000003,
kIOTimerEventSourceOptionsPriorityLow = 0x00000004,
kIOTimerEventSourceOptionsPriorityWorkLoop = 0x000000ff,
kIOTimerEventSourceOptionsAllowReenter = 0x00000100,
kIOTimerEventSourceOptionsDefault = kIOTimerEventSourceOptionsPriorityKernelHigh
};
enum
{
kIOTimeOptionsWithLeeway = 0x00000020,
kIOTimeOptionsContinuous = 0x00000100,
};
extern vm_size_t vm_page_size;
extern vm_size_t vm_page_mask;
extern int vm_page_shift;
extern vm_size_t vm_kernel_page_size ;
extern vm_size_t vm_kernel_page_mask ;
extern int vm_kernel_page_shift ;
extern mach_port_t mach_host_self(void);
extern mach_port_t mach_thread_self(void);
extern kern_return_t host_page_size(host_t, vm_size_t *);
extern mach_port_t mach_task_self_;
extern mach_port_name_t mach_reply_port(void);
extern mach_port_name_t thread_get_special_reply_port(void);
extern mach_port_name_t thread_self_trap(void);
extern mach_port_name_t host_self_trap(void);
extern mach_msg_return_t mach_msg_trap(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
extern mach_msg_return_t mach_msg_overwrite_trap(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_msg_priority_t override,
mach_msg_header_t *rcv_msg,
mach_msg_size_t rcv_limit);
extern kern_return_t semaphore_signal_trap(
mach_port_name_t signal_name);
extern kern_return_t semaphore_signal_all_trap(
mach_port_name_t signal_name);
extern kern_return_t semaphore_signal_thread_trap(
mach_port_name_t signal_name,
mach_port_name_t thread_name);
extern kern_return_t semaphore_wait_trap(
mach_port_name_t wait_name);
extern kern_return_t semaphore_wait_signal_trap(
mach_port_name_t wait_name,
mach_port_name_t signal_name);
extern kern_return_t semaphore_timedwait_trap(
mach_port_name_t wait_name,
unsigned int sec,
clock_res_t nsec);
extern kern_return_t semaphore_timedwait_signal_trap(
mach_port_name_t wait_name,
mach_port_name_t signal_name,
unsigned int sec,
clock_res_t nsec);
extern kern_return_t clock_sleep_trap(
mach_port_name_t clock_name,
sleep_type_t sleep_type,
int sleep_sec,
int sleep_nsec,
mach_timespec_t *wakeup_time);
extern kern_return_t _kernelrpc_mach_vm_allocate_trap(
mach_port_name_t target,
mach_vm_offset_t *addr,
mach_vm_size_t size,
int flags);
extern kern_return_t _kernelrpc_mach_vm_deallocate_trap(
mach_port_name_t target,
mach_vm_address_t address,
mach_vm_size_t size
);
extern kern_return_t _kernelrpc_mach_vm_protect_trap(
mach_port_name_t target,
mach_vm_address_t address,
mach_vm_size_t size,
boolean_t set_maximum,
vm_prot_t new_protection
);
extern kern_return_t _kernelrpc_mach_vm_map_trap(
mach_port_name_t target,
mach_vm_offset_t *address,
mach_vm_size_t size,
mach_vm_offset_t mask,
int flags,
vm_prot_t cur_protection
);
extern kern_return_t _kernelrpc_mach_vm_purgable_control_trap(
mach_port_name_t target,
mach_vm_offset_t address,
vm_purgable_t control,
int *state);
extern kern_return_t _kernelrpc_mach_port_allocate_trap(
mach_port_name_t target,
mach_port_right_t right,
mach_port_name_t *name
);
extern kern_return_t _kernelrpc_mach_port_destroy_trap(
mach_port_name_t target,
mach_port_name_t name
);
extern kern_return_t _kernelrpc_mach_port_deallocate_trap(
mach_port_name_t target,
mach_port_name_t name
);
extern kern_return_t _kernelrpc_mach_port_mod_refs_trap(
mach_port_name_t target,
mach_port_name_t name,
mach_port_right_t right,
mach_port_delta_t delta
);
extern kern_return_t _kernelrpc_mach_port_move_member_trap(
mach_port_name_t target,
mach_port_name_t member,
mach_port_name_t after
);
extern kern_return_t _kernelrpc_mach_port_insert_right_trap(
mach_port_name_t target,
mach_port_name_t name,
mach_port_name_t poly,
mach_msg_type_name_t polyPoly
);
extern kern_return_t _kernelrpc_mach_port_insert_member_trap(
mach_port_name_t target,
mach_port_name_t name,
mach_port_name_t pset
);
extern kern_return_t _kernelrpc_mach_port_extract_member_trap(
mach_port_name_t target,
mach_port_name_t name,
mach_port_name_t pset
);
extern kern_return_t _kernelrpc_mach_port_construct_trap(
mach_port_name_t target,
mach_port_options_t *options,
uint64_t context,
mach_port_name_t *name
);
extern kern_return_t _kernelrpc_mach_port_destruct_trap(
mach_port_name_t target,
mach_port_name_t name,
mach_port_delta_t srdelta,
uint64_t guard
);
extern kern_return_t _kernelrpc_mach_port_guard_trap(
mach_port_name_t target,
mach_port_name_t name,
uint64_t guard,
boolean_t strict
);
extern kern_return_t _kernelrpc_mach_port_unguard_trap(
mach_port_name_t target,
mach_port_name_t name,
uint64_t guard
);
extern kern_return_t mach_generate_activity_id(
mach_port_name_t target,
int count,
uint64_t *activity_id
);
extern kern_return_t macx_swapon(
uint64_t filename,
int flags,
int size,
int priority);
extern kern_return_t macx_swapoff(
uint64_t filename,
int flags);
extern kern_return_t macx_triggers(
int hi_water,
int low_water,
int flags,
mach_port_t alert_port);
extern kern_return_t macx_backing_store_suspend(
boolean_t suspend);
extern kern_return_t macx_backing_store_recovery(
int pid);
extern boolean_t swtch_pri(int pri);
extern boolean_t swtch(void);
extern kern_return_t thread_switch(
mach_port_name_t thread_name,
int option,
mach_msg_timeout_t option_time);
extern mach_port_name_t task_self_trap(void);
extern kern_return_t host_create_mach_voucher_trap(
mach_port_name_t host,
mach_voucher_attr_raw_recipe_array_t recipes,
int recipes_size,
mach_port_name_t *voucher);
extern kern_return_t mach_voucher_extract_attr_recipe_trap(
mach_port_name_t voucher_name,
mach_voucher_attr_key_t key,
mach_voucher_attr_raw_recipe_t recipe,
mach_msg_type_number_t *recipe_size);
extern kern_return_t task_for_pid(
mach_port_name_t target_tport,
int pid,
mach_port_name_t *t);
extern kern_return_t task_name_for_pid(
mach_port_name_t target_tport,
int pid,
mach_port_name_t *tn);
extern kern_return_t pid_for_task(
mach_port_name_t t,
int *x);
extern mach_port_t bootstrap_port;
extern int (*vprintf_stderr_func)(const char *format, va_list ap);
extern void *_Block_copy(const void *aBlock)
;
extern void _Block_release(const void *aBlock)
;
extern void _Block_object_assign(void *, const void *, const int)
;
extern void _Block_object_dispose(const void *, const int)
;
extern void * _NSConcreteGlobalBlock[32]
;
extern void * _NSConcreteStackBlock[32]
;
typedef unsigned char UInt8;
typedef signed char SInt8;
typedef unsigned short UInt16;
typedef signed short SInt16;
typedef unsigned int UInt32;
typedef signed int SInt32;
typedef signed long long SInt64;
typedef unsigned long long UInt64;
typedef SInt32 Fixed;
typedef Fixed * FixedPtr;
typedef SInt32 Fract;
typedef Fract * FractPtr;
typedef UInt32 UnsignedFixed;
typedef UnsignedFixed * UnsignedFixedPtr;
typedef short ShortFixed;
typedef ShortFixed * ShortFixedPtr;
typedef float Float32;
typedef double Float64;
struct Float80 {
SInt16 exp;
UInt16 man[4];
};
typedef struct Float80 Float80;
struct Float96 {
SInt16 exp[2];
UInt16 man[4];
};
typedef struct Float96 Float96;
struct Float32Point {
Float32 x;
Float32 y;
};
typedef struct Float32Point Float32Point;
typedef char * Ptr;
typedef Ptr * Handle;
typedef long Size;
typedef SInt16 OSErr;
typedef SInt32 OSStatus;
typedef void * LogicalAddress;
typedef const void * ConstLogicalAddress;
typedef void * PhysicalAddress;
typedef UInt8 * BytePtr;
typedef unsigned long ByteCount;
typedef unsigned long ByteOffset;
typedef SInt32 Duration;
typedef UnsignedWide AbsoluteTime;
typedef UInt32 OptionBits;
typedef unsigned long ItemCount;
typedef UInt32 PBVersion;
typedef SInt16 ScriptCode;
typedef SInt16 LangCode;
typedef SInt16 RegionCode;
typedef UInt32 FourCharCode;
typedef FourCharCode OSType;
typedef FourCharCode ResType;
typedef OSType * OSTypePtr;
typedef ResType * ResTypePtr;
typedef unsigned char Boolean;
typedef long ( * ProcPtr)(void);
typedef void ( * Register68kProcPtr)(void);
typedef ProcPtr UniversalProcPtr;
typedef ProcPtr * ProcHandle;
typedef UniversalProcPtr * UniversalProcHandle;
typedef void * PRefCon;
typedef void * URefCon;
typedef void * SRefCon;
enum {
noErr = 0
};
enum {
kNilOptions = 0
};
enum {
kVariableLengthArray

= 1
};
enum {
kUnknownType = 0x3F3F3F3F
};
typedef UInt32 UnicodeScalarValue;
typedef UInt32 UTF32Char;
typedef UInt16 UniChar;
typedef UInt16 UTF16Char;
typedef UInt8 UTF8Char;
typedef UniChar * UniCharPtr;
typedef unsigned long UniCharCount;
typedef UniCharCount * UniCharCountPtr;
typedef unsigned char Str255[256];
typedef unsigned char Str63[64];
typedef unsigned char Str32[33];
typedef unsigned char Str31[32];
typedef unsigned char Str27[28];
typedef unsigned char Str15[16];
typedef unsigned char Str32Field[34];
typedef Str63 StrFileName;
typedef unsigned char * StringPtr;
typedef StringPtr * StringHandle;
typedef const unsigned char * ConstStringPtr;
typedef const unsigned char * ConstStr255Param;
typedef const unsigned char * ConstStr63Param;
typedef const unsigned char * ConstStr32Param;
typedef const unsigned char * ConstStr31Param;
typedef const unsigned char * ConstStr27Param;
typedef const unsigned char * ConstStr15Param;
typedef ConstStr63Param ConstStrFileNameParam;
struct ProcessSerialNumber {
UInt32 highLongOfPSN;
UInt32 lowLongOfPSN;
};
typedef struct ProcessSerialNumber ProcessSerialNumber;
typedef ProcessSerialNumber * ProcessSerialNumberPtr;
struct Point {
short v;
short h;
};
typedef struct Point Point;
typedef Point * PointPtr;
struct Rect {
short top;
short left;
short bottom;
short right;
};
typedef struct Rect Rect;
typedef Rect * RectPtr;
struct FixedPoint {
Fixed x;
Fixed y;
};
typedef struct FixedPoint FixedPoint;
struct FixedRect {
Fixed left;
Fixed top;
Fixed right;
Fixed bottom;
};
typedef struct FixedRect FixedRect;
typedef short CharParameter;
enum {
normal = 0,
bold = 1,
italic = 2,
underline = 4,
outline = 8,
shadow = 0x10,
condense = 0x20,
extend = 0x40
};
typedef unsigned char Style;
typedef short StyleParameter;
typedef Style StyleField;
typedef SInt32 TimeValue;
typedef SInt32 TimeScale;
typedef wide CompTimeValue;
typedef SInt64 TimeValue64;
typedef struct TimeBaseRecord* TimeBase;
struct TimeRecord {
CompTimeValue value;
TimeScale scale;
TimeBase base;
};
typedef struct TimeRecord TimeRecord;
struct NumVersion {
UInt8 nonRelRev;
UInt8 stage;
UInt8 minorAndBugRev;
UInt8 majorRev;
};
typedef struct NumVersion NumVersion;
enum {
developStage = 0x20,
alphaStage = 0x40,
betaStage = 0x60,
finalStage = 0x80
};
union NumVersionVariant {
NumVersion parts;
UInt32 whole;
};
typedef union NumVersionVariant NumVersionVariant;
typedef NumVersionVariant * NumVersionVariantPtr;
typedef NumVersionVariantPtr * NumVersionVariantHandle;
struct VersRec {
NumVersion numericVersion;
short countryCode;
Str255 shortVersion;
Str255 reserved;
};
typedef struct VersRec VersRec;
typedef VersRec * VersRecPtr;
typedef VersRecPtr * VersRecHndl;
typedef UInt8 Byte;
typedef SInt8 SignedByte;
typedef wide * WidePtr;
typedef UnsignedWide * UnsignedWidePtr;
typedef Float80 extended80;
typedef Float96 extended96;
typedef SInt8 VHSelect;
extern void
Debugger(void) ;
extern void
DebugStr(ConstStr255Param debuggerMsg) ;
extern void
SysBreak(void) ;
extern void
SysBreakStr(ConstStr255Param debuggerMsg) ;
extern void
SysBreakFunc(ConstStr255Param debuggerMsg) ;
extern double kCFCoreFoundationVersionNumber;
typedef unsigned long CFTypeID;
typedef unsigned long CFOptionFlags;
typedef unsigned long CFHashCode;
typedef signed long CFIndex;
typedef const  void * CFTypeRef;
typedef const struct  __CFString * CFStringRef;
typedef struct  __CFString * CFMutableStringRef;
typedef  CFTypeRef CFPropertyListRef;
typedef CFIndex CFComparisonResult; enum {
kCFCompareLessThan = -1L,
kCFCompareEqualTo = 0,
kCFCompareGreaterThan = 1
};
typedef CFComparisonResult (*CFComparatorFunction)(const void *val1, const void *val2, void *context);
static const CFIndex kCFNotFound = -1;
typedef struct {
CFIndex location;
CFIndex length;
} CFRange;
static   CFRange CFRangeMake(CFIndex loc, CFIndex len) {
CFRange range;
range.location = loc;
range.length = len;
return range;
}
extern
CFRange __CFRangeMake(CFIndex loc, CFIndex len);
typedef const struct  __CFNull * CFNullRef;
extern
CFTypeID CFNullGetTypeID(void);
extern
const CFNullRef kCFNull;
typedef const struct  __CFAllocator * CFAllocatorRef;
extern
const CFAllocatorRef kCFAllocatorDefault;
extern
const CFAllocatorRef kCFAllocatorSystemDefault;
extern
const CFAllocatorRef kCFAllocatorMalloc;
extern
const CFAllocatorRef kCFAllocatorMallocZone;
extern
const CFAllocatorRef kCFAllocatorNull;
extern
const CFAllocatorRef kCFAllocatorUseContext;
typedef const void * (*CFAllocatorRetainCallBack)(const void *info);
typedef void (*CFAllocatorReleaseCallBack)(const void *info);
typedef CFStringRef (*CFAllocatorCopyDescriptionCallBack)(const void *info);
typedef void * (*CFAllocatorAllocateCallBack)(CFIndex allocSize, CFOptionFlags hint, void *info);
typedef void * (*CFAllocatorReallocateCallBack)(void *ptr, CFIndex newsize, CFOptionFlags hint, void *info);
typedef void (*CFAllocatorDeallocateCallBack)(void *ptr, void *info);
typedef CFIndex (*CFAllocatorPreferredSizeCallBack)(CFIndex size, CFOptionFlags hint, void *info);
typedef struct {
CFIndex version;
void * info;
CFAllocatorRetainCallBack retain;
CFAllocatorReleaseCallBack release;
CFAllocatorCopyDescriptionCallBack copyDescription;
CFAllocatorAllocateCallBack allocate;
CFAllocatorReallocateCallBack reallocate;
CFAllocatorDeallocateCallBack deallocate;
CFAllocatorPreferredSizeCallBack preferredSize;
} CFAllocatorContext;
extern
CFTypeID CFAllocatorGetTypeID(void);
extern
void CFAllocatorSetDefault(CFAllocatorRef allocator);
extern
CFAllocatorRef CFAllocatorGetDefault(void);
extern
CFAllocatorRef CFAllocatorCreate(CFAllocatorRef allocator, CFAllocatorContext *context);
extern
void *CFAllocatorAllocate(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint);
extern
void *CFAllocatorReallocate(CFAllocatorRef allocator, void *ptr, CFIndex newsize, CFOptionFlags hint);
extern
void CFAllocatorDeallocate(CFAllocatorRef allocator, void *ptr);
extern
CFIndex CFAllocatorGetPreferredSizeForSize(CFAllocatorRef allocator, CFIndex size, CFOptionFlags hint);
extern
void CFAllocatorGetContext(CFAllocatorRef allocator, CFAllocatorContext *context);
extern
CFTypeID CFGetTypeID(CFTypeRef cf);
extern
CFStringRef CFCopyTypeIDDescription(CFTypeID type_id);
extern
CFTypeRef CFRetain(CFTypeRef cf);
extern
void CFRelease(CFTypeRef cf);
extern
CFTypeRef CFAutorelease(CFTypeRef  arg)    ;
extern
CFIndex CFGetRetainCount(CFTypeRef cf);
extern
Boolean CFEqual(CFTypeRef cf1, CFTypeRef cf2);
extern
CFHashCode CFHash(CFTypeRef cf);
extern
CFStringRef CFCopyDescription(CFTypeRef cf);
extern
CFAllocatorRef CFGetAllocator(CFTypeRef cf);
extern
CFTypeRef CFMakeCollectable(CFTypeRef cf) ;
typedef const void * (*CFDictionaryRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void (*CFDictionaryReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFDictionaryCopyDescriptionCallBack)(const void *value);
typedef Boolean (*CFDictionaryEqualCallBack)(const void *value1, const void *value2);
typedef CFHashCode (*CFDictionaryHashCallBack)(const void *value);
typedef struct {
CFIndex version;
CFDictionaryRetainCallBack retain;
CFDictionaryReleaseCallBack release;
CFDictionaryCopyDescriptionCallBack copyDescription;
CFDictionaryEqualCallBack equal;
CFDictionaryHashCallBack hash;
} CFDictionaryKeyCallBacks;
extern
const CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
extern
const CFDictionaryKeyCallBacks kCFCopyStringDictionaryKeyCallBacks;
typedef struct {
CFIndex version;
CFDictionaryRetainCallBack retain;
CFDictionaryReleaseCallBack release;
CFDictionaryCopyDescriptionCallBack copyDescription;
CFDictionaryEqualCallBack equal;
} CFDictionaryValueCallBacks;
extern
const CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;
typedef void (*CFDictionaryApplierFunction)(const void *key, const void *value, void *context);
typedef const struct  __CFDictionary * CFDictionaryRef;
typedef struct  __CFDictionary * CFMutableDictionaryRef;
extern
CFTypeID CFDictionaryGetTypeID(void);
extern
CFDictionaryRef CFDictionaryCreate(CFAllocatorRef allocator, const void **keys, const void **values, CFIndex numValues, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
extern
CFDictionaryRef CFDictionaryCreateCopy(CFAllocatorRef allocator, CFDictionaryRef theDict);
extern
CFMutableDictionaryRef CFDictionaryCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks);
extern
CFMutableDictionaryRef CFDictionaryCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFDictionaryRef theDict);
extern
CFIndex CFDictionaryGetCount(CFDictionaryRef theDict);
extern
CFIndex CFDictionaryGetCountOfKey(CFDictionaryRef theDict, const void *key);
extern
CFIndex CFDictionaryGetCountOfValue(CFDictionaryRef theDict, const void *value);
extern
Boolean CFDictionaryContainsKey(CFDictionaryRef theDict, const void *key);
extern
Boolean CFDictionaryContainsValue(CFDictionaryRef theDict, const void *value);
extern
const void *CFDictionaryGetValue(CFDictionaryRef theDict, const void *key);
extern
Boolean CFDictionaryGetValueIfPresent(CFDictionaryRef theDict, const void *key, const void **value);
extern
void CFDictionaryGetKeysAndValues(CFDictionaryRef theDict, const void **keys, const void **values);
extern
void CFDictionaryApplyFunction(CFDictionaryRef theDict, CFDictionaryApplierFunction  applier, void *context);
extern
void CFDictionaryAddValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern
void CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern
void CFDictionaryReplaceValue(CFMutableDictionaryRef theDict, const void *key, const void *value);
extern
void CFDictionaryRemoveValue(CFMutableDictionaryRef theDict, const void *key);
extern
void CFDictionaryRemoveAllValues(CFMutableDictionaryRef theDict);
typedef const void * (*CFArrayRetainCallBack)(CFAllocatorRef allocator, const void *value);
typedef void (*CFArrayReleaseCallBack)(CFAllocatorRef allocator, const void *value);
typedef CFStringRef (*CFArrayCopyDescriptionCallBack)(const void *value);
typedef Boolean (*CFArrayEqualCallBack)(const void *value1, const void *value2);
typedef struct {
CFIndex version;
CFArrayRetainCallBack retain;
CFArrayReleaseCallBack release;
CFArrayCopyDescriptionCallBack copyDescription;
CFArrayEqualCallBack equal;
} CFArrayCallBacks;
extern
const CFArrayCallBacks kCFTypeArrayCallBacks;
typedef void (*CFArrayApplierFunction)(const void *value, void *context);
typedef const struct  __CFArray * CFArrayRef;
typedef struct  __CFArray * CFMutableArrayRef;
extern
CFTypeID CFArrayGetTypeID(void);
extern
CFArrayRef CFArrayCreate(CFAllocatorRef allocator, const void **values, CFIndex numValues, const CFArrayCallBacks *callBacks);
extern
CFArrayRef CFArrayCreateCopy(CFAllocatorRef allocator, CFArrayRef theArray);
extern
CFMutableArrayRef CFArrayCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFArrayCallBacks *callBacks);
extern
CFMutableArrayRef CFArrayCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFArrayRef theArray);
extern
CFIndex CFArrayGetCount(CFArrayRef theArray);
extern
CFIndex CFArrayGetCountOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern
Boolean CFArrayContainsValue(CFArrayRef theArray, CFRange range, const void *value);
extern
const void *CFArrayGetValueAtIndex(CFArrayRef theArray, CFIndex idx);
extern
void CFArrayGetValues(CFArrayRef theArray, CFRange range, const void **values);
extern
void CFArrayApplyFunction(CFArrayRef theArray, CFRange range, CFArrayApplierFunction  applier, void *context);
extern
CFIndex CFArrayGetFirstIndexOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern
CFIndex CFArrayGetLastIndexOfValue(CFArrayRef theArray, CFRange range, const void *value);
extern
CFIndex CFArrayBSearchValues(CFArrayRef theArray, CFRange range, const void *value, CFComparatorFunction comparator, void *context);
extern
void CFArrayAppendValue(CFMutableArrayRef theArray, const void *value);
extern
void CFArrayInsertValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value);
extern
void CFArraySetValueAtIndex(CFMutableArrayRef theArray, CFIndex idx, const void *value);
extern
void CFArrayRemoveValueAtIndex(CFMutableArrayRef theArray, CFIndex idx);
extern
void CFArrayRemoveAllValues(CFMutableArrayRef theArray);
extern
void CFArrayReplaceValues(CFMutableArrayRef theArray, CFRange range, const void **newValues, CFIndex newCount);
extern
void CFArrayExchangeValuesAtIndices(CFMutableArrayRef theArray, CFIndex idx1, CFIndex idx2);
extern
void CFArraySortValues(CFMutableArrayRef theArray, CFRange range, CFComparatorFunction comparator, void *context);
extern
void CFArrayAppendArray(CFMutableArrayRef theArray, CFArrayRef otherArray, CFRange otherRange);
typedef double CFTimeInterval;
typedef CFTimeInterval CFAbsoluteTime;
extern
CFAbsoluteTime CFAbsoluteTimeGetCurrent(void);
extern
const CFTimeInterval kCFAbsoluteTimeIntervalSince1970;
extern
const CFTimeInterval kCFAbsoluteTimeIntervalSince1904;
typedef const struct  __CFDate * CFDateRef;
extern
CFTypeID CFDateGetTypeID(void);
extern
CFDateRef CFDateCreate(CFAllocatorRef allocator, CFAbsoluteTime at);
extern
CFAbsoluteTime CFDateGetAbsoluteTime(CFDateRef theDate);
extern
CFTimeInterval CFDateGetTimeIntervalSinceDate(CFDateRef theDate, CFDateRef otherDate);
extern
CFComparisonResult CFDateCompare(CFDateRef theDate, CFDateRef otherDate, void *context);
typedef const struct  __CFTimeZone * CFTimeZoneRef;
typedef struct {
SInt32 year;
SInt8 month;
SInt8 day;
SInt8 hour;
SInt8 minute;
double second;
} CFGregorianDate ;
typedef struct {
SInt32 years;
SInt32 months;
SInt32 days;
SInt32 hours;
SInt32 minutes;
double seconds;
} CFGregorianUnits ;
typedef CFOptionFlags CFGregorianUnitFlags; enum {
kCFGregorianUnitsYears  = (1UL << 0),
kCFGregorianUnitsMonths  = (1UL << 1),
kCFGregorianUnitsDays  = (1UL << 2),
kCFGregorianUnitsHours  = (1UL << 3),
kCFGregorianUnitsMinutes  = (1UL << 4),
kCFGregorianUnitsSeconds  = (1UL << 5),
kCFGregorianAllUnits  = 0x00FFFFFF
};
extern
Boolean CFGregorianDateIsValid(CFGregorianDate gdate, CFOptionFlags unitFlags) ;
extern
CFAbsoluteTime CFGregorianDateGetAbsoluteTime(CFGregorianDate gdate, CFTimeZoneRef tz) ;
extern
CFGregorianDate CFAbsoluteTimeGetGregorianDate(CFAbsoluteTime at, CFTimeZoneRef tz) ;
extern
CFAbsoluteTime CFAbsoluteTimeAddGregorianUnits(CFAbsoluteTime at, CFTimeZoneRef tz, CFGregorianUnits units) ;
extern
CFGregorianUnits CFAbsoluteTimeGetDifferenceAsGregorianUnits(CFAbsoluteTime at1, CFAbsoluteTime at2, CFTimeZoneRef tz, CFOptionFlags unitFlags) ;
extern
SInt32 CFAbsoluteTimeGetDayOfWeek(CFAbsoluteTime at, CFTimeZoneRef tz) ;
extern
SInt32 CFAbsoluteTimeGetDayOfYear(CFAbsoluteTime at, CFTimeZoneRef tz) ;
extern
SInt32 CFAbsoluteTimeGetWeekOfYear(CFAbsoluteTime at, CFTimeZoneRef tz) ;
typedef const struct  __CFData * CFDataRef;
typedef struct  __CFData * CFMutableDataRef;
extern
CFTypeID CFDataGetTypeID(void);
extern
CFDataRef CFDataCreate(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length);
extern
CFDataRef CFDataCreateWithBytesNoCopy(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length, CFAllocatorRef bytesDeallocator);
extern
CFDataRef CFDataCreateCopy(CFAllocatorRef allocator, CFDataRef theData);
extern
CFMutableDataRef CFDataCreateMutable(CFAllocatorRef allocator, CFIndex capacity);
extern
CFMutableDataRef CFDataCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFDataRef theData);
extern
CFIndex CFDataGetLength(CFDataRef theData);
extern
const UInt8 *CFDataGetBytePtr(CFDataRef theData);
extern
UInt8 *CFDataGetMutableBytePtr(CFMutableDataRef theData);
extern
void CFDataGetBytes(CFDataRef theData, CFRange range, UInt8 *buffer);
extern
void CFDataSetLength(CFMutableDataRef theData, CFIndex length);
extern
void CFDataIncreaseLength(CFMutableDataRef theData, CFIndex extraLength);
extern
void CFDataAppendBytes(CFMutableDataRef theData, const UInt8 *bytes, CFIndex length);
extern
void CFDataReplaceBytes(CFMutableDataRef theData, CFRange range, const UInt8 *newBytes, CFIndex newLength);
extern
void CFDataDeleteBytes(CFMutableDataRef theData, CFRange range);
typedef CFOptionFlags CFDataSearchFlags; enum {
kCFDataSearchBackwards = 1UL << 0,
kCFDataSearchAnchored = 1UL << 1
}    ;
extern
CFRange CFDataFind(CFDataRef theData, CFDataRef dataToFind, CFRange searchRange, CFDataSearchFlags compareOptions)    ;
typedef const struct  __CFCharacterSet * CFCharacterSetRef;
typedef struct  __CFCharacterSet * CFMutableCharacterSetRef;
typedef CFIndex CFCharacterSetPredefinedSet; enum {
kCFCharacterSetControl = 1,
kCFCharacterSetWhitespace,
kCFCharacterSetWhitespaceAndNewline,
kCFCharacterSetDecimalDigit,
kCFCharacterSetLetter,
kCFCharacterSetLowercaseLetter,
kCFCharacterSetUppercaseLetter,
kCFCharacterSetNonBase,
kCFCharacterSetDecomposable,
kCFCharacterSetAlphaNumeric,
kCFCharacterSetPunctuation,
kCFCharacterSetCapitalizedLetter = 13,
kCFCharacterSetSymbol = 14,
kCFCharacterSetNewline     = 15,
kCFCharacterSetIllegal = 12
};
extern
CFTypeID CFCharacterSetGetTypeID(void);
extern
CFCharacterSetRef CFCharacterSetGetPredefined(CFCharacterSetPredefinedSet theSetIdentifier);
extern
CFCharacterSetRef CFCharacterSetCreateWithCharactersInRange(CFAllocatorRef alloc, CFRange theRange);
extern
CFCharacterSetRef CFCharacterSetCreateWithCharactersInString(CFAllocatorRef alloc, CFStringRef theString);
extern
CFCharacterSetRef CFCharacterSetCreateWithBitmapRepresentation(CFAllocatorRef alloc, CFDataRef theData);
extern CFCharacterSetRef CFCharacterSetCreateInvertedSet(CFAllocatorRef alloc, CFCharacterSetRef theSet);
extern Boolean CFCharacterSetIsSupersetOfSet(CFCharacterSetRef theSet, CFCharacterSetRef theOtherset);
extern Boolean CFCharacterSetHasMemberInPlane(CFCharacterSetRef theSet, CFIndex thePlane);
extern
CFMutableCharacterSetRef CFCharacterSetCreateMutable(CFAllocatorRef alloc);
extern
CFCharacterSetRef CFCharacterSetCreateCopy(CFAllocatorRef alloc, CFCharacterSetRef theSet);
extern
CFMutableCharacterSetRef CFCharacterSetCreateMutableCopy(CFAllocatorRef alloc, CFCharacterSetRef theSet);
extern
Boolean CFCharacterSetIsCharacterMember(CFCharacterSetRef theSet, UniChar theChar);
extern Boolean CFCharacterSetIsLongCharacterMember(CFCharacterSetRef theSet, UTF32Char theChar);
extern
CFDataRef CFCharacterSetCreateBitmapRepresentation(CFAllocatorRef alloc, CFCharacterSetRef theSet);
extern
void CFCharacterSetAddCharactersInRange(CFMutableCharacterSetRef theSet, CFRange theRange);
extern
void CFCharacterSetRemoveCharactersInRange(CFMutableCharacterSetRef theSet, CFRange theRange);
extern
void CFCharacterSetAddCharactersInString(CFMutableCharacterSetRef theSet, CFStringRef theString);
extern
void CFCharacterSetRemoveCharactersInString(CFMutableCharacterSetRef theSet, CFStringRef theString);
extern
void CFCharacterSetUnion(CFMutableCharacterSetRef theSet, CFCharacterSetRef theOtherSet);
extern
void CFCharacterSetIntersect(CFMutableCharacterSetRef theSet, CFCharacterSetRef theOtherSet);
extern
void CFCharacterSetInvert(CFMutableCharacterSetRef theSet);
typedef CFStringRef CFNotificationName ;
typedef struct  __CFNotificationCenter * CFNotificationCenterRef;
typedef void (*CFNotificationCallback)(CFNotificationCenterRef center, void *observer, CFNotificationName name, const void *object, CFDictionaryRef userInfo);
typedef CFIndex CFNotificationSuspensionBehavior; enum {
CFNotificationSuspensionBehaviorDrop = 1,
CFNotificationSuspensionBehaviorCoalesce = 2,
CFNotificationSuspensionBehaviorHold = 3,
CFNotificationSuspensionBehaviorDeliverImmediately = 4
};
extern CFTypeID CFNotificationCenterGetTypeID(void);
extern CFNotificationCenterRef CFNotificationCenterGetLocalCenter(void);
extern CFNotificationCenterRef CFNotificationCenterGetDistributedCenter(void);
extern CFNotificationCenterRef CFNotificationCenterGetDarwinNotifyCenter(void);
extern void CFNotificationCenterAddObserver(CFNotificationCenterRef center, const void *observer, CFNotificationCallback callBack, CFStringRef name, const void *object, CFNotificationSuspensionBehavior suspensionBehavior);
extern void CFNotificationCenterRemoveObserver(CFNotificationCenterRef center, const void *observer, CFNotificationName name, const void *object);
extern void CFNotificationCenterRemoveEveryObserver(CFNotificationCenterRef center, const void *observer);
extern void CFNotificationCenterPostNotification(CFNotificationCenterRef center, CFNotificationName name, const void *object, CFDictionaryRef userInfo, Boolean deliverImmediately);
enum {
kCFNotificationDeliverImmediately = (1UL << 0),
kCFNotificationPostToAllSessions = (1UL << 1)
};
extern void CFNotificationCenterPostNotificationWithOptions(CFNotificationCenterRef center, CFNotificationName name, const void *object, CFDictionaryRef userInfo, CFOptionFlags options);
typedef CFStringRef CFLocaleIdentifier ;
typedef CFStringRef CFLocaleKey ;
typedef const struct  __CFLocale *CFLocaleRef;
extern
CFTypeID CFLocaleGetTypeID(void);
extern
CFLocaleRef CFLocaleGetSystem(void);
extern
CFLocaleRef CFLocaleCopyCurrent(void);
extern
CFArrayRef CFLocaleCopyAvailableLocaleIdentifiers(void);
extern
CFArrayRef CFLocaleCopyISOLanguageCodes(void);
extern
CFArrayRef CFLocaleCopyISOCountryCodes(void);
extern
CFArrayRef CFLocaleCopyISOCurrencyCodes(void);
extern
CFArrayRef CFLocaleCopyCommonISOCurrencyCodes(void)    ;
extern
CFArrayRef CFLocaleCopyPreferredLanguages(void)    ;
extern
CFLocaleIdentifier CFLocaleCreateCanonicalLanguageIdentifierFromString(CFAllocatorRef allocator, CFStringRef localeIdentifier);
extern
CFLocaleIdentifier CFLocaleCreateCanonicalLocaleIdentifierFromString(CFAllocatorRef allocator, CFStringRef localeIdentifier);
extern
CFLocaleIdentifier CFLocaleCreateCanonicalLocaleIdentifierFromScriptManagerCodes(CFAllocatorRef allocator, LangCode lcode, RegionCode rcode);
extern
CFLocaleIdentifier CFLocaleCreateLocaleIdentifierFromWindowsLocaleCode(CFAllocatorRef allocator, uint32_t lcid)    ;
extern
uint32_t CFLocaleGetWindowsLocaleCodeFromLocaleIdentifier(CFLocaleIdentifier localeIdentifier)    ;
typedef CFIndex CFLocaleLanguageDirection; enum {
kCFLocaleLanguageDirectionUnknown = 0,
kCFLocaleLanguageDirectionLeftToRight = 1,
kCFLocaleLanguageDirectionRightToLeft = 2,
kCFLocaleLanguageDirectionTopToBottom = 3,
kCFLocaleLanguageDirectionBottomToTop = 4
};
extern
CFLocaleLanguageDirection CFLocaleGetLanguageCharacterDirection(CFStringRef isoLangCode)    ;
extern
CFLocaleLanguageDirection CFLocaleGetLanguageLineDirection(CFStringRef isoLangCode)    ;
extern
CFDictionaryRef CFLocaleCreateComponentsFromLocaleIdentifier(CFAllocatorRef allocator, CFLocaleIdentifier localeID);
extern
CFLocaleIdentifier CFLocaleCreateLocaleIdentifierFromComponents(CFAllocatorRef allocator, CFDictionaryRef dictionary);
extern
CFLocaleRef CFLocaleCreate(CFAllocatorRef allocator, CFLocaleIdentifier localeIdentifier);
extern
CFLocaleRef CFLocaleCreateCopy(CFAllocatorRef allocator, CFLocaleRef locale);
extern
CFLocaleIdentifier CFLocaleGetIdentifier(CFLocaleRef locale);
extern
CFTypeRef CFLocaleGetValue(CFLocaleRef locale, CFLocaleKey key);
extern
CFStringRef CFLocaleCopyDisplayNameForPropertyValue(CFLocaleRef displayLocale, CFLocaleKey key, CFStringRef value);
extern const CFNotificationName kCFLocaleCurrentLocaleDidChangeNotification    ;
extern const CFLocaleKey kCFLocaleIdentifier;
extern const CFLocaleKey kCFLocaleLanguageCode;
extern const CFLocaleKey kCFLocaleCountryCode;
extern const CFLocaleKey kCFLocaleScriptCode;
extern const CFLocaleKey kCFLocaleVariantCode;
extern const CFLocaleKey kCFLocaleExemplarCharacterSet;
extern const CFLocaleKey kCFLocaleCalendarIdentifier;
extern const CFLocaleKey kCFLocaleCalendar;
extern const CFLocaleKey kCFLocaleCollationIdentifier;
extern const CFLocaleKey kCFLocaleUsesMetricSystem;
extern const CFLocaleKey kCFLocaleMeasurementSystem;
extern const CFLocaleKey kCFLocaleDecimalSeparator;
extern const CFLocaleKey kCFLocaleGroupingSeparator;
extern const CFLocaleKey kCFLocaleCurrencySymbol;
extern const CFLocaleKey kCFLocaleCurrencyCode;
extern const CFLocaleKey kCFLocaleCollatorIdentifier    ;
extern const CFLocaleKey kCFLocaleQuotationBeginDelimiterKey    ;
extern const CFLocaleKey kCFLocaleQuotationEndDelimiterKey    ;
extern const CFLocaleKey kCFLocaleAlternateQuotationBeginDelimiterKey    ;
extern const CFLocaleKey kCFLocaleAlternateQuotationEndDelimiterKey    ;
typedef CFStringRef CFCalendarIdentifier ;
extern const CFCalendarIdentifier kCFGregorianCalendar;
extern const CFCalendarIdentifier kCFBuddhistCalendar;
extern const CFCalendarIdentifier kCFChineseCalendar;
extern const CFCalendarIdentifier kCFHebrewCalendar;
extern const CFCalendarIdentifier kCFIslamicCalendar;
extern const CFCalendarIdentifier kCFIslamicCivilCalendar;
extern const CFCalendarIdentifier kCFJapaneseCalendar;
extern const CFCalendarIdentifier kCFRepublicOfChinaCalendar    ;
extern const CFCalendarIdentifier kCFPersianCalendar    ;
extern const CFCalendarIdentifier kCFIndianCalendar    ;
extern const CFCalendarIdentifier kCFISO8601Calendar    ;
extern const CFCalendarIdentifier kCFIslamicTabularCalendar    ;
extern const CFCalendarIdentifier kCFIslamicUmmAlQuraCalendar    ;
typedef UInt32 CFStringEncoding;
typedef CFStringEncoding CFStringBuiltInEncodings; enum {
kCFStringEncodingMacRoman = 0,
kCFStringEncodingWindowsLatin1 = 0x0500,
kCFStringEncodingISOLatin1 = 0x0201,
kCFStringEncodingNextStepLatin = 0x0B01,
kCFStringEncodingASCII = 0x0600,
kCFStringEncodingUnicode = 0x0100,
kCFStringEncodingUTF8 = 0x08000100,
kCFStringEncodingNonLossyASCII = 0x0BFF,
kCFStringEncodingUTF16 = 0x0100,
kCFStringEncodingUTF16BE = 0x10000100,
kCFStringEncodingUTF16LE = 0x14000100,
kCFStringEncodingUTF32 = 0x0c000100,
kCFStringEncodingUTF32BE = 0x18000100,
kCFStringEncodingUTF32LE = 0x1c000100
};
extern
CFTypeID CFStringGetTypeID(void);
extern
CFStringRef CFStringCreateWithPascalString(CFAllocatorRef alloc, ConstStr255Param pStr, CFStringEncoding encoding);
extern
CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
extern
CFStringRef CFStringCreateWithBytes(CFAllocatorRef alloc, const UInt8 *bytes, CFIndex numBytes, CFStringEncoding encoding, Boolean isExternalRepresentation);
extern
CFStringRef CFStringCreateWithCharacters(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars);
extern
CFStringRef CFStringCreateWithPascalStringNoCopy(CFAllocatorRef alloc, ConstStr255Param pStr, CFStringEncoding encoding, CFAllocatorRef contentsDeallocator);
extern
CFStringRef CFStringCreateWithCStringNoCopy(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding, CFAllocatorRef contentsDeallocator);
extern
CFStringRef CFStringCreateWithBytesNoCopy(CFAllocatorRef alloc, const UInt8 *bytes, CFIndex numBytes, CFStringEncoding encoding, Boolean isExternalRepresentation, CFAllocatorRef contentsDeallocator);
extern
CFStringRef CFStringCreateWithCharactersNoCopy(CFAllocatorRef alloc, const UniChar *chars, CFIndex numChars, CFAllocatorRef contentsDeallocator);
extern
CFStringRef CFStringCreateWithSubstring(CFAllocatorRef alloc, CFStringRef str, CFRange range);
extern
CFStringRef CFStringCreateCopy(CFAllocatorRef alloc, CFStringRef theString);
extern
CFStringRef CFStringCreateWithFormat(CFAllocatorRef alloc, CFDictionaryRef formatOptions, CFStringRef format, ...) ;
extern
CFStringRef CFStringCreateWithFormatAndArguments(CFAllocatorRef alloc, CFDictionaryRef formatOptions, CFStringRef format, va_list arguments) ;
extern
CFMutableStringRef CFStringCreateMutable(CFAllocatorRef alloc, CFIndex maxLength);
extern
CFMutableStringRef CFStringCreateMutableCopy(CFAllocatorRef alloc, CFIndex maxLength, CFStringRef theString);
extern
CFMutableStringRef CFStringCreateMutableWithExternalCharactersNoCopy(CFAllocatorRef alloc, UniChar *chars, CFIndex numChars, CFIndex capacity, CFAllocatorRef externalCharactersAllocator);
extern
CFIndex CFStringGetLength(CFStringRef theString);
extern
UniChar CFStringGetCharacterAtIndex(CFStringRef theString, CFIndex idx);
extern
void CFStringGetCharacters(CFStringRef theString, CFRange range, UniChar *buffer);
extern
Boolean CFStringGetPascalString(CFStringRef theString, StringPtr buffer, CFIndex bufferSize, CFStringEncoding encoding);
extern
Boolean CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding);
extern
ConstStringPtr CFStringGetPascalStringPtr(CFStringRef theString, CFStringEncoding encoding);
extern
const char *CFStringGetCStringPtr(CFStringRef theString, CFStringEncoding encoding);
extern
const UniChar *CFStringGetCharactersPtr(CFStringRef theString);
extern
CFIndex CFStringGetBytes(CFStringRef theString, CFRange range, CFStringEncoding encoding, UInt8 lossByte, Boolean isExternalRepresentation, UInt8 *buffer, CFIndex maxBufLen, CFIndex *usedBufLen);
extern
CFStringRef CFStringCreateFromExternalRepresentation(CFAllocatorRef alloc, CFDataRef data, CFStringEncoding encoding);
extern
CFDataRef CFStringCreateExternalRepresentation(CFAllocatorRef alloc, CFStringRef theString, CFStringEncoding encoding, UInt8 lossByte);
extern
CFStringEncoding CFStringGetSmallestEncoding(CFStringRef theString);
extern
CFStringEncoding CFStringGetFastestEncoding(CFStringRef theString);
extern
CFStringEncoding CFStringGetSystemEncoding(void);
extern
CFIndex CFStringGetMaximumSizeForEncoding(CFIndex length, CFStringEncoding encoding);
extern
Boolean CFStringGetFileSystemRepresentation(CFStringRef string, char *buffer, CFIndex maxBufLen);
extern
CFIndex CFStringGetMaximumSizeOfFileSystemRepresentation(CFStringRef string);
extern
CFStringRef CFStringCreateWithFileSystemRepresentation(CFAllocatorRef alloc, const char *buffer);
typedef CFOptionFlags CFStringCompareFlags; enum {
kCFCompareCaseInsensitive = 1,
kCFCompareBackwards = 4,
kCFCompareAnchored = 8,
kCFCompareNonliteral = 16,
kCFCompareLocalized = 32,
kCFCompareNumerically = 64,
kCFCompareDiacriticInsensitive     = 128,
kCFCompareWidthInsensitive     = 256,
kCFCompareForcedOrdering     = 512
};
extern
CFComparisonResult CFStringCompareWithOptionsAndLocale(CFStringRef theString1, CFStringRef theString2, CFRange rangeToCompare, CFStringCompareFlags compareOptions, CFLocaleRef locale)    ;
extern
CFComparisonResult CFStringCompareWithOptions(CFStringRef theString1, CFStringRef theString2, CFRange rangeToCompare, CFStringCompareFlags compareOptions);
extern
CFComparisonResult CFStringCompare(CFStringRef theString1, CFStringRef theString2, CFStringCompareFlags compareOptions);
extern
Boolean CFStringFindWithOptionsAndLocale(CFStringRef theString, CFStringRef stringToFind, CFRange rangeToSearch, CFStringCompareFlags searchOptions, CFLocaleRef locale, CFRange *result)    ;
extern
Boolean CFStringFindWithOptions(CFStringRef theString, CFStringRef stringToFind, CFRange rangeToSearch, CFStringCompareFlags searchOptions, CFRange *result);
extern
CFArrayRef CFStringCreateArrayWithFindResults(CFAllocatorRef alloc, CFStringRef theString, CFStringRef stringToFind, CFRange rangeToSearch, CFStringCompareFlags compareOptions);
extern
CFRange CFStringFind(CFStringRef theString, CFStringRef stringToFind, CFStringCompareFlags compareOptions);
extern
Boolean CFStringHasPrefix(CFStringRef theString, CFStringRef prefix);
extern
Boolean CFStringHasSuffix(CFStringRef theString, CFStringRef suffix);
extern CFRange CFStringGetRangeOfComposedCharactersAtIndex(CFStringRef theString, CFIndex theIndex);
extern Boolean CFStringFindCharacterFromSet(CFStringRef theString, CFCharacterSetRef theSet, CFRange rangeToSearch, CFStringCompareFlags searchOptions, CFRange *result);
extern
void CFStringGetLineBounds(CFStringRef theString, CFRange range, CFIndex *lineBeginIndex, CFIndex *lineEndIndex, CFIndex *contentsEndIndex);
extern
void CFStringGetParagraphBounds(CFStringRef string, CFRange range, CFIndex *parBeginIndex, CFIndex *parEndIndex, CFIndex *contentsEndIndex)    ;
extern
CFIndex CFStringGetHyphenationLocationBeforeIndex(CFStringRef string, CFIndex location, CFRange limitRange, CFOptionFlags options, CFLocaleRef locale, UTF32Char *character)    ;
extern
Boolean CFStringIsHyphenationAvailableForLocale(CFLocaleRef locale)    ;
extern
CFStringRef CFStringCreateByCombiningStrings(CFAllocatorRef alloc, CFArrayRef theArray, CFStringRef separatorString);
extern
CFArrayRef CFStringCreateArrayBySeparatingStrings(CFAllocatorRef alloc, CFStringRef theString, CFStringRef separatorString);
extern
SInt32 CFStringGetIntValue(CFStringRef str);
extern
double CFStringGetDoubleValue(CFStringRef str);
extern
void CFStringAppend(CFMutableStringRef theString, CFStringRef appendedString);
extern
void CFStringAppendCharacters(CFMutableStringRef theString, const UniChar *chars, CFIndex numChars);
extern
void CFStringAppendPascalString(CFMutableStringRef theString, ConstStr255Param pStr, CFStringEncoding encoding);
extern
void CFStringAppendCString(CFMutableStringRef theString, const char *cStr, CFStringEncoding encoding);
extern
void CFStringAppendFormat(CFMutableStringRef theString, CFDictionaryRef formatOptions, CFStringRef format, ...) ;
extern
void CFStringAppendFormatAndArguments(CFMutableStringRef theString, CFDictionaryRef formatOptions, CFStringRef format, va_list arguments) ;
extern
void CFStringInsert(CFMutableStringRef str, CFIndex idx, CFStringRef insertedStr);
extern
void CFStringDelete(CFMutableStringRef theString, CFRange range);
extern
void CFStringReplace(CFMutableStringRef theString, CFRange range, CFStringRef replacement);
extern
void CFStringReplaceAll(CFMutableStringRef theString, CFStringRef replacement);
extern
CFIndex CFStringFindAndReplace(CFMutableStringRef theString, CFStringRef stringToFind, CFStringRef replacementString, CFRange rangeToSearch, CFStringCompareFlags compareOptions);
extern
void CFStringSetExternalCharactersNoCopy(CFMutableStringRef theString, UniChar *chars, CFIndex length, CFIndex capacity);
extern
void CFStringPad(CFMutableStringRef theString, CFStringRef padString, CFIndex length, CFIndex indexIntoPad);
extern
void CFStringTrim(CFMutableStringRef theString, CFStringRef trimString);
extern
void CFStringTrimWhitespace(CFMutableStringRef theString);
extern
void CFStringLowercase(CFMutableStringRef theString, CFLocaleRef locale);
extern
void CFStringUppercase(CFMutableStringRef theString, CFLocaleRef locale);
extern
void CFStringCapitalize(CFMutableStringRef theString, CFLocaleRef locale);
typedef CFIndex CFStringNormalizationForm; enum {
kCFStringNormalizationFormD = 0,
kCFStringNormalizationFormKD,
kCFStringNormalizationFormC,
kCFStringNormalizationFormKC
};
extern void CFStringNormalize(CFMutableStringRef theString, CFStringNormalizationForm theForm);
extern
void CFStringFold(CFMutableStringRef theString, CFStringCompareFlags theFlags, CFLocaleRef theLocale)    ;
extern
Boolean CFStringTransform(CFMutableStringRef string, CFRange *range, CFStringRef transform, Boolean reverse);
extern const CFStringRef kCFStringTransformStripCombiningMarks;
extern const CFStringRef kCFStringTransformToLatin;
extern const CFStringRef kCFStringTransformFullwidthHalfwidth;
extern const CFStringRef kCFStringTransformLatinKatakana;
extern const CFStringRef kCFStringTransformLatinHiragana;
extern const CFStringRef kCFStringTransformHiraganaKatakana;
extern const CFStringRef kCFStringTransformMandarinLatin;
extern const CFStringRef kCFStringTransformLatinHangul;
extern const CFStringRef kCFStringTransformLatinArabic;
extern const CFStringRef kCFStringTransformLatinHebrew;
extern const CFStringRef kCFStringTransformLatinThai;
extern const CFStringRef kCFStringTransformLatinCyrillic;
extern const CFStringRef kCFStringTransformLatinGreek;
extern const CFStringRef kCFStringTransformToXMLHex;
extern const CFStringRef kCFStringTransformToUnicodeName;
extern const CFStringRef kCFStringTransformStripDiacritics    ;
extern
Boolean CFStringIsEncodingAvailable(CFStringEncoding encoding);
extern
const CFStringEncoding *CFStringGetListOfAvailableEncodings(void);
extern
CFStringRef CFStringGetNameOfEncoding(CFStringEncoding encoding);
extern
unsigned long CFStringConvertEncodingToNSStringEncoding(CFStringEncoding encoding);
extern
CFStringEncoding CFStringConvertNSStringEncodingToEncoding(unsigned long encoding);
extern
UInt32 CFStringConvertEncodingToWindowsCodepage(CFStringEncoding encoding);
extern
CFStringEncoding CFStringConvertWindowsCodepageToEncoding(UInt32 codepage);
extern
CFStringEncoding CFStringConvertIANACharSetNameToEncoding(CFStringRef theString);
extern
CFStringRef CFStringConvertEncodingToIANACharSetName(CFStringEncoding encoding);
extern
CFStringEncoding CFStringGetMostCompatibleMacStringEncoding(CFStringEncoding encoding);
typedef struct {
UniChar buffer[64];
CFStringRef theString;
const UniChar *directUniCharBuffer;
const char *directCStringBuffer;
CFRange rangeToBuffer;
CFIndex bufferedRangeStart;
CFIndex bufferedRangeEnd;
} CFStringInlineBuffer;
static   void CFStringInitInlineBuffer(CFStringRef str, CFStringInlineBuffer *buf, CFRange range) {
buf->theString = str;
buf->rangeToBuffer = range;
buf->directCStringBuffer = (buf->directUniCharBuffer = CFStringGetCharactersPtr(str)) ? ((void*)0) : CFStringGetCStringPtr(str, kCFStringEncodingASCII);
buf->bufferedRangeStart = buf->bufferedRangeEnd = 0;
}
static   UniChar CFStringGetCharacterFromInlineBuffer(CFStringInlineBuffer *buf, CFIndex idx) {
if (idx < 0 || idx >= buf->rangeToBuffer.length) return 0;
if (buf->directUniCharBuffer) return buf->directUniCharBuffer[idx + buf->rangeToBuffer.location];
if (buf->directCStringBuffer) return (UniChar)(buf->directCStringBuffer[idx + buf->rangeToBuffer.location]);
if (idx >= buf->bufferedRangeEnd || idx < buf->bufferedRangeStart) {
if ((buf->bufferedRangeStart = idx - 4) < 0) buf->bufferedRangeStart = 0;
buf->bufferedRangeEnd = buf->bufferedRangeStart + 64;
if (buf->bufferedRangeEnd > buf->rangeToBuffer.length) buf->bufferedRangeEnd = buf->rangeToBuffer.length;
CFStringGetCharacters(buf->theString, CFRangeMake(buf->rangeToBuffer.location + buf->bufferedRangeStart, buf->bufferedRangeEnd - buf->bufferedRangeStart), buf->buffer);
}
return buf->buffer[idx - buf->bufferedRangeStart];
}
static   Boolean CFStringIsSurrogateHighCharacter(UniChar character) {
return ((character >= 0xD800UL) && (character <= 0xDBFFUL) ? 1 : 0);
}
static   Boolean CFStringIsSurrogateLowCharacter(UniChar character) {
return ((character >= 0xDC00UL) && (character <= 0xDFFFUL) ? 1 : 0);
}
static   UTF32Char CFStringGetLongCharacterForSurrogatePair(UniChar surrogateHigh, UniChar surrogateLow) {
return (UTF32Char)(((surrogateHigh - 0xD800UL) << 10) + (surrogateLow - 0xDC00UL) + 0x0010000UL);
}
static   Boolean CFStringGetSurrogatePairForLongCharacter(UTF32Char character, UniChar *surrogates) {
if ((character > 0xFFFFUL) && (character < 0x110000UL)) {
character -= 0x10000;
if (((void*)0) != surrogates) {
surrogates[0] = (UniChar)((character >> 10) + 0xD800UL);
surrogates[1] = (UniChar)((character & 0x3FF) + 0xDC00UL);
}
return 1;
} else {
if (((void*)0) != surrogates) *surrogates = (UniChar)character;
return 0;
}
}
extern
void CFShow(CFTypeRef obj);
extern
void CFShowStr(CFStringRef str);
extern
CFStringRef __CFStringMakeConstantString(const char *cStr) ;
typedef CFStringRef CFRunLoopMode ;
typedef struct  __CFRunLoop * CFRunLoopRef;
typedef struct  __CFRunLoopSource * CFRunLoopSourceRef;
typedef struct  __CFRunLoopObserver * CFRunLoopObserverRef;
typedef struct  __CFRunLoopTimer * CFRunLoopTimerRef;
typedef SInt32 CFRunLoopRunResult; enum {
kCFRunLoopRunFinished = 1,
kCFRunLoopRunStopped = 2,
kCFRunLoopRunTimedOut = 3,
kCFRunLoopRunHandledSource = 4
};
typedef CFOptionFlags CFRunLoopActivity; enum {
kCFRunLoopEntry = (1UL << 0),
kCFRunLoopBeforeTimers = (1UL << 1),
kCFRunLoopBeforeSources = (1UL << 2),
kCFRunLoopBeforeWaiting = (1UL << 5),
kCFRunLoopAfterWaiting = (1UL << 6),
kCFRunLoopExit = (1UL << 7),
kCFRunLoopAllActivities = 0x0FFFFFFFU
};
extern const CFRunLoopMode kCFRunLoopDefaultMode;
extern const CFRunLoopMode kCFRunLoopCommonModes;
extern CFTypeID CFRunLoopGetTypeID(void);
extern CFRunLoopRef CFRunLoopGetCurrent(void);
extern CFRunLoopRef CFRunLoopGetMain(void);
extern CFRunLoopMode CFRunLoopCopyCurrentMode(CFRunLoopRef rl);
extern CFArrayRef CFRunLoopCopyAllModes(CFRunLoopRef rl);
extern void CFRunLoopAddCommonMode(CFRunLoopRef rl, CFRunLoopMode mode);
extern CFAbsoluteTime CFRunLoopGetNextTimerFireDate(CFRunLoopRef rl, CFRunLoopMode mode);
extern void CFRunLoopRun(void);
extern CFRunLoopRunResult CFRunLoopRunInMode(CFRunLoopMode mode, CFTimeInterval seconds, Boolean returnAfterSourceHandled);
extern Boolean CFRunLoopIsWaiting(CFRunLoopRef rl);
extern void CFRunLoopWakeUp(CFRunLoopRef rl);
extern void CFRunLoopStop(CFRunLoopRef rl);
extern void CFRunLoopPerformBlock(CFRunLoopRef rl, CFTypeRef mode, void (*block)(void))    ;
extern Boolean CFRunLoopContainsSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode);
extern void CFRunLoopAddSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode);
extern void CFRunLoopRemoveSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode);
extern Boolean CFRunLoopContainsObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode mode);
extern void CFRunLoopAddObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode mode);
extern void CFRunLoopRemoveObserver(CFRunLoopRef rl, CFRunLoopObserverRef observer, CFRunLoopMode mode);
extern Boolean CFRunLoopContainsTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode mode);
extern void CFRunLoopAddTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode mode);
extern void CFRunLoopRemoveTimer(CFRunLoopRef rl, CFRunLoopTimerRef timer, CFRunLoopMode mode);
typedef struct {
CFIndex version;
void * info;
const void *(*retain)(const void *info);
void (*release)(const void *info);
CFStringRef (*copyDescription)(const void *info);
Boolean (*equal)(const void *info1, const void *info2);
CFHashCode (*hash)(const void *info);
void (*schedule)(void *info, CFRunLoopRef rl, CFRunLoopMode mode);
void (*cancel)(void *info, CFRunLoopRef rl, CFRunLoopMode mode);
void (*perform)(void *info);
} CFRunLoopSourceContext;
typedef struct {
CFIndex version;
void * info;
const void *(*retain)(const void *info);
void (*release)(const void *info);
CFStringRef (*copyDescription)(const void *info);
Boolean (*equal)(const void *info1, const void *info2);
CFHashCode (*hash)(const void *info);
mach_port_t (*getPort)(void *info);
void * (*perform)(void *msg, CFIndex size, CFAllocatorRef allocator, void *info);
} CFRunLoopSourceContext1;
extern CFTypeID CFRunLoopSourceGetTypeID(void);
extern CFRunLoopSourceRef CFRunLoopSourceCreate(CFAllocatorRef allocator, CFIndex order, CFRunLoopSourceContext *context);
extern CFIndex CFRunLoopSourceGetOrder(CFRunLoopSourceRef source);
extern void CFRunLoopSourceInvalidate(CFRunLoopSourceRef source);
extern Boolean CFRunLoopSourceIsValid(CFRunLoopSourceRef source);
extern void CFRunLoopSourceGetContext(CFRunLoopSourceRef source, CFRunLoopSourceContext *context);
extern void CFRunLoopSourceSignal(CFRunLoopSourceRef source);
typedef struct {
CFIndex version;
void * info;
const void *(*retain)(const void *info);
void (*release)(const void *info);
CFStringRef (*copyDescription)(const void *info);
} CFRunLoopObserverContext;
typedef void (*CFRunLoopObserverCallBack)(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info);
extern CFTypeID CFRunLoopObserverGetTypeID(void);
extern CFRunLoopObserverRef CFRunLoopObserverCreate(CFAllocatorRef allocator, CFOptionFlags activities, Boolean repeats, CFIndex order, CFRunLoopObserverCallBack callout, CFRunLoopObserverContext *context);
extern CFRunLoopObserverRef CFRunLoopObserverCreateWithHandler(CFAllocatorRef allocator, CFOptionFlags activities, Boolean repeats, CFIndex order, void (*block) (CFRunLoopObserverRef observer, CFRunLoopActivity activity))    ;
extern CFOptionFlags CFRunLoopObserverGetActivities(CFRunLoopObserverRef observer);
extern Boolean CFRunLoopObserverDoesRepeat(CFRunLoopObserverRef observer);
extern CFIndex CFRunLoopObserverGetOrder(CFRunLoopObserverRef observer);
extern void CFRunLoopObserverInvalidate(CFRunLoopObserverRef observer);
extern Boolean CFRunLoopObserverIsValid(CFRunLoopObserverRef observer);
extern void CFRunLoopObserverGetContext(CFRunLoopObserverRef observer, CFRunLoopObserverContext *context);
typedef struct {
CFIndex version;
void * info;
const void *(*retain)(const void *info);
void (*release)(const void *info);
CFStringRef (*copyDescription)(const void *info);
} CFRunLoopTimerContext;
typedef void (*CFRunLoopTimerCallBack)(CFRunLoopTimerRef timer, void *info);
extern CFTypeID CFRunLoopTimerGetTypeID(void);
extern CFRunLoopTimerRef CFRunLoopTimerCreate(CFAllocatorRef allocator, CFAbsoluteTime fireDate, CFTimeInterval interval, CFOptionFlags flags, CFIndex order, CFRunLoopTimerCallBack callout, CFRunLoopTimerContext *context);
extern CFRunLoopTimerRef CFRunLoopTimerCreateWithHandler(CFAllocatorRef allocator, CFAbsoluteTime fireDate, CFTimeInterval interval, CFOptionFlags flags, CFIndex order, void (*block) (CFRunLoopTimerRef timer))    ;
extern CFAbsoluteTime CFRunLoopTimerGetNextFireDate(CFRunLoopTimerRef timer);
extern void CFRunLoopTimerSetNextFireDate(CFRunLoopTimerRef timer, CFAbsoluteTime fireDate);
extern CFTimeInterval CFRunLoopTimerGetInterval(CFRunLoopTimerRef timer);
extern Boolean CFRunLoopTimerDoesRepeat(CFRunLoopTimerRef timer);
extern CFIndex CFRunLoopTimerGetOrder(CFRunLoopTimerRef timer);
extern void CFRunLoopTimerInvalidate(CFRunLoopTimerRef timer);
extern Boolean CFRunLoopTimerIsValid(CFRunLoopTimerRef timer);
extern void CFRunLoopTimerGetContext(CFRunLoopTimerRef timer, CFRunLoopTimerContext *context);
extern CFTimeInterval CFRunLoopTimerGetTolerance(CFRunLoopTimerRef timer)    ;
extern void CFRunLoopTimerSetTolerance(CFRunLoopTimerRef timer, CFTimeInterval tolerance)    ;
void _exit(int) ;
int access(const char *, int);
unsigned int
alarm(unsigned int);
int chdir(const char *);
int chown(const char *, uid_t, gid_t);
int close(int) ;
int dup(int);
int dup2(int, int);
int execl(const char * __path, const char * __arg0, ...)  ;
int execle(const char * __path, const char * __arg0, ...)  ;
int execlp(const char * __file, const char * __arg0, ...)  ;
int execv(const char * __path, char * const * __argv)  ;
int execve(const char * __file, char * const * __argv, char * const * __envp)  ;
int execvp(const char * __file, char * const * __argv)  ;
pid_t fork(void)  ;
long fpathconf(int, int);
char *getcwd(char *, size_t);
gid_t getegid(void);
uid_t geteuid(void);
gid_t getgid(void);
int getgroups(int, gid_t []);
char *getlogin(void);
pid_t getpgrp(void);
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
int isatty(int);
int link(const char *, const char *);
off_t lseek(int, off_t, int);
long pathconf(const char *, int);
int pause(void) ;
int pipe(int [2]);
ssize_t read(int, void *, size_t) ;
int rmdir(const char *);
int setgid(gid_t);
int setpgid(pid_t, pid_t);
pid_t setsid(void);
int setuid(uid_t);
unsigned int
sleep(unsigned int) ;
long sysconf(int);
pid_t tcgetpgrp(int);
int tcsetpgrp(int, pid_t);
char *ttyname(int);
char *ttyname_r(int, char *, size_t);
int unlink(const char *);
ssize_t write(int __fd, const void * __buf, size_t __nbyte) ;
size_t confstr(int, char *, size_t) ;
int getopt(int, char * const [], const char *) ;
extern char *optarg;
extern int optind, opterr, optopt;
  
void *brk(const void *);
int chroot(const char *) ;
char *crypt(const char *, const char *);
int encrypt(char *, int);
int fchdir(int);
long gethostid(void);
pid_t getpgid(pid_t);
pid_t getsid(pid_t);
int getdtablesize(void) ;
int getpagesize(void)  ;
char *getpass(const char *) ;
char *getwd(char *) ;
int lchown(const char *, uid_t, gid_t) ;
int lockf(int, int, off_t) ;
int nice(int) ;
ssize_t pread(int __fd, void * __buf, size_t __nbyte, off_t __offset) ;
ssize_t pwrite(int __fd, const void * __buf, size_t __nbyte, off_t __offset) ;
  
void *sbrk(int);
int setpgrp(pid_t pid, pid_t pgrp);
int setregid(gid_t, gid_t) ;
int setreuid(uid_t, uid_t) ;
void swab(const void *, void *, ssize_t);
void sync(void);
int truncate(const char *, off_t);
useconds_t ualarm(useconds_t, useconds_t);
int usleep(useconds_t) ;
pid_t vfork(void)  ;
int fsync(int) ;
int ftruncate(int, off_t);
int getlogin_r(char *, size_t);
int fchown(int, uid_t, gid_t);
int gethostname(char *, size_t);
ssize_t readlink(const char *, char *, size_t);
int setegid(gid_t);
int seteuid(uid_t);
int symlink(const char *, const char *);
void _Exit(int) ;
int accessx_np(const struct accessx_descriptor *, size_t, int *, uid_t);
int acct(const char *);
int add_profil(char *, size_t, unsigned long, unsigned int)  ;
void endusershell(void);
int execvP(const char * __file, const char * __searchpath, char * const * __argv)  ;
char *fflagstostr(unsigned long);
int getdomainname(char *, int);
int getgrouplist(const char *, int, int *, int *);
int _getprivatesystemidentifier(uuid_t uuid, const struct timespec *timeout) ;
int gethostuuid(uuid_t, const struct timespec *) ;
int _register_gethostuuid_callback(int (*)(uuid_t)) ;
mode_t getmode(const void *, mode_t);
int getpeereid(int, uid_t *, gid_t *);
int getsgroups_np(int *, uuid_t);
char *getusershell(void);
int getwgroups_np(int *, uuid_t);
int initgroups(const char *, int);
int issetugid(void);
char *mkdtemp(char *);
int mknod(const char *, mode_t, dev_t);
int mkpath_np(const char *path, mode_t omode) ;
int mkpathat_np(int dfd, const char *path, mode_t omode)
 
 ;
int mkstemp(char *);
int mkstemps(char *, int);
char *mktemp(char *);
int mkostemp(char *path, int oflags)
 
 ;
int mkostemps(char *path, int slen, int oflags)
 
 ;
int mkstemp_dprotected_np(char *path, int dpclass, int dpflags)
 
 ;
char *mkdtempat_np(int dfd, char *path)
 
 ;
int mkstempsat_np(int dfd, char *path, int slen)
 
 ;
int mkostempsat_np(int dfd, char *path, int slen, int oflags)
 
 ;
int nfssvc(int, void *);
int profil(char *, size_t, unsigned long, unsigned int);

int pthread_setugid_np(uid_t, gid_t);
int pthread_getugid_np( uid_t *, gid_t *);
int reboot(int);
int revoke(const char *);
 int rcmd(char **, int, const char *, const char *, const char *, int *);
 int rcmd_af(char **, int, const char *, const char *, const char *, int *,
int);
 int rresvport(int *);
 int rresvport_af(int *, int);
 int iruserok(unsigned long, int, const char *, const char *);
 int iruserok_sa(const void *, int, int, const char *, const char *);
 int ruserok(const char *, int, const char *, const char *);
int setdomainname(const char *, int);
int setgroups(int, const gid_t *);
void sethostid(long);
int sethostname(const char *, int);
int setkey(const char *);
int setlogin(const char *);
void *setmode(const char *) ;
int setrgid(gid_t);
int setruid(uid_t);
int setsgroups_np(int, const uuid_t);
void setusershell(void);
int setwgroups_np(int, const uuid_t);
int strtofflags(char **, unsigned long *, unsigned long *);
int swapon(const char *);
int ttyslot(void);
int undelete(const char *);
int unwhiteout(const char *);
void *valloc(size_t);
 


int syscall(int, ...);
extern char *suboptarg;
int getsubopt(char **, char * const *, char **);
int fgetattrlist(int,void*,void*,size_t,unsigned int) ;
int fsetattrlist(int,void*,void*,size_t,unsigned int) ;
int getattrlist(const char*,void*,void*,size_t,unsigned int) ;
int setattrlist(const char*,void*,void*,size_t,unsigned int) ;
int exchangedata(const char*,const char*,unsigned int)  ;
int getdirentriesattr(int,void*,void*,size_t,unsigned int*,unsigned int*,unsigned int*,unsigned int)  ;
struct fssearchblock;
struct searchstate;
int searchfs(const char *, struct fssearchblock *, unsigned long *, unsigned int, unsigned int, struct searchstate *)  ;
int fsctl(const char *,unsigned long,void*,unsigned int);
int ffsctl(int,unsigned long,void*,unsigned int) ;
int fsync_volume_np(int, int) ;
int sync_volume_np(const char *, int) ;
extern int optreset;

extern 
void*
os_retain(void *object);

extern 
void
os_release(void *object);
typedef void (*dispatch_function_t)(void *);
struct timespec;
typedef uint64_t dispatch_time_t;
 
extern   
dispatch_time_t
dispatch_time(dispatch_time_t when, int64_t delta);
 
extern   
dispatch_time_t
dispatch_walltime(const struct timespec * when, int64_t delta);
typedef union {
struct _os_object_s *_os_obj;
struct dispatch_object_s *_do;
struct dispatch_continuation_s *_dc;
struct dispatch_queue_s *_dq;
struct dispatch_queue_attr_s *_dqa;
struct dispatch_group_s *_dg;
//struct dispatch_source_s *_ds;
struct dispatch_mach_s *_dm;
struct dispatch_mach_msg_s *_dmsg;
struct dispatch_source_attr_s *_dsa;
struct dispatch_semaphore_s *_dsema;
struct dispatch_data_s *_ddata;
struct dispatch_io_s *_dchannel;
struct dispatch_operation_s *_doperation;
struct dispatch_disk_s *_ddisk;
} dispatch_object_t ;
typedef void (*dispatch_block_t)(void);
 
extern   

void
dispatch_retain(dispatch_object_t object);
 
extern   

void
dispatch_release(dispatch_object_t object);
 
extern    

void *
dispatch_get_context(dispatch_object_t object);
 
extern  
void
dispatch_set_context(dispatch_object_t object, void * context);
 
extern  
void
dispatch_set_finalizer_f(dispatch_object_t object,
dispatch_function_t  finalizer);
   
extern   
void
dispatch_activate(dispatch_object_t object);
 
extern   
void
dispatch_suspend(dispatch_object_t object);
 
extern   
void
dispatch_resume(dispatch_object_t object);

extern   
long
dispatch_wait(void *object, dispatch_time_t timeout);

extern   
void
dispatch_notify(void *object, dispatch_object_t queue,
dispatch_block_t notification_block);

extern   
void
dispatch_cancel(void *object);

extern    

long
dispatch_testcancel(void *object);
 
extern   

void
dispatch_debug(dispatch_object_t object, const char *message, ...);
 
extern   

void
dispatch_debugv(dispatch_object_t object, const char *message, va_list ap);
enum { QOS_CLASS_USER_INTERACTIVE   = 0x21, QOS_CLASS_USER_INITIATED   = 0x19, QOS_CLASS_DEFAULT   = 0x15, QOS_CLASS_UTILITY   = 0x11, QOS_CLASS_BACKGROUND   = 0x09, QOS_CLASS_UNSPECIFIED   = 0x00, }; typedef unsigned int qos_class_t;
 
qos_class_t
qos_class_self(void);
 
qos_class_t
qos_class_main(void);
typedef struct dispatch_queue_s *dispatch_queue_t;
 
extern   
void
dispatch_async(dispatch_queue_t queue, dispatch_block_t block);
 
extern    
void
dispatch_async_f(dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_sync(dispatch_queue_t queue,  dispatch_block_t block);
 
extern    
void
dispatch_sync_f(dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_apply(size_t iterations, dispatch_queue_t queue,
 void (*block)(size_t));
 
extern   
void
dispatch_apply_f(size_t iterations, dispatch_queue_t queue,
void * context,
void (*work)(void *, size_t));
 
extern    
dispatch_queue_t
dispatch_get_current_queue(void);
 
extern  struct dispatch_queue_s _dispatch_main_q;
static    
dispatch_queue_t
dispatch_get_main_queue(void)
{
return (&(_dispatch_main_q));
}
typedef long dispatch_queue_priority_t;
typedef qos_class_t dispatch_qos_class_t;
 
extern    
dispatch_queue_t
dispatch_get_global_queue(long identifier, unsigned long flags);
typedef struct dispatch_queue_attr_s *dispatch_queue_attr_t;
 
extern 
struct dispatch_queue_attr_s _dispatch_queue_attr_concurrent;
   
extern    
dispatch_queue_attr_t
dispatch_queue_attr_make_initially_inactive(
dispatch_queue_attr_t  attr);
enum { DISPATCH_AUTORELEASE_FREQUENCY_INHERIT     = 0, DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM     = 1, DISPATCH_AUTORELEASE_FREQUENCY_NEVER     = 2, }; typedef unsigned long dispatch_autorelease_frequency_t;
   
extern    
dispatch_queue_attr_t
dispatch_queue_attr_make_with_autorelease_frequency(
dispatch_queue_attr_t  attr,
dispatch_autorelease_frequency_t frequency);
 
extern    
dispatch_queue_attr_t
dispatch_queue_attr_make_with_qos_class(dispatch_queue_attr_t  attr,
dispatch_qos_class_t qos_class, int relative_priority);
   
extern   

dispatch_queue_t
dispatch_queue_create_with_target(const char * label,
dispatch_queue_attr_t  attr, dispatch_queue_t  target)
;
 
extern   

dispatch_queue_t
dispatch_queue_create(const char * label,
dispatch_queue_attr_t  attr);
 
extern    
const char *
dispatch_queue_get_label(dispatch_queue_t  queue);
 
extern    
dispatch_qos_class_t
dispatch_queue_get_qos_class(dispatch_queue_t queue,
int * relative_priority_ptr);
 
extern  
void
dispatch_set_target_queue(dispatch_object_t object,
dispatch_queue_t  queue);
 
extern   
void
dispatch_main(void);
 
extern    
void
dispatch_after(dispatch_time_t when,
dispatch_queue_t queue,
dispatch_block_t block);
 
extern    
void
dispatch_after_f(dispatch_time_t when,
dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_barrier_async(dispatch_queue_t queue, dispatch_block_t block);
 
extern    
void
dispatch_barrier_async_f(dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_barrier_sync(dispatch_queue_t queue,
 dispatch_block_t block);
 
extern    
void
dispatch_barrier_sync_f(dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_queue_set_specific(dispatch_queue_t queue, const void *key,
void * context, dispatch_function_t  destructor);
 
extern    

void *
dispatch_queue_get_specific(dispatch_queue_t queue, const void *key);
 
extern    
void *
dispatch_get_specific(const void *key);
   
extern  
void
dispatch_assert_queue(dispatch_queue_t queue)
;
   
extern  
void
dispatch_assert_queue_barrier(dispatch_queue_t queue);
   
extern  
void
dispatch_assert_queue_not(dispatch_queue_t queue)
;
enum { DISPATCH_BLOCK_BARRIER   = 0x1, DISPATCH_BLOCK_DETACHED   = 0x2, DISPATCH_BLOCK_ASSIGN_CURRENT   = 0x4, DISPATCH_BLOCK_NO_QOS_CLASS   = 0x8, DISPATCH_BLOCK_INHERIT_QOS_CLASS   = 0x10, DISPATCH_BLOCK_ENFORCE_QOS_CLASS   = 0x20, }; typedef unsigned long dispatch_block_flags_t;
 
extern   
 
dispatch_block_t
dispatch_block_create(dispatch_block_flags_t flags, dispatch_block_t block);
 
extern   
 
dispatch_block_t
dispatch_block_create_with_qos_class(dispatch_block_flags_t flags,
dispatch_qos_class_t qos_class, int relative_priority,
dispatch_block_t block);
 
extern   
void
dispatch_block_perform(dispatch_block_flags_t flags,
 dispatch_block_t block);
 
extern   
long
dispatch_block_wait(dispatch_block_t block, dispatch_time_t timeout);
 
extern   
void
dispatch_block_notify(dispatch_block_t block, dispatch_queue_t queue,
dispatch_block_t notification_block);
 
extern   
void
dispatch_block_cancel(dispatch_block_t block);
 
extern    

long
dispatch_block_testcancel(dispatch_block_t block);
typedef struct dispatch_source_s *dispatch_source_t;;
typedef const struct dispatch_source_type_s *dispatch_source_type_t;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_data_add;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_data_or;
   
extern  const struct dispatch_source_type_s _dispatch_source_type_data_replace;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_mach_send;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_mach_recv;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_memorypressure;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_proc;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_read;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_signal;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_timer;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_vnode;
 
extern  const struct dispatch_source_type_s _dispatch_source_type_write;
typedef unsigned long dispatch_source_mach_send_flags_t;
typedef unsigned long dispatch_source_memorypressure_flags_t;
typedef unsigned long dispatch_source_proc_flags_t;
typedef unsigned long dispatch_source_vnode_flags_t;
typedef unsigned long dispatch_source_timer_flags_t;
 
extern   

dispatch_source_t
dispatch_source_create(dispatch_source_type_t type,
uintptr_t handle,
unsigned long mask,
dispatch_queue_t  queue);
 
extern   
void
dispatch_source_set_event_handler(dispatch_source_t source,
dispatch_block_t  handler);
 
extern   
void
dispatch_source_set_event_handler_f(dispatch_source_t source,
dispatch_function_t  handler);
 
extern   
void
dispatch_source_set_cancel_handler(dispatch_source_t source,
dispatch_block_t  handler);
 
extern   
void
dispatch_source_set_cancel_handler_f(dispatch_source_t source,
dispatch_function_t  handler);
 
extern   
void
dispatch_source_cancel(dispatch_source_t source);
 
extern    

long
dispatch_source_testcancel(dispatch_source_t source);
 
extern    

uintptr_t
dispatch_source_get_handle(dispatch_source_t source);
 
extern    

unsigned long
dispatch_source_get_mask(dispatch_source_t source);
 
extern    

unsigned long
dispatch_source_get_data(dispatch_source_t source);
 
extern   
void
dispatch_source_merge_data(dispatch_source_t source, unsigned long value);
 
extern   
void
dispatch_source_set_timer(dispatch_source_t source,
dispatch_time_t start,
uint64_t interval,
uint64_t leeway);
 
extern   
void
dispatch_source_set_registration_handler(dispatch_source_t source,
dispatch_block_t  handler);
 
extern   
void
dispatch_source_set_registration_handler_f(dispatch_source_t source,
dispatch_function_t  handler);
typedef struct dispatch_group_s *dispatch_group_t;
 
extern   

dispatch_group_t
dispatch_group_create(void);
 
extern   
void
dispatch_group_async(dispatch_group_t group,
dispatch_queue_t queue,
dispatch_block_t block);
 
extern    

void
dispatch_group_async_f(dispatch_group_t group,
dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
long
dispatch_group_wait(dispatch_group_t group, dispatch_time_t timeout);
 
extern   
void
dispatch_group_notify(dispatch_group_t group,
dispatch_queue_t queue,
dispatch_block_t block);
 
extern    

void
dispatch_group_notify_f(dispatch_group_t group,
dispatch_queue_t queue,
void * context,
dispatch_function_t work);
 
extern   
void
dispatch_group_enter(dispatch_group_t group);
 
extern   
void
dispatch_group_leave(dispatch_group_t group);
typedef struct dispatch_semaphore_s *dispatch_semaphore_t;
 
extern   

dispatch_semaphore_t
dispatch_semaphore_create(long value);
 
extern   
long
dispatch_semaphore_wait(dispatch_semaphore_t dsema, dispatch_time_t timeout);
 
extern   
long
dispatch_semaphore_signal(dispatch_semaphore_t dsema);
typedef long dispatch_once_t;
 
extern   
void
dispatch_once(dispatch_once_t *predicate,
 dispatch_block_t block);
static    
void
_dispatch_once(dispatch_once_t *predicate,
 dispatch_block_t block)
{
if (__builtin_expect((*predicate), (~0l)) != ~0l) {
dispatch_once(predicate, block);
} else {

}
__builtin_assume(*predicate == ~0l);
}
 
extern    
void
dispatch_once_f(dispatch_once_t *predicate, void * context,
dispatch_function_t function);
static    

void
_dispatch_once_f(dispatch_once_t *predicate, void * context,
dispatch_function_t function)
{
if (__builtin_expect((*predicate), (~0l)) != ~0l) {
dispatch_once_f(predicate, context, function);
} else {

}
__builtin_assume(*predicate == ~0l);
}
typedef struct dispatch_data_s *dispatch_data_t;
 
extern  struct dispatch_data_s _dispatch_data_empty;
 
extern  const dispatch_block_t _dispatch_data_destructor_free;
 
extern  const dispatch_block_t _dispatch_data_destructor_munmap;
 
extern   
dispatch_data_t
dispatch_data_create(const void *buffer,
size_t size,
dispatch_queue_t  queue,
dispatch_block_t  destructor);
 
extern    
size_t
dispatch_data_get_size(dispatch_data_t data);
 
extern  
 
dispatch_data_t
dispatch_data_create_map(dispatch_data_t data,
const void * * buffer_ptr,
size_t * size_ptr);
 
extern  
 
dispatch_data_t
dispatch_data_create_concat(dispatch_data_t data1, dispatch_data_t data2);
 
extern  
 
dispatch_data_t
dispatch_data_create_subrange(dispatch_data_t data,
size_t offset,
size_t length);
typedef _Bool (*dispatch_data_applier_t)(dispatch_data_t region,
size_t offset,
const void *buffer,
size_t size);
 
extern   
_Bool
dispatch_data_apply(dispatch_data_t data,
 dispatch_data_applier_t applier);
 
extern   
 
dispatch_data_t
dispatch_data_copy_region(dispatch_data_t data,
size_t location,
size_t *offset_ptr);
typedef int dispatch_fd_t;
 
extern    
void
dispatch_read(dispatch_fd_t fd,
size_t length,
dispatch_queue_t queue,
void (*handler)(dispatch_data_t data, int error));
 
extern    

void
dispatch_write(dispatch_fd_t fd,
dispatch_data_t data,
dispatch_queue_t queue,
void (*handler)(dispatch_data_t  data, int error));
typedef struct dispatch_io_s *dispatch_io_t;
typedef unsigned long dispatch_io_type_t;
 
extern   

dispatch_io_t
dispatch_io_create(dispatch_io_type_t type,
dispatch_fd_t fd,
dispatch_queue_t queue,
void (*cleanup_handler)(int error));
 
extern   
 
dispatch_io_t
dispatch_io_create_with_path(dispatch_io_type_t type,
const char *path, int oflag, mode_t mode,
dispatch_queue_t queue,
void (*cleanup_handler)(int error));
 
extern   
 
dispatch_io_t
dispatch_io_create_with_io(dispatch_io_type_t type,
dispatch_io_t io,
dispatch_queue_t queue,
void (*cleanup_handler)(int error));
typedef void (*dispatch_io_handler_t)(_Bool done, dispatch_data_t  data,
int error);
 
extern    

void
dispatch_io_read(dispatch_io_t channel,
off_t offset,
size_t length,
dispatch_queue_t queue,
dispatch_io_handler_t io_handler);
 
extern    
 
void
dispatch_io_write(dispatch_io_t channel,
off_t offset,
dispatch_data_t data,
dispatch_queue_t queue,
dispatch_io_handler_t io_handler);
typedef unsigned long dispatch_io_close_flags_t;
 
extern   
void
dispatch_io_close(dispatch_io_t channel, dispatch_io_close_flags_t flags);
 
extern   
void
dispatch_io_barrier(dispatch_io_t channel, dispatch_block_t barrier);
 
extern    
dispatch_fd_t
dispatch_io_get_descriptor(dispatch_io_t channel);
 
extern   
void
dispatch_io_set_high_water(dispatch_io_t channel, size_t high_water);
 
extern   
void
dispatch_io_set_low_water(dispatch_io_t channel, size_t low_water);
typedef unsigned long dispatch_io_interval_flags_t;
 
extern   
void
dispatch_io_set_interval(dispatch_io_t channel,
uint64_t interval,
dispatch_io_interval_flags_t flags);
typedef struct IONotificationPort * IONotificationPortRef;
typedef void
(*IOServiceMatchingCallback)(
void * refcon,
io_iterator_t iterator );
typedef void
(*IOServiceInterestCallback)(
void * refcon,
io_service_t service,
uint32_t messageType,
void * messageArgument );
extern
const mach_port_t kIOMasterPortDefault;
kern_return_t
IOMasterPort( mach_port_t bootstrapPort,
mach_port_t * masterPort );
IONotificationPortRef
IONotificationPortCreate(
mach_port_t masterPort );
void
IONotificationPortDestroy(
IONotificationPortRef notify );
CFRunLoopSourceRef
IONotificationPortGetRunLoopSource(
IONotificationPortRef notify );
mach_port_t
IONotificationPortGetMachPort(
IONotificationPortRef notify );
kern_return_t
IONotificationPortSetImportanceReceiver(
IONotificationPortRef notify );
void
IONotificationPortSetDispatchQueue(
IONotificationPortRef notify, dispatch_queue_t queue )
;
void
IODispatchCalloutFromMessage(
void *unused,
mach_msg_header_t *msg,
void *reference );
kern_return_t
IOCreateReceivePort( uint32_t msgType, mach_port_t * recvPort );
kern_return_t
IOObjectRelease(
io_object_t object );
kern_return_t
IOObjectRetain(
io_object_t object );
kern_return_t
IOObjectGetClass(
io_object_t object,
io_name_t className );
CFStringRef
IOObjectCopyClass(io_object_t object)
;
CFStringRef
IOObjectCopySuperclassForClass(CFStringRef classname)
;
CFStringRef
IOObjectCopyBundleIdentifierForClass(CFStringRef classname)
;
boolean_t
IOObjectConformsTo(
io_object_t object,
const io_name_t className );
boolean_t
IOObjectIsEqualTo(
io_object_t object,
io_object_t anObject );
uint32_t
IOObjectGetKernelRetainCount(
io_object_t object )
;
uint32_t
IOObjectGetUserRetainCount(
io_object_t object )
;
uint32_t
IOObjectGetRetainCount(
io_object_t object );
io_object_t
IOIteratorNext(
io_iterator_t iterator );
void
IOIteratorReset(
io_iterator_t iterator );
boolean_t
IOIteratorIsValid(
io_iterator_t iterator );
io_service_t
IOServiceGetMatchingService(
mach_port_t masterPort,
CFDictionaryRef matching );
kern_return_t
IOServiceGetMatchingServices(
mach_port_t masterPort,
CFDictionaryRef matching ,
io_iterator_t * existing );
kern_return_t
IOServiceAddNotification(
mach_port_t masterPort,
const io_name_t notificationType,
CFDictionaryRef matching,
mach_port_t wakePort,
uintptr_t reference,
io_iterator_t * notification ) ;
kern_return_t
IOServiceAddMatchingNotification(
IONotificationPortRef notifyPort,
const io_name_t notificationType,
CFDictionaryRef matching ,
IOServiceMatchingCallback callback,
void * refCon,
io_iterator_t * notification );
kern_return_t
IOServiceAddInterestNotification(
IONotificationPortRef notifyPort,
io_service_t service,
const io_name_t interestType,
IOServiceInterestCallback callback,
void * refCon,
io_object_t * notification );
kern_return_t
IOServiceMatchPropertyTable(
io_service_t service,
CFDictionaryRef matching,
boolean_t * matches );
kern_return_t
IOServiceGetBusyState(
io_service_t service,
uint32_t * busyState );
kern_return_t
IOServiceWaitQuiet(
io_service_t service,
mach_timespec_t * waitTime );
kern_return_t
IOKitGetBusyState(
mach_port_t masterPort,
uint32_t * busyState );
kern_return_t
IOKitWaitQuiet(
mach_port_t masterPort,
mach_timespec_t * waitTime );
kern_return_t
IOServiceOpen(
io_service_t service,
task_port_t owningTask,
uint32_t type,
io_connect_t * connect );
kern_return_t
IOServiceRequestProbe(
io_service_t service,
uint32_t options );
enum {
kIOServiceInteractionAllowed = 0x00000001
};
kern_return_t
IOServiceAuthorize(
io_service_t service,
uint32_t options );
int
IOServiceOpenAsFileDescriptor(
io_service_t service,
int oflag );
kern_return_t
IOServiceClose(
io_connect_t connect );
kern_return_t
IOConnectAddRef(
io_connect_t connect );
kern_return_t
IOConnectRelease(
io_connect_t connect );
kern_return_t
IOConnectGetService(
io_connect_t connect,
io_service_t * service );
kern_return_t
IOConnectSetNotificationPort(
io_connect_t connect,
uint32_t type,
mach_port_t port,
uintptr_t reference );
kern_return_t
IOConnectMapMemory(
io_connect_t connect,
uint32_t memoryType,
task_port_t intoTask,
mach_vm_address_t *atAddress,
mach_vm_size_t *ofSize,
IOOptionBits options );
kern_return_t IOConnectMapMemory64(
io_connect_t connect,
uint32_t memoryType,
task_port_t intoTask,
mach_vm_address_t *atAddress,
mach_vm_size_t *ofSize,
IOOptionBits options );
kern_return_t
IOConnectUnmapMemory(
io_connect_t connect,
uint32_t memoryType,
task_port_t fromTask,
mach_vm_address_t atAddress );
kern_return_t IOConnectUnmapMemory64(
io_connect_t connect,
uint32_t memoryType,
task_port_t fromTask,
mach_vm_address_t atAddress );
kern_return_t
IOConnectSetCFProperties(
io_connect_t connect,
CFTypeRef properties );
kern_return_t
IOConnectSetCFProperty(
io_connect_t connect,
CFStringRef propertyName,
CFTypeRef property );
kern_return_t
IOConnectCallMethod(
mach_port_t connection,
uint32_t selector,
const uint64_t *input,
uint32_t inputCnt,
const void *inputStruct,
size_t inputStructCnt,
uint64_t *output,
uint32_t *outputCnt,
void *outputStruct,
size_t *outputStructCnt)
;
kern_return_t
IOConnectCallAsyncMethod(
mach_port_t connection,
uint32_t selector,
mach_port_t wake_port,
uint64_t *reference,
uint32_t referenceCnt,
const uint64_t *input,
uint32_t inputCnt,
const void *inputStruct,
size_t inputStructCnt,
uint64_t *output,
uint32_t *outputCnt,
void *outputStruct,
size_t *outputStructCnt)
;
kern_return_t
IOConnectCallStructMethod(
mach_port_t connection,
uint32_t selector,
const void *inputStruct,
size_t inputStructCnt,
void *outputStruct,
size_t *outputStructCnt)
;
kern_return_t
IOConnectCallAsyncStructMethod(
mach_port_t connection,
uint32_t selector,
mach_port_t wake_port,
uint64_t *reference,
uint32_t referenceCnt,
const void *inputStruct,
size_t inputStructCnt,
void *outputStruct,
size_t *outputStructCnt)
;
kern_return_t
IOConnectCallScalarMethod(
mach_port_t connection,
uint32_t selector,
const uint64_t *input,
uint32_t inputCnt,
uint64_t *output,
uint32_t *outputCnt)
;
kern_return_t
IOConnectCallAsyncScalarMethod(
mach_port_t connection,
uint32_t selector,
mach_port_t wake_port,
uint64_t *reference,
uint32_t referenceCnt,
const uint64_t *input,
uint32_t inputCnt,
uint64_t *output,
uint32_t *outputCnt)
;
kern_return_t
IOConnectTrap0(io_connect_t connect,
uint32_t index );
kern_return_t
IOConnectTrap1(io_connect_t connect,
uint32_t index,
uintptr_t p1 );
kern_return_t
IOConnectTrap2(io_connect_t connect,
uint32_t index,
uintptr_t p1,
uintptr_t p2);
kern_return_t
IOConnectTrap3(io_connect_t connect,
uint32_t index,
uintptr_t p1,
uintptr_t p2,
uintptr_t p3);
kern_return_t
IOConnectTrap4(io_connect_t connect,
uint32_t index,
uintptr_t p1,
uintptr_t p2,
uintptr_t p3,
uintptr_t p4);
kern_return_t
IOConnectTrap5(io_connect_t connect,
uint32_t index,
uintptr_t p1,
uintptr_t p2,
uintptr_t p3,
uintptr_t p4,
uintptr_t p5);
kern_return_t
IOConnectTrap6(io_connect_t connect,
uint32_t index,
uintptr_t p1,
uintptr_t p2,
uintptr_t p3,
uintptr_t p4,
uintptr_t p5,
uintptr_t p6);
kern_return_t
IOConnectAddClient(
io_connect_t connect,
io_connect_t client );
io_registry_entry_t
IORegistryGetRootEntry(
mach_port_t masterPort );
io_registry_entry_t
IORegistryEntryFromPath(
mach_port_t masterPort,
const io_string_t path );
io_registry_entry_t
IORegistryEntryCopyFromPath(
mach_port_t masterPort,
CFStringRef path )

;
enum {
kIORegistryIterateRecursively = 0x00000001,
kIORegistryIterateParents = 0x00000002
};
kern_return_t
IORegistryCreateIterator(
mach_port_t masterPort,
const io_name_t plane,
IOOptionBits options,
io_iterator_t * iterator );
kern_return_t
IORegistryEntryCreateIterator(
io_registry_entry_t entry,
const io_name_t plane,
IOOptionBits options,
io_iterator_t * iterator );
kern_return_t
IORegistryIteratorEnterEntry(
io_iterator_t iterator );
kern_return_t
IORegistryIteratorExitEntry(
io_iterator_t iterator );
kern_return_t
IORegistryEntryGetName(
io_registry_entry_t entry,
io_name_t name );
kern_return_t
IORegistryEntryGetNameInPlane(
io_registry_entry_t entry,
const io_name_t plane,
io_name_t name );
kern_return_t
IORegistryEntryGetLocationInPlane(
io_registry_entry_t entry,
const io_name_t plane,
io_name_t location );
kern_return_t
IORegistryEntryGetPath(
io_registry_entry_t entry,
const io_name_t plane,
io_string_t path );
CFStringRef
IORegistryEntryCopyPath(
io_registry_entry_t entry,
const io_name_t plane)

;
kern_return_t
IORegistryEntryGetRegistryEntryID(
io_registry_entry_t entry,
uint64_t * entryID );
kern_return_t
IORegistryEntryCreateCFProperties(
io_registry_entry_t entry,
CFMutableDictionaryRef * properties,
CFAllocatorRef allocator,
IOOptionBits options );
CFTypeRef
IORegistryEntryCreateCFProperty(
io_registry_entry_t entry,
CFStringRef key,
CFAllocatorRef allocator,
IOOptionBits options );
CFTypeRef
IORegistryEntrySearchCFProperty(
io_registry_entry_t entry,
const io_name_t plane,
CFStringRef key,
CFAllocatorRef allocator,
IOOptionBits options ) ;
kern_return_t
IORegistryEntryGetProperty(
io_registry_entry_t entry,
const io_name_t propertyName,
io_struct_inband_t buffer,
uint32_t * size );
kern_return_t
IORegistryEntrySetCFProperties(
io_registry_entry_t entry,
CFTypeRef properties );
kern_return_t
IORegistryEntrySetCFProperty(
io_registry_entry_t entry,
CFStringRef propertyName,
CFTypeRef property );
kern_return_t
IORegistryEntryGetChildIterator(
io_registry_entry_t entry,
const io_name_t plane,
io_iterator_t * iterator );
kern_return_t
IORegistryEntryGetChildEntry(
io_registry_entry_t entry,
const io_name_t plane,
io_registry_entry_t * child );
kern_return_t
IORegistryEntryGetParentIterator(
io_registry_entry_t entry,
const io_name_t plane,
io_iterator_t * iterator );
kern_return_t
IORegistryEntryGetParentEntry(
io_registry_entry_t entry,
const io_name_t plane,
io_registry_entry_t * parent );
boolean_t
IORegistryEntryInPlane(
io_registry_entry_t entry,
const io_name_t plane );
CFMutableDictionaryRef
IOServiceMatching(
const char * name ) ;
CFMutableDictionaryRef
IOServiceNameMatching(
const char * name ) ;
CFMutableDictionaryRef
IOBSDNameMatching(
mach_port_t masterPort,
uint32_t options,
const char * bsdName ) ;
CFMutableDictionaryRef
IOOpenFirmwarePathMatching(
mach_port_t masterPort,
uint32_t options,
const char * path ) ;
CFMutableDictionaryRef
IORegistryEntryIDMatching(
uint64_t entryID ) ;
kern_return_t
IOServiceOFPathToBSDName(mach_port_t masterPort,
const io_name_t openFirmwarePath,
io_name_t bsdName) ;
typedef void (*IOAsyncCallback0)(void *refcon, IOReturn result);
typedef void (*IOAsyncCallback1)(void *refcon, IOReturn result, void *arg0);
typedef void (*IOAsyncCallback2)(void *refcon, IOReturn result, void *arg0, void *arg1);
typedef void (*IOAsyncCallback)(void *refcon, IOReturn result, void **args,
uint32_t numArgs);
kern_return_t
OSGetNotificationFromMessage(
mach_msg_header_t * msg,
uint32_t index,
uint32_t * type,
uintptr_t * reference,
void ** content,
vm_size_t * size );
kern_return_t
IOCatalogueSendData(
mach_port_t masterPort,
uint32_t flag,
const char *buffer,
uint32_t size );
kern_return_t
IOCatalogueTerminate(
mach_port_t masterPort,
uint32_t flag,
io_name_t description );
kern_return_t
IOCatalogueGetData(
mach_port_t masterPort,
uint32_t flag,
char **buffer,
uint32_t *size );
kern_return_t
IOCatalogueModuleLoaded(
mach_port_t masterPort,
io_name_t name );
kern_return_t
IOCatalogueReset(
mach_port_t masterPort,
uint32_t flag );
typedef IOByteCount IORangeScalar;
typedef __darwin_ptrdiff_t ptrdiff_t;
typedef unsigned int vUInt32 ;
typedef signed int vSInt32 ;
typedef unsigned char vUInt8 ;
typedef struct { uint8_t bytes[3];} vDSP_uint24;
typedef struct { uint8_t bytes[3];} vDSP_int24;
void
vDSP_conv(
const float vDSP_signal[],
ptrdiff_t vDSP_signalStride,
const float vDSP_filter[],
ptrdiff_t vDSP_strideFilter,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_lenResult,
size_t vDSP_lenFilter,
char *temp);
void
vDSP_deq22(
float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_input2[],
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_maxmgv(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_result[],
size_t vDSP_size);
void
vDSP_rmsqv(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_result[],
size_t vDSP_size);
void
vDSP_svesq(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_result[],
size_t vDSP_size);
void
vDSP_svs(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_result[],
size_t vDSP_size);
void
vDSP_vabs(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vadd(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
ptrdiff_t vDSP_stride2,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vdiv(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
ptrdiff_t vDSP_stride2,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vfix32(float const *vDSP_input1, ptrdiff_t vDSP_stride1,
int *vDSP_input2, ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vfix16(float const *vDSP_input1, ptrdiff_t vDSP_stride1,
int16_t *vDSP_input2, ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vflt32(int const *vDSP_input1, ptrdiff_t vDSP_stride1,
float *vDSP_input2, ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vflt16(int16_t const *vDSP_input1, ptrdiff_t vDSP_stride1,
float *vDSP_input2, ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vsmfix24(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
vDSP_int24* vDSP_input3,
ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vsmfixu24(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
vDSP_uint24* vDSP_input3,
ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vflt24(
const vDSP_int24* vDSP_input1,
ptrdiff_t vDSP_stride1,
float* vDSP_input2,
ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vfltu24(
const vDSP_uint24* vDSP_input1,
ptrdiff_t vDSP_stride1,
float* vDSP_input2,
ptrdiff_t vDSP_stride2,
size_t vDSP_size);
void
vDSP_vma(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
ptrdiff_t vDSP_stride2,
const float vDSP_input3[],
ptrdiff_t vDSP_stride3,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vmul(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
ptrdiff_t vDSP_stride2,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vsmul(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
void
vDSP_vsub(
const float vDSP_input1[],
ptrdiff_t vDSP_stride1,
const float vDSP_input2[],
ptrdiff_t vDSP_stride2,
float vDSP_result[],
ptrdiff_t vDSP_strideResult,
size_t vDSP_size);
typedef struct vDSP_biquad_SetupStruct *vDSP_biquad_Setup;
typedef int IIRChannel;
enum {
vDSP_IIRStereo = 0,
vDSP_IIRMonoLeft = 1,
vDSP_IIRMonoRight = 2
};
vDSP_biquad_Setup
vDSP_biquad2_CreateSetup(const double*, const size_t, const IIRChannel);
void vDSP_biquad2_DestroySetup(vDSP_biquad_Setup);
void
vDSP_biquad2(const struct vDSP_biquad_SetupStruct*,
const float*, float*, size_t);
void vDSP_biquad2_ResetState(vDSP_biquad_Setup);
void vDSP_biquad2_CopyState(vDSP_biquad_Setup, vDSP_biquad_Setup);
vSInt32
vS64FullMulOdd(
vSInt32 vA,
vSInt32 vB);
vUInt32
vU64FullMulOdd(
vUInt32 vA,
vUInt32 vB);
vUInt32
vU128Sub(
vUInt32 vA,
vUInt32 vB);
vUInt32
vU128SubS(
vUInt32 vA,
vUInt32 vB);
vSInt32
vS128Sub(
vSInt32 vA,
vSInt32 vB);
vSInt32
vS128SubS(
vSInt32 vA,
vSInt32 vB);
vUInt32
vU128Add(
vUInt32 vA,
vUInt32 vB);
vUInt32
vU128AddS(
vUInt32 vA,
vUInt32 vB);
vSInt32
vS128Add(
vSInt32 vA,
vSInt32 vB);
vSInt32
vS128AddS(
vSInt32 vA,
vSInt32 vB);
vUInt32
vLL128Shift(
vUInt32 vA,
vUInt8 vShiftFactor);
vUInt32
vLR128Shift(
vUInt32 vA,
vUInt8 vShiftFactor);
vUInt32
vA128Shift(
vUInt32 vA,
vUInt8 vShiftFactor);
extern float expf(float);
extern float logf(float);
extern float log10f(float);
extern float sqrtf(float);
extern float sinf(float);
extern float cosf(float);
extern float __sinpif(float);
extern float __cospif(float);
void vvexpf (float * , const float * , const int * );
typedef __uint32_t tcp_seq;
typedef __uint32_t tcp_cc;
struct tcphdr {
unsigned short th_sport;
unsigned short th_dport;
tcp_seq th_seq;
tcp_seq th_ack;
unsigned int th_x2:4,
th_off:4;
unsigned char th_flags;
unsigned short th_win;
unsigned short th_sum;
unsigned short th_urp;
};
struct tcp_connection_info {
u_int8_t tcpi_state;
u_int8_t tcpi_snd_wscale;
u_int8_t tcpi_rcv_wscale;
u_int8_t __pad1;
u_int32_t tcpi_options;
u_int32_t tcpi_flags;
u_int32_t tcpi_rto;
u_int32_t tcpi_maxseg;
u_int32_t tcpi_snd_ssthresh;
u_int32_t tcpi_snd_cwnd;
u_int32_t tcpi_snd_wnd;
u_int32_t tcpi_snd_sbbytes;
u_int32_t tcpi_rcv_wnd;
u_int32_t tcpi_rttcur;
u_int32_t tcpi_srtt;
u_int32_t tcpi_rttvar;
u_int32_t
tcpi_tfo_cookie_req:1,
tcpi_tfo_cookie_rcv:1,
tcpi_tfo_syn_loss:1,
tcpi_tfo_syn_data_sent:1,
tcpi_tfo_syn_data_acked:1,
tcpi_tfo_syn_data_rcv:1,
tcpi_tfo_cookie_req_rcv:1,
tcpi_tfo_cookie_sent:1,
tcpi_tfo_cookie_invalid:1,
tcpi_tfo_cookie_wrong:1,
tcpi_tfo_no_cookie_rcv:1,
tcpi_tfo_heuristics_disable:1,
tcpi_tfo_send_blackhole:1,
tcpi_tfo_recv_blackhole:1,
tcpi_tfo_onebyte_proxy:1,
__pad2:17;
u_int64_t tcpi_txpackets ;
u_int64_t tcpi_txbytes ;
u_int64_t tcpi_txretransmitbytes ;
u_int64_t tcpi_rxpackets ;
u_int64_t tcpi_rxbytes ;
u_int64_t tcpi_rxoutoforderbytes ;
u_int64_t tcpi_txretransmitpackets ;
};
struct icmp_ra_addr {
u_int32_t ira_addr;
u_int32_t ira_preference;
};
struct icmp {
u_char icmp_type;
u_char icmp_code;
u_short icmp_cksum;
union {
u_char ih_pptr;
struct in_addr ih_gwaddr;
struct ih_idseq {
n_short icd_id;
n_short icd_seq;
} ih_idseq;
int ih_void;
struct ih_pmtu {
n_short ipm_void;
n_short ipm_nextmtu;
} ih_pmtu;
struct ih_rtradv {
u_char irt_num_addrs;
u_char irt_wpa;
u_int16_t irt_lifetime;
} ih_rtradv;
} icmp_hun;
union {
struct id_ts {
n_time its_otime;
n_time its_rtime;
n_time its_ttime;
} id_ts;
struct id_ip {
struct ip idi_ip;
} id_ip;
struct icmp_ra_addr id_radv;
u_int32_t id_mask;
char id_data[1];
} icmp_dun;
};
struct igmp {
u_char igmp_type;
u_char igmp_code;
u_short igmp_cksum;
struct in_addr igmp_group;
};
struct igmpv3 {
u_char igmp_type;
u_char igmp_code;
u_short igmp_cksum;
struct in_addr igmp_group;
u_char igmp_misc;
u_char igmp_qqi;
u_short igmp_numsrc;
};
struct igmp_grouprec {
u_char ig_type;
u_char ig_datalen;
u_short ig_numsrc;
struct in_addr ig_group;
};
struct igmp_report {
u_char ir_type;
u_char ir_rsv1;
u_short ir_cksum;
u_short ir_rsv2;
u_short ir_numgrps;
};
struct ipovly {
u_char ih_x1[9];
u_char ih_pr;
u_short ih_len;
struct in_addr ih_src;
struct in_addr ih_dst;
};
struct ipstat {
u_int32_t ips_total;
u_int32_t ips_badsum;
u_int32_t ips_tooshort;
u_int32_t ips_toosmall;
u_int32_t ips_badhlen;
u_int32_t ips_badlen;
u_int32_t ips_fragments;
u_int32_t ips_fragdropped;
u_int32_t ips_fragtimeout;
u_int32_t ips_forward;
u_int32_t ips_fastforward;
u_int32_t ips_cantforward;
u_int32_t ips_redirectsent;
u_int32_t ips_noproto;
u_int32_t ips_delivered;
u_int32_t ips_localout;
u_int32_t ips_odropped;
u_int32_t ips_reassembled;
u_int32_t ips_fragmented;
u_int32_t ips_ofragments;
u_int32_t ips_cantfrag;
u_int32_t ips_badoptions;
u_int32_t ips_noroute;
u_int32_t ips_badvers;
u_int32_t ips_rawout;
u_int32_t ips_toolong;
u_int32_t ips_notmember;
u_int32_t ips_nogif;
u_int32_t ips_badaddr;
u_int32_t ips_pktdropcntrl;
u_int32_t ips_rcv_swcsum;
u_int32_t ips_rcv_swcsum_bytes;
u_int32_t ips_snd_swcsum;
u_int32_t ips_snd_swcsum_bytes;
u_int32_t ips_adj;
u_int32_t ips_adj_hwcsum_clr;
u_int32_t ips_rxc_collisions;
u_int32_t ips_rxc_chained;
u_int32_t ips_rxc_notchain;
u_int32_t ips_rxc_chainsz_gt2;
u_int32_t ips_rxc_chainsz_gt4;
u_int32_t ips_rxc_notlist;
u_int32_t ips_raw_sappend_fail;
u_int32_t ips_necp_policy_drop;
};
struct ip_linklocal_stat {
u_int32_t iplls_in_total;
u_int32_t iplls_in_badttl;
u_int32_t iplls_out_total;
u_int32_t iplls_out_badttl;
};
struct tcpiphdr {
struct ipovly ti_i;
struct tcphdr ti_t;
};
struct icmpstat {
u_int32_t icps_error;
u_int32_t icps_oldshort;
u_int32_t icps_oldicmp;
u_int32_t icps_outhist[40 + 1];
u_int32_t icps_badcode;
u_int32_t icps_tooshort;
u_int32_t icps_checksum;
u_int32_t icps_badlen;
u_int32_t icps_reflect;
u_int32_t icps_inhist[40 + 1];
u_int32_t icps_bmcastecho;
u_int32_t icps_bmcasttstamp;
};
struct udphdr {
u_short uh_sport;
u_short uh_dport;
u_short uh_ulen;
u_short uh_sum;
};
struct bootp {
u_char bp_op;
u_char bp_htype;
u_char bp_hlen;
u_char bp_hops;
u_int32_t bp_xid;
u_short bp_secs;
u_short bp_unused;
struct in_addr bp_ciaddr;
struct in_addr bp_yiaddr;
struct in_addr bp_siaddr;
struct in_addr bp_giaddr;
u_char bp_chaddr[16];
u_char bp_sname[64];
u_char bp_file[128];
u_char bp_vend[64];
};
struct vend {
u_char v_magic[4];
u_int32_t v_flags;
u_char v_unused[56];
};
struct nextvend {
u_char nv_magic[4];
u_char nv_version;
unsigned short :0;
union {
u_char NV0[58];
struct {
u_char NV1_opcode;
u_char NV1_xid;
u_char NV1_text[55];
u_char NV1_null;
} NV1;
} nv_U;
};
struct bootp_packet {
struct ip bp_ip;
struct udphdr bp_udp;
struct bootp bp_bootp;
};
typedef u_quad_t inp_gen_t;
struct in_addr_4in6 {
u_int32_t ia46_pad32[3];
struct in_addr ia46_addr4;
};
struct _inpcb_list_entry {
u_int32_t le_next;
u_int32_t le_prev;
};
struct inpcbinfo;
struct inpcbport;
struct mbuf;
struct ip6_pktopts;
struct ip6_moptions;
struct icmp6_filter;
struct inpcbpolicy;
struct inpcb {
struct _inpcb_list_entry inp_hash;
struct in_addr reserved1;
struct in_addr reserved2;
u_short inp_fport;
u_short inp_lport;
struct _inpcb_list_entry inp_list;
u_int32_t inp_ppcb;
u_int32_t inp_pcbinfo;
u_int32_t inp_socket;
u_char nat_owner;
u_int32_t nat_cookie;
struct _inpcb_list_entry inp_portlist;
u_int32_t inp_phd;
inp_gen_t inp_gencnt;
int inp_flags;
u_int32_t inp_flow;
u_char inp_vflag;
u_char inp_ip_ttl;
u_char inp_ip_p;
union {
struct in_addr_4in6 inp46_foreign;
struct in6_addr inp6_foreign;
} inp_dependfaddr;
union {
struct in_addr_4in6 inp46_local;
struct in6_addr inp6_local;
} inp_dependladdr;
union {
u_char inp4_route[20];
u_char inp6_route[32];
} inp_dependroute;
struct {
u_char inp4_ip_tos;
u_int32_t inp4_options;
u_int32_t inp4_moptions;
} inp_depend4;
struct {
u_int32_t inp6_options;
u_int8_t inp6_hlim;
u_int8_t unused_uint8_1;
ushort unused_uint16_1;
u_int32_t inp6_outputopts;
u_int32_t inp6_moptions;
u_int32_t inp6_icmp6filt;
int inp6_cksum;
u_short inp6_ifindex;
short inp6_hops;
} inp_depend6;
int hash_element;
u_int32_t inp_saved_ppcb;
u_int32_t inp_sp;
u_int32_t reserved[3];
};
struct xinpcb {
u_int32_t xi_len;
struct inpcb xi_inp;
struct xsocket xi_socket;
u_quad_t xi_alignment_hack;
};
struct inpcb64_list_entry {
u_int64_t le_next;
u_int64_t le_prev;
};
struct xinpcb64 {
u_int64_t xi_len;
u_int64_t xi_inpp;
u_short inp_fport;
u_short inp_lport;
struct inpcb64_list_entry inp_list;
u_int64_t inp_ppcb;
u_int64_t inp_pcbinfo;
struct inpcb64_list_entry inp_portlist;
u_int64_t inp_phd;
inp_gen_t inp_gencnt;
int inp_flags;
u_int32_t inp_flow;
u_char inp_vflag;
u_char inp_ip_ttl;
u_char inp_ip_p;
union {
struct in_addr_4in6 inp46_foreign;
struct in6_addr inp6_foreign;
} inp_dependfaddr;
union {
struct in_addr_4in6 inp46_local;
struct in6_addr inp6_local;
} inp_dependladdr;
struct {
u_char inp4_ip_tos;
} inp_depend4;
struct {
u_int8_t inp6_hlim;
int inp6_cksum;
u_short inp6_ifindex;
short inp6_hops;
} inp_depend6;
struct xsocket64 xi_socket;
u_quad_t xi_alignment_hack;
};
struct xinpgen {
u_int32_t xig_len;
u_int xig_count;
inp_gen_t xig_gen;
so_gen_t xig_sogen;
};
struct tseg_qent;
struct tsegqe_head { u_int32_t lh_first; };
struct tcpcb {
struct tsegqe_head t_segq;
int t_dupacks;
u_int32_t unused;
int t_timer[4];
u_int32_t t_inpcb;
int t_state;
u_int t_flags;
int t_force;
tcp_seq snd_una;
tcp_seq snd_max;
tcp_seq snd_nxt;
tcp_seq snd_up;
tcp_seq snd_wl1;
tcp_seq snd_wl2;
tcp_seq iss;
tcp_seq irs;
tcp_seq rcv_nxt;
tcp_seq rcv_adv;
u_int32_t rcv_wnd;
tcp_seq rcv_up;
u_int32_t snd_wnd;
u_int32_t snd_cwnd;
u_int32_t snd_ssthresh;
u_int t_maxopd;
u_int32_t t_rcvtime;
u_int32_t t_starttime;
int t_rtttime;
tcp_seq t_rtseq;
int t_rxtcur;
u_int t_maxseg;
int t_srtt;
int t_rttvar;
int t_rxtshift;
u_int t_rttmin;
u_int32_t t_rttupdated;
u_int32_t max_sndwnd;
int t_softerror;
char t_oobflags;
char t_iobc;
u_char snd_scale;
u_char rcv_scale;
u_char request_r_scale;
u_char requested_s_scale;
u_int32_t ts_recent;
u_int32_t ts_recent_age;
tcp_seq last_ack_sent;
tcp_cc cc_send;
tcp_cc cc_recv;
tcp_seq snd_recover;
u_int32_t snd_cwnd_prev;
u_int32_t snd_ssthresh_prev;
u_int32_t t_badrxtwin;
};
struct tcpstat {
u_int32_t tcps_connattempt;
u_int32_t tcps_accepts;
u_int32_t tcps_connects;
u_int32_t tcps_drops;
u_int32_t tcps_conndrops;
u_int32_t tcps_closed;
u_int32_t tcps_segstimed;
u_int32_t tcps_rttupdated;
u_int32_t tcps_delack;
u_int32_t tcps_timeoutdrop;
u_int32_t tcps_rexmttimeo;
u_int32_t tcps_persisttimeo;
u_int32_t tcps_keeptimeo;
u_int32_t tcps_keepprobe;
u_int32_t tcps_keepdrops;
u_int32_t tcps_sndtotal;
u_int32_t tcps_sndpack;
u_int32_t tcps_sndbyte;
u_int32_t tcps_sndrexmitpack;
u_int32_t tcps_sndrexmitbyte;
u_int32_t tcps_sndacks;
u_int32_t tcps_sndprobe;
u_int32_t tcps_sndurg;
u_int32_t tcps_sndwinup;
u_int32_t tcps_sndctrl;
u_int32_t tcps_rcvtotal;
u_int32_t tcps_rcvpack;
u_int32_t tcps_rcvbyte;
u_int32_t tcps_rcvbadsum;
u_int32_t tcps_rcvbadoff;
u_int32_t tcps_rcvmemdrop;
u_int32_t tcps_rcvshort;
u_int32_t tcps_rcvduppack;
u_int32_t tcps_rcvdupbyte;
u_int32_t tcps_rcvpartduppack;
u_int32_t tcps_rcvpartdupbyte;
u_int32_t tcps_rcvoopack;
u_int32_t tcps_rcvoobyte;
u_int32_t tcps_rcvpackafterwin;
u_int32_t tcps_rcvbyteafterwin;
u_int32_t tcps_rcvafterclose;
u_int32_t tcps_rcvwinprobe;
u_int32_t tcps_rcvdupack;
u_int32_t tcps_rcvacktoomuch;
u_int32_t tcps_rcvackpack;
u_int32_t tcps_rcvackbyte;
u_int32_t tcps_rcvwinupd;
u_int32_t tcps_pawsdrop;
u_int32_t tcps_predack;
u_int32_t tcps_preddat;
u_int32_t tcps_pcbcachemiss;
u_int32_t tcps_cachedrtt;
u_int32_t tcps_cachedrttvar;
u_int32_t tcps_cachedssthresh;
u_int32_t tcps_usedrtt;
u_int32_t tcps_usedrttvar;
u_int32_t tcps_usedssthresh;
u_int32_t tcps_persistdrop;
u_int32_t tcps_badsyn;
u_int32_t tcps_mturesent;
u_int32_t tcps_listendrop;
u_int32_t tcps_minmssdrops;
u_int32_t tcps_sndrexmitbad;
u_int32_t tcps_badrst;
u_int32_t tcps_sc_added;
u_int32_t tcps_sc_retransmitted;
u_int32_t tcps_sc_dupsyn;
u_int32_t tcps_sc_dropped;
u_int32_t tcps_sc_completed;
u_int32_t tcps_sc_bucketoverflow;
u_int32_t tcps_sc_cacheoverflow;
u_int32_t tcps_sc_reset;
u_int32_t tcps_sc_stale;
u_int32_t tcps_sc_aborted;
u_int32_t tcps_sc_badack;
u_int32_t tcps_sc_unreach;
u_int32_t tcps_sc_zonefail;
u_int32_t tcps_sc_sendcookie;
u_int32_t tcps_sc_recvcookie;
u_int32_t tcps_hc_added;
u_int32_t tcps_hc_bucketoverflow;
u_int32_t tcps_sack_recovery_episode;
u_int32_t tcps_sack_rexmits;
u_int32_t tcps_sack_rexmit_bytes;
u_int32_t tcps_sack_rcv_blocks;
u_int32_t tcps_sack_send_blocks;
u_int32_t tcps_sack_sboverflow;
u_int32_t tcps_bg_rcvtotal;
u_int32_t tcps_rxtfindrop;
u_int32_t tcps_fcholdpacket;
u_int32_t tcps_coalesced_pack;
u_int32_t tcps_flowtbl_full;
u_int32_t tcps_flowtbl_collision;
u_int32_t tcps_lro_twopack;
u_int32_t tcps_lro_multpack;
u_int32_t tcps_lro_largepack;
u_int32_t tcps_limited_txt;
u_int32_t tcps_early_rexmt;
u_int32_t tcps_sack_ackadv;
u_int32_t tcps_rcv_swcsum;
u_int32_t tcps_rcv_swcsum_bytes;
u_int32_t tcps_rcv6_swcsum;
u_int32_t tcps_rcv6_swcsum_bytes;
u_int32_t tcps_snd_swcsum;
u_int32_t tcps_snd_swcsum_bytes;
u_int32_t tcps_snd6_swcsum;
u_int32_t tcps_snd6_swcsum_bytes;
u_int32_t tcps_msg_unopkts;
u_int32_t tcps_msg_unoappendfail;
u_int32_t tcps_msg_sndwaithipri;
u_int32_t tcps_invalid_mpcap;
u_int32_t tcps_invalid_joins;
u_int32_t tcps_mpcap_fallback;
u_int32_t tcps_join_fallback;
u_int32_t tcps_estab_fallback;
u_int32_t tcps_invalid_opt;
u_int32_t tcps_mp_outofwin;
u_int32_t tcps_mp_reducedwin;
u_int32_t tcps_mp_badcsum;
u_int32_t tcps_mp_oodata;
u_int32_t tcps_mp_switches;
u_int32_t tcps_mp_rcvtotal;
u_int32_t tcps_mp_rcvbytes;
u_int32_t tcps_mp_sndpacks;
u_int32_t tcps_mp_sndbytes;
u_int32_t tcps_join_rxmts;
u_int32_t tcps_tailloss_rto;
u_int32_t tcps_reordered_pkts;
u_int32_t tcps_recovered_pkts;
u_int32_t tcps_pto;
u_int32_t tcps_rto_after_pto;
u_int32_t tcps_tlp_recovery;
u_int32_t tcps_tlp_recoverlastpkt;
u_int32_t tcps_ecn_client_success;
u_int32_t tcps_ecn_recv_ece;
u_int32_t tcps_ecn_sent_ece;
u_int32_t tcps_detect_reordering;
u_int32_t tcps_delay_recovery;
u_int32_t tcps_avoid_rxmt;
u_int32_t tcps_unnecessary_rxmt;
u_int32_t tcps_nostretchack;
u_int32_t tcps_rescue_rxmt;
u_int32_t tcps_pto_in_recovery;
u_int32_t tcps_pmtudbh_reverted;
u_int32_t tcps_dsack_disable;
u_int32_t tcps_dsack_ackloss;
u_int32_t tcps_dsack_badrexmt;
u_int32_t tcps_dsack_sent;
u_int32_t tcps_dsack_recvd;
u_int32_t tcps_dsack_recvd_old;
u_int32_t tcps_mp_sel_symtomsd;
u_int32_t tcps_mp_sel_rtt;
u_int32_t tcps_mp_sel_rto;
u_int32_t tcps_mp_sel_peer;
u_int32_t tcps_mp_num_probes;
u_int32_t tcps_mp_verdowngrade;
u_int32_t tcps_drop_after_sleep;
u_int32_t tcps_probe_if;
u_int32_t tcps_probe_if_conflict;
u_int32_t tcps_ecn_client_setup;
u_int32_t tcps_ecn_server_setup;
u_int32_t tcps_ecn_server_success;
u_int32_t tcps_ecn_lost_synack;
u_int32_t tcps_ecn_lost_syn;
u_int32_t tcps_ecn_not_supported;
u_int32_t tcps_ecn_recv_ce;
u_int32_t tcps_ecn_conn_recv_ce;
u_int32_t tcps_ecn_conn_recv_ece;
u_int32_t tcps_ecn_conn_plnoce;
u_int32_t tcps_ecn_conn_pl_ce;
u_int32_t tcps_ecn_conn_nopl_ce;
u_int32_t tcps_ecn_fallback_synloss;
u_int32_t tcps_ecn_fallback_reorder;
u_int32_t tcps_ecn_fallback_ce;
u_int32_t tcps_tfo_syn_data_rcv;
u_int32_t tcps_tfo_cookie_req_rcv;
u_int32_t tcps_tfo_cookie_sent;
u_int32_t tcps_tfo_cookie_invalid;
u_int32_t tcps_tfo_cookie_req;
u_int32_t tcps_tfo_cookie_rcv;
u_int32_t tcps_tfo_syn_data_sent;
u_int32_t tcps_tfo_syn_data_acked;
u_int32_t tcps_tfo_syn_loss;
u_int32_t tcps_tfo_blackhole;
u_int32_t tcps_tfo_cookie_wrong;
u_int32_t tcps_tfo_no_cookie_rcv;
u_int32_t tcps_tfo_heuristics_disable;
u_int32_t tcps_tfo_sndblackhole;
u_int32_t tcps_mss_to_default;
u_int32_t tcps_mss_to_medium;
u_int32_t tcps_mss_to_low;
u_int32_t tcps_ecn_fallback_droprst;
u_int32_t tcps_ecn_fallback_droprxmt;
u_int32_t tcps_ecn_fallback_synrst;
u_int32_t tcps_mptcp_rcvmemdrop;
u_int32_t tcps_mptcp_rcvduppack;
u_int32_t tcps_mptcp_rcvpackafterwin;
u_int32_t tcps_timer_drift_le_1_ms;
u_int32_t tcps_timer_drift_le_10_ms;
u_int32_t tcps_timer_drift_le_20_ms;
u_int32_t tcps_timer_drift_le_50_ms;
u_int32_t tcps_timer_drift_le_100_ms;
u_int32_t tcps_timer_drift_le_200_ms;
u_int32_t tcps_timer_drift_le_500_ms;
u_int32_t tcps_timer_drift_le_1000_ms;
u_int32_t tcps_timer_drift_gt_1000_ms;
u_int32_t tcps_mptcp_handover_attempt;
u_int32_t tcps_mptcp_interactive_attempt;
u_int32_t tcps_mptcp_aggregate_attempt;
u_int32_t tcps_mptcp_fp_handover_attempt;
u_int32_t tcps_mptcp_fp_interactive_attempt;
u_int32_t tcps_mptcp_fp_aggregate_attempt;
u_int32_t tcps_mptcp_heuristic_fallback;
u_int32_t tcps_mptcp_fp_heuristic_fallback;
u_int32_t tcps_mptcp_handover_success_wifi;
u_int32_t tcps_mptcp_handover_success_cell;
u_int32_t tcps_mptcp_interactive_success;
u_int32_t tcps_mptcp_aggregate_success;
u_int32_t tcps_mptcp_fp_handover_success_wifi;
u_int32_t tcps_mptcp_fp_handover_success_cell;
u_int32_t tcps_mptcp_fp_interactive_success;
u_int32_t tcps_mptcp_fp_aggregate_success;
u_int32_t tcps_mptcp_handover_cell_from_wifi;
u_int32_t tcps_mptcp_handover_wifi_from_cell;
u_int32_t tcps_mptcp_interactive_cell_from_wifi;
u_int64_t tcps_mptcp_handover_cell_bytes;
u_int64_t tcps_mptcp_interactive_cell_bytes;
u_int64_t tcps_mptcp_aggregate_cell_bytes;
u_int64_t tcps_mptcp_handover_all_bytes;
u_int64_t tcps_mptcp_interactive_all_bytes;
u_int64_t tcps_mptcp_aggregate_all_bytes;
u_int32_t tcps_mptcp_back_to_wifi;
u_int32_t tcps_mptcp_wifi_proxy;
u_int32_t tcps_mptcp_cell_proxy;
};
struct tcpstat_local {
u_int64_t badformat;
u_int64_t unspecv6;
u_int64_t synfin;
u_int64_t badformatipsec;
u_int64_t noconnnolist;
u_int64_t noconnlist;
u_int64_t listbadsyn;
u_int64_t icmp6unreach;
u_int64_t deprecate6;
u_int64_t ooopacket;
u_int64_t rstinsynrcv;
u_int64_t dospacket;
u_int64_t cleanup;
u_int64_t synwindow;
};
struct xtcpcb {
u_int32_t xt_len;
struct inpcb xt_inp;
struct tcpcb xt_tp;
struct xsocket xt_socket;
u_quad_t xt_alignment_hack;
};
struct xtcpcb64 {
u_int32_t xt_len;
struct xinpcb64 xt_inpcb;
u_int64_t t_segq;
int t_dupacks;
int t_timer[4];
int t_state;
u_int t_flags;
int t_force;
tcp_seq snd_una;
tcp_seq snd_max;
tcp_seq snd_nxt;
tcp_seq snd_up;
tcp_seq snd_wl1;
tcp_seq snd_wl2;
tcp_seq iss;
tcp_seq irs;
tcp_seq rcv_nxt;
tcp_seq rcv_adv;
u_int32_t rcv_wnd;
tcp_seq rcv_up;
u_int32_t snd_wnd;
u_int32_t snd_cwnd;
u_int32_t snd_ssthresh;
u_int t_maxopd;
u_int32_t t_rcvtime;
u_int32_t t_starttime;
int t_rtttime;
tcp_seq t_rtseq;
int t_rxtcur;
u_int t_maxseg;
int t_srtt;
int t_rttvar;
int t_rxtshift;
u_int t_rttmin;
u_int32_t t_rttupdated;
u_int32_t max_sndwnd;
int t_softerror;
char t_oobflags;
char t_iobc;
u_char snd_scale;
u_char rcv_scale;
u_char request_r_scale;
u_char requested_s_scale;
u_int32_t ts_recent;
u_int32_t ts_recent_age;
tcp_seq last_ack_sent;
tcp_cc cc_send;
tcp_cc cc_recv;
tcp_seq snd_recover;
u_int32_t snd_cwnd_prev;
u_int32_t snd_ssthresh_prev;
u_int32_t t_badrxtwin;
u_quad_t xt_alignment_hack;
};
struct ether_arp {
struct arphdr ea_hdr;
u_char arp_sha[6];
u_char arp_spa[4];
u_char arp_tha[6];
u_char arp_tpa[4];
};
struct sockaddr_inarp {
u_char sin_len;
u_char sin_family;
u_short sin_port;
struct in_addr sin_addr;
struct in_addr sin_srcaddr;
u_short sin_tos;
u_short sin_other;
};
struct sockaddr;
struct sockaddr_dl;
struct sockaddr_in;
extern errno_t inet_arp_lookup(ifnet_t interface,
const struct sockaddr_in *ip_dest, struct sockaddr_dl *ll_dest,
size_t ll_dest_len, route_t hint, mbuf_t packet);
extern errno_t inet_arp_handle_input(ifnet_t ifp, u_int16_t arpop,
const struct sockaddr_dl *sender_hw, const struct sockaddr_in *sender_ip,
const struct sockaddr_in *target_ip);
extern void inet_arp_init_ifaddr(ifnet_t interface, ifaddr_t ipaddr);
struct sockaddr_sys {
u_char ss_len;
u_char ss_family;
u_int16_t ss_sysaddr;
u_int32_t ss_reserved[7];
};
struct kern_event_msg {
u_int32_t total_size;
u_int32_t vendor_code;
u_int32_t kev_class;
u_int32_t kev_subclass;
u_int32_t id;
u_int32_t event_code;
u_int32_t event_data[1];
};
struct kev_request {
u_int32_t vendor_code;
u_int32_t kev_class;
u_int32_t kev_subclass;
};
struct kev_vendor_code {
u_int32_t vendor_code;
char vendor_string[200];
};
struct kev_d_vectors {
u_int32_t data_length;
void *data_ptr;
};
struct kev_msg {
u_int32_t vendor_code;
u_int32_t kev_class;
u_int32_t kev_subclass;
u_int32_t event_code;
struct kev_d_vectors dv[5];
};
errno_t kev_vendor_code_find(const char *vendor_string, u_int32_t *vendor_code);
errno_t kev_msg_post(struct kev_msg *event_msg);
struct in_aliasreq {
char ifra_name[16];
struct sockaddr_in ifra_addr;
struct sockaddr_in ifra_broadaddr;
struct sockaddr_in ifra_mask;
};
struct kev_in_data {
struct net_event_data link_data;
struct in_addr ia_addr;
u_int32_t ia_net;
u_int32_t ia_netmask;
u_int32_t ia_subnet;
u_int32_t ia_subnetmask;
struct in_addr ia_netbroadcast;
struct in_addr ia_dstaddr;
};
struct kev_in_collision {
struct net_event_data link_data;
struct in_addr ia_ipaddr;
u_char hw_len;
u_char hw_addr[0];
};
struct kev_in_arpfailure {
struct net_event_data link_data;
};
struct kev_in_arpalive {
struct net_event_data link_data;
};
struct kev_in_portinuse {
u_int16_t port;
u_int32_t req_pid;
u_int32_t reserved[2];
};
struct in6_addrlifetime {
time_t ia6t_expire;
time_t ia6t_preferred;
u_int32_t ia6t_vltime;
u_int32_t ia6t_pltime;
};
struct in6_addrpolicy {
struct sockaddr_in6 addr;
struct sockaddr_in6 addrmask;
int preced;
int label;
u_quad_t use;
};
struct in6_ifstat {
u_quad_t ifs6_in_receive;
u_quad_t ifs6_in_hdrerr;
u_quad_t ifs6_in_toobig;
u_quad_t ifs6_in_noroute;
u_quad_t ifs6_in_addrerr;
u_quad_t ifs6_in_protounknown;
u_quad_t ifs6_in_truncated;
u_quad_t ifs6_in_discard;
u_quad_t ifs6_in_deliver;
u_quad_t ifs6_out_forward;
u_quad_t ifs6_out_request;
u_quad_t ifs6_out_discard;
u_quad_t ifs6_out_fragok;
u_quad_t ifs6_out_fragfail;
u_quad_t ifs6_out_fragcreat;
u_quad_t ifs6_reass_reqd;
u_quad_t ifs6_reass_ok;
u_quad_t ifs6_atmfrag_rcvd;
u_quad_t ifs6_reass_fail;
u_quad_t ifs6_in_mcast;
u_quad_t ifs6_out_mcast;
u_quad_t ifs6_cantfoward_icmp6;
u_quad_t ifs6_addr_expiry_cnt;
u_quad_t ifs6_pfx_expiry_cnt;
u_quad_t ifs6_defrtr_expiry_cnt;
};
struct icmp6_ifstat {
u_quad_t ifs6_in_msg;
u_quad_t ifs6_in_error;
u_quad_t ifs6_in_dstunreach;
u_quad_t ifs6_in_adminprohib;
u_quad_t ifs6_in_timeexceed;
u_quad_t ifs6_in_paramprob;
u_quad_t ifs6_in_pkttoobig;
u_quad_t ifs6_in_echo;
u_quad_t ifs6_in_echoreply;
u_quad_t ifs6_in_routersolicit;
u_quad_t ifs6_in_routeradvert;
u_quad_t ifs6_in_neighborsolicit;
u_quad_t ifs6_in_neighboradvert;
u_quad_t ifs6_in_redirect;
u_quad_t ifs6_in_mldquery;
u_quad_t ifs6_in_mldreport;
u_quad_t ifs6_in_mlddone;
u_quad_t ifs6_out_msg;
u_quad_t ifs6_out_error;
u_quad_t ifs6_out_dstunreach;
u_quad_t ifs6_out_adminprohib;
u_quad_t ifs6_out_timeexceed;
u_quad_t ifs6_out_paramprob;
u_quad_t ifs6_out_pkttoobig;
u_quad_t ifs6_out_echo;
u_quad_t ifs6_out_echoreply;
u_quad_t ifs6_out_routersolicit;
u_quad_t ifs6_out_routeradvert;
u_quad_t ifs6_out_neighborsolicit;
u_quad_t ifs6_out_neighboradvert;
u_quad_t ifs6_out_redirect;
u_quad_t ifs6_out_mldquery;
u_quad_t ifs6_out_mldreport;
u_quad_t ifs6_out_mlddone;
};
struct in6_ifreq {
char ifr_name[16];
union {
struct sockaddr_in6 ifru_addr;
struct sockaddr_in6 ifru_dstaddr;
int ifru_flags;
int ifru_flags6;
int ifru_metric;
int ifru_intval;
caddr_t ifru_data;
struct in6_addrlifetime ifru_lifetime;
struct in6_ifstat ifru_stat;
struct icmp6_ifstat ifru_icmp6stat;
u_int32_t ifru_scope_id[16];
} ifr_ifru;
};
struct in6_aliasreq {
char ifra_name[16];
struct sockaddr_in6 ifra_addr;
struct sockaddr_in6 ifra_broadaddr;
struct sockaddr_in6 ifra_prefixmask;
int ifra_flags;
struct in6_addrlifetime ifra_lifetime;
};
struct in6_prflags {
struct prf_ra {
u_char onlink : 1;
u_char autonomous : 1;
u_char reserved : 6;
} prf_ra;
u_char prf_reserved1;
u_short prf_reserved2;
struct prf_rr {
u_char decrvalid : 1;
u_char decrprefd : 1;
u_char reserved : 6;
} prf_rr;
u_char prf_reserved3;
u_short prf_reserved4;
};
struct in6_prefixreq {
char ipr_name[16];
u_char ipr_origin;
u_char ipr_plen;
u_int32_t ipr_vltime;
u_int32_t ipr_pltime;
struct in6_prflags ipr_flags;
struct sockaddr_in6 ipr_prefix;
};
struct in6_rrenumreq {
char irr_name[16];
u_char irr_origin;
u_char irr_m_len;
u_char irr_m_minlen;
u_char irr_m_maxlen;
u_char irr_u_uselen;
u_char irr_u_keeplen;
struct irr_raflagmask {
u_char onlink : 1;
u_char autonomous : 1;
u_char reserved : 6;
} irr_raflagmask;
u_int32_t irr_vltime;
u_int32_t irr_pltime;
struct in6_prflags irr_flags;
struct sockaddr_in6 irr_matchprefix;
struct sockaddr_in6 irr_useprefix;
};
struct kev_in6_addrlifetime {
u_int32_t ia6t_expire;
u_int32_t ia6t_preferred;
u_int32_t ia6t_vltime;
u_int32_t ia6t_pltime;
};
struct kev_in6_data {
struct net_event_data link_data;
struct sockaddr_in6 ia_addr;
struct sockaddr_in6 ia_net;
struct sockaddr_in6 ia_dstaddr;
struct sockaddr_in6 ia_prefixmask;
u_int32_t ia_plen;
u_int32_t ia6_flags;
struct kev_in6_addrlifetime ia_lifetime;
uint8_t ia_mac[6];
};
struct ipf_pktopts {
u_int32_t ippo_flags;
ifnet_t ippo_mcast_ifnet;
int ippo_mcast_loop;
u_int8_t ippo_mcast_ttl;
};
typedef struct ipf_pktopts *ipf_pktopts_t;
typedef errno_t (*ipf_input_func)(void *cookie, mbuf_t *data, int offset,
u_int8_t protocol);
typedef errno_t (*ipf_output_func)(void *cookie, mbuf_t *data,
ipf_pktopts_t options);
typedef void (*ipf_detach_func)(void *cookie);
struct ipf_filter {
void *cookie;
const char *name;
ipf_input_func ipf_input;
ipf_output_func ipf_output;
ipf_detach_func ipf_detach;
};
struct opaque_ipfilter;
typedef struct opaque_ipfilter *ipfilter_t;
extern errno_t ipf_addv4(const struct ipf_filter *filter,
ipfilter_t *filter_ref);
extern errno_t ipf_addv6(const struct ipf_filter *filter,
ipfilter_t *filter_ref);
extern errno_t ipf_remove(ipfilter_t filter_ref);
extern errno_t ipf_inject_input(mbuf_t data, ipfilter_t filter_ref);
extern errno_t ipf_inject_output(mbuf_t data, ipfilter_t filter_ref,
ipf_pktopts_t options);
int sysctlbyname(const char *, void *, size_t *, void *, size_t);
struct vmspace {
int32_t dummy;
caddr_t dummy2;
int32_t dummy3[5];
caddr_t dummy4[3];
};
struct proc *current_proc(void);
struct ctlname {
char *ctl_name;
int ctl_type;
};
struct sysctl_req {
struct proc *p;
int lock;
user_addr_t oldptr;
size_t oldlen;
size_t oldidx;
int (*oldfunc)(struct sysctl_req *, const void *, size_t);
user_addr_t newptr;
size_t newlen;
size_t newidx;
int (*newfunc)(struct sysctl_req *, void *, size_t);
};
struct sysctl_oid_list { struct sysctl_oid *slh_first; } ;
struct sysctl_oid {
struct sysctl_oid_list *oid_parent;
struct { struct sysctl_oid *sle_next; } oid_link;
int oid_number;
int oid_kind;
void *oid_arg1;
int oid_arg2;
const char *oid_name;
int (*oid_handler) (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
const char *oid_fmt;
const char *oid_descr;
int oid_version;
int oid_refcnt;
};
typedef int (* sysctl_handler_t) (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_int (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_long (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_quad (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_int2quad (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_string (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_handle_opaque (struct sysctl_oid *oidp, void *arg1, int arg2, struct sysctl_req *req);
int sysctl_io_number(struct sysctl_req *req, long long bigValue, size_t valueSize, void *pValue, int *changed);
int sysctl_io_string(struct sysctl_req *req, char *pValue, size_t valueSize, int trunc, int *changed);
int sysctl_io_opaque(struct sysctl_req *req, void *pValue, size_t valueSize, int *changed);
void sysctl_register_oid(struct sysctl_oid *oidp);
void sysctl_unregister_oid(struct sysctl_oid *oidp);
void sysctl_register_fixed(void) ;
extern struct sysctl_oid_list sysctl__children;
extern struct sysctl_oid_list sysctl__kern_children;
extern struct sysctl_oid_list sysctl__sysctl_children;
extern struct sysctl_oid_list sysctl__vm_children;
extern struct sysctl_oid_list sysctl__vfs_children;
extern struct sysctl_oid_list sysctl__net_children;
extern struct sysctl_oid_list sysctl__debug_children;
extern struct sysctl_oid_list sysctl__hw_children;
extern struct sysctl_oid_list sysctl__machdep_children;
extern struct sysctl_oid_list sysctl__user_children;
struct udpiphdr {
struct ipovly ui_i;
struct udphdr ui_u;
};
struct udpstat {
u_int32_t udps_ipackets;
u_int32_t udps_hdrops;
u_int32_t udps_badsum;
u_int32_t udps_badlen;
u_int32_t udps_noport;
u_int32_t udps_noportbcast;
u_int32_t udps_fullsock;
u_int32_t udpps_pcbcachemiss;
u_int32_t udpps_pcbhashmiss;
u_int32_t udps_opackets;
u_int32_t udps_fastout;
u_int32_t udps_nosum;
u_int32_t udps_noportmcast;
u_int32_t udps_filtermcast;
u_int32_t udps_rcv_swcsum;
u_int32_t udps_rcv_swcsum_bytes;
u_int32_t udps_rcv6_swcsum;
u_int32_t udps_rcv6_swcsum_bytes;
u_int32_t udps_snd_swcsum;
u_int32_t udps_snd_swcsum_bytes;
u_int32_t udps_snd6_swcsum;
u_int32_t udps_snd6_swcsum_bytes;
};
struct ip6_hdr {
union {
struct ip6_hdrctl {
u_int32_t ip6_un1_flow;
u_int16_t ip6_un1_plen;
u_int8_t ip6_un1_nxt;
u_int8_t ip6_un1_hlim;
} ip6_un1;
u_int8_t ip6_un2_vfc;
} ip6_ctlun;
struct in6_addr ip6_src;
struct in6_addr ip6_dst;
} ;
struct ip6_ext {
u_int8_t ip6e_nxt;
u_int8_t ip6e_len;
} ;
struct ip6_hbh {
u_int8_t ip6h_nxt;
u_int8_t ip6h_len;
} ;
struct ip6_dest {
u_int8_t ip6d_nxt;
u_int8_t ip6d_len;
} ;
struct ip6_opt {
u_int8_t ip6o_type;
u_int8_t ip6o_len;
} ;
struct ip6_opt_jumbo {
u_int8_t ip6oj_type;
u_int8_t ip6oj_len;
u_int8_t ip6oj_jumbo_len[4];
} ;
struct ip6_opt_nsap {
u_int8_t ip6on_type;
u_int8_t ip6on_len;
u_int8_t ip6on_src_nsap_len;
u_int8_t ip6on_dst_nsap_len;
};
struct ip6_opt_tunnel {
u_int8_t ip6ot_type;
u_int8_t ip6ot_len;
u_int8_t ip6ot_encap_limit;
};
struct ip6_opt_router {
u_int8_t ip6or_type;
u_int8_t ip6or_len;
u_int8_t ip6or_value[2];
};
struct ip6_rthdr {
u_int8_t ip6r_nxt;
u_int8_t ip6r_len;
u_int8_t ip6r_type;
u_int8_t ip6r_segleft;
} ;
struct ip6_rthdr0 {
u_int8_t ip6r0_nxt;
u_int8_t ip6r0_len;
u_int8_t ip6r0_type;
u_int8_t ip6r0_segleft;
u_int8_t ip6r0_reserved;
u_int8_t ip6r0_slmap[3];
struct in6_addr ip6r0_addr[1];
} ;
struct ip6_frag {
u_int8_t ip6f_nxt;
u_int8_t ip6f_reserved;
u_int16_t ip6f_offlg;
u_int32_t ip6f_ident;
} ;
struct icmp6_hdr {
u_int8_t icmp6_type;
u_int8_t icmp6_code;
u_int16_t icmp6_cksum;
union {
u_int32_t icmp6_un_data32[1];
u_int16_t icmp6_un_data16[2];
u_int8_t icmp6_un_data8[4];
} icmp6_dataun;
} ;
struct mld_hdr {
struct icmp6_hdr mld_icmp6_hdr;
struct in6_addr mld_addr;
} ;
struct nd_router_solicit {
struct icmp6_hdr nd_rs_hdr;
};
struct nd_router_advert {
struct icmp6_hdr nd_ra_hdr;
u_int32_t nd_ra_reachable;
u_int32_t nd_ra_retransmit;
} ;
struct nd_neighbor_solicit {
struct icmp6_hdr nd_ns_hdr;
struct in6_addr nd_ns_target;
};
struct nd_neighbor_advert {
struct icmp6_hdr nd_na_hdr;
struct in6_addr nd_na_target;
};
struct nd_redirect {
struct icmp6_hdr nd_rd_hdr;
struct in6_addr nd_rd_target;
struct in6_addr nd_rd_dst;
};
struct nd_opt_hdr {
u_int8_t nd_opt_type;
u_int8_t nd_opt_len;
};
struct nd_opt_prefix_info {
u_int8_t nd_opt_pi_type;
u_int8_t nd_opt_pi_len;
u_int8_t nd_opt_pi_prefix_len;
u_int8_t nd_opt_pi_flags_reserved;
u_int32_t nd_opt_pi_valid_time;
u_int32_t nd_opt_pi_preferred_time;
u_int32_t nd_opt_pi_reserved2;
struct in6_addr nd_opt_pi_prefix;
};
struct nd_opt_nonce {
u_int8_t nd_opt_nonce_type;
u_int8_t nd_opt_nonce_len;
u_int8_t nd_opt_nonce[((1 * 8) - 2)];
} ;
struct nd_opt_rd_hdr {
u_int8_t nd_opt_rh_type;
u_int8_t nd_opt_rh_len;
u_int16_t nd_opt_rh_reserved1;
u_int32_t nd_opt_rh_reserved2;
} ;
struct nd_opt_mtu {
u_int8_t nd_opt_mtu_type;
u_int8_t nd_opt_mtu_len;
u_int16_t nd_opt_mtu_reserved;
u_int32_t nd_opt_mtu_mtu;
};
struct nd_opt_route_info {
u_int8_t nd_opt_rti_type;
u_int8_t nd_opt_rti_len;
u_int8_t nd_opt_rti_prefixlen;
u_int8_t nd_opt_rti_flags;
u_int32_t nd_opt_rti_lifetime;
};
struct nd_opt_rdnss {
u_int8_t nd_opt_rdnss_type;
u_int8_t nd_opt_rdnss_len;
u_int16_t nd_opt_rdnss_reserved;
u_int32_t nd_opt_rdnss_lifetime;
struct in6_addr nd_opt_rdnss_addr[1];
} ;
struct nd_opt_dnssl {
u_int8_t nd_opt_dnssl_type;
u_int8_t nd_opt_dnssl_len;
u_int16_t nd_opt_dnssl_reserved;
u_int32_t nd_opt_dnssl_lifetime;
u_int8_t nd_opt_dnssl_domains[8];
} ;
struct icmp6_namelookup {
struct icmp6_hdr icmp6_nl_hdr;
u_int8_t icmp6_nl_nonce[8];
int32_t icmp6_nl_ttl;
};
struct icmp6_nodeinfo {
struct icmp6_hdr icmp6_ni_hdr;
u_int8_t icmp6_ni_nonce[8];
};
struct ni_reply_fqdn {
u_int32_t ni_fqdn_ttl;
u_int8_t ni_fqdn_namelen;
u_int8_t ni_fqdn_name[3];
};
struct icmp6_router_renum {
struct icmp6_hdr rr_hdr;
u_int8_t rr_segnum;
u_int8_t rr_flags;
u_int16_t rr_maxdelay;
u_int32_t rr_reserved;
} ;
struct rr_pco_match {
u_int8_t rpm_code;
u_int8_t rpm_len;
u_int8_t rpm_ordinal;
u_int8_t rpm_matchlen;
u_int8_t rpm_minlen;
u_int8_t rpm_maxlen;
u_int16_t rpm_reserved;
struct in6_addr rpm_prefix;
} ;
struct rr_pco_use {
u_int8_t rpu_uselen;
u_int8_t rpu_keeplen;
u_int8_t rpu_ramask;
u_int8_t rpu_raflags;
u_int32_t rpu_vltime;
u_int32_t rpu_pltime;
u_int32_t rpu_flags;
struct in6_addr rpu_prefix;
} ;
struct rr_result {
u_int16_t rrr_flags;
u_int8_t rrr_ordinal;
u_int8_t rrr_matchedlen;
u_int32_t rrr_ifid;
struct in6_addr rrr_prefix;
} ;
struct icmp6_filter {
u_int32_t icmp6_filt[8];
};
struct icmp6errstat {
u_quad_t icp6errs_dst_unreach_noroute;
u_quad_t icp6errs_dst_unreach_admin;
u_quad_t icp6errs_dst_unreach_beyondscope;
u_quad_t icp6errs_dst_unreach_addr;
u_quad_t icp6errs_dst_unreach_noport;
u_quad_t icp6errs_packet_too_big;
u_quad_t icp6errs_time_exceed_transit;
u_quad_t icp6errs_time_exceed_reassembly;
u_quad_t icp6errs_paramprob_header;
u_quad_t icp6errs_paramprob_nextheader;
u_quad_t icp6errs_paramprob_option;
u_quad_t icp6errs_redirect;
u_quad_t icp6errs_unknown;
};
struct icmp6stat {
u_quad_t icp6s_error;
u_quad_t icp6s_canterror;
u_quad_t icp6s_toofreq;
u_quad_t icp6s_outhist[256];
u_quad_t icp6s_badcode;
u_quad_t icp6s_tooshort;
u_quad_t icp6s_checksum;
u_quad_t icp6s_badlen;
u_quad_t icp6s_reflect;
u_quad_t icp6s_inhist[256];
u_quad_t icp6s_nd_toomanyopt;
struct icmp6errstat icp6s_outerrhist;
u_quad_t icp6s_pmtuchg;
u_quad_t icp6s_nd_badopt;
u_quad_t icp6s_badns;
u_quad_t icp6s_badna;
u_quad_t icp6s_badrs;
u_quad_t icp6s_badra;
u_quad_t icp6s_badredirect;
u_quad_t icp6s_rfc6980_drop;
};
typedef __uint16_t n_short;
typedef __uint32_t n_long;
typedef __uint32_t n_time;
struct ip {
u_int ip_hl:4,
ip_v:4;
u_char ip_tos;
u_short ip_len;
u_short ip_id;
u_short ip_off;
u_char ip_ttl;
u_char ip_p;
u_short ip_sum;
struct in_addr ip_src,ip_dst;
};
struct ip_timestamp {
u_char ipt_code;
u_char ipt_len;
u_char ipt_ptr;
u_int ipt_flg:4,
ipt_oflw:4;
union ipt_timestamp {
n_long ipt_time[1];
struct ipt_ta {
struct in_addr ipt_addr;
n_long ipt_time;
} ipt_ta[1];
} ipt_timestamp;
};
struct igmpstat_v3 {
uint32_t igps_version;
uint32_t igps_len;
uint64_t igps_rcv_total;
uint64_t igps_rcv_tooshort;
uint64_t igps_rcv_badttl;
uint64_t igps_rcv_badsum;
uint64_t igps_rcv_v1v2_queries;
uint64_t igps_rcv_v3_queries;
uint64_t igps_rcv_badqueries;
uint64_t igps_rcv_gen_queries;
uint64_t igps_rcv_group_queries;
uint64_t igps_rcv_gsr_queries;
uint64_t igps_drop_gsr_queries;
uint64_t igps_rcv_reports;
uint64_t igps_rcv_badreports;
uint64_t igps_rcv_ourreports;
uint64_t igps_rcv_nora;
uint64_t igps_snd_reports;
uint64_t __igps_pad[4];
} ;
struct igmpstat {
u_int igps_rcv_total;
u_int igps_rcv_tooshort;
u_int igps_rcv_badsum;
u_int igps_rcv_queries;
u_int igps_rcv_badqueries;
u_int igps_rcv_reports;
u_int igps_rcv_badreports;
u_int igps_rcv_ourreports;
u_int igps_snd_reports;
};
typedef struct kcdata_item *task_crashinfo_item_t;
typedef void (*kdp_send_t)(void * pkt, unsigned int pkt_len);
typedef void (*kdp_receive_t)(void * pkt, unsigned int * pkt_len,
unsigned int timeout);
void
kdp_register_send_receive(kdp_send_t send, kdp_receive_t receive);
void
kdp_unregister_send_receive(kdp_send_t send, kdp_receive_t receive);
typedef enum {
KDP_EVENT_ENTER,
KDP_EVENT_EXIT,
KDP_EVENT_PANICLOG
} kdp_event_t;
typedef void (*kdp_callout_fn_t)(void *arg, kdp_event_t event);
extern void kdp_register_callout(kdp_callout_fn_t fn, void *arg);
typedef unsigned int WK_word;
void
WKdm_decompress_new (WK_word* src_buf,
WK_word* dest_buf,
WK_word* scratch,
unsigned int bytes);
int
WKdm_compress_new (const WK_word* src_buf,
WK_word* dest_buf,
WK_word* scratch,
unsigned int limit);
typedef struct code_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:2,
opsz :1,
granular:1;
unsigned char base24;
} code_desc_t;
typedef struct data_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:2,
stksz :1,
granular:1;
unsigned char base24;
} data_desc_t;
typedef struct ldt_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
:2,
present :1;
unsigned char limit16 :4,
:3,
granular:1;
unsigned char base24;
} ldt_desc_t;
typedef struct sel {
unsigned short rpl :2,
ti :1,
index :13;
} sel_t;
typedef struct call_gate {
unsigned short offset00;
sel_t seg;
unsigned int argcnt :5,
:3,
type :5,
dpl :2,
present :1,
offset16:16;
} call_gate_t;
typedef struct trap_gate {
unsigned short offset00;
sel_t seg;
unsigned int :8,
type :5,
dpl :2,
present :1,
offset16:16;
} trap_gate_t;
typedef struct intr_gate {
unsigned short offset00;
sel_t seg;
unsigned int :8,
type :5,
dpl :2,
present :1,
offset16:16;
} intr_gate_t;
typedef unsigned short i386_ioport_t;
static  unsigned int inl(
i386_ioport_t port)
{
unsigned int datum;
;
return(datum);
}
static  unsigned short inw(
i386_ioport_t port)
{
unsigned short datum;
;
return(datum);
}
static  unsigned char inb(
i386_ioport_t port)
{
unsigned char datum;
;
return(datum);
}
static  void outl(
i386_ioport_t port,
unsigned int datum)
{
;
}
static  void outw(
i386_ioport_t port,
unsigned short datum)
{
;
}
static  void outb(
i386_ioport_t port,
unsigned char datum)
{
;
}
typedef unsigned short io_addr_t;
typedef unsigned short io_len_t;
typedef struct _cr0 {
unsigned int pe :1,
mp :1,
em :1,
ts :1,
:1,
ne :1,
:10,
wp :1,
:1,
am :1,
:10,
nw :1,
cd :1,
pg :1;
} cr0_t;
typedef struct code_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:2,
opsz :1,
granular:1;
unsigned char base24;
} code_desc_t;
typedef struct data_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:2,
stksz :1,
granular:1;
unsigned char base24;
} data_desc_t;
typedef struct ldt_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
:2,
present :1;
unsigned char limit16 :4,
:3,
granular:1;
unsigned char base24;
} ldt_desc_t;
typedef struct call_gate {
unsigned short offset00;
sel_t seg;
unsigned int argcnt :5,
:3,
type :5,
dpl :2,
present :1,
offset16:16;
} call_gate_t;
typedef struct trap_gate {
unsigned short offset00;
sel_t seg;
unsigned int :8,
type :5,
dpl :2,
present :1,
offset16:16;
} trap_gate_t;
typedef struct intr_gate {
unsigned short offset00;
sel_t seg;
unsigned int :8,
type :5,
dpl :2,
present :1,
offset16:16;
} intr_gate_t;
typedef struct tss {
sel_t oldtss;
unsigned int :0;
unsigned int esp0;
sel_t ss0;
unsigned int :0;
unsigned int esp1;
sel_t ss1;
unsigned int :0;
unsigned int esp2;
sel_t ss2;
unsigned int :0;
unsigned int cr3;
unsigned int eip;
unsigned int eflags;
unsigned int eax;
unsigned int ecx;
unsigned int edx;
unsigned int ebx;
unsigned int esp;
unsigned int ebp;
unsigned int esi;
unsigned int edi;
sel_t es;
unsigned int :0;
sel_t cs;
unsigned int :0;
sel_t ss;
unsigned int :0;
sel_t ds;
unsigned int :0;
sel_t fs;
unsigned int :0;
sel_t gs;
unsigned int :0;
sel_t ldt;
unsigned int :0;
unsigned int t :1,
:15,
io_bmap :16;
} tss_t;
typedef struct tss_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:3,
granular:1;
unsigned char base24;
} tss_desc_t;
typedef struct task_gate {
unsigned short :16;
sel_t tss;
unsigned int :8,
type :5,
dpl :2,
present :1,
:0;
} task_gate_t;
typedef union dt_entry {
code_desc_t code;
data_desc_t data;
ldt_desc_t ldt;
tss_desc_t task_state;
call_gate_t call_gate;
trap_gate_t trap_gate;
intr_gate_t intr_gate;
task_gate_t task_gate;
} dt_entry_t;
typedef union gdt_entry {
code_desc_t code;
data_desc_t data;
ldt_desc_t ldt;
call_gate_t call_gate;
task_gate_t task_gate;
tss_desc_t task_state;
} gdt_entry_t;
typedef gdt_entry_t gdt_t;
typedef union idt_entry {
trap_gate_t trap_gate;
intr_gate_t intr_gate;
task_gate_t task_gate;
} idt_entry_t;
typedef idt_entry_t idt_t;
typedef union ldt_entry {
code_desc_t code;
data_desc_t data;
call_gate_t call_gate;
task_gate_t task_gate;
} ldt_entry_t;
typedef ldt_entry_t ldt_t;
typedef struct tss {
sel_t oldtss;
unsigned int :0;
unsigned int esp0;
sel_t ss0;
unsigned int :0;
unsigned int esp1;
sel_t ss1;
unsigned int :0;
unsigned int esp2;
sel_t ss2;
unsigned int :0;
unsigned int cr3;
unsigned int eip;
unsigned int eflags;
unsigned int eax;
unsigned int ecx;
unsigned int edx;
unsigned int ebx;
unsigned int esp;
unsigned int ebp;
unsigned int esi;
unsigned int edi;
sel_t es;
unsigned int :0;
sel_t cs;
unsigned int :0;
sel_t ss;
unsigned int :0;
sel_t ds;
unsigned int :0;
sel_t fs;
unsigned int :0;
sel_t gs;
unsigned int :0;
sel_t ldt;
unsigned int :0;
unsigned int t :1,
:15,
io_bmap :16;
} tss_t;
typedef struct tss_desc {
unsigned short limit00;
unsigned short base00;
unsigned char base16;
unsigned char type :5,
dpl :2,
present :1;
unsigned char limit16 :4,
:3,
granular:1;
unsigned char base24;
} tss_desc_t;
typedef struct task_gate {
unsigned short :16;
sel_t tss;
unsigned int :8,
type :5,
dpl :2,
present :1,
:0;
} task_gate_t;
typedef unsigned long NXSwappedFloat;
typedef unsigned long long NXSwappedDouble;
static 
unsigned short
NXSwapShort(
unsigned short inv
)
{
return (unsigned short)((__uint16_t)(__builtin_constant_p((uint16_t)inv) ? ((__uint16_t)((((__uint16_t)((uint16_t)inv) & 0xff00) >> 8) | (((__uint16_t)((uint16_t)inv) & 0x00ff) << 8))) : _OSSwapInt16((uint16_t)inv)));
}
static 
unsigned int
NXSwapInt(
unsigned int inv
)
{
return (unsigned int)(__builtin_constant_p((uint32_t)inv) ? ((__uint32_t)((((__uint32_t)((uint32_t)inv) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)inv) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)inv) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)inv) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)inv));
}
static 
unsigned long
NXSwapLong(
unsigned long inv
)
{
return (unsigned long)(__builtin_constant_p((uint32_t)inv) ? ((__uint32_t)((((__uint32_t)((uint32_t)inv) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)inv) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)inv) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)inv) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)inv));
}
static 
unsigned long long
NXSwapLongLong(
unsigned long long inv
)
{
return (unsigned long long)(__builtin_constant_p((uint64_t)inv) ? ((__uint64_t)((((__uint64_t)((uint64_t)inv) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)inv) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)inv) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)inv) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)inv) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)inv) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)inv) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)inv) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)inv));
}
static  NXSwappedFloat
NXConvertHostFloatToSwapped(float x)
{
union fconv {
float number;
NXSwappedFloat sf;
} u;
u.number = x;
return u.sf;
}
static  float
NXConvertSwappedFloatToHost(NXSwappedFloat x)
{
union fconv {
float number;
NXSwappedFloat sf;
} u;
u.sf = x;
return u.number;
}
static  NXSwappedDouble
NXConvertHostDoubleToSwapped(double x)
{
union dconv {
double number;
NXSwappedDouble sd;
} u;
u.number = x;
return u.sd;
}
static  double
NXConvertSwappedDoubleToHost(NXSwappedDouble x)
{
union dconv {
double number;
NXSwappedDouble sd;
} u;
u.sd = x;
return u.number;
}
static  NXSwappedFloat
NXSwapFloat(NXSwappedFloat x)
{
return (NXSwappedFloat)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x));
}
static  NXSwappedDouble
NXSwapDouble(NXSwappedDouble x)
{
return (NXSwappedDouble)(__builtin_constant_p((uint64_t)x) ? ((__uint64_t)((((__uint64_t)((uint64_t)x) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)x) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)x) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)x) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)x) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)x) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)x) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)x) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)x));
}
enum NXByteOrder {
NX_UnknownByteOrder,
NX_LittleEndian,
NX_BigEndian
};
static 
enum NXByteOrder
NXHostByteOrder(void)
{
return NX_LittleEndian;
}
static 
unsigned short
NXSwapBigShortToHost(
unsigned short x
)
{
return (unsigned short)((__uint16_t)(__builtin_constant_p((uint16_t)x) ? ((__uint16_t)((((__uint16_t)((uint16_t)x) & 0xff00) >> 8) | (((__uint16_t)((uint16_t)x) & 0x00ff) << 8))) : _OSSwapInt16((uint16_t)x)));
}
static 
unsigned int
NXSwapBigIntToHost(
unsigned int x
)
{
return (unsigned int)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x));
}
static 
unsigned long
NXSwapBigLongToHost(
unsigned long x
)
{
return (unsigned long)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x));
}
static 
unsigned long long
NXSwapBigLongLongToHost(
unsigned long long x
)
{
return (unsigned long long)(__builtin_constant_p((uint64_t)x) ? ((__uint64_t)((((__uint64_t)((uint64_t)x) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)x) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)x) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)x) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)x) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)x) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)x) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)x) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)x));
}
static 
double
NXSwapBigDoubleToHost(
NXSwappedDouble x
)
{
return NXConvertSwappedDoubleToHost((NXSwappedDouble)(__builtin_constant_p((uint64_t)x) ? ((__uint64_t)((((__uint64_t)((uint64_t)x) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)x) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)x) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)x) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)x) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)x) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)x) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)x) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)x)));
}
static 
float
NXSwapBigFloatToHost(
NXSwappedFloat x
)
{
return NXConvertSwappedFloatToHost((NXSwappedFloat)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x)));
}
static 
unsigned short
NXSwapHostShortToBig(
unsigned short x
)
{
return (unsigned short)((__uint16_t)(__builtin_constant_p((uint16_t)x) ? ((__uint16_t)((((__uint16_t)((uint16_t)x) & 0xff00) >> 8) | (((__uint16_t)((uint16_t)x) & 0x00ff) << 8))) : _OSSwapInt16((uint16_t)x)));
}
static 
unsigned int
NXSwapHostIntToBig(
unsigned int x
)
{
return (unsigned int)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x));
}
static 
unsigned long
NXSwapHostLongToBig(
unsigned long x
)
{
return (unsigned long)(__builtin_constant_p((uint32_t)x) ? ((__uint32_t)((((__uint32_t)((uint32_t)x) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)x) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)x) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)x) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)x));
}
static 
unsigned long long
NXSwapHostLongLongToBig(
unsigned long long x
)
{
return (unsigned long long)(__builtin_constant_p((uint64_t)x) ? ((__uint64_t)((((__uint64_t)((uint64_t)x) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)x) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)x) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)x) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)x) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)x) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)x) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)x) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)x));
}
static 
NXSwappedDouble
NXSwapHostDoubleToBig(
double x
)
{
return (NXSwappedDouble)(__builtin_constant_p((uint64_t)NXConvertHostDoubleToSwapped(x)) ? ((__uint64_t)((((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)) & 0x00000000000000ffULL) << 56))) : _OSSwapInt64((uint64_t)NXConvertHostDoubleToSwapped(x)));
}
static 
NXSwappedFloat
NXSwapHostFloatToBig(
float x
)
{
return (NXSwappedFloat)(__builtin_constant_p((uint32_t)NXConvertHostFloatToSwapped(x)) ? ((__uint32_t)((((__uint32_t)((uint32_t)NXConvertHostFloatToSwapped(x)) & 0xff000000) >> 24) | (((__uint32_t)((uint32_t)NXConvertHostFloatToSwapped(x)) & 0x00ff0000) >> 8) | (((__uint32_t)((uint32_t)NXConvertHostFloatToSwapped(x)) & 0x0000ff00) << 8) | (((__uint32_t)((uint32_t)NXConvertHostFloatToSwapped(x)) & 0x000000ff) << 24))) : _OSSwapInt32((uint32_t)NXConvertHostFloatToSwapped(x)));
}
static 
unsigned short
NXSwapLittleShortToHost(
unsigned short x
)
{
return (unsigned short)((uint16_t)((uint16_t)x));
}
static 
unsigned int
NXSwapLittleIntToHost(
unsigned int x
)
{
return (unsigned int)((uint32_t)((uint32_t)x));
}
static 
unsigned long
NXSwapLittleLongToHost(
unsigned long x
)
{
return (unsigned long)((uint32_t)((uint32_t)x));
}
static 
unsigned long long
NXSwapLittleLongLongToHost(
unsigned long long x
)
{
return (unsigned long long)((uint64_t)((uint64_t)x));
}
static 
double
NXSwapLittleDoubleToHost(
NXSwappedDouble x
)
{
return NXConvertSwappedDoubleToHost((NXSwappedDouble)((uint64_t)((uint64_t)x)));
}
static 
float
NXSwapLittleFloatToHost(
NXSwappedFloat x
)
{
return NXConvertSwappedFloatToHost((NXSwappedFloat)((uint32_t)((uint32_t)x)));
}
static 
unsigned short
NXSwapHostShortToLittle(
unsigned short x
)
{
return (unsigned short)((uint16_t)((uint16_t)x));
}
static 
unsigned int
NXSwapHostIntToLittle(
unsigned int x
)
{
return (unsigned int)((uint32_t)((uint32_t)x));
}
static 
unsigned long
NXSwapHostLongToLittle(
unsigned long x
)
{
return (unsigned long)((uint32_t)((uint32_t)x));
}
static 
unsigned long long
NXSwapHostLongLongToLittle(
unsigned long long x
)
{
return (unsigned long long)((uint64_t)((uint64_t)x));
}
static 
NXSwappedDouble
NXSwapHostDoubleToLittle(
double x
)
{
return (NXSwappedDouble)((uint64_t)((uint64_t)NXConvertHostDoubleToSwapped(x)));
}
static 
NXSwappedFloat
NXSwapHostFloatToLittle(
float x
)
{
return (NXSwappedFloat)((uint32_t)((uint32_t)NXConvertHostFloatToSwapped(x)));
}
struct sockaddr_un {
unsigned char sun_len;
sa_family_t sun_family;
char sun_path[104];
};
typedef u_quad_t so_gen_t;
struct xsockbuf {
u_int32_t sb_cc;
u_int32_t sb_hiwat;
u_int32_t sb_mbcnt;
u_int32_t sb_mbmax;
int32_t sb_lowat;
short sb_flags;
short sb_timeo;
};
struct xsocket {
u_int32_t xso_len;
u_int32_t xso_so;
short so_type;
short so_options;
short so_linger;
short so_state;
u_int32_t so_pcb;
int xso_protocol;
int xso_family;
short so_qlen;
short so_incqlen;
short so_qlimit;
short so_timeo;
u_short so_error;
pid_t so_pgid;
u_int32_t so_oobmark;
struct xsockbuf so_rcv;
struct xsockbuf so_snd;
uid_t so_uid;
};
struct xsocket64 {
u_int32_t xso_len;
u_int64_t xso_so;
short so_type;
short so_options;
short so_linger;
short so_state;
u_int64_t so_pcb;
int xso_protocol;
int xso_family;
short so_qlen;
short so_incqlen;
short so_qlimit;
short so_timeo;
u_short so_error;
pid_t so_pgid;
u_int32_t so_oobmark;
struct xsockbuf so_rcv;
struct xsockbuf so_snd;
uid_t so_uid;
};
typedef u_quad_t unp_gen_t;
struct _unpcb_list_entry {
u_int32_t le_next;
u_int32_t le_prev;
};
struct xunpgen {
u_int32_t xug_len;
u_int xug_count;
unp_gen_t xug_gen;
so_gen_t xug_sogen;
};
struct ipc_perm
{
uid_t uid;
gid_t gid;
uid_t cuid;
gid_t cgid;
mode_t mode;
unsigned short _seq;
key_t _key;
};
struct __ipc_perm_old {
__uint16_t cuid;
__uint16_t cgid;
__uint16_t uid;
__uint16_t gid;
mode_t mode;
__uint16_t seq;
key_t key;
};
struct __semid_ds_new
{
struct ipc_perm sem_perm;
__int32_t sem_base;
unsigned short sem_nsems;
time_t sem_otime;
__int32_t sem_pad1;
time_t sem_ctime;
__int32_t sem_pad2;
__int32_t sem_pad3[4];
};
struct __semid_ds_old {
struct __ipc_perm_old sem_perm;
__int32_t sem_base;
unsigned short sem_nsems;
time_t sem_otime;
__int32_t sem_pad1;
time_t sem_ctime;
__int32_t sem_pad2;
__int32_t sem_pad3[4];
};
struct sem {
unsigned short semval;
pid_t sempid;
unsigned short semncnt;
unsigned short semzcnt;
};
struct sembuf {
unsigned short sem_num;
short sem_op;
short sem_flg;
};
union semun {
int val;
struct __semid_ds_new *buf;
unsigned short *array;
};
typedef union semun semun_t;
struct label;
struct pseminfo {
unsigned int psem_flags;
unsigned int psem_usecount;
mode_t psem_mode;
uid_t psem_uid;
gid_t psem_gid;
char psem_name[31 + 1];
void * psem_semobject;
struct label * psem_label;
pid_t psem_creator_pid;
uint64_t psem_creator_uniqueid;
};
struct ttychars {
char tc_erase;
char tc_kill;
char tc_intrc;
char tc_quitc;
char tc_startc;
char tc_stopc;
char tc_eofc;
char tc_brkc;
char tc_suspc;
char tc_dsuspc;
char tc_rprntc;
char tc_flushc;
char tc_werasc;
char tc_lnextc;
};
struct tchars {
char t_intrc;
char t_quitc;
char t_startc;
char t_stopc;
char t_eofc;
char t_brkc;
};
struct ltchars {
char t_suspc;
char t_dsuspc;
char t_rprntc;
char t_flushc;
char t_werasc;
char t_lnextc;
};
struct sgttyb {
char sg_ispeed;
char sg_ospeed;
char sg_erase;
char sg_kill;
short sg_flags;
};
struct label;
struct proc;
struct nameidata;
struct image_params {
user_addr_t ip_user_fname;
user_addr_t ip_user_argv;
user_addr_t ip_user_envv;
int ip_seg;
struct vnode *ip_vp;
struct vnode_attr *ip_vattr;
struct vnode_attr *ip_origvattr;
cpu_type_t ip_origcputype;
cpu_subtype_t ip_origcpusubtype;
char *ip_vdata;
int ip_flags;
int ip_argc;
int ip_envc;
int ip_applec;
char *ip_startargv;
char *ip_endargv;
char *ip_endenvv;
char *ip_strings;
char *ip_strendp;
int ip_argspace;
int ip_strspace;
user_size_t ip_arch_offset;
user_size_t ip_arch_size;
char ip_interp_buffer[512];
int ip_interp_sugid_fd;
struct vfs_context *ip_vfs_context;
struct nameidata *ip_ndp;
thread_t ip_new_thread;
struct label *ip_execlabelp;
struct label *ip_scriptlabelp;
struct vnode *ip_scriptvp;
unsigned int ip_csflags;
int ip_mac_return;
void *ip_px_sa;
void *ip_px_sfa;
void *ip_px_spa;
void *ip_px_smpx;
void *ip_px_persona;
void *ip_cs_error;
uint64_t ip_dyld_fsid;
uint64_t ip_dyld_fsobjid;
};
struct user32_ntptimeval
{
struct user32_timespec time;
user32_long_t maxerror;
user32_long_t esterror;
user32_long_t tai;
__int32_t time_state;
};
struct user64_timex
{
u_int64_t modes;
user64_long_t offset;
user64_long_t freq;
user64_long_t maxerror;
user64_long_t esterror;
__int64_t status;
user64_long_t constant;
user64_long_t precision;
user64_long_t tolerance;
user64_long_t ppsfreq;
user64_long_t jitter;
__int64_t shift;
user64_long_t stabil;
user64_long_t jitcnt;
user64_long_t calcnt;
user64_long_t errcnt;
user64_long_t stbcnt;
};
struct ucontext64
{
int uc_onstack;
__darwin_sigset_t uc_sigmask;
struct sigaltstack uc_stack;
struct ucontext64 *uc_link;
__darwin_size_t uc_mcsize;
struct mcontext64 *uc_mcontext64;
};
typedef struct ucontext64 ucontext64_t;
struct user32_timex
{
u_int32_t modes;
user32_long_t offset;
user32_long_t freq;
user32_long_t maxerror;
user32_long_t esterror;
__int32_t status;
user32_long_t constant;
user32_long_t precision;
user32_long_t tolerance;
user32_long_t ppsfreq;
user32_long_t jitter;
__int32_t shift;
user32_long_t stabil;
user32_long_t jitcnt;
user32_long_t calcnt;
user32_long_t errcnt;
user32_long_t stbcnt;
};
typedef __darwin_rune_t rune_t;
struct _filesec;
typedef struct _filesec *filesec_t;
typedef __darwin_ct_rune_t ct_rune_t;
typedef __darwin_mach_port_t mach_port_t;
typedef __darwin_wint_t wint_t;
struct user64_ntptimeval
{
struct user64_timespec time;
user64_long_t maxerror;
user64_long_t esterror;
user64_long_t tai;
__int64_t time_state;
};
typedef __darwin_mbstate_t mbstate_t;
struct label;
typedef uint64_t pending_io_t;
struct vnodelst { struct vnode *tqh_first; struct vnode **tqh_last; } ;
struct mount {
struct { struct mount *tqe_next; struct mount **tqe_prev; } mnt_list;
int32_t mnt_count;
lck_mtx_t mnt_mlock;
struct vfsops *mnt_op;
struct vfstable *mnt_vtable;
struct vnode *mnt_vnodecovered;
struct vnodelst mnt_vnodelist;
struct vnodelst mnt_workerqueue;
struct vnodelst mnt_newvnodes;
uint32_t mnt_flag;
uint32_t mnt_kern_flag;
uint32_t mnt_compound_ops;
uint32_t mnt_lflag;
uint32_t mnt_maxsymlinklen;
struct vfsstatfs mnt_vfsstat;
qaddr_t mnt_data;
uint32_t mnt_maxreadcnt;
uint32_t mnt_maxwritecnt;
uint32_t mnt_segreadcnt;
uint32_t mnt_segwritecnt;
uint32_t mnt_maxsegreadsize;
uint32_t mnt_maxsegwritesize;
uint32_t mnt_alignmentmask;
uint32_t mnt_devblocksize;
uint32_t mnt_ioqueue_depth;
uint32_t mnt_ioscale;
uint32_t mnt_ioflags;
uint32_t mnt_minsaturationbytecount;
pending_io_t mnt_pending_write_size ;
pending_io_t mnt_pending_read_size ;
struct timeval mnt_last_write_issued_timestamp;
struct timeval mnt_last_write_completed_timestamp;
int64_t mnt_max_swappin_available;
lck_rw_t mnt_rwlock;
lck_mtx_t mnt_renamelock;
vnode_t mnt_devvp;
uint32_t mnt_devbsdunit;
uint64_t mnt_throttle_mask;
void *mnt_throttle_info;
int32_t mnt_crossref;
int32_t mnt_iterref;
uid_t mnt_fsowner;
gid_t mnt_fsgroup;
struct label *mnt_mntlabel;
struct label *mnt_fslabel;
vnode_t mnt_realrootvp;
uint32_t mnt_realrootvp_vid;
uint32_t mnt_generation;
int mnt_authcache_ttl;
char fstypename_override[16];
uint32_t mnt_iobufinuse;
void *mnt_disk_conditioner_info;
lck_mtx_t mnt_iter_lock;
};
extern struct mount * dead_mountp;
struct fhandle {
int fh_len;
unsigned char fh_data[128];
};
typedef struct fhandle fhandle_t;
struct vfstable {
struct vfsops *vfc_vfsops;
char vfc_name[15];
int vfc_typenum;
int vfc_refcount;
int vfc_flags;
int (*vfc_mountroot)(mount_t, vnode_t, vfs_context_t);
struct vfstable *vfc_next;
int32_t vfc_reserved1;
int32_t vfc_reserved2;
int vfc_vfsflags;
void * vfc_descptr;
int vfc_descsize;
struct sysctl_oid *vfc_sysctl;
};
extern int maxvfstypenum;
extern struct vfstable *vfsconf;
extern const int maxvfsslots;
extern int numused_vfsslots;
extern int numregistered_fses;
struct vfstable * vfstable_add(struct vfstable *);
int vfstable_del(struct vfstable *);
struct vfsmount_args {
union {
struct {
char * mnt_fspec;
void * mnt_fsdata;
} mnt_localfs_args;
struct {
void * mnt_fsdata;
} mnt_remotefs_args;
} mountfs_args;
};
struct user64_statfs {
short f_otype;
short f_oflags;
user64_long_t f_bsize;
user64_long_t f_iosize;
user64_long_t f_blocks;
user64_long_t f_bfree;
user64_long_t f_bavail;
user64_long_t f_files;
user64_long_t f_ffree;
fsid_t f_fsid;
uid_t f_owner;
short f_reserved1;
short f_type;
user64_long_t f_flags;
user64_long_t f_reserved2[2];
char f_fstypename[15];
char f_mntonname[90];
char f_mntfromname[90];
char f_reserved3;
user64_long_t f_reserved4[4];
};
struct user32_statfs {
short f_otype;
short f_oflags;
user32_long_t f_bsize;
user32_long_t f_iosize;
user32_long_t f_blocks;
user32_long_t f_bfree;
user32_long_t f_bavail;
user32_long_t f_files;
user32_long_t f_ffree;
fsid_t f_fsid;
uid_t f_owner;
short f_reserved1;
short f_type;
user32_long_t f_flags;
user32_long_t f_reserved2[2];
char f_fstypename[15];
char f_mntonname[90];
char f_mntfromname[90];
char f_reserved3;
user32_long_t f_reserved4[4];
};
extern uint32_t mount_generation;
extern struct mntlist { struct mount *tqh_first; struct mount **tqh_last; } mountlist;
void mount_list_lock(void);
void mount_list_unlock(void);
void mount_lock_init(mount_t);
void mount_lock_destroy(mount_t);
void mount_lock(mount_t);
void mount_lock_spin(mount_t);
void mount_unlock(mount_t);
void mount_iterate_lock(mount_t);
void mount_iterate_unlock(mount_t);
void mount_lock_renames(mount_t);
void mount_unlock_renames(mount_t);
void mount_ref(mount_t, int);
void mount_drop(mount_t, int);
int mount_refdrain(mount_t);
errno_t vfs_rootmountalloc(const char *, const char *, mount_t *mpp);
int vfs_mountroot(void);
void vfs_unmountall(void);
int safedounmount(struct mount *, int, vfs_context_t);
int dounmount(struct mount *, int, int, vfs_context_t);
void dounmount_submounts(struct mount *, int, vfs_context_t);
void mount_dropcrossref(mount_t, vnode_t, int);
mount_t mount_lookupby_volfsid(int, int);
mount_t mount_list_lookupby_fsid(fsid_t *, int, int);
int mount_list_add(mount_t);
void mount_list_remove(mount_t);
int mount_iterref(mount_t, int);
int mount_isdrained(mount_t, int);
void mount_iterdrop(mount_t);
void mount_iterdrain(mount_t);
void mount_iterreset(mount_t);
int throttle_get_io_policy(struct uthread **ut);
int throttle_get_passive_io_policy(struct uthread **ut);
void *throttle_info_update_by_mount(mount_t mp);
//void rethrottle_thread(uthread_t ut);
void rethrottle_thread(void *ut);
extern int num_trailing_0(uint64_t n);
extern lck_mtx_t * sync_mtx_lck;
extern int sync_timeout;
struct user_semid_ds {
struct ipc_perm sem_perm;
struct sem *sem_base;
unsigned short sem_nsems;
user_time_t sem_otime;
__int32_t sem_pad1;
user_time_t sem_ctime;
__int32_t sem_pad2;
__int32_t sem_pad3[4];
};
struct user64_semid_ds {
struct ipc_perm sem_perm;
int32_t sem_base;
unsigned short sem_nsems;
user64_time_t sem_otime;
int32_t sem_pad1;
user64_time_t sem_ctime;
int32_t sem_pad2;
int32_t sem_pad3[4];
};
struct user32_semid_ds {
struct ipc_perm sem_perm;
int32_t sem_base;
unsigned short sem_nsems;
user32_time_t sem_otime;
int32_t sem_pad1;
user32_time_t sem_ctime;
int32_t sem_pad2;
int32_t sem_pad3[4];
};
union user_semun {
user_addr_t buf;
user_addr_t array;
};
typedef union user_semun user_semun_t;
struct sem_undo {
int un_next_idx;
struct proc *un_proc;
short un_cnt;
struct undo {
short une_adjval;
short une_num;
int une_id;
struct undo *une_next;
} *un_ent;
};
struct seminfo {
int semmap,
semmni,
semmns,
semmnu,
semmsl,
semopm,
semume,
semusz,
semvmx,
semaem;
};
extern struct seminfo seminfo;
struct semid_kernel {
struct user_semid_ds u;
struct label *label;
};
extern struct semid_kernel *sema;
extern struct sem *sem_pool;
extern struct sem_undo *semu;
void semexit(struct proc *p);
typedef int sem_t;
int sem_close(sem_t *);
int sem_destroy(sem_t *) ;
int sem_getvalue(sem_t *, int *) ;
int sem_init(sem_t *, int, unsigned int) ;
sem_t * sem_open(const char *, int, ...);
int sem_post(sem_t *);
int sem_trywait(sem_t *);
int sem_unlink(const char *);
int sem_wait(sem_t *) ;
typedef enum {
P_ALL,
P_PID,
P_PGID
} idtype_t;
union wait {
int w_status;
struct {
unsigned int w_Termsig:7,
w_Coredump:1,
w_Retcode:8,
w_Filler:16;
} w_T;
struct {
unsigned int w_Stopval:8,
w_Stopsig:8,
w_Filler:16;
} w_S;
};
struct shared_file_mapping_np {
mach_vm_address_t sfm_address;
mach_vm_size_t sfm_size;
mach_vm_offset_t sfm_file_offset;
vm_prot_t sfm_max_prot;
vm_prot_t sfm_init_prot;
};
void munge_w(void *args);
void munge_ww(void *args);
void munge_www(void *args);
void munge_wwww(void *args);
void munge_wwwww(void *args);
void munge_wwwwww(void *args);
void munge_wwwwwww(void *args);
void munge_wwwwwwww(void *args);
void munge_wl(void *args);
void munge_wwl(void *args);
void munge_wwlw(void *args);
void munge_wwlll(void *args);
void munge_wwllww(void *args);
void munge_wlw(void *args);
void munge_wlww(void *args);
void munge_wlwwwl(void *args);
void munge_wlwwwll(void *args);
void munge_wlwwwllw(void *args);
void munge_wlwwlwlw(void *args);
void munge_wll(void *args);
void munge_wllww(void *args);
void munge_wlll(void *args);
void munge_wllll(void *args);
void munge_wllwwll(void *args);
void munge_wwwlw(void *args);
void munge_wwwlww(void *args);
void munge_wwwl(void *args);
void munge_wwwwlw(void *args);
void munge_wwwwl(void *args);
void munge_wwwwwl(void *args);
void munge_wwwwwlww(void *args);
void munge_wwwwwllw(void *args);
void munge_wwwwwlll(void *args);
void munge_wwwwwwl(void *args);
void munge_wwwwwwlw(void *args);
void munge_wwwwwwll(void *args);
void munge_wsw(void *args);
void munge_wws(void *args);
void munge_wwws(void *args);
void munge_wwwsw(void *args);
void munge_llllll(void *args);
void munge_l(void *args);
void munge_ll(void *args);
void munge_lw(void *args);
void munge_lwww(void *args);
void munge_lwwwwwww(void *args);
void munge_wwlww(void *args);
void munge_wwlwww(void *args);
void munge_wwlwwwl(void *args);
struct nosys_args {
int32_t dummy;
};
struct exit_args {
char rval_l_[0]; int rval; char rval_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fork_args {
int32_t dummy;
};
struct read_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cbuf_l_[0]; user_addr_t cbuf; char cbuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct write_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cbuf_l_[0]; user_addr_t cbuf; char cbuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct open_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct close_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct wait4_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char status_l_[0]; user_addr_t status; char status_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char rusage_l_[0]; user_addr_t rusage; char rusage_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct link_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char link_l_[0]; user_addr_t link; char link_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct unlink_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct chdir_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fchdir_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct mknod_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dev_l_[0]; int dev; char dev_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct chmod_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct chown_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; int uid; char uid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char gid_l_[0]; int gid; char gid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getfsstat_args {
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; int bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getpid_args {
int32_t dummy;
};
struct setuid_args {
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
};
struct getuid_args {
int32_t dummy;
};
struct geteuid_args {
int32_t dummy;
};
struct ptrace_args {
char req_l_[0]; int req; char req_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char data_l_[0]; int data; char data_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct access_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct chflags_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fchflags_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct sync_args {
int32_t dummy;
};
struct kill_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char signum_l_[0]; int signum; char signum_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char posix_l_[0]; int posix; char posix_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getppid_args {
int32_t dummy;
};
struct dup_args {
char fd_l_[0]; u_int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct pipe_args {
int32_t dummy;
};
struct getegid_args {
int32_t dummy;
};
struct sigaction_args {
char signum_l_[0]; int signum; char signum_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char nsa_l_[0]; user_addr_t nsa; char nsa_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char osa_l_[0]; user_addr_t osa; char osa_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getgid_args {
int32_t dummy;
};
struct sigprocmask_args {
char how_l_[0]; int how; char how_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mask_l_[0]; user_addr_t mask; char mask_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char omask_l_[0]; user_addr_t omask; char omask_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getlogin_args {
char namebuf_l_[0]; user_addr_t namebuf; char namebuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char namelen_l_[0]; u_int namelen; char namelen_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct setlogin_args {
char namebuf_l_[0]; user_addr_t namebuf; char namebuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct acct_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sigpending_args {
char osv_l_[0]; user_addr_t osv; char osv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sigaltstack_args {
char nss_l_[0]; user_addr_t nss; char nss_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oss_l_[0]; user_addr_t oss; char oss_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct ioctl_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char com_l_[0]; user_ulong_t com; char com_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct reboot_args {
char opt_l_[0]; int opt; char opt_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char command_l_[0]; user_addr_t command; char command_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct revoke_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct symlink_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char link_l_[0]; user_addr_t link; char link_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct readlink_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char count_l_[0]; int count; char count_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct execve_args {
char fname_l_[0]; user_addr_t fname; char fname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char argp_l_[0]; user_addr_t argp; char argp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char envp_l_[0]; user_addr_t envp; char envp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct umask_args {
char newmask_l_[0]; int newmask; char newmask_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct chroot_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct msync_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct vfork_args {
int32_t dummy;
};
struct munmap_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct mprotect_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char prot_l_[0]; int prot; char prot_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct madvise_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char behav_l_[0]; int behav; char behav_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct mincore_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char vec_l_[0]; user_addr_t vec; char vec_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getgroups_args {
char gidsetsize_l_[0]; u_int gidsetsize; char gidsetsize_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char gidset_l_[0]; user_addr_t gidset; char gidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct setgroups_args {
char gidsetsize_l_[0]; u_int gidsetsize; char gidsetsize_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char gidset_l_[0]; user_addr_t gidset; char gidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getpgrp_args {
int32_t dummy;
};
struct setpgid_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char pgid_l_[0]; int pgid; char pgid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setitimer_args {
char which_l_[0]; u_int which; char which_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char itv_l_[0]; user_addr_t itv; char itv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oitv_l_[0]; user_addr_t oitv; char oitv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct swapon_args {
int32_t dummy;
};
struct getitimer_args {
char which_l_[0]; u_int which; char which_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char itv_l_[0]; user_addr_t itv; char itv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getdtablesize_args {
int32_t dummy;
};
struct dup2_args {
char from_l_[0]; u_int from; char from_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char to_l_[0]; u_int to; char to_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct fcntl_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg_l_[0]; user_long_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_long_t) ? 0 : sizeof(uint32_t) - sizeof(user_long_t))];
};
struct select_args {
char nd_l_[0]; int nd; char nd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char in_l_[0]; user_addr_t in; char in_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ou_l_[0]; user_addr_t ou; char ou_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ex_l_[0]; user_addr_t ex; char ex_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tv_l_[0]; user_addr_t tv; char tv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fsync_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setpriority_args {
char which_l_[0]; int which; char which_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char who_l_[0]; id_t who; char who_r_[(sizeof(uint32_t) <= sizeof(id_t) ? 0 : sizeof(uint32_t) - sizeof(id_t))];
char prio_l_[0]; int prio; char prio_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getpriority_args {
char which_l_[0]; int which; char which_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char who_l_[0]; id_t who; char who_r_[(sizeof(uint32_t) <= sizeof(id_t) ? 0 : sizeof(uint32_t) - sizeof(id_t))];
};
struct sigsuspend_args {
char mask_l_[0]; sigset_t mask; char mask_r_[(sizeof(uint32_t) <= sizeof(sigset_t) ? 0 : sizeof(uint32_t) - sizeof(sigset_t))];
};
struct gettimeofday_args {
char tp_l_[0]; user_addr_t tp; char tp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tzp_l_[0]; user_addr_t tzp; char tzp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mach_absolute_time_l_[0]; user_addr_t mach_absolute_time; char mach_absolute_time_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getrusage_args {
char who_l_[0]; int who; char who_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char rusage_l_[0]; user_addr_t rusage; char rusage_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct readv_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char iovp_l_[0]; user_addr_t iovp; char iovp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovcnt_l_[0]; u_int iovcnt; char iovcnt_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct writev_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char iovp_l_[0]; user_addr_t iovp; char iovp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovcnt_l_[0]; u_int iovcnt; char iovcnt_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct settimeofday_args {
char tv_l_[0]; user_addr_t tv; char tv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tzp_l_[0]; user_addr_t tzp; char tzp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fchown_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char uid_l_[0]; int uid; char uid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char gid_l_[0]; int gid; char gid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fchmod_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setreuid_args {
char ruid_l_[0]; uid_t ruid; char ruid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char euid_l_[0]; uid_t euid; char euid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
};
struct setregid_args {
char rgid_l_[0]; gid_t rgid; char rgid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char egid_l_[0]; gid_t egid; char egid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
};
struct rename_args {
char from_l_[0]; user_addr_t from; char from_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char to_l_[0]; user_addr_t to; char to_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct flock_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char how_l_[0]; int how; char how_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct mkfifo_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct mkdir_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct rmdir_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct utimes_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tptr_l_[0]; user_addr_t tptr; char tptr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct futimes_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char tptr_l_[0]; user_addr_t tptr; char tptr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct adjtime_args {
char delta_l_[0]; user_addr_t delta; char delta_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char olddelta_l_[0]; user_addr_t olddelta; char olddelta_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct gethostuuid_args {
char uuid_buf_l_[0]; user_addr_t uuid_buf; char uuid_buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char timeoutp_l_[0]; user_addr_t timeoutp; char timeoutp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char spi_l_[0]; int spi; char spi_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setsid_args {
int32_t dummy;
};
struct getpgid_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
};
struct setprivexec_args {
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct pread_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct pwrite_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct statfs_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstatfs_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct unmount_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct quotactl_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char uid_l_[0]; int uid; char uid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg_l_[0]; user_addr_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct mount_args {
char type_l_[0]; user_addr_t type; char type_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct csops_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char ops_l_[0]; uint32_t ops; char ops_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char useraddr_l_[0]; user_addr_t useraddr; char useraddr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char usersize_l_[0]; user_size_t usersize; char usersize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct csops_audittoken_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char ops_l_[0]; uint32_t ops; char ops_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char useraddr_l_[0]; user_addr_t useraddr; char useraddr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char usersize_l_[0]; user_size_t usersize; char usersize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char uaudittoken_l_[0]; user_addr_t uaudittoken; char uaudittoken_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct waitid_args {
char idtype_l_[0]; idtype_t idtype; char idtype_r_[(sizeof(uint32_t) <= sizeof(idtype_t) ? 0 : sizeof(uint32_t) - sizeof(idtype_t))];
char id_l_[0]; id_t id; char id_r_[(sizeof(uint32_t) <= sizeof(id_t) ? 0 : sizeof(uint32_t) - sizeof(id_t))];
char infop_l_[0]; user_addr_t infop; char infop_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct kdebug_typefilter_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_addr_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct kdebug_trace_string_args {
char debugid_l_[0]; uint32_t debugid; char debugid_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char str_id_l_[0]; uint64_t str_id; char str_id_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char str_l_[0]; user_addr_t str; char str_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct kdebug_trace64_args {
char code_l_[0]; uint32_t code; char code_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char arg1_l_[0]; uint64_t arg1; char arg1_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg2_l_[0]; uint64_t arg2; char arg2_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg3_l_[0]; uint64_t arg3; char arg3_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg4_l_[0]; uint64_t arg4; char arg4_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct kdebug_trace_args {
char code_l_[0]; uint32_t code; char code_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char arg1_l_[0]; user_ulong_t arg1; char arg1_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char arg2_l_[0]; user_ulong_t arg2; char arg2_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char arg3_l_[0]; user_ulong_t arg3; char arg3_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char arg4_l_[0]; user_ulong_t arg4; char arg4_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct setgid_args {
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
};
struct setegid_args {
char egid_l_[0]; gid_t egid; char egid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
};
struct seteuid_args {
char euid_l_[0]; uid_t euid; char euid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
};
struct sigreturn_args {
char uctx_l_[0]; user_addr_t uctx; char uctx_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char infostyle_l_[0]; int infostyle; char infostyle_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct thread_selfcounts_args {
char type_l_[0]; int type; char type_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbytes_l_[0]; user_size_t nbytes; char nbytes_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct fdatasync_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct stat_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lstat_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct pathconf_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char name_l_[0]; int name; char name_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fpathconf_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char name_l_[0]; int name; char name_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getrlimit_args {
char which_l_[0]; u_int which; char which_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char rlp_l_[0]; user_addr_t rlp; char rlp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct setrlimit_args {
char which_l_[0]; u_int which; char which_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char rlp_l_[0]; user_addr_t rlp; char rlp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getdirentries_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char count_l_[0]; u_int count; char count_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char basep_l_[0]; user_addr_t basep; char basep_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct mmap_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char prot_l_[0]; int prot; char prot_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char pos_l_[0]; off_t pos; char pos_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct lseek_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
char whence_l_[0]; int whence; char whence_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct truncate_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char length_l_[0]; off_t length; char length_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct ftruncate_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char length_l_[0]; off_t length; char length_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct sysctl_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char namelen_l_[0]; u_int namelen; char namelen_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char old_l_[0]; user_addr_t old; char old_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oldlenp_l_[0]; user_addr_t oldlenp; char oldlenp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char new_l_[0]; user_addr_t new0; char new_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char newlen_l_[0]; user_size_t newlen; char newlen_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct mlock_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct munlock_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct undelete_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct open_dprotected_np_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char class_l_[0]; int class0; char class_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dpflags_l_[0]; int dpflags; char dpflags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getattrlist_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct setattrlist_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct getdirentriesattr_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buffer_l_[0]; user_addr_t buffer; char buffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buffersize_l_[0]; user_size_t buffersize; char buffersize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char count_l_[0]; user_addr_t count; char count_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char basep_l_[0]; user_addr_t basep; char basep_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char newstate_l_[0]; user_addr_t newstate; char newstate_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct exchangedata_args {
char path1_l_[0]; user_addr_t path1; char path1_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char path2_l_[0]; user_addr_t path2; char path2_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct searchfs_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char searchblock_l_[0]; user_addr_t searchblock; char searchblock_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nummatches_l_[0]; user_addr_t nummatches; char nummatches_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char scriptcode_l_[0]; uint32_t scriptcode; char scriptcode_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char options_l_[0]; uint32_t options; char options_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char state_l_[0]; user_addr_t state; char state_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct delete_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct copyfile_args {
char from_l_[0]; user_addr_t from; char from_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char to_l_[0]; user_addr_t to; char to_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fgetattrlist_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct fsetattrlist_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct poll_args {
char fds_l_[0]; user_addr_t fds; char fds_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nfds_l_[0]; u_int nfds; char nfds_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char timeout_l_[0]; int timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct watchevent_args {
char u_req_l_[0]; user_addr_t u_req; char u_req_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char u_eventmask_l_[0]; int u_eventmask; char u_eventmask_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct waitevent_args {
char u_req_l_[0]; user_addr_t u_req; char u_req_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tv_l_[0]; user_addr_t tv; char tv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct modwatch_args {
char u_req_l_[0]; user_addr_t u_req; char u_req_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char u_eventmask_l_[0]; int u_eventmask; char u_eventmask_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getxattr_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char value_l_[0]; user_addr_t value; char value_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char position_l_[0]; uint32_t position; char position_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fgetxattr_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char value_l_[0]; user_addr_t value; char value_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char position_l_[0]; uint32_t position; char position_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setxattr_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char value_l_[0]; user_addr_t value; char value_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char position_l_[0]; uint32_t position; char position_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fsetxattr_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char value_l_[0]; user_addr_t value; char value_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char position_l_[0]; uint32_t position; char position_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct removexattr_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fremovexattr_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char attrname_l_[0]; user_addr_t attrname; char attrname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct listxattr_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char namebuf_l_[0]; user_addr_t namebuf; char namebuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; user_size_t bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct flistxattr_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char namebuf_l_[0]; user_addr_t namebuf; char namebuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; user_size_t bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fsctl_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char cmd_l_[0]; user_ulong_t cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; u_int options; char options_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct initgroups_args {
char gidsetsize_l_[0]; u_int gidsetsize; char gidsetsize_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char gidset_l_[0]; user_addr_t gidset; char gidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char gmuid_l_[0]; int gmuid; char gmuid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct posix_spawn_args {
char pid_l_[0]; user_addr_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char adesc_l_[0]; user_addr_t adesc; char adesc_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char argv_l_[0]; user_addr_t argv; char argv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char envp_l_[0]; user_addr_t envp; char envp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct ffsctl_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cmd_l_[0]; user_ulong_t cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; u_int options; char options_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct minherit_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char inherit_l_[0]; int inherit; char inherit_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct shm_open_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oflag_l_[0]; int oflag; char oflag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct shm_unlink_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sem_open_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oflag_l_[0]; int oflag; char oflag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char value_l_[0]; int value; char value_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct sem_close_args {
char sem_l_[0]; user_addr_t sem; char sem_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sem_unlink_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sem_wait_args {
char sem_l_[0]; user_addr_t sem; char sem_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sem_trywait_args {
char sem_l_[0]; user_addr_t sem; char sem_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sem_post_args {
char sem_l_[0]; user_addr_t sem; char sem_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sysctlbyname_args {
char name_l_[0]; user_addr_t name; char name_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char namelen_l_[0]; user_size_t namelen; char namelen_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char old_l_[0]; user_addr_t old; char old_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oldlenp_l_[0]; user_addr_t oldlenp; char oldlenp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char new_l_[0]; user_addr_t new0; char new_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char newlen_l_[0]; user_size_t newlen; char newlen_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct open_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct umask_extended_args {
char newmask_l_[0]; int newmask; char newmask_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct stat_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lstat_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstat_extended_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct chmod_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fchmod_extended_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct access_extended_args {
char entries_l_[0]; user_addr_t entries; char entries_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char results_l_[0]; user_addr_t results; char results_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
};
struct settid_args {
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
};
struct gettid_args {
char uidp_l_[0]; user_addr_t uidp; char uidp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char gidp_l_[0]; user_addr_t gidp; char gidp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct setsgroups_args {
char setlen_l_[0]; int setlen; char setlen_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guidset_l_[0]; user_addr_t guidset; char guidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getsgroups_args {
char setlen_l_[0]; user_addr_t setlen; char setlen_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guidset_l_[0]; user_addr_t guidset; char guidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct setwgroups_args {
char setlen_l_[0]; int setlen; char setlen_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guidset_l_[0]; user_addr_t guidset; char guidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getwgroups_args {
char setlen_l_[0]; user_addr_t setlen; char setlen_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guidset_l_[0]; user_addr_t guidset; char guidset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct mkfifo_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct mkdir_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct shared_region_check_np_args {
char start_address_l_[0]; user_addr_t start_address; char start_address_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct vm_pressure_monitor_args {
char wait_for_pressure_l_[0]; int wait_for_pressure; char wait_for_pressure_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char nsecs_monitored_l_[0]; int nsecs_monitored; char nsecs_monitored_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char pages_reclaimed_l_[0]; user_addr_t pages_reclaimed; char pages_reclaimed_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getsid_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
};
struct settid_with_pid_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char assume_l_[0]; int assume; char assume_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct aio_fsync_args {
char op_l_[0]; int op; char op_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_return_args {
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_suspend_args {
char aiocblist_l_[0]; user_addr_t aiocblist; char aiocblist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nent_l_[0]; int nent; char nent_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char timeoutp_l_[0]; user_addr_t timeoutp; char timeoutp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_cancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_error_args {
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_read_args {
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_write_args {
char aiocbp_l_[0]; user_addr_t aiocbp; char aiocbp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lio_listio_args {
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char aiocblist_l_[0]; user_addr_t aiocblist; char aiocblist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nent_l_[0]; int nent; char nent_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char sigp_l_[0]; user_addr_t sigp; char sigp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct iopolicysys_args {
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg_l_[0]; user_addr_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct process_policy_args {
char scope_l_[0]; int scope; char scope_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char action_l_[0]; int action; char action_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char policy_l_[0]; int policy; char policy_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char policy_subtype_l_[0]; int policy_subtype; char policy_subtype_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char attrp_l_[0]; user_addr_t attrp; char attrp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char target_pid_l_[0]; pid_t target_pid; char target_pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char target_threadid_l_[0]; uint64_t target_threadid; char target_threadid_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct mlockall_args {
char how_l_[0]; int how; char how_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct munlockall_args {
char how_l_[0]; int how; char how_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct issetugid_args {
int32_t dummy;
};
struct __pthread_kill_args {
char thread_port_l_[0]; int thread_port; char thread_port_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char sig_l_[0]; int sig; char sig_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct __pthread_sigmask_args {
char how_l_[0]; int how; char how_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char set_l_[0]; user_addr_t set; char set_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oset_l_[0]; user_addr_t oset; char oset_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __sigwait_args {
char set_l_[0]; user_addr_t set; char set_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char sig_l_[0]; user_addr_t sig; char sig_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __disable_threadsignal_args {
char value_l_[0]; int value; char value_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct __pthread_markcancel_args {
char thread_port_l_[0]; int thread_port; char thread_port_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct __pthread_canceled_args {
char action_l_[0]; int action; char action_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct __semwait_signal_args {
char cond_sem_l_[0]; int cond_sem; char cond_sem_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mutex_sem_l_[0]; int mutex_sem; char mutex_sem_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char timeout_l_[0]; int timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char relative_l_[0]; int relative; char relative_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char tv_sec_l_[0]; int64_t tv_sec; char tv_sec_r_[(sizeof(uint32_t) <= sizeof(int64_t) ? 0 : sizeof(uint32_t) - sizeof(int64_t))];
char tv_nsec_l_[0]; int32_t tv_nsec; char tv_nsec_r_[(sizeof(uint32_t) <= sizeof(int32_t) ? 0 : sizeof(uint32_t) - sizeof(int32_t))];
};
struct proc_info_args {
char callnum_l_[0]; int32_t callnum; char callnum_r_[(sizeof(uint32_t) <= sizeof(int32_t) ? 0 : sizeof(uint32_t) - sizeof(int32_t))];
char pid_l_[0]; int32_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int32_t) ? 0 : sizeof(uint32_t) - sizeof(int32_t))];
char flavor_l_[0]; uint32_t flavor; char flavor_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char arg_l_[0]; uint64_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char buffer_l_[0]; user_addr_t buffer; char buffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buffersize_l_[0]; int32_t buffersize; char buffersize_r_[(sizeof(uint32_t) <= sizeof(int32_t) ? 0 : sizeof(uint32_t) - sizeof(int32_t))];
};
struct stat64_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstat64_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lstat64_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct stat64_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lstat64_extended_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstat64_extended_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_l_[0]; user_addr_t xsecurity; char xsecurity_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char xsecurity_size_l_[0]; user_addr_t xsecurity_size; char xsecurity_size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getdirentries64_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; user_size_t bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char position_l_[0]; user_addr_t position; char position_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct statfs64_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fstatfs64_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getfsstat64_args {
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; int bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct __pthread_chdir_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __pthread_fchdir_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct audit_args {
char record_l_[0]; user_addr_t record; char record_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char length_l_[0]; int length; char length_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct auditon_args {
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char length_l_[0]; int length; char length_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getauid_args {
char auid_l_[0]; user_addr_t auid; char auid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct setauid_args {
char auid_l_[0]; user_addr_t auid; char auid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getaudit_addr_args {
char auditinfo_addr_l_[0]; user_addr_t auditinfo_addr; char auditinfo_addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char length_l_[0]; int length; char length_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct setaudit_addr_args {
char auditinfo_addr_l_[0]; user_addr_t auditinfo_addr; char auditinfo_addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char length_l_[0]; int length; char length_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct auditctl_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct kqueue_args {
int32_t dummy;
};
struct kevent_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char changelist_l_[0]; user_addr_t changelist; char changelist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nchanges_l_[0]; int nchanges; char nchanges_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char eventlist_l_[0]; user_addr_t eventlist; char eventlist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nevents_l_[0]; int nevents; char nevents_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char timeout_l_[0]; user_addr_t timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct lchown_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char owner_l_[0]; uid_t owner; char owner_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char group_l_[0]; gid_t group; char group_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
};
struct kevent64_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char changelist_l_[0]; user_addr_t changelist; char changelist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nchanges_l_[0]; int nchanges; char nchanges_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char eventlist_l_[0]; user_addr_t eventlist; char eventlist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nevents_l_[0]; int nevents; char nevents_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; unsigned int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(unsigned int) ? 0 : sizeof(uint32_t) - sizeof(unsigned int))];
char timeout_l_[0]; user_addr_t timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct thread_selfid_args {
int32_t dummy;
};
struct ledger_args {
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg1_l_[0]; user_addr_t arg1; char arg1_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char arg2_l_[0]; user_addr_t arg2; char arg2_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char arg3_l_[0]; user_addr_t arg3; char arg3_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct kevent_qos_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char changelist_l_[0]; user_addr_t changelist; char changelist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nchanges_l_[0]; int nchanges; char nchanges_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char eventlist_l_[0]; user_addr_t eventlist; char eventlist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nevents_l_[0]; int nevents; char nevents_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_out_l_[0]; user_addr_t data_out; char data_out_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char data_available_l_[0]; user_addr_t data_available; char data_available_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; unsigned int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(unsigned int) ? 0 : sizeof(uint32_t) - sizeof(unsigned int))];
};
struct kevent_id_args {
char id_l_[0]; uint64_t id; char id_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char changelist_l_[0]; user_addr_t changelist; char changelist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nchanges_l_[0]; int nchanges; char nchanges_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char eventlist_l_[0]; user_addr_t eventlist; char eventlist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nevents_l_[0]; int nevents; char nevents_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_out_l_[0]; user_addr_t data_out; char data_out_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char data_available_l_[0]; user_addr_t data_available; char data_available_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; unsigned int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(unsigned int) ? 0 : sizeof(uint32_t) - sizeof(unsigned int))];
};
struct __mac_execve_args {
char fname_l_[0]; user_addr_t fname; char fname_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char argp_l_[0]; user_addr_t argp; char argp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char envp_l_[0]; user_addr_t envp; char envp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mac_p_l_[0]; user_addr_t mac_p; char mac_p_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct pselect_args {
char nd_l_[0]; int nd; char nd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char in_l_[0]; user_addr_t in; char in_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ou_l_[0]; user_addr_t ou; char ou_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ex_l_[0]; user_addr_t ex; char ex_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ts_l_[0]; user_addr_t ts; char ts_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mask_l_[0]; user_addr_t mask; char mask_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct pselect_nocancel_args {
char nd_l_[0]; int nd; char nd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char in_l_[0]; user_addr_t in; char in_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ou_l_[0]; user_addr_t ou; char ou_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ex_l_[0]; user_addr_t ex; char ex_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ts_l_[0]; user_addr_t ts; char ts_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mask_l_[0]; user_addr_t mask; char mask_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct read_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cbuf_l_[0]; user_addr_t cbuf; char cbuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct write_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cbuf_l_[0]; user_addr_t cbuf; char cbuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct open_nocancel_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct close_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct wait4_nocancel_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char status_l_[0]; user_addr_t status; char status_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char rusage_l_[0]; user_addr_t rusage; char rusage_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct msync_nocancel_args {
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fcntl_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char cmd_l_[0]; int cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg_l_[0]; user_long_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_long_t) ? 0 : sizeof(uint32_t) - sizeof(user_long_t))];
};
struct select_nocancel_args {
char nd_l_[0]; int nd; char nd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char in_l_[0]; user_addr_t in; char in_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ou_l_[0]; user_addr_t ou; char ou_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ex_l_[0]; user_addr_t ex; char ex_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tv_l_[0]; user_addr_t tv; char tv_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fsync_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct sigsuspend_nocancel_args {
char mask_l_[0]; sigset_t mask; char mask_r_[(sizeof(uint32_t) <= sizeof(sigset_t) ? 0 : sizeof(uint32_t) - sizeof(sigset_t))];
};
struct readv_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char iovp_l_[0]; user_addr_t iovp; char iovp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovcnt_l_[0]; u_int iovcnt; char iovcnt_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct writev_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char iovp_l_[0]; user_addr_t iovp; char iovp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovcnt_l_[0]; u_int iovcnt; char iovcnt_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct pread_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct pwrite_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct waitid_nocancel_args {
char idtype_l_[0]; idtype_t idtype; char idtype_r_[(sizeof(uint32_t) <= sizeof(idtype_t) ? 0 : sizeof(uint32_t) - sizeof(idtype_t))];
char id_l_[0]; id_t id; char id_r_[(sizeof(uint32_t) <= sizeof(id_t) ? 0 : sizeof(uint32_t) - sizeof(id_t))];
char infop_l_[0]; user_addr_t infop; char infop_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char options_l_[0]; int options; char options_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct poll_nocancel_args {
char fds_l_[0]; user_addr_t fds; char fds_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nfds_l_[0]; u_int nfds; char nfds_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char timeout_l_[0]; int timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct sem_wait_nocancel_args {
char sem_l_[0]; user_addr_t sem; char sem_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct aio_suspend_nocancel_args {
char aiocblist_l_[0]; user_addr_t aiocblist; char aiocblist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nent_l_[0]; int nent; char nent_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char timeoutp_l_[0]; user_addr_t timeoutp; char timeoutp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __sigwait_nocancel_args {
char set_l_[0]; user_addr_t set; char set_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char sig_l_[0]; user_addr_t sig; char sig_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __semwait_signal_nocancel_args {
char cond_sem_l_[0]; int cond_sem; char cond_sem_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mutex_sem_l_[0]; int mutex_sem; char mutex_sem_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char timeout_l_[0]; int timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char relative_l_[0]; int relative; char relative_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char tv_sec_l_[0]; int64_t tv_sec; char tv_sec_r_[(sizeof(uint32_t) <= sizeof(int64_t) ? 0 : sizeof(uint32_t) - sizeof(int64_t))];
char tv_nsec_l_[0]; int32_t tv_nsec; char tv_nsec_r_[(sizeof(uint32_t) <= sizeof(int32_t) ? 0 : sizeof(uint32_t) - sizeof(int32_t))];
};
struct __mac_mount_args {
char type_l_[0]; user_addr_t type; char type_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mac_p_l_[0]; user_addr_t mac_p; char mac_p_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct __mac_getfsstat_args {
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; int bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mac_l_[0]; user_addr_t mac; char mac_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char macsize_l_[0]; int macsize; char macsize_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fsgetpath_args {
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; user_size_t bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char fsid_l_[0]; user_addr_t fsid; char fsid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char objid_l_[0]; uint64_t objid; char objid_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct audit_session_self_args {
int32_t dummy;
};
struct audit_session_join_args {
char port_l_[0]; mach_port_name_t port; char port_r_[(sizeof(uint32_t) <= sizeof(mach_port_name_t) ? 0 : sizeof(uint32_t) - sizeof(mach_port_name_t))];
};
struct fileport_makeport_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char portnamep_l_[0]; user_addr_t portnamep; char portnamep_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct fileport_makefd_args {
char port_l_[0]; mach_port_name_t port; char port_r_[(sizeof(uint32_t) <= sizeof(mach_port_name_t) ? 0 : sizeof(uint32_t) - sizeof(mach_port_name_t))];
};
struct audit_session_port_args {
char asid_l_[0]; au_asid_t asid; char asid_r_[(sizeof(uint32_t) <= sizeof(au_asid_t) ? 0 : sizeof(uint32_t) - sizeof(au_asid_t))];
char portnamep_l_[0]; user_addr_t portnamep; char portnamep_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct pid_suspend_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct pid_resume_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct shared_region_map_and_slide_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char count_l_[0]; uint32_t count; char count_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char mappings_l_[0]; user_addr_t mappings; char mappings_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char slide_l_[0]; uint32_t slide; char slide_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char slide_start_l_[0]; user_addr_t slide_start; char slide_start_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char slide_size_l_[0]; uint32_t slide_size; char slide_size_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct kas_info_args {
char selector_l_[0]; int selector; char selector_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char value_l_[0]; user_addr_t value; char value_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_addr_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct guarded_open_np_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guardflags_l_[0]; u_int guardflags; char guardflags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct guarded_close_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct guarded_kqueue_np_args {
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guardflags_l_[0]; u_int guardflags; char guardflags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct change_fdguard_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guardflags_l_[0]; u_int guardflags; char guardflags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char nguard_l_[0]; user_addr_t nguard; char nguard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nguardflags_l_[0]; u_int nguardflags; char nguardflags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char fdflagsp_l_[0]; user_addr_t fdflagsp; char fdflagsp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct usrctl_args {
char flags_l_[0]; uint32_t flags; char flags_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct proc_rlimit_control_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char flavor_l_[0]; int flavor; char flavor_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char arg_l_[0]; user_addr_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct telemetry_args {
char cmd_l_[0]; uint64_t cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char deadline_l_[0]; uint64_t deadline; char deadline_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char interval_l_[0]; uint64_t interval; char interval_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char leeway_l_[0]; uint64_t leeway; char leeway_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg4_l_[0]; uint64_t arg4; char arg4_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg5_l_[0]; uint64_t arg5; char arg5_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct system_override_args {
char timeout_l_[0]; uint64_t timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char flags_l_[0]; uint64_t flags; char flags_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct vfs_purge_args {
int32_t dummy;
};
struct sfi_ctl_args {
char operation_l_[0]; uint32_t operation; char operation_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char sfi_class_l_[0]; uint32_t sfi_class; char sfi_class_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char time_l_[0]; uint64_t time; char time_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char out_time_l_[0]; user_addr_t out_time; char out_time_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct sfi_pidctl_args {
char operation_l_[0]; uint32_t operation; char operation_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char sfi_flags_l_[0]; uint32_t sfi_flags; char sfi_flags_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char out_sfi_flags_l_[0]; user_addr_t out_sfi_flags; char out_sfi_flags_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct getattrlistbulk_args {
char dirfd_l_[0]; int dirfd; char dirfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; uint64_t options; char options_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct clonefileat_args {
char src_dirfd_l_[0]; int src_dirfd; char src_dirfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char src_l_[0]; user_addr_t src; char src_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char dst_dirfd_l_[0]; int dst_dirfd; char dst_dirfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dst_l_[0]; user_addr_t dst; char dst_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; uint32_t flags; char flags_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct openat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct openat_nocancel_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct renameat_args {
char fromfd_l_[0]; int fromfd; char fromfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char from_l_[0]; user_addr_t from; char from_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tofd_l_[0]; int tofd; char tofd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char to_l_[0]; user_addr_t to; char to_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct faccessat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char amode_l_[0]; int amode; char amode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fchmodat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fchownat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char uid_l_[0]; uid_t uid; char uid_r_[(sizeof(uint32_t) <= sizeof(uid_t) ? 0 : sizeof(uint32_t) - sizeof(uid_t))];
char gid_l_[0]; gid_t gid; char gid_r_[(sizeof(uint32_t) <= sizeof(gid_t) ? 0 : sizeof(uint32_t) - sizeof(gid_t))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fstatat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct fstatat64_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char ub_l_[0]; user_addr_t ub; char ub_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct linkat_args {
char fd1_l_[0]; int fd1; char fd1_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char fd2_l_[0]; int fd2; char fd2_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char link_l_[0]; user_addr_t link; char link_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct unlinkat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flag_l_[0]; int flag; char flag_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct readlinkat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufsize_l_[0]; user_size_t bufsize; char bufsize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct symlinkat_args {
char path1_l_[0]; user_addr_t path1; char path1_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path2_l_[0]; user_addr_t path2; char path2_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct mkdirat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct getattrlistat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; user_ulong_t options; char options_r_[(sizeof(uint32_t) <= sizeof(user_ulong_t) ? 0 : sizeof(uint32_t) - sizeof(user_ulong_t))];
};
struct proc_trace_log_args {
char pid_l_[0]; pid_t pid; char pid_r_[(sizeof(uint32_t) <= sizeof(pid_t) ? 0 : sizeof(uint32_t) - sizeof(pid_t))];
char uniqueid_l_[0]; uint64_t uniqueid; char uniqueid_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct bsdthread_ctl_args {
char cmd_l_[0]; user_addr_t cmd; char cmd_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char arg1_l_[0]; user_addr_t arg1; char arg1_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char arg2_l_[0]; user_addr_t arg2; char arg2_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char arg3_l_[0]; user_addr_t arg3; char arg3_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct openbyid_np_args {
char fsid_l_[0]; user_addr_t fsid; char fsid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char objid_l_[0]; user_addr_t objid; char objid_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char oflags_l_[0]; int oflags; char oflags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct thread_selfusage_args {
int32_t dummy;
};
struct guarded_open_dprotected_np_args {
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char guardflags_l_[0]; u_int guardflags; char guardflags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dpclass_l_[0]; int dpclass; char dpclass_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dpflags_l_[0]; int dpflags; char dpflags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char mode_l_[0]; int mode; char mode_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct guarded_write_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char cbuf_l_[0]; user_addr_t cbuf; char cbuf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct guarded_pwrite_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char buf_l_[0]; user_addr_t buf; char buf_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char nbyte_l_[0]; user_size_t nbyte; char nbyte_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char offset_l_[0]; off_t offset; char offset_r_[(sizeof(uint32_t) <= sizeof(off_t) ? 0 : sizeof(uint32_t) - sizeof(off_t))];
};
struct guarded_writev_np_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char guard_l_[0]; user_addr_t guard; char guard_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovp_l_[0]; user_addr_t iovp; char iovp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char iovcnt_l_[0]; int iovcnt; char iovcnt_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
};
struct renameatx_np_args {
char fromfd_l_[0]; int fromfd; char fromfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char from_l_[0]; user_addr_t from; char from_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char tofd_l_[0]; int tofd; char tofd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char to_l_[0]; user_addr_t to; char to_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; u_int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(u_int) ? 0 : sizeof(uint32_t) - sizeof(u_int))];
};
struct stack_snapshot_with_config_args {
char stackshot_config_version_l_[0]; int stackshot_config_version; char stackshot_config_version_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char stackshot_config_l_[0]; user_addr_t stackshot_config; char stackshot_config_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char stackshot_config_size_l_[0]; user_size_t stackshot_config_size; char stackshot_config_size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct work_interval_ctl_args {
char operation_l_[0]; uint32_t operation; char operation_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char work_interval_id_l_[0]; uint64_t work_interval_id; char work_interval_id_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char arg_l_[0]; user_addr_t arg; char arg_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char len_l_[0]; user_size_t len; char len_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct getentropy_args {
char buffer_l_[0]; user_addr_t buffer; char buffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char size_l_[0]; user_size_t size; char size_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
};
struct ulock_wait_args {
char operation_l_[0]; uint32_t operation; char operation_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char value_l_[0]; uint64_t value; char value_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char timeout_l_[0]; uint32_t timeout; char timeout_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct ulock_wake_args {
char operation_l_[0]; uint32_t operation; char operation_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char addr_l_[0]; user_addr_t addr; char addr_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char wake_value_l_[0]; uint64_t wake_value; char wake_value_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct fclonefileat_args {
char src_fd_l_[0]; int src_fd; char src_fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dst_dirfd_l_[0]; int dst_dirfd; char dst_dirfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char dst_l_[0]; user_addr_t dst; char dst_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; uint32_t flags; char flags_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct fs_snapshot_args {
char op_l_[0]; uint32_t op; char op_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char dirfd_l_[0]; int dirfd; char dirfd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char name1_l_[0]; user_addr_t name1; char name1_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char name2_l_[0]; user_addr_t name2; char name2_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char flags_l_[0]; uint32_t flags; char flags_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct terminate_with_payload_args {
char pid_l_[0]; int pid; char pid_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char reason_namespace_l_[0]; uint32_t reason_namespace; char reason_namespace_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_code_l_[0]; uint64_t reason_code; char reason_code_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char payload_l_[0]; user_addr_t payload; char payload_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char payload_size_l_[0]; uint32_t payload_size; char payload_size_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_string_l_[0]; user_addr_t reason_string; char reason_string_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char reason_flags_l_[0]; uint64_t reason_flags; char reason_flags_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct abort_with_payload_args {
char reason_namespace_l_[0]; uint32_t reason_namespace; char reason_namespace_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_code_l_[0]; uint64_t reason_code; char reason_code_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char payload_l_[0]; user_addr_t payload; char payload_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char payload_size_l_[0]; uint32_t payload_size; char payload_size_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_string_l_[0]; user_addr_t reason_string; char reason_string_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char reason_flags_l_[0]; uint64_t reason_flags; char reason_flags_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
struct setattrlistat_args {
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char path_l_[0]; user_addr_t path; char path_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char alist_l_[0]; user_addr_t alist; char alist_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char attributeBuffer_l_[0]; user_addr_t attributeBuffer; char attributeBuffer_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char bufferSize_l_[0]; user_size_t bufferSize; char bufferSize_r_[(sizeof(uint32_t) <= sizeof(user_size_t) ? 0 : sizeof(uint32_t) - sizeof(user_size_t))];
char options_l_[0]; uint32_t options; char options_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct net_qos_guideline_args {
char param_l_[0]; user_addr_t param; char param_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char param_len_l_[0]; uint32_t param_len; char param_len_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
};
struct fmount_args {
char type_l_[0]; user_addr_t type; char type_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char fd_l_[0]; int fd; char fd_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char flags_l_[0]; int flags; char flags_r_[(sizeof(uint32_t) <= sizeof(int) ? 0 : sizeof(uint32_t) - sizeof(int))];
char data_l_[0]; user_addr_t data; char data_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct ntp_adjtime_args {
char tp_l_[0]; user_addr_t tp; char tp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct ntp_gettime_args {
char ntvp_l_[0]; user_addr_t ntvp; char ntvp_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
};
struct os_fault_with_payload_args {
char reason_namespace_l_[0]; uint32_t reason_namespace; char reason_namespace_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_code_l_[0]; uint64_t reason_code; char reason_code_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
char payload_l_[0]; user_addr_t payload; char payload_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char payload_size_l_[0]; uint32_t payload_size; char payload_size_r_[(sizeof(uint32_t) <= sizeof(uint32_t) ? 0 : sizeof(uint32_t) - sizeof(uint32_t))];
char reason_string_l_[0]; user_addr_t reason_string; char reason_string_r_[(sizeof(uint32_t) <= sizeof(user_addr_t) ? 0 : sizeof(uint32_t) - sizeof(user_addr_t))];
char reason_flags_l_[0]; uint64_t reason_flags; char reason_flags_r_[(sizeof(uint32_t) <= sizeof(uint64_t) ? 0 : sizeof(uint32_t) - sizeof(uint64_t))];
};
int nosys(struct proc *, struct nosys_args *, int *);
void exit(struct proc *, struct exit_args *, int32_t *);
int fork(struct proc *, struct fork_args *, int *);
int read(struct proc *, struct read_args *, user_ssize_t *);
int write(struct proc *, struct write_args *, user_ssize_t *);
int open(struct proc *, struct open_args *, int *);
int close(struct proc *, struct close_args *, int *);
int wait4(struct proc *, struct wait4_args *, int *);
int link(struct proc *, struct link_args *, int *);
int unlink(struct proc *, struct unlink_args *, int *);
int chdir(struct proc *, struct chdir_args *, int *);
int fchdir(struct proc *, struct fchdir_args *, int *);
int mknod(struct proc *, struct mknod_args *, int *);
int chmod(struct proc *, struct chmod_args *, int *);
int chown(struct proc *, struct chown_args *, int *);
int getfsstat(struct proc *, struct getfsstat_args *, int *);
int getpid(struct proc *, struct getpid_args *, int *);
int setuid(struct proc *, struct setuid_args *, int *);
int getuid(struct proc *, struct getuid_args *, int *);
int geteuid(struct proc *, struct geteuid_args *, int *);
int ptrace(struct proc *, struct ptrace_args *, int *);
int access(struct proc *, struct access_args *, int *);
int chflags(struct proc *, struct chflags_args *, int *);
int fchflags(struct proc *, struct fchflags_args *, int *);
int sync(struct proc *, struct sync_args *, int *);
int kill(struct proc *, struct kill_args *, int *);
int getppid(struct proc *, struct getppid_args *, int *);
int dup(struct proc *, struct dup_args *, int *);
int pipe(struct proc *, struct pipe_args *, int *);
int getegid(struct proc *, struct getegid_args *, int *);
int sigaction(struct proc *, struct sigaction_args *, int *);
int getgid(struct proc *, struct getgid_args *, int *);
int sigprocmask(struct proc *, struct sigprocmask_args *, int *);
int getlogin(struct proc *, struct getlogin_args *, int *);
int setlogin(struct proc *, struct setlogin_args *, int *);
int acct(struct proc *, struct acct_args *, int *);
int sigpending(struct proc *, struct sigpending_args *, int *);
int sigaltstack(struct proc *, struct sigaltstack_args *, int *);
int ioctl(struct proc *, struct ioctl_args *, int *);
int reboot(struct proc *, struct reboot_args *, int *);
int revoke(struct proc *, struct revoke_args *, int *);
int symlink(struct proc *, struct symlink_args *, int *);
int readlink(struct proc *, struct readlink_args *, int *);
int execve(struct proc *, struct execve_args *, int *);
int umask(struct proc *, struct umask_args *, int *);
int chroot(struct proc *, struct chroot_args *, int *);
int msync(struct proc *, struct msync_args *, int *);
int vfork(struct proc *, struct vfork_args *, int *);
int munmap(struct proc *, struct munmap_args *, int *);
int mprotect(struct proc *, struct mprotect_args *, int *);
int madvise(struct proc *, struct madvise_args *, int *);
int mincore(struct proc *, struct mincore_args *, int *);
int getgroups(struct proc *, struct getgroups_args *, int *);
int setgroups(struct proc *, struct setgroups_args *, int *);
int getpgrp(struct proc *, struct getpgrp_args *, int *);
int setpgid(struct proc *, struct setpgid_args *, int *);
int setitimer(struct proc *, struct setitimer_args *, int *);
int swapon(struct proc *, struct swapon_args *, int *);
int getitimer(struct proc *, struct getitimer_args *, int *);
int getdtablesize(struct proc *, struct getdtablesize_args *, int *);
int dup2(struct proc *, struct dup2_args *, int *);
int fcntl(struct proc *, struct fcntl_args *, int *);
int select(struct proc *, struct select_args *, int *);
int fsync(struct proc *, struct fsync_args *, int *);
int setpriority(struct proc *, struct setpriority_args *, int *);
int getpriority(struct proc *, struct getpriority_args *, int *);
int sigsuspend(struct proc *, struct sigsuspend_args *, int *);
int gettimeofday(struct proc *, struct gettimeofday_args *, int *);
int getrusage(struct proc *, struct getrusage_args *, int *);
int readv(struct proc *, struct readv_args *, user_ssize_t *);
int writev(struct proc *, struct writev_args *, user_ssize_t *);
int settimeofday(struct proc *, struct settimeofday_args *, int *);
int fchown(struct proc *, struct fchown_args *, int *);
int fchmod(struct proc *, struct fchmod_args *, int *);
int setreuid(struct proc *, struct setreuid_args *, int *);
int setregid(struct proc *, struct setregid_args *, int *);
int rename(struct proc *, struct rename_args *, int *);
int flock(struct proc *, struct flock_args *, int *);
int mkfifo(struct proc *, struct mkfifo_args *, int *);
int mkdir(struct proc *, struct mkdir_args *, int *);
int rmdir(struct proc *, struct rmdir_args *, int *);
int utimes(struct proc *, struct utimes_args *, int *);
int futimes(struct proc *, struct futimes_args *, int *);
int adjtime(struct proc *, struct adjtime_args *, int *);
int gethostuuid(struct proc *, struct gethostuuid_args *, int *);
int setsid(struct proc *, struct setsid_args *, int *);
int getpgid(struct proc *, struct getpgid_args *, int *);
int setprivexec(struct proc *, struct setprivexec_args *, int *);
int pread(struct proc *, struct pread_args *, user_ssize_t *);
int pwrite(struct proc *, struct pwrite_args *, user_ssize_t *);
int statfs(struct proc *, struct statfs_args *, int *);
int fstatfs(struct proc *, struct fstatfs_args *, int *);
int unmount(struct proc *, struct unmount_args *, int *);
int quotactl(struct proc *, struct quotactl_args *, int *);
int mount(struct proc *, struct mount_args *, int *);
int csops(struct proc *, struct csops_args *, int *);
int csops_audittoken(struct proc *, struct csops_audittoken_args *, int *);
int waitid(struct proc *, struct waitid_args *, int *);
int kdebug_typefilter(struct proc *, struct kdebug_typefilter_args *, int *);
int kdebug_trace_string(struct proc *, struct kdebug_trace_string_args *, uint64_t *);
int kdebug_trace64(struct proc *, struct kdebug_trace64_args *, int *);
int kdebug_trace(struct proc *, struct kdebug_trace_args *, int *);
int setgid(struct proc *, struct setgid_args *, int *);
int setegid(struct proc *, struct setegid_args *, int *);
int seteuid(struct proc *, struct seteuid_args *, int *);
int sigreturn(struct proc *, struct sigreturn_args *, int *);
int thread_selfcounts(struct proc *, struct thread_selfcounts_args *, int *);
int fdatasync(struct proc *, struct fdatasync_args *, int *);
int stat(struct proc *, struct stat_args *, int *);
int fstat(struct proc *, struct fstat_args *, int *);
int lstat(struct proc *, struct lstat_args *, int *);
int pathconf(struct proc *, struct pathconf_args *, int *);
int fpathconf(struct proc *, struct fpathconf_args *, int *);
int getrlimit(struct proc *, struct getrlimit_args *, int *);
int setrlimit(struct proc *, struct setrlimit_args *, int *);
int getdirentries(struct proc *, struct getdirentries_args *, int *);
int mmap(struct proc *, struct mmap_args *, user_addr_t *);
int lseek(struct proc *, struct lseek_args *, off_t *);
int truncate(struct proc *, struct truncate_args *, int *);
int ftruncate(struct proc *, struct ftruncate_args *, int *);
int sysctl(struct proc *, struct sysctl_args *, int *);
int mlock(struct proc *, struct mlock_args *, int *);
int munlock(struct proc *, struct munlock_args *, int *);
int undelete(struct proc *, struct undelete_args *, int *);
int open_dprotected_np(struct proc *, struct open_dprotected_np_args *, int *);
int getattrlist(struct proc *, struct getattrlist_args *, int *);
int setattrlist(struct proc *, struct setattrlist_args *, int *);
int getdirentriesattr(struct proc *, struct getdirentriesattr_args *, int *);
int exchangedata(struct proc *, struct exchangedata_args *, int *);
int searchfs(struct proc *, struct searchfs_args *, int *);
int delete(struct proc *, struct delete_args *, int *);
int copyfile(struct proc *, struct copyfile_args *, int *);
int fgetattrlist(struct proc *, struct fgetattrlist_args *, int *);
int fsetattrlist(struct proc *, struct fsetattrlist_args *, int *);
int poll(struct proc *, struct poll_args *, int *);
int watchevent(struct proc *, struct watchevent_args *, int *);
int waitevent(struct proc *, struct waitevent_args *, int *);
int modwatch(struct proc *, struct modwatch_args *, int *);
int getxattr(struct proc *, struct getxattr_args *, user_ssize_t *);
int fgetxattr(struct proc *, struct fgetxattr_args *, user_ssize_t *);
int setxattr(struct proc *, struct setxattr_args *, int *);
int fsetxattr(struct proc *, struct fsetxattr_args *, int *);
int removexattr(struct proc *, struct removexattr_args *, int *);
int fremovexattr(struct proc *, struct fremovexattr_args *, int *);
int listxattr(struct proc *, struct listxattr_args *, user_ssize_t *);
int flistxattr(struct proc *, struct flistxattr_args *, user_ssize_t *);
int fsctl(struct proc *, struct fsctl_args *, int *);
int initgroups(struct proc *, struct initgroups_args *, int *);
int posix_spawn(struct proc *, struct posix_spawn_args *, int *);
int ffsctl(struct proc *, struct ffsctl_args *, int *);
int minherit(struct proc *, struct minherit_args *, int *);
int shm_open(struct proc *, struct shm_open_args *, int *);
int shm_unlink(struct proc *, struct shm_unlink_args *, int *);
int sem_open(struct proc *, struct sem_open_args *, user_addr_t *);
int sem_close(struct proc *, struct sem_close_args *, int *);
int sem_unlink(struct proc *, struct sem_unlink_args *, int *);
int sem_wait(struct proc *, struct sem_wait_args *, int *);
int sem_trywait(struct proc *, struct sem_trywait_args *, int *);
int sem_post(struct proc *, struct sem_post_args *, int *);
int sysctlbyname(struct proc *, struct sysctlbyname_args *, int *);
int open_extended(struct proc *, struct open_extended_args *, int *);
int umask_extended(struct proc *, struct umask_extended_args *, int *);
int stat_extended(struct proc *, struct stat_extended_args *, int *);
int lstat_extended(struct proc *, struct lstat_extended_args *, int *);
int fstat_extended(struct proc *, struct fstat_extended_args *, int *);
int chmod_extended(struct proc *, struct chmod_extended_args *, int *);
int fchmod_extended(struct proc *, struct fchmod_extended_args *, int *);
int access_extended(struct proc *, struct access_extended_args *, int *);
int settid(struct proc *, struct settid_args *, int *);
int gettid(struct proc *, struct gettid_args *, int *);
int setsgroups(struct proc *, struct setsgroups_args *, int *);
int getsgroups(struct proc *, struct getsgroups_args *, int *);
int setwgroups(struct proc *, struct setwgroups_args *, int *);
int getwgroups(struct proc *, struct getwgroups_args *, int *);
int mkfifo_extended(struct proc *, struct mkfifo_extended_args *, int *);
int mkdir_extended(struct proc *, struct mkdir_extended_args *, int *);
int shared_region_check_np(struct proc *, struct shared_region_check_np_args *, int *);
int vm_pressure_monitor(struct proc *, struct vm_pressure_monitor_args *, int *);
int getsid(struct proc *, struct getsid_args *, int *);
int settid_with_pid(struct proc *, struct settid_with_pid_args *, int *);
int aio_fsync(struct proc *, struct aio_fsync_args *, int *);
int aio_return(struct proc *, struct aio_return_args *, user_ssize_t *);
int aio_suspend(struct proc *, struct aio_suspend_args *, int *);
int aio_cancel(struct proc *, struct aio_cancel_args *, int *);
int aio_error(struct proc *, struct aio_error_args *, int *);
int aio_read(struct proc *, struct aio_read_args *, int *);
int aio_write(struct proc *, struct aio_write_args *, int *);
int lio_listio(struct proc *, struct lio_listio_args *, int *);
int iopolicysys(struct proc *, struct iopolicysys_args *, int *);
int process_policy(struct proc *, struct process_policy_args *, int *);
int mlockall(struct proc *, struct mlockall_args *, int *);
int munlockall(struct proc *, struct munlockall_args *, int *);
int issetugid(struct proc *, struct issetugid_args *, int *);
int __pthread_kill(struct proc *, struct __pthread_kill_args *, int *);
int __pthread_sigmask(struct proc *, struct __pthread_sigmask_args *, int *);
int __sigwait(struct proc *, struct __sigwait_args *, int *);
int __disable_threadsignal(struct proc *, struct __disable_threadsignal_args *, int *);
int __pthread_markcancel(struct proc *, struct __pthread_markcancel_args *, int *);
int __pthread_canceled(struct proc *, struct __pthread_canceled_args *, int *);
int __semwait_signal(struct proc *, struct __semwait_signal_args *, int *);
int proc_info(struct proc *, struct proc_info_args *, int *);
int stat64(struct proc *, struct stat64_args *, int *);
int fstat64(struct proc *, struct fstat64_args *, int *);
int lstat64(struct proc *, struct lstat64_args *, int *);
int stat64_extended(struct proc *, struct stat64_extended_args *, int *);
int lstat64_extended(struct proc *, struct lstat64_extended_args *, int *);
int fstat64_extended(struct proc *, struct fstat64_extended_args *, int *);
int getdirentries64(struct proc *, struct getdirentries64_args *, user_ssize_t *);
int statfs64(struct proc *, struct statfs64_args *, int *);
int fstatfs64(struct proc *, struct fstatfs64_args *, int *);
int getfsstat64(struct proc *, struct getfsstat64_args *, int *);
int __pthread_chdir(struct proc *, struct __pthread_chdir_args *, int *);
int __pthread_fchdir(struct proc *, struct __pthread_fchdir_args *, int *);
int audit(struct proc *, struct audit_args *, int *);
int auditon(struct proc *, struct auditon_args *, int *);
int getauid(struct proc *, struct getauid_args *, int *);
int setauid(struct proc *, struct setauid_args *, int *);
int getaudit_addr(struct proc *, struct getaudit_addr_args *, int *);
int setaudit_addr(struct proc *, struct setaudit_addr_args *, int *);
int auditctl(struct proc *, struct auditctl_args *, int *);
int kqueue(struct proc *, struct kqueue_args *, int *);
int kevent(struct proc *, struct kevent_args *, int *);
int lchown(struct proc *, struct lchown_args *, int *);
int kevent64(struct proc *, struct kevent64_args *, int *);
int thread_selfid(struct proc *, struct thread_selfid_args *, uint64_t *);
int ledger(struct proc *, struct ledger_args *, int *);
int kevent_qos(struct proc *, struct kevent_qos_args *, int *);
int kevent_id(struct proc *, struct kevent_id_args *, int *);
int __mac_execve(struct proc *, struct __mac_execve_args *, int *);
int pselect(struct proc *, struct pselect_args *, int *);
int pselect_nocancel(struct proc *, struct pselect_nocancel_args *, int *);
int read_nocancel(struct proc *, struct read_nocancel_args *, user_ssize_t *);
int write_nocancel(struct proc *, struct write_nocancel_args *, user_ssize_t *);
int open_nocancel(struct proc *, struct open_nocancel_args *, int *);
int close_nocancel(struct proc *, struct close_nocancel_args *, int *);
int wait4_nocancel(struct proc *, struct wait4_nocancel_args *, int *);
int msync_nocancel(struct proc *, struct msync_nocancel_args *, int *);
int fcntl_nocancel(struct proc *, struct fcntl_nocancel_args *, int *);
int select_nocancel(struct proc *, struct select_nocancel_args *, int *);
int fsync_nocancel(struct proc *, struct fsync_nocancel_args *, int *);
int sigsuspend_nocancel(struct proc *, struct sigsuspend_nocancel_args *, int *);
int readv_nocancel(struct proc *, struct readv_nocancel_args *, user_ssize_t *);
int writev_nocancel(struct proc *, struct writev_nocancel_args *, user_ssize_t *);
int pread_nocancel(struct proc *, struct pread_nocancel_args *, user_ssize_t *);
int pwrite_nocancel(struct proc *, struct pwrite_nocancel_args *, user_ssize_t *);
int waitid_nocancel(struct proc *, struct waitid_nocancel_args *, int *);
int poll_nocancel(struct proc *, struct poll_nocancel_args *, int *);
int sem_wait_nocancel(struct proc *, struct sem_wait_nocancel_args *, int *);
int aio_suspend_nocancel(struct proc *, struct aio_suspend_nocancel_args *, int *);
int __sigwait_nocancel(struct proc *, struct __sigwait_nocancel_args *, int *);
int __semwait_signal_nocancel(struct proc *, struct __semwait_signal_nocancel_args *, int *);
int __mac_mount(struct proc *, struct __mac_mount_args *, int *);
int __mac_getfsstat(struct proc *, struct __mac_getfsstat_args *, int *);
int fsgetpath(struct proc *, struct fsgetpath_args *, user_ssize_t *);
int audit_session_self(struct proc *, struct audit_session_self_args *, mach_port_name_t *);
int audit_session_join(struct proc *, struct audit_session_join_args *, int *);
int fileport_makeport(struct proc *, struct fileport_makeport_args *, int *);
int fileport_makefd(struct proc *, struct fileport_makefd_args *, int *);
int audit_session_port(struct proc *, struct audit_session_port_args *, int *);
int pid_suspend(struct proc *, struct pid_suspend_args *, int *);
int pid_resume(struct proc *, struct pid_resume_args *, int *);
int shared_region_map_and_slide_np(struct proc *, struct shared_region_map_and_slide_np_args *, int *);
int kas_info(struct proc *, struct kas_info_args *, int *);
int guarded_open_np(struct proc *, struct guarded_open_np_args *, int *);
int guarded_close_np(struct proc *, struct guarded_close_np_args *, int *);
int guarded_kqueue_np(struct proc *, struct guarded_kqueue_np_args *, int *);
int change_fdguard_np(struct proc *, struct change_fdguard_np_args *, int *);
int usrctl(struct proc *, struct usrctl_args *, int *);
int proc_rlimit_control(struct proc *, struct proc_rlimit_control_args *, int *);
int telemetry(struct proc *, struct telemetry_args *, int *);
int system_override(struct proc *, struct system_override_args *, int *);
int vfs_purge(struct proc *, struct vfs_purge_args *, int *);
int sfi_ctl(struct proc *, struct sfi_ctl_args *, int *);
int sfi_pidctl(struct proc *, struct sfi_pidctl_args *, int *);
int getattrlistbulk(struct proc *, struct getattrlistbulk_args *, int *);
int clonefileat(struct proc *, struct clonefileat_args *, int *);
int openat(struct proc *, struct openat_args *, int *);
int openat_nocancel(struct proc *, struct openat_nocancel_args *, int *);
int renameat(struct proc *, struct renameat_args *, int *);
int faccessat(struct proc *, struct faccessat_args *, int *);
int fchmodat(struct proc *, struct fchmodat_args *, int *);
int fchownat(struct proc *, struct fchownat_args *, int *);
int fstatat(struct proc *, struct fstatat_args *, int *);
int fstatat64(struct proc *, struct fstatat64_args *, int *);
int linkat(struct proc *, struct linkat_args *, int *);
int unlinkat(struct proc *, struct unlinkat_args *, int *);
int readlinkat(struct proc *, struct readlinkat_args *, int *);
int symlinkat(struct proc *, struct symlinkat_args *, int *);
int mkdirat(struct proc *, struct mkdirat_args *, int *);
int getattrlistat(struct proc *, struct getattrlistat_args *, int *);
int proc_trace_log(struct proc *, struct proc_trace_log_args *, int *);
int bsdthread_ctl(struct proc *, struct bsdthread_ctl_args *, int *);
int openbyid_np(struct proc *, struct openbyid_np_args *, int *);
int thread_selfusage(struct proc *, struct thread_selfusage_args *, uint64_t *);
int guarded_open_dprotected_np(struct proc *, struct guarded_open_dprotected_np_args *, int *);
int guarded_write_np(struct proc *, struct guarded_write_np_args *, user_ssize_t *);
int guarded_pwrite_np(struct proc *, struct guarded_pwrite_np_args *, user_ssize_t *);
int guarded_writev_np(struct proc *, struct guarded_writev_np_args *, user_ssize_t *);
int renameatx_np(struct proc *, struct renameatx_np_args *, int *);
int stack_snapshot_with_config(struct proc *, struct stack_snapshot_with_config_args *, int *);
int work_interval_ctl(struct proc *, struct work_interval_ctl_args *, int *);
int getentropy(struct proc *, struct getentropy_args *, int *);
int ulock_wait(struct proc *, struct ulock_wait_args *, int *);
int ulock_wake(struct proc *, struct ulock_wake_args *, int *);
int fclonefileat(struct proc *, struct fclonefileat_args *, int *);
int fs_snapshot(struct proc *, struct fs_snapshot_args *, int *);
int terminate_with_payload(struct proc *, struct terminate_with_payload_args *, int *);
int abort_with_payload(struct proc *, struct abort_with_payload_args *, void *);
int setattrlistat(struct proc *, struct setattrlistat_args *, int *);
int net_qos_guideline(struct proc *, struct net_qos_guideline_args *, int *);
int fmount(struct proc *, struct fmount_args *, int *);
int ntp_adjtime(struct proc *, struct ntp_adjtime_args *, int *);
int ntp_gettime(struct proc *, struct ntp_gettime_args *, int *);
int os_fault_with_payload(struct proc *, struct os_fault_with_payload_args *, int *);
typedef struct {
u_int32_t state[4];
u_int32_t count[2];
unsigned char buffer[64];
} MD5_CTX;
extern void MD5Init(MD5_CTX *);
extern void MD5Update(MD5_CTX *, const void *, unsigned int);
extern void MD5Final(unsigned char [16], MD5_CTX *);
enum {
MBUF_EXT = 0x0001,
MBUF_PKTHDR = 0x0002,
MBUF_EOR = 0x0004,
MBUF_LOOP = 0x0040,
MBUF_BCAST = 0x0100,
MBUF_MCAST = 0x0200,
MBUF_FRAG = 0x0400,
MBUF_FIRSTFRAG = 0x0800,
MBUF_LASTFRAG = 0x1000,
MBUF_PROMISC = 0x2000,
MBUF_HASFCS = 0x4000
};
typedef u_int32_t mbuf_flags_t;
enum {
MBUF_TYPE_FREE = 0,
MBUF_TYPE_DATA = 1,
MBUF_TYPE_HEADER = 2,
MBUF_TYPE_SOCKET = 3,
MBUF_TYPE_PCB = 4,
MBUF_TYPE_RTABLE = 5,
MBUF_TYPE_HTABLE = 6,
MBUF_TYPE_ATABLE = 7,
MBUF_TYPE_SONAME = 8,
MBUF_TYPE_SOOPTS = 10,
MBUF_TYPE_FTABLE = 11,
MBUF_TYPE_RIGHTS = 12,
MBUF_TYPE_IFADDR = 13,
MBUF_TYPE_CONTROL = 14,
MBUF_TYPE_OOBDATA = 15
};
typedef u_int32_t mbuf_type_t;
enum {
MBUF_TSO_IPV4 = 0x100000,
MBUF_TSO_IPV6 = 0x200000
};
typedef u_int32_t mbuf_tso_request_flags_t;
enum {
MBUF_CSUM_REQ_IP = 0x0001,
MBUF_CSUM_REQ_TCP = 0x0002,
MBUF_CSUM_REQ_UDP = 0x0004,
MBUF_CSUM_REQ_TCPIPV6 = 0x0020,
MBUF_CSUM_REQ_UDPIPV6 = 0x0040
};
typedef u_int32_t mbuf_csum_request_flags_t;
enum {
MBUF_CSUM_DID_IP = 0x0100,
MBUF_CSUM_IP_GOOD = 0x0200,
MBUF_CSUM_DID_DATA = 0x0400,
MBUF_CSUM_PSEUDO_HDR = 0x0800
};
typedef u_int32_t mbuf_csum_performed_flags_t;
enum {
MBUF_WAITOK = 0,
MBUF_DONTWAIT = 1
};
typedef u_int32_t mbuf_how_t;
typedef u_int32_t mbuf_tag_id_t;
typedef u_int16_t mbuf_tag_type_t;
struct mbuf_stat {
u_int32_t mbufs;
u_int32_t clusters;
u_int32_t clfree;
u_int32_t drops;
u_int32_t wait;
u_int32_t drain;
u_short mtypes[256];
u_int32_t mcfail;
u_int32_t mpfail;
u_int32_t msize;
u_int32_t mclbytes;
u_int32_t minclsize;
u_int32_t mlen;
u_int32_t mhlen;
u_int32_t bigclusters;
u_int32_t bigclfree;
u_int32_t bigmclbytes;
};
extern void *mbuf_data(mbuf_t mbuf);
extern void *mbuf_datastart(mbuf_t mbuf);
extern errno_t mbuf_setdata(mbuf_t mbuf, void *data, size_t len);
extern errno_t mbuf_align_32(mbuf_t mbuf, size_t len);
extern addr64_t mbuf_data_to_physical(void *ptr);
extern errno_t mbuf_get(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf);
extern errno_t mbuf_gethdr(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf);
extern errno_t mbuf_attachcluster(mbuf_how_t how, mbuf_type_t type,
mbuf_t *mbuf, caddr_t extbuf, void (*extfree)(caddr_t , u_int, caddr_t),
size_t extsize, caddr_t extarg);
extern errno_t mbuf_alloccluster(mbuf_how_t how, size_t *size, caddr_t *addr);
extern void mbuf_freecluster(caddr_t addr, size_t size);
extern errno_t mbuf_getcluster(mbuf_how_t how, mbuf_type_t type, size_t size,
mbuf_t *mbuf);
extern errno_t mbuf_mclget(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf);
extern errno_t mbuf_allocpacket(mbuf_how_t how, size_t packetlen,
unsigned int * maxchunks, mbuf_t *mbuf);
extern errno_t mbuf_allocpacket_list(unsigned int numpkts, mbuf_how_t how,
size_t packetlen, unsigned int * maxchunks, mbuf_t *mbuf);
extern errno_t mbuf_getpacket(mbuf_how_t how, mbuf_t *mbuf);
extern mbuf_t mbuf_free(mbuf_t mbuf);
extern void mbuf_freem(mbuf_t mbuf);
extern int mbuf_freem_list(mbuf_t mbuf);
extern size_t mbuf_leadingspace(const mbuf_t mbuf);
extern size_t mbuf_trailingspace(const mbuf_t mbuf);
extern errno_t mbuf_copym(const mbuf_t src, size_t offset, size_t len,
mbuf_how_t how, mbuf_t *new_mbuf);
extern errno_t mbuf_dup(const mbuf_t src, mbuf_how_t how, mbuf_t *new_mbuf);
extern errno_t mbuf_prepend(mbuf_t *mbuf, size_t len, mbuf_how_t how);
extern errno_t mbuf_split(mbuf_t src, size_t offset, mbuf_how_t how,
mbuf_t *new_mbuf);
extern errno_t mbuf_pullup(mbuf_t *mbuf, size_t len);
extern errno_t mbuf_pulldown(mbuf_t src, size_t *offset, size_t length,
mbuf_t *location);
extern void mbuf_adj(mbuf_t mbuf, int len);
extern errno_t mbuf_adjustlen(mbuf_t mbuf, int amount);
extern mbuf_t mbuf_concatenate(mbuf_t dst, mbuf_t src);
extern errno_t mbuf_copydata(const mbuf_t mbuf, size_t offset, size_t length,
void *out_data);
extern errno_t mbuf_copyback(mbuf_t mbuf, size_t offset, size_t length,
const void *data, mbuf_how_t how);
extern int mbuf_mclhasreference(mbuf_t mbuf);
extern mbuf_t mbuf_next(const mbuf_t mbuf);
extern errno_t mbuf_setnext(mbuf_t mbuf, mbuf_t next);
extern mbuf_t mbuf_nextpkt(const mbuf_t mbuf);
extern void mbuf_setnextpkt(mbuf_t mbuf, mbuf_t nextpkt);
extern size_t mbuf_len(const mbuf_t mbuf);
extern void mbuf_setlen(mbuf_t mbuf, size_t len);
extern size_t mbuf_maxlen(const mbuf_t mbuf);
extern mbuf_type_t mbuf_type(const mbuf_t mbuf);
extern errno_t mbuf_settype(mbuf_t mbuf, mbuf_type_t new_type);
extern mbuf_flags_t mbuf_flags(const mbuf_t mbuf);
extern errno_t mbuf_setflags(mbuf_t mbuf, mbuf_flags_t flags);
extern errno_t mbuf_setflags_mask(mbuf_t mbuf, mbuf_flags_t flags,
mbuf_flags_t mask);
extern errno_t mbuf_copy_pkthdr(mbuf_t dest, const mbuf_t src);
extern size_t mbuf_pkthdr_len(const mbuf_t mbuf);
extern void mbuf_pkthdr_setlen(mbuf_t mbuf, size_t len);
extern void mbuf_pkthdr_adjustlen(mbuf_t mbuf, int amount);
extern ifnet_t mbuf_pkthdr_rcvif(const mbuf_t mbuf);
extern errno_t mbuf_pkthdr_setrcvif(mbuf_t mbuf, ifnet_t ifp);
extern void *mbuf_pkthdr_header(const mbuf_t mbuf);
extern void mbuf_pkthdr_setheader(mbuf_t mbuf, void *header);
extern void mbuf_inbound_modified(mbuf_t mbuf);
extern void mbuf_outbound_finalize(mbuf_t mbuf, u_int32_t protocol_family,
size_t protocol_offset);
extern errno_t mbuf_set_vlan_tag(mbuf_t mbuf, u_int16_t vlan);
extern errno_t mbuf_get_vlan_tag(mbuf_t mbuf, u_int16_t *vlan);
extern errno_t mbuf_clear_vlan_tag(mbuf_t mbuf);
extern errno_t mbuf_get_csum_requested(mbuf_t mbuf,
mbuf_csum_request_flags_t *request, u_int32_t *value);
extern errno_t mbuf_get_tso_requested(mbuf_t mbuf,
mbuf_tso_request_flags_t *request, u_int32_t *value);
extern errno_t mbuf_clear_csum_requested(mbuf_t mbuf);
extern errno_t mbuf_set_csum_performed(mbuf_t mbuf,
mbuf_csum_performed_flags_t flags, u_int32_t value);
extern u_int32_t mbuf_get_mlen(void);
extern u_int32_t mbuf_get_mhlen(void);
extern u_int32_t mbuf_get_minclsize(void);
extern errno_t mbuf_clear_csum_performed(mbuf_t mbuf);
extern errno_t mbuf_inet_cksum(mbuf_t mbuf, int protocol, u_int32_t offset,
u_int32_t length, u_int16_t *csum);
extern errno_t mbuf_inet6_cksum(mbuf_t mbuf, int protocol, u_int32_t offset,
u_int32_t length, u_int16_t *csum);
extern errno_t mbuf_tag_id_find(const char *module_string,
mbuf_tag_id_t *module_id);
extern errno_t mbuf_tag_allocate(mbuf_t mbuf, mbuf_tag_id_t module_id,
mbuf_tag_type_t type, size_t length, mbuf_how_t how, void **data_p);
extern errno_t mbuf_tag_find(mbuf_t mbuf, mbuf_tag_id_t module_id,
mbuf_tag_type_t type, size_t *length, void **data_p);
extern void mbuf_tag_free(mbuf_t mbuf, mbuf_tag_id_t module_id,
mbuf_tag_type_t type);
extern void mbuf_stats(struct mbuf_stat *stats);
typedef enum {
MBUF_TC_BE = 0,
MBUF_TC_BK = 1,
MBUF_TC_VI = 2,
MBUF_TC_VO = 3
} mbuf_traffic_class_t;
extern mbuf_traffic_class_t mbuf_get_traffic_class(mbuf_t mbuf);
extern errno_t mbuf_set_traffic_class(mbuf_t mbuf, mbuf_traffic_class_t tc);
extern int mbuf_is_traffic_class_privileged(mbuf_t mbuf);
struct reg_values {
unsigned rv_value;
char *rv_name;
};
struct reg_desc {
unsigned rd_mask;
int rd_shift;
char *rd_name;
char *rd_format;
struct reg_values *rd_values;
};
void log(int, const char *, ...);
typedef struct
{
uint64_t offset;
uint64_t length;
} dk_extent_t;
typedef struct
{
char path[128];
} dk_firmware_path_t;
typedef struct
{
uint64_t blockCount;
uint32_t blockSize;
uint8_t reserved0096[4];
} dk_format_capacity_t;
typedef struct
{
dk_format_capacity_t * capacities;
uint32_t capacitiesCount;
uint8_t reserved0096[4];
} dk_format_capacities_t;
typedef struct
{
uint64_t offset;
uint64_t length;
uint32_t options;
uint8_t reserved0160[4];
} dk_synchronize_t;
typedef struct
{
dk_extent_t * extents;
uint32_t extentsCount;
uint32_t options;
} dk_unmap_t;
typedef struct
{
uint64_t flags;
uint64_t hotfile_size;
uint64_t hibernate_minsize;
uint64_t swapfile_pinning;
uint64_t padding[4];
} dk_corestorage_info_t;
typedef struct
{
uint64_t offset;
uint64_t length;
uint8_t provisionType;
uint8_t reserved[7];
} dk_provision_extent_t;
typedef struct
{
uint64_t offset;
uint64_t length;
uint64_t options;
uint32_t reserved;
uint32_t extentsCount;
dk_provision_extent_t * extents;
} dk_provision_status_t;
typedef struct
{
uint64_t options;
uint64_t reserved;
uint64_t description_size;
char * description;
} dk_error_description_t;
typedef struct
{
uint64_t offset;
uint64_t length;
uint8_t reserved0128[12];
dev_t dev;
} dk_physical_extent_t;
typedef struct
{
dk_extent_t * extents;
uint32_t extentsCount;
uint8_t tier;
uint8_t reserved0104[3];
} dk_set_tier_t;
typedef unsigned int uint32_t;
typedef uint32_t netaddr_t;
typedef struct {
long np_uid_high;
long np_uid_low;
} np_uid_t;
typedef struct {
netaddr_t np_receiver;
netaddr_t np_owner;
np_uid_t np_puid;
np_uid_t np_sid;
} network_port_t;
typedef struct {
uint32_t id;
const char *name;
} kd_event_t;
kd_event_t kd_events[] = {
{0x1020000, "KTrap_DivideError"},
{0x1020004, "KTrap_Debug"},
{0x1020008, "KTrap_NMI"},
{0x102000c, "KTrap_Int3"},
{0x1020010, "KTrap_Overflow"},
{0x1020014, "KTrap_BoundRange"},
{0x1020018, "KTrap_InvalidOpcode"},
{0x102001c, "KTrap_DeviceNotAvail"},
{0x1020020, "KTrap_DoubleFault"},
{0x1020024, "KTrap_Coprocessor"},
{0x1020028, "KTrap_InvalidTSS"},
{0x102002c, "KTrap_SegmentNotPresent"},
{0x1020030, "KTrap_StackFault"},
{0x1020034, "KTrap_GeneralProtection"},
{0x1020038, "KTrap_PageFault"},
{0x102003c, "KTrap_unknown"},
{0x1020040, "KTrap_FloatPointError"},
{0x1020044, "KTrap_AlignmentCheck"},
{0x1020048, "KTrap_MachineCheck"},
{0x102004c, "KTrap_SIMD_FP"},
{0x10203fc, "KTrap_Preempt"},
{0x1050000, "INTERRUPT"},
{0x1070000, "UTrap_DivideError"},
{0x1070004, "UTrap_Debug"},
{0x1070008, "UTrap_NMI"},
{0x107000c, "UTrap_Int3"},
{0x1070010, "UTrap_Overflow"},
{0x1070014, "UTrap_BoundRange"},
{0x1070018, "UTrap_InvalidOpcode"},
{0x107001c, "UTrap_DeviceNotAvail"},
{0x1070020, "UTrap_DoubleFault"},
{0x1070024, "UTrap_Coprocessor"},
{0x1070028, "UTrap_InvalidTSS"},
{0x107002c, "UTrap_SegmentNotPresent"},
{0x1070030, "UTrap_StackFault"},
{0x1070034, "UTrap_GeneralProtection"},
{0x1070038, "UTrap_PageFault"},
{0x107003c, "UTrap_unknown"},
{0x1070040, "UTrap_FloatPointError"},
{0x1070044, "UTrap_AlignmentCheck"},
{0x1070048, "UTrap_MachineCheck"},
{0x107004c, "UTrap_SIMD_FP"},
{0x1090000, "DecrTrap"},
{0x1090004, "DecrSet"},
{0x1090008, "TMR_TimerCallIntr"},
{0x109000c, "TMR_pmsStep"},
{0x1090010, "TMR_TimerMigration"},
{0x1090014, "TMR_rdHPET"},
{0x1090018, "TMR_set_tsc_deadline"},
{0x109001c, "TMR_TimerCallEnter"},
{0x1090020, "TMR_TimerCallCancel"},
{0x1090024, "TMR_TimerQueue"},
{0x1090028, "TMR_TimerCallExpire"},
{0x109002c, "TMR_AsyncDequeue"},
{0x1090030, "TMR_TimerUpdate"},
{0x1090034, "TMR_TimerEscalate"},
{0x1090038, "TMR_TimerOverdue"},
{0x109003c, "TMR_Rescan"},
{0x1090040, "TMR_set_apic_deadline"},
{0x10c0000, "MACH_SysCall"},
{0x10c0004, "MSC_kern_invalid_#1"},
{0x10c0008, "MSC_kern_invalid_#2"},
{0x10c000c, "MSC_kern_invalid_#3"},
{0x10c0010, "MSC_kern_invalid_#4"},
{0x10c0014, "MSC_kern_invalid_#5"},
{0x10c0018, "MSC_kern_invalid_#6"},
{0x10c001c, "MSC_kern_invalid_#7"},
{0x10c0020, "MSC_kern_invalid_#8"},
{0x10c0024, "MSC_kern_invalid_#9"},
{0x10c0028, "MSC_mach_vm_allocate_trap"},
{0x10c002c, "MSC_kern_invalid_#11"},
{0x10c0030, "MSC_mach_vm_deallocate_trap"},
{0x10c0034, "MSC_kern_invalid_#13"},
{0x10c0038, "MSC_mach_vm_protect_trap"},
{0x10c003c, "MSC_mach_vm_map_trap"},
{0x10c0040, "MSC_mach_port_allocate_trap"},
{0x10c0044, "MSC_mach_port_destroy_trap"},
{0x10c0048, "MSC_mach_port_deallocate_trap"},
{0x10c004c, "MSC_mach_port_mod_refs_trap"},
{0x10c0050, "MSC_mach_port_move_member_trap"},
{0x10c0054, "MSC_mach_port_insert_right_trap"},
{0x10c0058, "MSC_mach_port_insert_member_trap"},
{0x10c005c, "MSC_mach_port_extract_member_trap"},
{0x10c0060, "MSC_mach_port_construct_trap"},
{0x10c0064, "MSC_mach_port_destruct_trap"},
{0x10c0068, "MSC_mach_reply_port"},
{0x10c006c, "MSC_thread_self_trap"},
{0x10c0070, "MSC_task_self_trap"},
{0x10c0074, "MSC_host_self_trap"},
{0x10c0078, "MSC_kern_invalid_#30"},
{0x10c007c, "MSC_mach_msg_trap"},
{0x10c0080, "MSC_mach_msg_overwrite_trap"},
{0x10c0084, "MSC_semaphore_signal_trap"},
{0x10c0088, "MSC_semaphore_signal_all_trap"},
{0x10c008c, "MSC_semaphore_signal_thread_trap"},
{0x10c0090, "MSC_semaphore_wait_trap"},
{0x10c0094, "MSC_semaphore_wait_signal_trap"},
{0x10c0098, "MSC_semaphore_timedwait_trap"},
{0x10c009c, "MSC_semaphore_timedwait_signal_trap"},
{0x10c00a0, "MSC_kern_invalid_#40"},
{0x10c00a4, "MSC_mach_port_guard_trap"},
{0x10c00a8, "MSC_mach_port_unguard_trap"},
{0x10c00ac, "MSC_mach_generate_activity_id"},
{0x10c00b0, "MSC_task_name_for_pid"},
{0x10c00b4, "MSC_task_for_pid"},
{0x10c00b8, "MSC_pid_for_task"},
{0x10c00bc, "MSC_kern_invalid_#47"},
{0x10c00c0, "MSC_macx_swapon"},
{0x10c00c4, "MSC_macx_swapoff"},
{0x10c00c8, "MSC_thread_get_special_reply_port"},
{0x10c00cc, "MSC_macx_triggers"},
{0x10c00d0, "MSC_macx_backing_store_suspend"},
{0x10c00d4, "MSC_macx_backing_store_recovery"},
{0x10c00d8, "MSC_kern_invalid_#54"},
{0x10c00dc, "MSC_kern_invalid_#55"},
{0x10c00e0, "MSC_kern_invalid_#56"},
{0x10c00e4, "MSC_kern_invalid_#57"},
{0x10c00e8, "MSC_pfz_exit"},
{0x10c00ec, "MSC_swtch_pri"},
{0x10c00f0, "MSC_swtch"},
{0x10c00f4, "MSC_thread_switch"},
{0x10c00f8, "MSC_clock_sleep_trap"},
{0x10c00fc, "MSC_kern_invalid_#63"},
{0x10c0100, "MSC_kern_invalid_#64"},
{0x10c0104, "MSC_kern_invalid_#65"},
{0x10c0108, "MSC_kern_invalid_#66"},
{0x10c010c, "MSC_kern_invalid_#67"},
{0x10c0110, "MSC_kern_invalid_#68"},
{0x10c0114, "MSC_kern_invalid_#69"},
{0x10c0118, "MSC_host_create_mach_voucher_trap"},
{0x10c011c, "MSC_kern_invalid_#71"},
{0x10c0120, "MSC_mach_voucher_extract_attr_recipe_trap"},
{0x10c0124, "MSC_kern_invalid_#73"},
{0x10c0128, "MSC_kern_invalid_#74"},
{0x10c012c, "MSC_kern_invalid_#75"},
{0x10c0130, "MSC_kern_invalid_#76"},
{0x10c0134, "MSC_kern_invalid_#77"},
{0x10c0138, "MSC_kern_invalid_#78"},
{0x10c013c, "MSC_kern_invalid_#79"},
{0x10c0140, "MSC_kern_invalid_#80"},
{0x10c0144, "MSC_kern_invalid_#81"},
{0x10c0148, "MSC_kern_invalid_#82"},
{0x10c014c, "MSC_kern_invalid_#83"},
{0x10c0150, "MSC_kern_invalid_#84"},
{0x10c0154, "MSC_kern_invalid_#85"},
{0x10c0158, "MSC_kern_invalid_#86"},
{0x10c015c, "MSC_kern_invalid_#87"},
{0x10c0160, "MSC_kern_invalid_#88"},
{0x10c0164, "MSC_mach_timebase_info"},
{0x10c0168, "MSC_mach_wait_until"},
{0x10c016c, "MSC_mk_timer_create"},
{0x10c0170, "MSC_mk_timer_destroy"},
{0x10c0174, "MSC_mk_timer_arm"},
{0x10c0178, "MSC_mk_timer_cancel"},
{0x10c017c, "MSC_mk_timer_arm_leeway"},
{0x10c0180, "MSC_kern_invalid_#96"},
{0x10c0184, "MSC_kern_invalid_#97"},
{0x10c0188, "MSC_kern_invalid_#98"},
{0x10c018c, "MSC_kern_invalid_#99"},
{0x10c0190, "MSC_iokit_user_client"},
{0x10c0194, "MSC_kern_invalid_#101"},
{0x10c0198, "MSC_kern_invalid_#102"},
{0x10c019c, "MSC_kern_invalid_#103"},
{0x10c01a0, "MSC_kern_invalid_#104"},
{0x10c01a4, "MSC_kern_invalid_#105"},
{0x10c01a8, "MSC_kern_invalid_#106"},
{0x10c01ac, "MSC_kern_invalid_#107"},
{0x10c01b0, "MSC_kern_invalid_#108"},
{0x10c01b4, "MSC_kern_invalid_#109"},
{0x10c01b8, "MSC_kern_invalid_#110"},
{0x10c01bc, "MSC_kern_invalid_#111"},
{0x10c01c0, "MSC_kern_invalid_#112"},
{0x10c01c4, "MSC_kern_invalid_#113"},
{0x10c01c8, "MSC_kern_invalid_#114"},
{0x10c01cc, "MSC_kern_invalid_#115"},
{0x10c01d0, "MSC_kern_invalid_#116"},
{0x10c01d4, "MSC_kern_invalid_#117"},
{0x10c01d8, "MSC_kern_invalid_#118"},
{0x10c01dc, "MSC_kern_invalid_#119"},
{0x10c01e0, "MSC_kern_invalid_#120"},
{0x10c01e4, "MSC_kern_invalid_#121"},
{0x10c01e8, "MSC_kern_invalid_#122"},
{0x10c01ec, "MSC_kern_invalid_#123"},
{0x10c01f0, "MSC_kern_invalid_#124"},
{0x10c01f4, "MSC_kern_invalid_#125"},
{0x10c01f8, "MSC_kern_invalid_#126"},
{0x10c01fc, "MSC_kern_invalid_#127"},
{0x1200000, "MACH_task_suspend"},
{0x1200004, "MACH_task_resume"},
{0x1200008, "MACH_thread_set_voucher"},
{0x120000c, "MACH_IPC_msg_send"},
{0x1200010, "MACH_IPC_msg_recv"},
{0x1200014, "MACH_IPC_msg_recv_voucher_refused"},
{0x1200018, "MACH_IPC_kmsg_free"},
{0x120001c, "MACH_IPC_voucher_create"},
{0x1200020, "MACH_IPC_voucher_create_attr_data"},
{0x1200024, "MACH_IPC_voucher_destroy"},
{0x1200028, "MACH_IPC_kmsg_info"},
{0x120002c, "MACH_IPC_kmsg_link"},
{0x1250008, "MACH_RMON_CPUUSAGE_VIOLATED"},
{0x1250010, "MACH_RMON_CPUUSAGE_VIOLATED_K32A"},
{0x1250014, "MACH_RMON_CPUUSAGE_VIOLATED_K32B"},
{0x1250048, "MACH_RMON_CPUWAKES_VIOLATED"},
{0x1250050, "MACH_RMON_CPUWAKES_VIOLATED_K32A"},
{0x1250054, "MACH_RMON_CPUWAKES_VIOLATED_K32B"},
{0x1250088, "MACH_RMON_LOGWRITES_VIOLATED"},
{0x1250090, "MACH_RMON_LOGWRITES_VIOLATED_K32A"},
{0x1250094, "MACH_RMON_LOGWRITES_VIOLATED_K32A"},
{0x1300004, "MACH_Pageout"},
{0x1300008, "MACH_vmfault"},
{0x1300100, "MACH_purgable_token_add"},
{0x1300104, "MACH_purgable_token_delete"},
{0x1300108, "MACH_purgable_token_ripened"},
{0x130010c, "MACH_purgable_token_purged"},
{0x1300120, "MACH_purgable_object_add"},
{0x1300124, "MACH_purgable_object_remove"},
{0x1300128, "MACH_purgable_object_purge"},
{0x130012c, "MACH_purgable_object_purge_all"},
{0x1300150, "MACH_vm_map_partial_reap"},
{0x1300400, "MACH_vm_check_zf_delay"},
{0x1300404, "MACH_vm_cow_delay"},
{0x1300408, "MACH_vm_zf_delay"},
{0x130040c, "MACH_vm_compressor_delay"},
{0x1300410, "MACH_vm_pageout_scan"},
{0x1300414, "MACH_vm_pageout_balanceQ"},
{0x1300418, "MACH_vm_pageout_freelist"},
{0x130041c, "MACH_vm_pageout_purge_one"},
{0x1300420, "MACH_vm_pageout_cache_evict"},
{0x1300424, "MACH_vm_pageout_thread_block"},
{0x1300428, "MACH_vm_pageout_jetsam"},
{0x130042c, "MACH_vm_info1"},
{0x1300430, "MACH_vm_info2"},
{0x1300434, "MACH_vm_info3"},
{0x1300438, "MACH_vm_info4"},
{0x130043c, "MACH_vm_info5"},
{0x1300440, "MACH_vm_info6"},
{0x1300444, "MACH_vm_info7"},
{0x1300480, "MACH_vm_upl_page_wait"},
{0x1300484, "MACH_vm_iopl_page_wait"},
{0x1300488, "MACH_vm_page_wait_block"},
{0x130048c, "MACH_vm_page_sleep"},
{0x1300490, "MACH_vm_page_expedite"},
{0x1300494, "MACH_vm_page_expedite_no_memory"},
{0x13004c0, "MACH_vm_pressure_event"},
{0x1300500, "MACH_vm_data_write"},
{0x1320000, "vm_disconnect_all_page_mappings"},
{0x1320004, "vm_disconnect_task_page_mappings"},
{0x1320008, "RealFaultAddressInternal"},
{0x132000c, "RealFaultAddressPurgeable"},
{0x1320010, "RealFaultAddressExternal"},
{0x1320014, "RealFaultAddressSharedCache"},
{0x1400000, "MACH_SCHED"},
{0x1400004, "MACH_STKATTACH"},
{0x1400008, "MACH_STKHANDOFF"},
{0x140000c, "MACH_CALLCONT"},
{0x1400010, "MACH_CALLOUT"},
{0x1400014, "MACH_ServiceT"},
{0x1400018, "MACH_MKRUNNABLE"},
{0x140001c, "MACH_PROMOTE"},
{0x1400020, "MACH_DEMOTE"},
{0x1400024, "MACH_IDLE"},
{0x1400028, "MACH_STACK_DEPTH"},
{0x140002c, "MACH_MOVED"},
{0x1400030, "MACH_PSET_LOAD_AVERAGE"},
{0x1400034, "MACH_AMP_DEBUG"},
{0x1400038, "MACH_FAILSAFE"},
{0x140003c, "MACH_BLOCK"},
{0x1400040, "MACH_WAIT"},
{0x1400044, "MACH_SCHED_BT"},
{0x1400048, "MACH_IDLE_BT"},
{0x1400050, "MACH_SCHED_GET_URGENCY"},
{0x1400054, "MACH_SCHED_URGENCY"},
{0x1400058, "MACH_SCHED_REDISPATCH"},
{0x140005c, "MACH_SCHED_REMOTE_AST"},
{0x1400060, "MACH_SCHED_CHOOSE_PROCESSOR"},
{0x1400064, "MACH_DEEP_IDLE"},
{0x1400068, "MACH_SCHED_DECAY_PRIORITY"},
{0x140006c, "MACH_CPU_THROTTLE_DISABLE"},
{0x1400070, "MACH_RW_PROMOTE"},
{0x1400074, "MACH_RW_DEMOTE"},
{0x140007c, "MACH_SCHED_MAINTENANCE"},
{0x1400080, "MACH_DISPATCH"},
{0x1400084, "MACH_QUANTUM_HANDOFF"},
{0x1400088, "MACH_MULTIQ_DEQUEUE"},
{0x140008c, "MACH_SCHED_THREAD_SWITCH"},
{0x1400094, "MACH_SCHED_REMOTE_DEFERRED_AST"},
{0x1400098, "MACH_SCHED_REMOTE_CANCEL_AST"},
{0x140009c, "MACH_SCHED_CHANGE_PRIORITY"},
{0x14000a0, "MACH_SCHED_UPDATE_REC_CORES"},
{0x14000a4, "MACH_STACK_WAIT"},
{0x14000a8, "MACH_THREAD_BIND"},
{0x14000ac, "MACH_WAITQ_PROMOTE"},
{0x14000b0, "MACH_WAITQ_DEMOTE"},
{0x14000b4, "MACH_SCHED_LOAD"},
{0x14000b8, "MACH_REC_CORES_FAILSAFE"},
{0x14000bc, "MACH_SCHED_QUANTUM_EXPIRED"},
{0x14000c0, "MACH_EXEC_PROMOTE"},
{0x14000c4, "MACH_EXEC_DEMOTE"},
{0x14000c8, "MACH_AMP_SIGNAL_SPILL"},
{0x14000cc, "MACH_AMP_STEAL"},
{0x1500000, "MACH_MSGID_INVALID"},
{0x1600000, "MTX_SLEEP"},
{0x1600004, "MTX_SLEEP_DEADLINE"},
{0x1600008, "MTX_WAIT"},
{0x160000c, "MTX_WAKEUP"},
{0x1600010, "MTX_LOCK"},
{0x1600014, "MTX_UNLOCK"},
{0x1600080, "MTX_x86_wait"},
{0x1600084, "MTX_x86_wakeup"},
{0x1600088, "MTX_x86_spin"},
{0x160008c, "MTX_x86_acquire"},
{0x1600090, "MTX_x86_demote"},
{0x1600200, "MTX_full_lock"},
{0x1600400, "RW_EXCL_WaitForWriter"},
{0x1600404, "RW_EXCL_WaitForReaders"},
{0x1600408, "RW_SHRD_WaitForWriter"},
{0x160040c, "RW_SHRDtoEXCL_FailedUpgrade"},
{0x1600410, "RW_SHRDtoEXCL_WaitForReaders"},
{0x1600414, "RW_EXCLtoSHRD"},
{0x1600418, "RW_EXCL_SpinForWriter"},
{0x160041c, "RW_EXCL_WaitForWriter"},
{0x1600420, "RW_EXCL_SpinForReaders"},
{0x1600424, "RW_EXCL_WaitForReaders"},
{0x1600428, "RW_SHRD_unlock"},
{0x160042c, "RW_EXCL_unlock"},
{0x1600440, "RW_SHRD_SpinForWriter"},
{0x1600444, "RW_SHRD_WaitForWriter"},
{0x1600448, "RW_SHRDtoEXCL_SpinForReaders"},
{0x160044c, "RW_SHRDtoEXCL_WaitForReaders"},
{0x1700000, "PMAP_create"},
{0x1700004, "PMAP_destroy"},
{0x1700008, "PMAP_protect"},
{0x170000c, "PMAP_page_protect"},
{0x1700010, "PMAP_enter"},
{0x1700014, "PMAP_remove"},
{0x1700018, "PMAP_nest"},
{0x170001c, "PMAP_unnest"},
{0x1700020, "PMAP_flush_TLBS"},
{0x1700024, "PMAP_update_interrupt"},
{0x1700028, "PMAP_attribute_clear"},
{0x170002c, "PMAP_reusable"},
{0x1700030, "PMAP_query_resident"},
{0x1700034, "PMAP_flush_kernel_TLBS"},
{0x1700038, "PMAP_flush_delayed_TLBS"},
{0x170003c, "PMAP_flush_TLBS_TO"},
{0x1700040, "PMAP_flush_EPT"},
{0x1700044, "PMAP_fast_fault"},
{0x1800000, "MACH_CLOCK_EPOCH_CHANGE"},
{0x1800004, "MACH_CLOCK_BRIDGE_RCV_TS"},
{0x1800008, "MACH_CLOCK_BRIDGE_REMOTE_TIME"},
{0x180000c, "MACH_CLOCK_BRIDGE_RESET_TS"},
{0x1800010, "MACH_CLOCK_BRIDGE_TS_PARAMS"},
{0x1900000, "MP_TLB_FLUSH"},
{0x1900004, "MP_CPUS_CALL"},
{0x1900008, "MP_CPUS_CALL_LOCAL"},
{0x190000c, "MP_CPUS_CALL_ACTION"},
{0x1900010, "MP_CPUS_CALL_NOBUF"},
{0x1900014, "MP_CPU_FAST_START"},
{0x1900018, "MP_CPU_START"},
{0x190001c, "MP_CPU_DEACTIVATE"},
{0x1a10000, "MICROSTACKSHOT_RECORD"},
{0x1a10004, "MICROSTACKSHOT_GATHER"},
{0x1a20000, "SFI_SET_WINDOW"},
{0x1a20004, "SFI_CANCEL_WINDOW"},
{0x1a20008, "SFI_SET_CLASS_OFFTIME"},
{0x1a2000c, "SFI_CANCEL_CLASS_OFFTIME"},
{0x1a20010, "SFI_THREAD_DEFER"},
{0x1a20014, "SFI_OFF_TIMER"},
{0x1a20018, "SFI_ON_TIMER"},
{0x1a2001c, "SFI_WAIT_CANCELED"},
{0x1a20020, "SFI_PID_SET_MANAGED"},
{0x1a20024, "SFI_PID_CLEAR_MANAGED"},
{0x1a20028, "SFI_GLOBAL_DEFER"},
{0x1a30004, "ENERGY_PERF_GPU_DESCRIPTION"},
{0x1a30008, "ENERGY_PERF_GPU_TIME"},
{0x1a40000, "SYSDIAGNOSE_notify_user"},
{0x1a50000, "ZALLOC_ZCRAM"},
{0x1a60000, "THREAD_GROUP_NEW"},
{0x1a60004, "THREAD_GROUP_FREE"},
{0x1a60008, "THREAD_GROUP_SET"},
{0x1a6000c, "THREAD_GROUP_NAME"},
{0x1a60010, "THREAD_GROUP_NAME_FREE"},
{0x1a60014, "THREAD_GROUP_FLAGS"},
{0x1a70000, "COALITION_NEW"},
{0x1a70004, "COALITION_FREE"},
{0x1a70008, "COALITION_ADOPT"},
{0x1a7000c, "COALITION_REMOVE"},
{0x1a70010, "COALITION_THREAD_GROUP_SET"},
{0x2010000, "L_IP_In_Beg"},
{0x2010004, "L_IP_Out_Beg"},
{0x2010008, "L_IP_In_End"},
{0x201000c, "L_IP_Out_End"},
{0x2010404, "F_IP_Output"},
{0x2010800, "F_IP_Input"},
{0x2010c00, "F_In_CkSum"},
{0x2020000, "L_ARP_Req"},
{0x2020004, "L_ARP_Resp"},
{0x2020008, "L_ARP_Reply"},
{0x202000c, "L_ARP_Timo"},
{0x2020010, "L_ARP_Look"},
{0x2020014, "L_ARP_Input"},
{0x2030000, "L_UDP_In_Beg"},
{0x2030004, "L_UDP_Out_Beg"},
{0x2030008, "L_UDP_In_End"},
{0x203000c, "L_UDP_Out_End"},
{0x2031400, "F_UDP_Input"},
{0x2031804, "F_UDP_Output"},
{0x2040000, "L_TCP_In_Beg"},
{0x2040004, "L_TCP_Out_Beg"},
{0x2040008, "L_TCP_In_End"},
{0x204000c, "L_TCP_Out_End"},
{0x2040c00, "F_TCP_Input"},
{0x2041004, "F_TCP_Output"},
{0x2041400, "F_TCP_FastT"},
{0x2041404, "F_TCP_SlowT"},
{0x2041408, "F_TCP_Close"},
{0x2041800, "F_PCB_Lookup"},
{0x2041804, "F_PCB_HshLkup"},
{0x2041c00, "F_TCP_NewConn"},
{0x2041d00, "F_TCP_gotSync"},
{0x20b0010, "F_SBDrop"},
{0x20b0014, "F_SBAppend"},
{0x20b0404, "F_SendMsg"},
{0x20b0804, "F_SendTo"},
{0x20b0c04, "F_SendIt"},
{0x20b1004, "F_SoSend"},
{0x20b1008, "F_SoSend_CopyD"},
{0x20b100c, "F_SoSend_List"},
{0x20b1400, "F_RecvFrom"},
{0x20b1800, "F_RecvMsg"},
{0x20b1c00, "F_RecvIt"},
{0x20b2000, "F_SoReceive"},
{0x20b200c, "F_SoReceive_List"},
{0x20b2100, "F_SoShutdown"},
{0x20b2400, "F_SoAccept"},
{0x20b2800, "F_sendfile"},
{0x20b2804, "F_sendfile_wait"},
{0x20b2808, "F_sendfile_read"},
{0x20b280c, "F_sendfile_send"},
{0x20b2c00, "F_sendmsg_x"},
{0x20b3000, "F_recvmsg_x"},
{0x2650004, "AT_DDPinput"},
{0x2f00000, "F_FreemList"},
{0x2f00004, "F_m_copym"},
{0x2f00008, "F_getpackets"},
{0x2f0000c, "F_getpackethdrs"},
{0x3010000, "HFS_Write"},
{0x301001c, "HFS_Truncate"},
{0x3010028, "vinvalbuf"},
{0x3010030, "HFS_Read"},
{0x301003c, "MACH_copyiostr"},
{0x3010040, "UIO_copyout"},
{0x3010044, "UIO_copyin"},
{0x3010048, "MACH_copyio"},
{0x301004c, "Cl_bp"},
{0x3010050, "Cl_iodone"},
{0x3010054, "Cl_ubc_dump"},
{0x3010058, "Cl_io"},
{0x301005c, "Cl_zero"},
{0x3010060, "Cl_cmap"},
{0x3010068, "Cl_ioread"},
{0x301006c, "Cl_iowrite"},
{0x3010070, "Cl_ioabort"},
{0x3010074, "Cl_zero_commit"},
{0x3010078, "Cl_wrdel_commit"},
{0x301007c, "Cl_read_abort"},
{0x3010080, "Cl_read_copy"},
{0x3010084, "Cl_read_list_req"},
{0x3010088, "Cl_phys_uiomove"},
{0x301008c, "Cl_read_commit"},
{0x3010090, "VFS_LOOKUP"},
{0x3010094, "HFS_getnewvnode"},
{0x301009c, "VFS_LOOKUP_DONE"},
{0x30100a0, "Cl_write_copy"},
{0x30100a4, "Cl_write_list_req"},
{0x30100a8, "Cl_write_uiomove"},
{0x30100ac, "Cl_write_zeros"},
{0x30100b0, "Cl_write_delayed"},
{0x30100b4, "Cl_write_abort"},
{0x30100b8, "Cl_zero_info"},
{0x30100c0, "Cl_rd_ahead"},
{0x30100c4, "Cl_rd_prefetch"},
{0x30100c8, "Cl_rd_prefabort"},
{0x30100cc, "Cl_writepush"},
{0x30100d0, "Cl_pageout"},
{0x30100d4, "Cl_push"},
{0x30100e0, "Cl_pagein"},
{0x30100f0, "Cl_advisory_rd"},
{0x30100f4, "Cl_adv_fault_list"},
{0x30100f8, "Cl_adv_abort1"},
{0x30100fc, "Cl_adv_abort2"},
{0x3010118, "Cl_read_direct"},
{0x301011c, "Cl_ncpr_uiomv"},
{0x3010120, "Cl_ncpr_getupl"},
{0x3010124, "Cl_ncpr_clio"},
{0x301012c, "Cl_write_direct"},
{0x3010130, "Cl_ncpw_getupl"},
{0x3010134, "Cl_ncpw_clio"},
{0x3010138, "Cl_sparse_collect"},
{0x301013c, "Cl_sparse_push"},
{0x3010140, "Cl_sparse_add"},
{0x3010144, "Cl_release"},
{0x3010148, "Cl_drt_emptyfree"},
{0x301014c, "Cl_drt_retcluster"},
{0x3010150, "Cl_drt_alloctable"},
{0x3010154, "Cl_drt_insert"},
{0x3010158, "Cl_drt_mark"},
{0x301015c, "Cl_drt_6"},
{0x3010160, "Cl_drt_freetable"},
{0x3010170, "Cl_read_contig_getupl"},
{0x3010174, "Cl_write_contig_getupl"},
{0x3010178, "Cl_io_type"},
{0x301017c, "Cl_wait_IO"},
{0x3010180, "Vnode_Pagein"},
{0x3010184, "throttle_lowpri_io"},
{0x3010198, "rethrottle_wakeup"},
{0x301019c, "rethrottle_noted"},
{0x3010200, "Vnode_Pageout"},
{0x3010280, "Vnode_WaitForWrites"},
{0x3010300, "PageoutThrottle"},
{0x3010340, "SuperCluster"},
{0x3010344, "PS_Offsets"},
{0x3010348, "PS_Indexes"},
{0x301034c, "Dirty_Indexes"},
{0x3010350, "PS_Write"},
{0x3010354, "PS_WriteComplete"},
{0x3010380, "PageoutCollect"},
{0x3010384, "PagesOnInactive_Q"},
{0x3010388, "PagesOnActive_Q"},
{0x301038c, "PageoutScan"},
{0x3010390, "PageoutWait"},
{0x3010394, "PageoutWakeup1"},
{0x3010398, "PageoutWakeup2"},
{0x301039c, "PageoutWakeup3"},
{0x3010400, "NFS_doio"},
{0x3010404, "NFS_doio_offsets"},
{0x3010408, "NFS_doio_zero_read"},
{0x301040c, "NFS_doio_zero_write"},
{0x3010410, "NFS_doio_invalidate"},
{0x3010414, "NFS_doio_retry"},
{0x3010418, "NFS_doio_done"},
{0x3010500, "NFS_pagein_zero"},
{0x3010504, "NFS_pageout_zero"},
{0x3010508, "NFS_pagein"},
{0x301050c, "NFS_pageout"},
{0x3010600, "BIO_write_list_req"},
{0x3010604, "BIO_getblk_list_req"},
{0x3010608, "BIO_getblk"},
{0x301060c, "BIO_biodone"},
{0x3010610, "BIO_brelse"},
{0x3010614, "BIO_recovered_buf"},
{0x3010618, "BIO_dumped_buf"},
{0x301061c, "BIO_write_delayed"},
{0x3010620, "BIO_acquire_error"},
{0x3010624, "BIO_write_async"},
{0x3010628, "BIO_write_sync"},
{0x301062c, "BIO_flushdirty"},
{0x3010630, "BIO_getblk_msleep"},
{0x3010700, "VM_pageout_list_req"},
{0x3010704, "VM_pagein_list_req"},
{0x3010800, "NFS_setattr"},
{0x3010804, "NFS_getattr"},
{0x3010808, "NFS_read"},
{0x301080c, "NFS_write"},
{0x3010810, "NFS_truncate"},
{0x3010814, "NFS_flush"},
{0x3010818, "NFS_flush_again"},
{0x301081c, "NFS_flush_bvec"},
{0x3010820, "NFS_flush_upls"},
{0x3010824, "NFS_commit"},
{0x3010828, "NFS_flush_commit"},
{0x301082c, "NFS_flush_done"},
{0x3010830, "NFS_flush_busy"},
{0x3010834, "NFS_flush_bwrite"},
{0x3010838, "NFS_flush_normal"},
{0x301083c, "NFS_loadattrcache"},
{0x3010840, "NFS_getattrcache"},
{0x3010844, "NFS_connect"},
{0x3010848, "NFS_reply"},
{0x301084c, "NFS_request"},
{0x3010850, "NFS_softterm"},
{0x3010854, "NFS_rcvunlock"},
{0x3010858, "NFS_rcvlock"},
{0x301085c, "NFS_timer"},
{0x3010860, "NFS_vinvalbuf"},
{0x3010864, "NFS_srvcommit"},
{0x3010868, "NFS_srvfsync"},
{0x301086c, "NFS_RdAhead"},
{0x3010870, "NFS_srvread"},
{0x3010874, "NFS_srvVOPREAD"},
{0x3010900, "UBC_setsize"},
{0x3010904, "UBC_sync_range"},
{0x3010908, "UBC_upl_abort_range"},
{0x301090c, "UBC_upl_commit_range"},
{0x3011000, "UPL_iopl_req"},
{0x3011004, "UPL_upl_req"},
{0x3011008, "UPL_abort_range"},
{0x301100c, "UPL_abort"},
{0x3011010, "UPL_commit_range"},
{0x3011014, "UPL_commit"},
{0x3011018, "UPL_destroy"},
{0x301101c, "UPL_commit_range_active"},
{0x3011020, "UPL_commit_range_inactive"},
{0x3011024, "UPL_map_enter_upl"},
{0x3011028, "UPL_map_remove_upl"},
{0x301102c, "UPL_commit_range_speculative"},
{0x3018000, "HFS_update"},
{0x3018004, "HFS_modify_block_end"},
{0x3020000, "P_WrData"},
{0x3020004, "P_WrDataDone"},
{0x3020008, "P_RdData"},
{0x302000c, "P_RdDataDone"},
{0x3020010, "P_WrDataAsync"},
{0x3020014, "P_WrDataAsyncDone"},
{0x3020018, "P_RdDataAsync"},
{0x302001c, "P_RdDataAsyncDone"},
{0x3020020, "P_WrMeta"},
{0x3020024, "P_WrMetaDone"},
{0x3020028, "P_RdMeta"},
{0x302002c, "P_RdMetaDone"},
{0x3020030, "P_WrMetaAsync"},
{0x3020034, "P_WrMetaAsyncDone"},
{0x3020038, "P_RdMetaAsync"},
{0x302003c, "P_RdMetaAsyncDone"},
{0x3020040, "P_PgOut"},
{0x3020044, "P_PgOutDone"},
{0x3020048, "P_PgIn"},
{0x302004c, "P_PgInDone"},
{0x3020050, "P_PgOutAsync"},
{0x3020054, "P_PgOutAsyncDone"},
{0x3020058, "P_PgInAsync"},
{0x302005c, "P_PgInAsyncDone"},
{0x3020100, "P_WrDataP"},
{0x3020104, "P_WrDataPDone"},
{0x3020108, "P_RdDataP"},
{0x302010c, "P_RdDataPDone"},
{0x3020110, "P_WrDataAsyncP"},
{0x3020114, "P_WrDataAsyncPDone"},
{0x3020118, "P_RdDataAsyncP"},
{0x302011c, "P_RdDataAsyncPDone"},
{0x3020120, "P_WrMetaP"},
{0x3020124, "P_WrMetaPDone"},
{0x3020128, "P_RdMetaP"},
{0x302012c, "P_RdMetaPDone"},
{0x3020130, "P_WrMetaAsyncP"},
{0x3020134, "P_WrMetaAsyncPDone"},
{0x3020138, "P_RdMetaAsyncP"},
{0x302013c, "P_RdMetaAsyncPDone"},
{0x3020140, "P_PgOutP"},
{0x3020144, "P_PgOutPDone"},
{0x3020148, "P_PgInP"},
{0x302014c, "P_PgInPDone"},
{0x3020150, "P_PgOutAsyncP"},
{0x3020154, "P_PgOutAsyncPDone"},
{0x3020158, "P_PgInAsyncP"},
{0x302015c, "P_PgInAsyncPDone"},
{0x3020200, "P_WrDataN"},
{0x3020204, "P_WrDataNDone"},
{0x3020208, "P_RdDataN"},
{0x302020c, "P_RdDataNDone"},
{0x3020210, "P_WrDataAsyncN"},
{0x3020214, "P_WrDataAsyncNDone"},
{0x3020218, "P_RdDataAsyncN"},
{0x302021c, "P_RdDataAsyncNDone"},
{0x3020300, "P_WrDataNP"},
{0x3020304, "P_WrDataNPDone"},
{0x3020308, "P_RdDataNP"},
{0x302030c, "P_RdDataNPDone"},
{0x3020310, "P_WrDataAsyncNP"},
{0x3020314, "P_WrDataAsyncNPDone"},
{0x3020318, "P_RdDataAsyncNP"},
{0x302031c, "P_RdDataAsyncNPDone"},
{0x3020480, "P_WrDataT1"},
{0x3020484, "P_WrDataT1Done"},
{0x3020488, "P_RdDataT1"},
{0x302048c, "P_RdDataT1Done"},
{0x3020490, "P_WrDataAsyncT1"},
{0x3020494, "P_WrDataAsyncT1Done"},
{0x3020498, "P_RdDataAsyncT1"},
{0x302049c, "P_RdDataAsyncT1Done"},
{0x30204a0, "P_WrMetaT1"},
{0x30204a4, "P_WrMetaT1Done"},
{0x30204a8, "P_RdMetaT1"},
{0x30204ac, "P_RdMetaT1Done"},
{0x30204b0, "P_WrMetaAsyncT1"},
{0x30204b4, "P_WrMetaAsyncT1Done"},
{0x30204b8, "P_RdMetaAsyncT1"},
{0x30204bc, "P_RdMetaAsyncT1Done"},
{0x30204c0, "P_PgOutT1"},
{0x30204c4, "P_PgOutT1Done"},
{0x30204c8, "P_PgInT1"},
{0x30204cc, "P_PgInT1Done"},
{0x30204d0, "P_PgOutAsyncT1"},
{0x30204d4, "P_PgOutAsyncT1Done"},
{0x30204d8, "P_PgInAsyncT1"},
{0x30204dc, "P_PgInAsyncT1Done"},
{0x3020680, "P_WrDataNT1"},
{0x3020684, "P_WrDataNT1Done"},
{0x3020688, "P_RdDataNT1"},
{0x302068c, "P_RdDataNT1Done"},
{0x3020690, "P_WrDataAsyncNT1"},
{0x3020694, "P_WrDataAsyncNT1Done"},
{0x3020698, "P_RdDataAsyncNT1"},
{0x302069c, "P_RdDataAsyncNT1Done"},
{0x3020880, "P_WrDataT2"},
{0x3020884, "P_WrDataT2Done"},
{0x3020888, "P_RdDataT2"},
{0x302088c, "P_RdDataT2Done"},
{0x3020890, "P_WrDataAsyncT2"},
{0x3020894, "P_WrDataAsyncT2Done"},
{0x3020898, "P_RdDataAsyncT2"},
{0x302089c, "P_RdDataAsyncT2Done"},
{0x30208a0, "P_WrMetaT2"},
{0x30208a4, "P_WrMetaT2Done"},
{0x30208a8, "P_RdMetaT2"},
{0x30208ac, "P_RdMetaT2Done"},
{0x30208b0, "P_WrMetaAsyncT2"},
{0x30208b4, "P_WrMetaAsyncT2Done"},
{0x30208b8, "P_RdMetaAsyncT2"},
{0x30208bc, "P_RdMetaAsyncT2Done"},
{0x30208c0, "P_PgOutT2"},
{0x30208c4, "P_PgOutT2Done"},
{0x30208c8, "P_PgInT2"},
{0x30208cc, "P_PgInT2Done"},
{0x30208d0, "P_PgOutAsyncT2"},
{0x30208d4, "P_PgOutAsyncT2Done"},
{0x30208d8, "P_PgInAsyncT2"},
{0x30208dc, "P_PgInAsyncT2Done"},
{0x3020a80, "P_WrDataNT2"},
{0x3020a84, "P_WrDataNT2Done"},
{0x3020a88, "P_RdDataNT2"},
{0x3020a8c, "P_RdDataNT2Done"},
{0x3020a90, "P_WrDataAsyncNT2"},
{0x3020a94, "P_WrDataAsyncNT2Done"},
{0x3020a98, "P_RdDataAsyncNT2"},
{0x3020a9c, "P_RdDataAsyncNT2Done"},
{0x3020c80, "P_WrDataT3"},
{0x3020c84, "P_WrDataT3Done"},
{0x3020c88, "P_RdDataT3"},
{0x3020c8c, "P_RdDataT3Done"},
{0x3020c90, "P_WrDataAsyncT3"},
{0x3020c94, "P_WrDataAsyncT3Done"},
{0x3020c98, "P_RdDataAsyncT3"},
{0x3020c9c, "P_RdDataAsyncT3Done"},
{0x3020ca0, "P_WrMetaT3"},
{0x3020ca4, "P_WrMetaT3Done"},
{0x3020ca8, "P_RdMetaT3"},
{0x3020cac, "P_RdMetaT3Done"},
{0x3020cb0, "P_WrMetaAsyncT3"},
{0x3020cb4, "P_WrMetaAsyncT3Done"},
{0x3020cb8, "P_RdMetaAsyncT3"},
{0x3020cbc, "P_RdMetaAsyncT3Done"},
{0x3020cc0, "P_PgOutT3"},
{0x3020cc4, "P_PgOutT3Done"},
{0x3020cc8, "P_PgInT3"},
{0x3020ccc, "P_PgInT3Done"},
{0x3020cd0, "P_PgOutAsyncT3"},
{0x3020cd4, "P_PgOutAsyncT3Done"},
{0x3020cd8, "P_PgInAsyncT3"},
{0x3020cdc, "P_PgInAsyncT3Done"},
{0x3020e80, "P_WrDataNT3"},
{0x3020e84, "P_WrDataNT3Done"},
{0x3020e88, "P_RdDataNT3"},
{0x3020e8c, "P_RdDataNT3Done"},
{0x3020e90, "P_WrDataAsyncNT3"},
{0x3020e94, "P_WrDataAsyncNT3Done"},
{0x3020e98, "P_RdDataAsyncNT3"},
{0x3020e9c, "P_RdDataAsyncNT3Done"},
{0x3050004, "journal_flush"},
{0x3060000, "SPEC_ioctl"},
{0x3060004, "SPEC_trim_extent"},
{0x3070004, "BootCache_tag"},
{0x3070008, "BootCache_batch"},
{0x3070010, "BC_IO_HIT"},
{0x3070020, "BC_IO_HIT_STALLED"},
{0x3070040, "BC_IO_MISS"},
{0x3070080, "BC_IO_MISS_CUT_THROUGH"},
{0x3070100, "BC_PLAYBACK_IO"},
{0x3080000, "HFS_Unmap_free"},
{0x3080004, "HFS_Unmap_alloc"},
{0x3080008, "HFS_Unmap_callback"},
{0x3080010, "HFS_BlockAllocate"},
{0x3080014, "HFS_BlockDeallocate"},
{0x3080018, "HFS_ReadBitmapBlock"},
{0x308001c, "HFS_ReleaseBitmapBlock"},
{0x3080020, "HFS_BlockAllocateContig"},
{0x3080024, "HFS_BlockAllocateAnyBitmap"},
{0x3080028, "HFS_BlockAllocateKnown"},
{0x308002c, "HFS_BlockMarkAllocated"},
{0x3080030, "HFS_BlockMarkFree"},
{0x3080034, "HFS_BlockFindContiguous"},
{0x3080038, "HFS_IsAllocated"},
{0x3080040, "HFS_ResetFreeExtCache"},
{0x3080044, "HFS_remove_free_extcache"},
{0x3080048, "HFS_add_free_extcache"},
{0x308004c, "HFS_ReadBitmapRange"},
{0x3080050, "HFS_ReleaseScanBitmapRange"},
{0x3080054, "HFS_syncer"},
{0x3080058, "HFS_syncer_timed"},
{0x308005c, "HFS_ScanUnmapBlocks"},
{0x3080060, "HFS_issue_unmap"},
{0x3080064, "HFS_KR"},
{0x30a0000, "SMB_vop_mount"},
{0x30a0004, "SMB_vop_unmount"},
{0x30a0008, "SMB_vop_root"},
{0x30a000c, "SMB_vop_getattr"},
{0x30a0010, "SMB_vop_sync"},
{0x30a0014, "SMB_vop_vget"},
{0x30a0018, "SMB_vop_sysctl"},
{0x30a001c, "SMB_vnop_advlock"},
{0x30a0020, "SMB_vnop_close"},
{0x30a0024, "SMB_vnop_create"},
{0x30a0028, "SMB_vnop_fsync"},
{0x30a002c, "SMB_vnop_get_attr"},
{0x30a0030, "SMB_vnop_page_in"},
{0x30a0034, "SMB_vnop_inactive"},
{0x30a0038, "SMB_vnop_ioctl"},
{0x30a003c, "SMB_vnop_link"},
{0x30a0040, "SMB_vnop_lookup"},
{0x30a0044, "SMB_vnop_mkdir"},
{0x30a0048, "SMB_vnop_mknode"},
{0x30a004c, "SMB_vnop_mmap"},
{0x30a0050, "SMB_vnop_mnomap"},
{0x30a0054, "SMB_vnop_open"},
{0x30a0058, "SMB_vnop_cmpd_open"},
{0x30a005c, "SMB_vnop_pathconf"},
{0x30a0060, "SMB_vnop_page_out"},
{0x30a0064, "SMB_vnop_copyfile"},
{0x30a0068, "SMB_vnop_read"},
{0x30a006c, "SMB_vnop_read_dir"},
{0x30a0070, "SMB_vnop_read_dir_attr"},
{0x30a0074, "SMB_vnop_read_link"},
{0x30a0078, "SMB_vnop_reclaim"},
{0x30a007c, "SMB_vnop_remove"},
{0x30a0080, "SMB_vnop_rename"},
{0x30a0084, "SMB_vnop_rm_dir"},
{0x30a0088, "SMB_vnop_set_attr"},
{0x30a008c, "SMB_vnop_sym_link"},
{0x30a0090, "SMB_vnop_write"},
{0x30a0094, "SMB_vnop_strategy"},
{0x30a0098, "SMB_vnop_get_xattr"},
{0x30a009c, "SMB_vnop_set_xattr"},
{0x30a00a0, "SMB_vnop_rm_xattr"},
{0x30a00a4, "SMB_vnop_list_xattr"},
{0x30a00a8, "SMB_vnop_monitor"},
{0x30a00ac, "SMB_vnop_get_nstream"},
{0x30a00b0, "SMB_vnop_make_nstream"},
{0x30a00b4, "SMB_vnop_rm_nstream"},
{0x30a00b8, "SMB_vnop_access"},
{0x30a00bc, "SMB_vnop_allocate"},
{0x30a00c0, "SMB_smbfs_close"},
{0x30a00c4, "SMB_smbfs_create"},
{0x30a00c8, "SMB_smbfs_fsync"},
{0x30a00cc, "SMB_smb_fsync"},
{0x30a00d0, "SMB_smbfs_update_cache"},
{0x30a00d4, "SMB_smbfs_open"},
{0x30a00d8, "SMB_smb_read"},
{0x30a00dc, "SMB_smb_rw_async"},
{0x30a00e0, "SMB_smb_rw_fill"},
{0x30a00e4, "SMB_pack_attr_blk"},
{0x30a00e8, "SMB_smbfs_remove"},
{0x30a00ec, "SMB_smbfs_setattr"},
{0x30a00f0, "SMB_smbfs_get_sec"},
{0x30a00f4, "SMB_smbfs_set_sec"},
{0x30a00f8, "SMB_smbfs_get_max_access"},
{0x30a00fc, "SMB_smbfs_lookup"},
{0x30a0100, "SMB_smbfs_notify"},
{0x3110004, "OpenThrottleWindow"},
{0x3110008, "CauseIOThrottle"},
{0x311000c, "IO_THROTTLE_DISABLE"},
{0x3cf0000, "CP_OFFSET_IO"},
{0x4010004, "proc_exit"},
{0x4010008, "force_exit"},
{0x401000c, "proc_exec"},
{0x4010010, "exit_reason_create"},
{0x4010014, "exit_reason_commit"},
{0x4020004, "MEMSTAT_scan"},
{0x4020008, "MEMSTAT_jetsam"},
{0x402000c, "MEMSTAT_jetsam_hiwat"},
{0x4020010, "MEMSTAT_freeze"},
{0x4020014, "MEMSTAT_latency_coalesce"},
{0x4020018, "MEMSTAT_update"},
{0x402001c, "MEMSTAT_idle_demote"},
{0x4020020, "MEMSTAT_clear_errors"},
{0x4020024, "MEMSTAT_dirty_track"},
{0x4020028, "MEMSTAT_dirty_set"},
{0x402002c, "MEMSTAT_dirty_clear"},
{0x4020030, "MEMSTAT_grp_set_properties"},
{0x4020034, "MEMSTAT_do_kill"},
{0x4030004, "KEVENT_kq_processing_begin"},
{0x4030008, "KEVENT_kq_processing_end"},
{0x403000c, "KEVENT_kqwq_processing_begin"},
{0x4030010, "KEVENT_kqwq_processing_end"},
{0x4030014, "KEVENT_kqwq_bind"},
{0x4030018, "KEVENT_kqwq_unbind"},
{0x403001c, "KEVENT_kqwq_thread_request"},
{0x4030020, "KEVENT_kqwl_processing_begin"},
{0x4030024, "KEVENT_kqwl_processing_end"},
{0x4030028, "KEVENT_kqwl_thread_request"},
{0x403002c, "KEVENT_kqwl_thread_adjust"},
{0x4030030, "KEVENT_kq_register"},
{0x4030034, "KEVENT_kqwq_register"},
{0x4030038, "KEVENT_kqwl_register"},
{0x403003c, "KEVENT_knote_activate"},
{0x4030040, "KEVENT_kq_process"},
{0x4030044, "KEVENT_kqwq_process"},
{0x4030048, "KEVENT_kqwl_process"},
{0x403004c, "KEVENT_kqwl_bind"},
{0x4030050, "KEVENT_kqwl_unbind"},
{0x4030054, "KEVENT_knote_enable"},
{0x40c0000, "BSC_indirect_syscall"},
{0x40c0004, "BSC_exit"},
{0x40c0008, "BSC_fork"},
{0x40c000c, "BSC_read"},
{0x40c0010, "BSC_write"},
{0x40c0014, "BSC_open"},
{0x40c0018, "BSC_close"},
{0x40c001c, "BSC_wait4"},
{0x40c0020, "BSC_obs_creat"},
{0x40c0024, "BSC_link"},
{0x40c0028, "BSC_unlink"},
{0x40c002c, "BSC_obs_execv"},
{0x40c0030, "BSC_chdir"},
{0x40c0034, "BSC_fchdir"},
{0x40c0038, "BSC_mknod"},
{0x40c003c, "BSC_chmod"},
{0x40c0040, "BSC_chown"},
{0x40c0044, "BSC_obs_break"},
{0x40c0048, "BSC_getfsstat"},
{0x40c004c, "BSC_obs_lseek"},
{0x40c0050, "BSC_getpid"},
{0x40c0054, "BSC_obs_mount"},
{0x40c0058, "BSC_obs_umount"},
{0x40c005c, "BSC_setuid"},
{0x40c0060, "BSC_getuid"},
{0x40c0064, "BSC_geteuid"},
{0x40c0068, "BSC_ptrace"},
{0x40c006c, "BSC_recvmsg"},
{0x40c0070, "BSC_sendmsg"},
{0x40c0074, "BSC_recvfrom"},
{0x40c0078, "BSC_accept"},
{0x40c007c, "BSC_getpeername"},
{0x40c0080, "BSC_getsockname"},
{0x40c0084, "BSC_access"},
{0x40c0088, "BSC_chflags"},
{0x40c008c, "BSC_fchflags"},
{0x40c0090, "BSC_sync"},
{0x40c0094, "BSC_kill"},
{0x40c0098, "BSC_obs_stat"},
{0x40c009c, "BSC_getppid"},
{0x40c00a0, "BSC_obs_lstat"},
{0x40c00a4, "BSC_dup"},
{0x40c00a8, "BSC_pipe"},
{0x40c00ac, "BSC_getegid"},
{0x40c00b0, "BSC_obs_profil"},
{0x40c00b4, "BSC_obs_ktrace"},
{0x40c00b8, "BSC_sigaction"},
{0x40c00bc, "BSC_getgid"},
{0x40c00c0, "BSC_sigprocmask"},
{0x40c00c4, "BSC_getlogin"},
{0x40c00c8, "BSC_setlogin"},
{0x40c00cc, "BSC_acct"},
{0x40c00d0, "BSC_sigpending"},
{0x40c00d4, "BSC_sigaltstack"},
{0x40c00d8, "BSC_ioctl"},
{0x40c00dc, "BSC_reboot"},
{0x40c00e0, "BSC_revoke"},
{0x40c00e4, "BSC_symlink"},
{0x40c00e8, "BSC_readlink"},
{0x40c00ec, "BSC_execve"},
{0x40c00f0, "BSC_umask"},
{0x40c00f4, "BSC_chroot"},
{0x40c00f8, "BSC_obs_fstat"},
{0x40c00fc, "BSC_used_internally_and_reserved"},
{0x40c0100, "BSC_obs_getpagesize"},
{0x40c0104, "BSC_msync"},
{0x40c0108, "BSC_vfork"},
{0x40c010c, "BSC_obs_vread"},
{0x40c0110, "BSC_obs_vwrite"},
{0x40c0114, "BSC_obs_sbrk"},
{0x40c0118, "BSC_obs_sstk"},
{0x40c011c, "BSC_obs_mmap"},
{0x40c0120, "BSC_obs_vadvise"},
{0x40c0124, "BSC_munmap"},
{0x40c0128, "BSC_mprotect"},
{0x40c012c, "BSC_madvise"},
{0x40c0130, "BSC_obs_vhangup"},
{0x40c0134, "BSC_obs_vlimit"},
{0x40c0138, "BSC_mincore"},
{0x40c013c, "BSC_getgroups"},
{0x40c0140, "BSC_setgroups"},
{0x40c0144, "BSC_getpgrp"},
{0x40c0148, "BSC_setpgid"},
{0x40c014c, "BSC_setitimer"},
{0x40c0150, "BSC_obs_wait"},
{0x40c0154, "BSC_swapon"},
{0x40c0158, "BSC_getitimer"},
{0x40c015c, "BSC_obs_gethostname"},
{0x40c0160, "BSC_obs_sethostname"},
{0x40c0164, "BSC_getdtablesize"},
{0x40c0168, "BSC_dup2"},
{0x40c016c, "BSC_obs_getdopt"},
{0x40c0170, "BSC_fcntl"},
{0x40c0174, "BSC_select"},
{0x40c0178, "BSC_obs_setdopt"},
{0x40c017c, "BSC_fsync"},
{0x40c0180, "BSC_setpriority"},
{0x40c0184, "BSC_socket"},
{0x40c0188, "BSC_connect"},
{0x40c018c, "BSC_obs_accept"},
{0x40c0190, "BSC_getpriority"},
{0x40c0194, "BSC_obs_send"},
{0x40c0198, "BSC_obs_recv"},
{0x40c019c, "BSC_obs_sigreturn"},
{0x40c01a0, "BSC_bind"},
{0x40c01a4, "BSC_setsockopt"},
{0x40c01a8, "BSC_listen"},
{0x40c01ac, "BSC_obs_vtimes"},
{0x40c01b0, "BSC_obs_sigvec"},
{0x40c01b4, "BSC_obs_sigblock"},
{0x40c01b8, "BSC_obs_sigsetmask"},
{0x40c01bc, "BSC_sigsuspend"},
{0x40c01c0, "BSC_obs_sigstack"},
{0x40c01c4, "BSC_obs_recvmsg"},
{0x40c01c8, "BSC_obs_sendmsg"},
{0x40c01cc, "BSC_obs_vtrace"},
{0x40c01d0, "BSC_gettimeofday"},
{0x40c01d4, "BSC_getrusage"},
{0x40c01d8, "BSC_getsockopt"},
{0x40c01dc, "BSC_obs_resuba"},
{0x40c01e0, "BSC_readv"},
{0x40c01e4, "BSC_writev"},
{0x40c01e8, "BSC_settimeofday"},
{0x40c01ec, "BSC_fchown"},
{0x40c01f0, "BSC_fchmod"},
{0x40c01f4, "BSC_obs_recvfrom"},
{0x40c01f8, "BSC_setreuid"},
{0x40c01fc, "BSC_setregid"},
{0x40c0200, "BSC_rename"},
{0x40c0204, "BSC_obs_truncate"},
{0x40c0208, "BSC_obs_ftruncate"},
{0x40c020c, "BSC_flock"},
{0x40c0210, "BSC_mkfifo"},
{0x40c0214, "BSC_sendto"},
{0x40c0218, "BSC_shutdown"},
{0x40c021c, "BSC_socketpair"},
{0x40c0220, "BSC_mkdir"},
{0x40c0224, "BSC_rmdir"},
{0x40c0228, "BSC_utimes"},
{0x40c022c, "BSC_futimes"},
{0x40c0230, "BSC_adjtime"},
{0x40c0234, "BSC_obs_getpeername"},
{0x40c0238, "BSC_gethostuuid"},
{0x40c023c, "BSC_obs_sethostid"},
{0x40c0240, "BSC_obs_getrlimit"},
{0x40c0244, "BSC_obs_setrlimit"},
{0x40c0248, "BSC_obs_killpg"},
{0x40c024c, "BSC_setsid"},
{0x40c0250, "BSC_obs_setquota"},
{0x40c0254, "BSC_obs_qquota"},
{0x40c0258, "BSC_obs_getsockname"},
{0x40c025c, "BSC_getpgid"},
{0x40c0260, "BSC_setprivexec"},
{0x40c0264, "BSC_pread"},
{0x40c0268, "BSC_pwrite"},
{0x40c026c, "BSC_nfssvc"},
{0x40c0270, "BSC_obs_getdirentries"},
{0x40c0274, "BSC_statfs"},
{0x40c0278, "BSC_fstatfs"},
{0x40c027c, "BSC_unmount"},
{0x40c0280, "BSC_obs_async_daemon"},
{0x40c0284, "BSC_getfh"},
{0x40c0288, "BSC_obs_getdomainname"},
{0x40c028c, "BSC_obs_setdomainname"},
{0x40c0290, "BSC_#164"},
{0x40c0294, "BSC_quotactl"},
{0x40c0298, "BSC_obs_exportfs"},
{0x40c029c, "BSC_mount"},
{0x40c02a0, "BSC_obs_ustat"},
{0x40c02a4, "BSC_csops"},
{0x40c02a8, "BSC_csops_audittoken"},
{0x40c02ac, "BSC_obs_wait3"},
{0x40c02b0, "BSC_obs_rpause"},
{0x40c02b4, "BSC_waitid"},
{0x40c02b8, "BSC_obs_getdents"},
{0x40c02bc, "BSC_obs_gc_control"},
{0x40c02c0, "BSC_obs_add_profil"},
{0x40c02c4, "BSC_kdebug_typefilter"},
{0x40c02c8, "BSC_kdebug_trace_string"},
{0x40c02cc, "BSC_kdebug_trace64"},
{0x40c02d0, "BSC_kdebug_trace"},
{0x40c02d4, "BSC_setgid"},
{0x40c02d8, "BSC_setegid"},
{0x40c02dc, "BSC_seteuid"},
{0x40c02e0, "BSC_sigreturn"},
{0x40c02e4, "BSC_obs_chud"},
{0x40c02e8, "BSC_thread_selfcounts"},
{0x40c02ec, "BSC_fdatasync"},
{0x40c02f0, "BSC_stat"},
{0x40c02f4, "BSC_fstat"},
{0x40c02f8, "BSC_lstat"},
{0x40c02fc, "BSC_pathconf"},
{0x40c0300, "BSC_fpathconf"},
{0x40c0304, "BSC_obs_getfsstat"},
{0x40c0308, "BSC_getrlimit"},
{0x40c030c, "BSC_setrlimit"},
{0x40c0310, "BSC_getdirentries"},
{0x40c0314, "BSC_mmap"},
{0x40c0318, "BSC_obs___syscall"},
{0x40c031c, "BSC_lseek"},
{0x40c0320, "BSC_truncate"},
{0x40c0324, "BSC_ftruncate"},
{0x40c0328, "BSC_sysctl"},
{0x40c032c, "BSC_mlock"},
{0x40c0330, "BSC_munlock"},
{0x40c0334, "BSC_undelete"},
{0x40c0338, "BSC_obs_ATsocket"},
{0x40c033c, "BSC_obs_ATgetmsg"},
{0x40c0340, "BSC_obs_ATputmsg"},
{0x40c0344, "BSC_obs_ATsndreq"},
{0x40c0348, "BSC_obs_ATsndrsp"},
{0x40c034c, "BSC_obs_ATgetreq"},
{0x40c0350, "BSC_obs_ATgetrsp"},
{0x40c0354, "BSC_Reserved_for_AppleTalk"},
{0x40c0358, "BSC_#214"},
{0x40c035c, "BSC_#215"},
{0x40c0360, "BSC_open_dprotected_np"},
{0x40c0364, "BSC_obs_statv"},
{0x40c0368, "BSC_obs_lstatv"},
{0x40c036c, "BSC_obs_fstatv"},
{0x40c0370, "BSC_getattrlist"},
{0x40c0374, "BSC_setattrlist"},
{0x40c0378, "BSC_getdirentriesattr"},
{0x40c037c, "BSC_exchangedata"},
{0x40c0380, "BSC_obs_checkuseraccess_or_fsgetpath"},
{0x40c0384, "BSC_searchfs"},
{0x40c0388, "BSC_delete"},
{0x40c038c, "BSC_copyfile"},
{0x40c0390, "BSC_fgetattrlist"},
{0x40c0394, "BSC_fsetattrlist"},
{0x40c0398, "BSC_poll"},
{0x40c039c, "BSC_watchevent"},
{0x40c03a0, "BSC_waitevent"},
{0x40c03a4, "BSC_modwatch"},
{0x40c03a8, "BSC_getxattr"},
{0x40c03ac, "BSC_fgetxattr"},
{0x40c03b0, "BSC_setxattr"},
{0x40c03b4, "BSC_fsetxattr"},
{0x40c03b8, "BSC_removexattr"},
{0x40c03bc, "BSC_fremovexattr"},
{0x40c03c0, "BSC_listxattr"},
{0x40c03c4, "BSC_flistxattr"},
{0x40c03c8, "BSC_fsctl"},
{0x40c03cc, "BSC_initgroups"},
{0x40c03d0, "BSC_posix_spawn"},
{0x40c03d4, "BSC_ffsctl"},
{0x40c03d8, "BSC_#246"},
{0x40c03dc, "BSC_nfsclnt"},
{0x40c03e0, "BSC_fhopen"},
{0x40c03e4, "BSC_#249"},
{0x40c03e8, "BSC_minherit"},
{0x40c03ec, "BSC_semsys"},
{0x40c03f0, "BSC_msgsys"},
{0x40c03f4, "BSC_shmsys"},
{0x40c03f8, "BSC_semctl"},
{0x40c03fc, "BSC_semget"},
{0x40c0400, "BSC_semop"},
{0x40c0404, "BSC_obs_semconfig"},
{0x40c0408, "BSC_msgctl"},
{0x40c040c, "BSC_msgget"},
{0x40c0410, "BSC_msgsnd"},
{0x40c0414, "BSC_msgrcv"},
{0x40c0418, "BSC_shmat"},
{0x40c041c, "BSC_shmctl"},
{0x40c0420, "BSC_shmdt"},
{0x40c0424, "BSC_shmget"},
{0x40c0428, "BSC_shm_open"},
{0x40c042c, "BSC_shm_unlink"},
{0x40c0430, "BSC_sem_open"},
{0x40c0434, "BSC_sem_close"},
{0x40c0438, "BSC_sem_unlink"},
{0x40c043c, "BSC_sem_wait"},
{0x40c0440, "BSC_sem_trywait"},
{0x40c0444, "BSC_sem_post"},
{0x40c0448, "BSC_sysctlbyname"},
{0x40c044c, "BSC_obs_sem_init"},
{0x40c0450, "BSC_obs_sem_destroy"},
{0x40c0454, "BSC_open_extended"},
{0x40c0458, "BSC_umask_extended"},
{0x40c045c, "BSC_stat_extended"},
{0x40c0460, "BSC_lstat_extended"},
{0x40c0464, "BSC_fstat_extended"},
{0x40c0468, "BSC_chmod_extended"},
{0x40c046c, "BSC_fchmod_extended"},
{0x40c0470, "BSC_access_extended"},
{0x40c0474, "BSC_settid"},
{0x40c0478, "BSC_gettid"},
{0x40c047c, "BSC_setsgroups"},
{0x40c0480, "BSC_getsgroups"},
{0x40c0484, "BSC_setwgroups"},
{0x40c0488, "BSC_getwgroups"},
{0x40c048c, "BSC_mkfifo_extended"},
{0x40c0490, "BSC_mkdir_extended"},
{0x40c0494, "BSC_identitysvc"},
{0x40c0498, "BSC_shared_region_check_np"},
{0x40c049c, "BSC_obs_shared_region_map_np"},
{0x40c04a0, "BSC_vm_pressure_monitor"},
{0x40c04a4, "BSC_psynch_rw_longrdlock"},
{0x40c04a8, "BSC_psynch_rw_yieldwrlock"},
{0x40c04ac, "BSC_psynch_rw_downgrade"},
{0x40c04b0, "BSC_psynch_rw_upgrade"},
{0x40c04b4, "BSC_psynch_mutexwait"},
{0x40c04b8, "BSC_psynch_mutexdrop"},
{0x40c04bc, "BSC_psynch_cvbroad"},
{0x40c04c0, "BSC_psynch_cvsignal"},
{0x40c04c4, "BSC_psynch_cvwait"},
{0x40c04c8, "BSC_psynch_rw_rdlock"},
{0x40c04cc, "BSC_psynch_rw_wrlock"},
{0x40c04d0, "BSC_psynch_rw_unlock"},
{0x40c04d4, "BSC_psynch_rw_unlock2"},
{0x40c04d8, "BSC_getsid"},
{0x40c04dc, "BSC_settid_with_pid"},
{0x40c04e0, "BSC_psynch_cvclrprepost"},
{0x40c04e4, "BSC_aio_fsync"},
{0x40c04e8, "BSC_aio_return"},
{0x40c04ec, "BSC_aio_suspend"},
{0x40c04f0, "BSC_aio_cancel"},
{0x40c04f4, "BSC_aio_error"},
{0x40c04f8, "BSC_aio_read"},
{0x40c04fc, "BSC_aio_write"},
{0x40c0500, "BSC_lio_listio"},
{0x40c0504, "BSC_obs___pthread_cond_wait"},
{0x40c0508, "BSC_iopolicysys"},
{0x40c050c, "BSC_process_policy"},
{0x40c0510, "BSC_mlockall"},
{0x40c0514, "BSC_munlockall"},
{0x40c0518, "BSC_#326"},
{0x40c051c, "BSC_issetugid"},
{0x40c0520, "BSC_pthread_kill"},
{0x40c0524, "BSC_pthread_sigmask"},
{0x40c0528, "BSC_sigwait"},
{0x40c052c, "BSC_disable_threadsignal"},
{0x40c0530, "BSC_pthread_markcancel"},
{0x40c0534, "BSC_pthread_canceled"},
{0x40c0538, "BSC_semwait_signal"},
{0x40c053c, "BSC_obs_utrace"},
{0x40c0540, "BSC_proc_info"},
{0x40c0544, "BSC_sendfile"},
{0x40c0548, "BSC_stat64"},
{0x40c054c, "BSC_fstat64"},
{0x40c0550, "BSC_lstat64"},
{0x40c0554, "BSC_stat64_extended"},
{0x40c0558, "BSC_lstat64_extended"},
{0x40c055c, "BSC_fstat64_extended"},
{0x40c0560, "BSC_getdirentries64"},
{0x40c0564, "BSC_statfs64"},
{0x40c0568, "BSC_fstatfs64"},
{0x40c056c, "BSC_getfsstat64"},
{0x40c0570, "BSC_pthread_chdir"},
{0x40c0574, "BSC_pthread_fchdir"},
{0x40c0578, "BSC_audit"},
{0x40c057c, "BSC_auditon"},
{0x40c0580, "BSC_#352"},
{0x40c0584, "BSC_getauid"},
{0x40c0588, "BSC_setauid"},
{0x40c058c, "BSC_obs_getaudit"},
{0x40c0590, "BSC_obs_setaudit"},
{0x40c0594, "BSC_getaudit_addr"},
{0x40c0598, "BSC_setaudit_addr"},
{0x40c059c, "BSC_auditctl"},
{0x40c05a0, "BSC_bsdthread_create"},
{0x40c05a4, "BSC_bsdthread_terminate"},
{0x40c05a8, "BSC_kqueue"},
{0x40c05ac, "BSC_kevent"},
{0x40c05b0, "BSC_lchown"},
{0x40c05b4, "BSC_obs_stack_snapshot"},
{0x40c05b8, "BSC_bsdthread_register"},
{0x40c05bc, "BSC_workq_open"},
{0x40c05c0, "BSC_workq_kernreturn"},
{0x40c05c4, "BSC_kevent64"},
{0x40c05c8, "BSC_old_semwait_signal"},
{0x40c05cc, "BSC_old_semwait_signal_nocancel"},
{0x40c05d0, "BSC_thread_selfid"},
{0x40c05d4, "BSC_ledger"},
{0x40c05d8, "BSC_kevent_qos"},
{0x40c05dc, "BSC_kevent_id"},
{0x40c05e0, "BSC_#376"},
{0x40c05e4, "BSC_#377"},
{0x40c05e8, "BSC_#378"},
{0x40c05ec, "BSC_#379"},
{0x40c05f0, "BSC_mac_execve"},
{0x40c05f4, "BSC_mac_syscall"},
{0x40c05f8, "BSC_mac_get_file"},
{0x40c05fc, "BSC_mac_set_file"},
{0x40c0600, "BSC_mac_get_link"},
{0x40c0604, "BSC_mac_set_link"},
{0x40c0608, "BSC_mac_get_proc"},
{0x40c060c, "BSC_mac_set_proc"},
{0x40c0610, "BSC_mac_get_fd"},
{0x40c0614, "BSC_mac_set_fd"},
{0x40c0618, "BSC_mac_get_pid"},
{0x40c061c, "BSC_#391"},
{0x40c0620, "BSC_#392"},
{0x40c0624, "BSC_#393"},
{0x40c0628, "BSC_pselect"},
{0x40c062c, "BSC_pselect_nocancel"},
{0x40c0630, "BSC_read_nocancel"},
{0x40c0634, "BSC_write_nocancel"},
{0x40c0638, "BSC_open_nocancel"},
{0x40c063c, "BSC_close_nocancel"},
{0x40c0640, "BSC_wait4_nocancel"},
{0x40c0644, "BSC_recvmsg_nocancel"},
{0x40c0648, "BSC_sendmsg_nocancel"},
{0x40c064c, "BSC_recvfrom_nocancel"},
{0x40c0650, "BSC_accept_nocancel"},
{0x40c0654, "BSC_msync_nocancel"},
{0x40c0658, "BSC_fcntl_nocancel"},
{0x40c065c, "BSC_select_nocancel"},
{0x40c0660, "BSC_fsync_nocancel"},
{0x40c0664, "BSC_connect_nocancel"},
{0x40c0668, "BSC_sigsuspend_nocancel"},
{0x40c066c, "BSC_readv_nocancel"},
{0x40c0670, "BSC_writev_nocancel"},
{0x40c0674, "BSC_sendto_nocancel"},
{0x40c0678, "BSC_pread_nocancel"},
{0x40c067c, "BSC_pwrite_nocancel"},
{0x40c0680, "BSC_waitid_nocancel"},
{0x40c0684, "BSC_poll_nocancel"},
{0x40c0688, "BSC_msgsnd_nocancel"},
{0x40c068c, "BSC_msgrcv_nocancel"},
{0x40c0690, "BSC_sem_wait_nocancel"},
{0x40c0694, "BSC_aio_suspend_nocancel"},
{0x40c0698, "BSC_sigwait_nocancel"},
{0x40c069c, "BSC_semwait_signal_nocancel"},
{0x40c06a0, "BSC_mac_mount"},
{0x40c06a4, "BSC_mac_get_mount"},
{0x40c06a8, "BSC_mac_getfsstat"},
{0x40c06ac, "BSC_fsgetpath"},
{0x40c06b0, "BSC_audit_session_self"},
{0x40c06b4, "BSC_audit_session_join"},
{0x40c06b8, "BSC_fileport_makeport"},
{0x40c06bc, "BSC_fileport_makefd"},
{0x40c06c0, "BSC_audit_session_port"},
{0x40c06c4, "BSC_pid_suspend"},
{0x40c06c8, "BSC_pid_resume"},
{0x40c06cc, "BSC_pid_hibernate"},
{0x40c06d0, "BSC_pid_shutdown_sockets"},
{0x40c06d4, "BSC_obs_shared_region_slide_np"},
{0x40c06d8, "BSC_shared_region_map_and_slide_np"},
{0x40c06dc, "BSC_kas_info"},
{0x40c06e0, "BSC_memorystatus_control"},
{0x40c06e4, "BSC_guarded_open_np"},
{0x40c06e8, "BSC_guarded_close_np"},
{0x40c06ec, "BSC_guarded_kqueue_np"},
{0x40c06f0, "BSC_change_fdguard_np"},
{0x40c06f4, "BSC_usrctl"},
{0x40c06f8, "BSC_proc_rlimit_control"},
{0x40c06fc, "BSC_connectx"},
{0x40c0700, "BSC_disconnectx"},
{0x40c0704, "BSC_peeloff"},
{0x40c0708, "BSC_socket_delegate"},
{0x40c070c, "BSC_telemetry"},
{0x40c0710, "BSC_proc_uuid_policy"},
{0x40c0714, "BSC_memorystatus_get_level"},
{0x40c0718, "BSC_system_override"},
{0x40c071c, "BSC_vfs_purge"},
{0x40c0720, "BSC_sfi_ctl"},
{0x40c0724, "BSC_sfi_pidctl"},
{0x40c0728, "BSC_coalition"},
{0x40c072c, "BSC_coalition_info"},
{0x40c0730, "BSC_necp_match_policy"},
{0x40c0734, "BSC_getattrlistbulk"},
{0x40c0738, "BSC_clonefileat"},
{0x40c073c, "BSC_openat"},
{0x40c0740, "BSC_openat_nocancel"},
{0x40c0744, "BSC_renameat"},
{0x40c0748, "BSC_faccessat"},
{0x40c074c, "BSC_fchmodat"},
{0x40c0750, "BSC_fchownat"},
{0x40c0754, "BSC_fstatat"},
{0x40c0758, "BSC_fstatat64"},
{0x40c075c, "BSC_linkat"},
{0x40c0760, "BSC_unlinkat"},
{0x40c0764, "BSC_readlinkat"},
{0x40c0768, "BSC_symlinkat"},
{0x40c076c, "BSC_mkdirat"},
{0x40c0770, "BSC_getattrlistat"},
{0x40c0774, "BSC_proc_trace_log"},
{0x40c0778, "BSC_bsdthread_ctl"},
{0x40c077c, "BSC_openbyid_np"},
{0x40c0780, "BSC_recvmsg_x"},
{0x40c0784, "BSC_sendmsg_x"},
{0x40c0788, "BSC_thread_selfusage"},
{0x40c078c, "BSC_csrctl"},
{0x40c0790, "BSC_guarded_open_dprotected_np"},
{0x40c0794, "BSC_guarded_write_np"},
{0x40c0798, "BSC_guarded_pwrite_np"},
{0x40c079c, "BSC_guarded_writev_np"},
{0x40c07a0, "BSC_renameatx_np"},
{0x40c07a4, "BSC_mremap_encrypted"},
{0x40c07a8, "BSC_netagent_trigger"},
{0x40c07ac, "BSC_stack_snapshot_with_config"},
{0x40c07b0, "BSC_microstackshot"},
{0x40c07b4, "BSC_grab_pgo_data"},
{0x40c07b8, "BSC_persona"},
{0x40c07bc, "BSC_#495"},
{0x40c07c0, "BSC_#496"},
{0x40c07c4, "BSC_#497"},
{0x40c07c8, "BSC_#498"},
{0x40c07cc, "BSC_work_interval_ctl"},
{0x40c07d0, "BSC_getentropy"},
{0x40c07d4, "BSC_necp_open"},
{0x40c07d8, "BSC_necp_client_action"},
{0x40c07dc, "BSC_#503"},
{0x40c07e0, "BSC_#504"},
{0x40c07e4, "BSC_#505"},
{0x40c07e8, "BSC_#506"},
{0x40c07ec, "BSC_#507"},
{0x40c07f0, "BSC_#508"},
{0x40c07f4, "BSC_#509"},
{0x40c07f8, "BSC_#510"},
{0x40c07fc, "BSC_#511"},
{0x40c0800, "BSC_#512"},
{0x40c0804, "BSC_#513"},
{0x40c0808, "BSC_#514"},
{0x40c080c, "BSC_ulock_wait"},
{0x40c0810, "BSC_ulock_wake"},
{0x40c0814, "BSC_fclonefileat"},
{0x40c0818, "BSC_fs_snapshot"},
{0x40c081c, "BSC_#519"},
{0x40c0820, "BSC_terminate_with_payload"},
{0x40c0824, "BSC_abort_with_payload"},
{0x40c0828, "BSC_necp_session_open"},
{0x40c082c, "BSC_necp_session_action"},
{0x40c0830, "BSC_setattrlistat"},
{0x40c0834, "BSC_net_qos_guideline"},
{0x40c0838, "BSC_fmount"},
{0x40c083c, "BSC_ntp_adjtime"},
{0x40c0840, "BSC_ntp_gettime"},
{0x40c0844, "BSC_os_fault_with_payload"},
{0x40e0104, "BSC_msync_extended_info"},
{0x40e0264, "BSC_pread_extended_info"},
{0x40e0268, "BSC_pwrite_extended_info"},
{0x40e0314, "BSC_mmap_extended_info"},
{0x40f0314, "BSC_mmap_extended_info2"},
{0x5000004, "INTC_Handler"},
{0x5000008, "INTC_Spurious"},
{0x5010004, "WL_CheckForWork"},
{0x5010008, "WL_RunEventSources"},
{0x5020004, "IES_client"},
{0x5020008, "IES_latency"},
{0x502000c, "IES_sema"},
{0x5020010, "IES_intctxt"},
{0x5020014, "IES_intfltr"},
{0x5020018, "IES_action"},
{0x502001c, "IES_filter"},
{0x5030004, "TES_client"},
{0x5030008, "TES_latency"},
{0x503000c, "TES_sema"},
{0x5030010, "TES_action"},
{0x5040004, "CQ_client"},
{0x5040008, "CQ_latency"},
{0x504000c, "CQ_sema"},
{0x5040010, "CQ_psema"},
{0x5040014, "CQ_plock"},
{0x5040018, "CQ_action"},
{0x5070004, "PM_SetParent"},
{0x5070008, "PM_AddChild"},
{0x507000c, "PM_RemoveChild"},
{0x5070010, "PM_CtrlDriver"},
{0x5070014, "PM_CtrlDriverErr1"},
{0x5070018, "PM_CtrlDriverErr2"},
{0x507001c, "PM_CtrlDriverErr3"},
{0x5070020, "PM_CtrlDriverErr4"},
{0x5070024, "PM_InterestDriver"},
{0x5070028, "PM_InterestDriverAckErr1"},
{0x507002c, "PM_ChildAck"},
{0x5070030, "PM_InterestDriverAck"},
{0x5070034, "PM_InterestDriverAckErr2"},
{0x5070038, "PM_InterestDriverAckErr3"},
{0x507003c, "PM_CtrlDriverAckErr4"},
{0x5070040, "PM_CtrlDriverAck"},
{0x5070044, "PM_DomainWillChange"},
{0x5070048, "PM_DomainDidChange"},
{0x507004c, "PM_RequestDomainState"},
{0x5070050, "PM_MakeUsable"},
{0x5070054, "PM_ChangeStateTo"},
{0x5070058, "PM_ChangeStateToPriv"},
{0x507005c, "PM_SetAggressiveness"},
{0x5070060, "PM_CriticalTemp"},
{0x5070064, "PM_OverrideOn"},
{0x5070068, "PM_OverrideOff"},
{0x507006c, "PM_ChangeStateForRoot"},
{0x5070070, "PM_SynchronizeTree"},
{0x5070074, "PM_ChangeDone"},
{0x5070078, "PM_CtrlDriverTardy"},
{0x507007c, "PM_InterestDriverTardy"},
{0x5070080, "PM_StartAckTimer"},
{0x5070084, "PM_StartParentChange"},
{0x5070088, "PM_AmendParentChange"},
{0x507008c, "PM_StartDeviceChange"},
{0x5070090, "PM_RequestDenied"},
{0x5070094, "PM_CtrlDriverErr5"},
{0x5070098, "PM_ProgramHardware"},
{0x507009c, "PM_InformWillChange"},
{0x50700a0, "PM_InformDidChange"},
{0x50700a4, "PM_RemoveDriver"},
{0x50700a8, "PM_SetIdleTimer"},
{0x50700ac, "PM_SystemWake"},
{0x50700b4, "PM_ClientAck"},
{0x50700b8, "PM_ClientTardy"},
{0x50700bc, "PM_ClientCancel"},
{0x50700c0, "PM_ClientNotify"},
{0x50700c4, "PM_AppNotify"},
{0x50700d4, "PM_IdleCancel"},
{0x50700d8, "PM_SleepWakeTracePoint"},
{0x50700dc, "PM_QuiescePowerTree"},
{0x50700e0, "PM_ComponentWakeProgress"},
{0x50700e4, "PM_UserActiveState"},
{0x50700e8, "PM_AppResponseDelay"},
{0x50700ec, "PM_DriverResponseDelay"},
{0x50700f0, "PM_PCIDevChangeStart"},
{0x50700f4, "PM_PCIDevChangeDone"},
{0x50700f8, "PM_SleepWakeMessage"},
{0x50700fc, "PM_DriverPSChangeDelay"},
{0x5080004, "IOSERVICE_BUSY"},
{0x5080008, "IOSERVICE_NONBUSY"},
{0x508000c, "IOSERVICE_MODULESTALL"},
{0x5080010, "IOSERVICE_MODULEUNSTALL"},
{0x5080014, "IOSERVICE_TERM_PHASE1"},
{0x5080018, "IOSERVICE_TERM_REQUEST_OK"},
{0x508001c, "IOSERVICE_TERM_REQUEST_FAIL"},
{0x5080020, "IOSERVICE_TERM_SCHEDULE_STOP"},
{0x5080024, "IOSERVICE_TERM_SCHEDULE_FINALIZE"},
{0x5080028, "IOSERVICE_TERM_WILL"},
{0x508002c, "IOSERVICE_TERM_DID"},
{0x5080030, "IOSERVICE_TERM_DID_DEFER"},
{0x5080034, "IOSERVICE_TERM_FINALIZE"},
{0x5080038, "IOSERVICE_TERM_STOP"},
{0x508003c, "IOSERVICE_TERM_STOP_NOP"},
{0x5080040, "IOSERVICE_TERM_STOP_DEFER"},
{0x5080044, "IOSERVICE_TERM_DONE"},
{0x5080048, "IOSERVICE_KEXTD_ALIVE"},
{0x508004c, "IOSERVICE_KEXTD_READY"},
{0x5080050, "IOSERVICE_REGISTRY_QUIET"},
{0x5230000, "HID_Unexpected"},
{0x5230004, "HID_KeyboardLEDThreadTrigger"},
{0x5230008, "HID_KeyboardLEDThreadActive"},
{0x523000c, "HID_KeyboardSetParam"},
{0x5230010, "HID_KeyboardCapsThreadTrigger"},
{0x5230014, "HID_KeyboardCapsThreadActive"},
{0x5230018, "HID_PostEvent"},
{0x523001c, "HID_NewUserClient"},
{0x5230020, "HID_InturruptReport"},
{0x5230024, "HID_DispatchScroll"},
{0x5230028, "HID_DispatchRelativePointer"},
{0x523002c, "HID_DispatchAbsolutePointer"},
{0x5230030, "HID_DispatchKeyboard"},
{0x5230034, "HID_EjectCallback"},
{0x5230038, "HID_CapsCallback"},
{0x523003c, "HID_HandleReport"},
{0x5230040, "HID_DispatchTabletPointer"},
{0x5230044, "HID_DispatchTabletProx"},
{0x5230048, "HID_DispatchHIDEvent"},
{0x523004c, "HID_CalculateCapsDelay"},
{0x5230050, "HID_Invalid"},
{0x5310004, "CPUPM_PSTATE"},
{0x5310008, "CPUPM_IDLE_CSTATE"},
{0x531000c, "CPUPM_IDLE_HALT"},
{0x5310010, "CPUPM_IDLE_LOOP"},
{0x5310014, "CPUPM_HPET_START"},
{0x5310018, "CPUPM_HPET_END"},
{0x531001c, "CPUPM_HPET_INTR"},
{0x5310020, "CPUPM_PSTATE_HW"},
{0x5310024, "CPUPM_PSTATE_LIMIT"},
{0x5310028, "CPUPM_PSTATE_PARK"},
{0x531002c, "CPUPM_PSTATE_START"},
{0x5310030, "CPUPM_PSTATE_PAUSE"},
{0x5310034, "CPUPM_PSTATE_RESUME"},
{0x5310038, "CPUPM_PSTATE_DOWN"},
{0x531003c, "CPUPM_PSTATE_UP"},
{0x5310040, "CPUPM_PSTATE_NORM"},
{0x5310044, "CPUPM_PSTATE_FORCE"},
{0x5310048, "CPUPM_PSTATE_TIMEOUT"},
{0x531004c, "CPUPM_PSTATE_SETTO"},
{0x5310050, "CPUPM_SET_DEADLINE"},
{0x5310054, "CPUPM_GET_DEADLINE"},
{0x5310058, "CPUPM_DEADLINE"},
{0x531005c, "CPUPM_IDLE_SNOOP"},
{0x5310060, "CPUPM_IDLE_LATENCY"},
{0x5310064, "CPUPM_IDLE_WAKEUP"},
{0x5310068, "CPUPM_IDLE_SW_WAKEUP"},
{0x531006c, "CPUPM_IDLE_SELECT"},
{0x5310070, "CPUPM_IDLE_SELECTED"},
{0x5310074, "CPUPM_IDLE_INTSKIP"},
{0x5310078, "CPUPM_IDLE_LOCK"},
{0x531007c, "CPUPM_IDLE_UNLOCK"},
{0x5310080, "CPUPM_IDLE_NO_HPET"},
{0x5310084, "CPUPM_FI_UP"},
{0x5310088, "CPUPM_FI_UP_CPU"},
{0x531008c, "CPUPM_FI_MP"},
{0x5310090, "CPUPM_FI_MP_CPU"},
{0x5310094, "CPUPM_FI_PAUSE"},
{0x5310098, "CPUPM_FI_RUN"},
{0x531009c, "CPUPM_PROC_HALT"},
{0x53100a0, "CPUPM_TRACE_STOPPED"},
{0x53100a4, "CPUPM_HPET_INT_LOCK"},
{0x53100a8, "CPUPM_HPET_INT_UNLOCK"},
{0x53100ac, "CPUPM_HPET_TRY_AGAIN"},
{0x53100b0, "CPUPM_HPET_SETDEADLINE"},
{0x53100b4, "CPUPM_LOCK_HELDBY"},
{0x53100b8, "CPUPM_HPET_DELTA"},
{0x53100bc, "CPUPM_HPET_TOO_LATE"},
{0x53100c0, "CPUPM_HPET_NO_DEADLINE"},
{0x53100c4, "CPUPM_IDLE"},
{0x53100c8, "CPUPM_CORE_CHK_DEADLINE"},
{0x53100cc, "CPUPM_SET_HPET_DEADLINE"},
{0x53100d0, "CPUPM_HPET_READ"},
{0x53100d4, "CPUPM_TIME_ADJUST"},
{0x53100d8, "CPUPM_IDLE_MWAIT"},
{0x53100dc, "CPUPM_FI_SLAVE_IDLE"},
{0x53100e0, "CPUPM_FI_SLAVE_BLOCK"},
{0x53100e4, "CPUPM_FI_MAST_SIGNAL"},
{0x53100e8, "CPUPM_CORE_DEADLINE"},
{0x53100ec, "CPUPM_IDLE_FAST"},
{0x53100f0, "CPUPM_IDLE_PAUSE"},
{0x53100f4, "CPUPM_IDLE_SHORT"},
{0x53100f8, "CPUPM_IDLE_NORMAL"},
{0x53100fc, "CPUPM_IDLE_SPURIOUS"},
{0x5310100, "CPUPM_PSTATE_INFO"},
{0x5310104, "CPUPM_PSTATE_INFO_HW"},
{0x5310108, "CPUPM_PSTATE_FSM"},
{0x531010c, "CPUPM_PSTATE_FSM_STEP"},
{0x5310110, "CPUPM_PSTATE_FSM_EVAL"},
{0x5310114, "CPUPM_PSTATE_FSM_MAP"},
{0x5310118, "CPUPM_CPUSTEP_STEP"},
{0x531011c, "CPUPM_CPUSTEP_STEP_UP"},
{0x5310120, "CPUPM_CPUSTEP_STEP_DOWN"},
{0x5310124, "CPUPM_CPUSTEP_AVAIL"},
{0x5310128, "CPUPM_CPUSTEP_AVAIL_STEP"},
{0x531012c, "CPUPM_CPUSTEP_AVAIL_CHNG"},
{0x5310130, "CPUPM_CPUSTEP_LOAD"},
{0x5310134, "CPUPM_CPUSTEP_START"},
{0x5310138, "CPUPM_CPUSTEP_STOP"},
{0x531013c, "CPUPM_CPUSTEP_COPY"},
{0x5310140, "CPUPM_CPUSTEP_CLEAR"},
{0x5310144, "CPUPM_CPUSTEP_RUNCOUNT"},
{0x5310148, "CPUPM_CPUSTEP_WAKEUP"},
{0x531014c, "CPUPM_PSTATE_TRACE"},
{0x5310150, "CPUPM_PSTATE_EVENT"},
{0x5310154, "CPUPM_IDLE_RATE"},
{0x5310158, "CPUPM_PSTATE_FSM_RESUME"},
{0x531015c, "CPUPM_PSTATE_FSM_PAUSE"},
{0x5310160, "CPUPM_PSTATE_INSTRUCTION"},
{0x5310164, "CPUPM_PSTATE_INST_ARG"},
{0x5310168, "CPUPM_PSTATE_STACK_PUSH"},
{0x531016c, "CPUPM_PSTATE_STACK_POP"},
{0x5310170, "CPUPM_IDLE_PREFIRE"},
{0x5310174, "CPUPM_PSTATE_VERIFY"},
{0x5310178, "CPUPM_TIMER_MIGRATE"},
{0x531017c, "CPUPM_RING_LIMIT"},
{0x5310180, "CPUPM_CONTEXT_PAUSE"},
{0x5310184, "CPUPM_CONTEXT_RESUME"},
{0x5310188, "CPUPM_CONTEXT_RESUME_INFO"},
{0x531018c, "CPUPM_THREAD_RESUME"},
{0x5310190, "CPUPM_THREAD_PAUSE_INFO"},
{0x5310194, "CPUPM_THREAD_RESUME_INFO"},
{0x5310198, "CPUPM_TEST_MASTER_INFO"},
{0x531019c, "CPUPM_TEST_SLAVE_INFO"},
{0x53101a0, "CPUPM_TEST_INFO"},
{0x53101a4, "CPUPM_TEST_RUN_INFO"},
{0x53101a8, "CPUPM_TEST_SLAVE_INFO"},
{0x53101ac, "CPUPM_FORCED_IDLE"},
{0x53101b4, "CPUPM_PSTATE_CHOOSE"},
{0x53101b8, "CPUPM_PSTATE_COMMIT"},
{0x53101bc, "CPUPM_PSTATE_CHECK"},
{0x5310200, "CPUPM_PST_RESOLVE"},
{0x5310204, "CPUPM_PST_LOAD_TXFR"},
{0x5310208, "CPUPM_PST_IDLE_EXIT"},
{0x531020c, "CPUPM_PST_IDLE_ENTRY"},
{0x5310210, "CPUPM_PST_TIMER"},
{0x5310214, "CPUPM_PST_MAXBUS"},
{0x5310218, "CPUPM_PST_MAXINT"},
{0x531021c, "CPUPM_PST_PLIMIT"},
{0x5310220, "CPUPM_PST_SELFSEL"},
{0x5310224, "CPUPM_PST_RATELIMIT"},
{0x5310228, "CPUPM_PST_RATEUNLIMIT"},
{0x531022c, "CPUPM_DVFS_PAUSE"},
{0x5310230, "CPUPM_DVFS_RESUME"},
{0x5310234, "CPUPM_DVFS_ADVANCE"},
{0x5310238, "CPUPM_DVFS_TRANSIT"},
{0x531023c, "CPUPM_TQM"},
{0x5310240, "CPUPM_QUIESCE"},
{0x5310244, "CPUPM_MBD"},
{0x5310248, "CPUPM_PST_RATELIMIT_QOS"},
{0x531024c, "CPUPM_PST_QOS_RATEUNLIMIT"},
{0x5310250, "CPUPM_PST_QOS_SWITCH"},
{0x5310254, "CPUPM_FORCED_IDLE"},
{0x5310258, "CPUPM_PST_RAW_PERF"},
{0x531025c, "CPUPM_CPU_HALT_DEEP"},
{0x5310260, "CPUPM_CPU_HALT"},
{0x5310264, "CPUPM_CPU_OFFLINE"},
{0x5310268, "CPUPM_CPU_EXIT_HALT"},
{0x531026c, "CPUPM_PST_QOS_CHARGE"},
{0x5310270, "CPUPM_PST_QOS_APPLY"},
{0x5310274, "CPUPM_PST_QOS_SWITCH2"},
{0x5310278, "CPUPM_PST_UIB"},
{0x531027c, "CPUPM_PST_PLIMIT_UIB"},
{0x5310280, "CPUPM_IO"},
{0x5310284, "CPUPM_FI"},
{0x5330000, "HIBERNATE"},
{0x5330004, "HIBERNATE_WRITE_IMAGE"},
{0x5330008, "HIBERNATE_MACHINE_INIT"},
{0x533000c, "HIBERNATE_FLUSH_MEMORY"},
{0x5330010, "HIBERNATE_flush_queue"},
{0x5330014, "HIBERNATE_flush_wait"},
{0x5330018, "HIBERNATE_flush_in_progress"},
{0x533001c, "HIBERNATE_flush_bufs"},
{0x5330020, "HIBERNATE_page_list_setall"},
{0x5330024, "HIBERNATE_aes_decrypt_cbc"},
{0x5330028, "HIBERNATE_flush_compressor"},
{0x533002c, "HIBERNATE_fastwake_warmup"},
{0x5330030, "HIBERNATE_teardown"},
{0x5330034, "HIBERNATE_rebuild"},
{0x5330038, "HIBERNATE_stats"},
{0x533003c, "HIBERNATE_idle_kernel"},
{0x5350000, "BOOTER_timestamps"},
{0x7000004, "TRACE_DATA_NEWTHREAD"},
{0x7000008, "TRACE_DATA_EXEC"},
{0x700000c, "TRACE_DATA_THREAD_TERMINATE"},
{0x7000010, "TRACE_DATA_THREAD_TERMINATE_PID"},
{0x7010000, "TRACE_STRING_GLOBAL"},
{0x7010004, "TRACE_STRING_NEWTHREAD"},
{0x7010008, "TRACE_STRING_EXEC"},
{0x701000c, "TRACE_STRING_PROC_EXIT"},
{0x7010010, "TRACE_STRING_THREADNAME"},
{0x7020000, "TRACE_PANIC"},
{0x7020004, "TRACE_TIMESTAMPS"},
{0x7020008, "TRACE_LOST_EVENTS"},
{0x702000c, "TRACE_WRITING_EVENTS"},
{0x7020010, "TRACE_INFO_STRING"},
{0x7020014, "TRACE_RETROGRADE_EVENTS"},
{0x8000000, "USER_TEST"},
{0x8000004, "USER_run"},
{0x8000008, "USER_join"},
{0x800000c, "USER_create"},
{0x8000010, "USER_pthread_create"},
{0x8000014, "USER_pthread_exit"},
{0x8000018, "USER_pthread_join"},
{0x800001c, "USER_pthread_run"},
{0x8000020, "USER_pthread_cleanup_push"},
{0x8000100, "FW_underrun"},
{0x8000104, "FW_interrupt"},
{0x8000108, "FW_workloop"},
{0x8010400, "F_DLIL_Input"},
{0x8010800, "F_DLIL_Output"},
{0x8010c00, "F_DLIL_IfOut"},
{0x8040000, "USER_STOP"},
{0x9000084, "wq_deallocate_stack"},
{0x9000088, "wq_allocate_stack"},
{0x9008070, "wq_run_item"},
{0x9008074, "wq_clean_thread"},
{0x9008078, "wq_post_done"},
{0x900807c, "wq_stk_cleanup"},
{0x9008080, "wq_tsd_cleanup"},
{0x9008084, "wq_tsd_destructor"},
{0x9008088, "wq_pthread_exit"},
{0x900808c, "wq_workqueue_exit"},
{0xa000100, "P_CS_Read"},
{0xa000104, "P_CS_ReadDone"},
{0xa000110, "P_CS_Write"},
{0xa000114, "P_CS_WriteDone"},
{0xa000200, "P_CS_ReadChunk"},
{0xa000204, "P_CS_ReadChunkDone"},
{0xa000210, "P_CS_WriteChunk"},
{0xa000214, "P_CS_WriteChunkDone"},
{0xa000300, "P_CS_ReadMeta"},
{0xa000304, "P_CS_ReadMetaDone"},
{0xa000310, "P_CS_WriteMeta"},
{0xa000314, "P_CS_WriteMetaDone"},
{0xa000400, "P_CS_ReadCrypto"},
{0xa000404, "P_CS_ReadCryptoDone"},
{0xa000410, "P_CS_WriteCrypto"},
{0xa000414, "P_CS_WriteCryptoDone"},
{0xa000500, "P_CS_TransformRead"},
{0xa000504, "P_CS_TransformReadDone"},
{0xa000510, "P_CS_TransformWrite"},
{0xa000514, "P_CS_TransformWriteDone"},
{0xa000600, "P_CS_MigrationRead"},
{0xa000604, "P_CS_MigrationReadDone"},
{0xa000610, "P_CS_MigrationWrite"},
{0xa000614, "P_CS_MigrationWriteDone"},
{0xa000700, "P_CS_DirectRead"},
{0xa000704, "P_CS_DirectReadDone"},
{0xa000710, "P_CS_DirectWrite"},
{0xa000714, "P_CS_DirectWriteDone"},
{0xa008000, "P_CS_SYNC_DISK"},
{0xa008004, "P_CS_WaitForBuffer"},
{0xa008008, "P_CS_NoBuffer"},
{0xc010000, "MT_InstrsCycles"},
{0xc010004, "MT_InsCyc_CPU_CSwitch"},
{0xcfe0000, "MT_TmpThread"},
{0xcff0000, "MT_TmpCPU"},
{0x11000000, "DNC_PURGE1"},
{0x11000004, "DNC_PURGE2"},
{0x11000008, "DNC_FOUND"},
{0x1100000c, "DNC_FAILED"},
{0x11000010, "DNC_ENTER"},
{0x11000014, "DNC_remove_name"},
{0x11000018, "DNC_ENTER_CREATE"},
{0x1100001c, "DNC_update_identity"},
{0x11000020, "DNC_PURGE"},
{0x11000030, "DNC_LOOKUP_PATH"},
{0x11000038, "NAMEI"},
{0x11000048, "VFS_SUSPENDED"},
{0x1100004c, "VFS_CACHEPURGE"},
{0x11000050, "VFS_CACHELOOKUP_SUCCESS"},
{0x11000054, "VFS_CACHELOOKUP_FAILED"},
{0x11000058, "VFS_CACHELOOKUP_ENTER"},
{0x1100005c, "VFS_CACHELOOKUP"},
{0x11000060, "VFS_GETIOCOUNT"},
{0x11000064, "VFS_vnode_recycle"},
{0x11000068, "VFS_vnode_reclaim"},
{0x11000080, "VOLFS_lookup"},
{0x11000084, "lookup_mountedhere"},
{0x11000088, "VNOP_LOOKUP"},
{0x11000090, "VFS_vnode_rele"},
{0x11000094, "VFS_vnode_put"},
{0x11004100, "NC_lock_shared"},
{0x11004104, "NC_lock_exclusive"},
{0x11004108, "NC_unlock"},
{0x1e000000, "SEC_ENTROPY_READ0"},
{0x1e000004, "SEC_ENTROPY_READ1"},
{0x1e000008, "SEC_ENTROPY_READ2"},
{0x1e00000c, "SEC_ENTROPY_READ3"},
{0x1f000000, "DYLD_initialize"},
{0x1f010000, "DYLD_CALL_image_init_routine"},
{0x1f010004, "DYLD_CALL_dependent_init_routine"},
{0x1f010008, "DYLD_CALL_lazy_init_routine"},
{0x1f01000c, "DYLD_CALL_module_init_for_library"},
{0x1f010010, "DYLD_CALL_module_init_for_object"},
{0x1f010014, "DYLD_CALL_module_terminator_for_object"},
{0x1f010018, "DYLD_CALL_module_init_for_dylib"},
{0x1f01001c, "DYLD_CALL_mod_term_func"},
{0x1f010020, "DYLD_CALL_object_func"},
{0x1f010024, "DYLD_CALL_library_func"},
{0x1f010028, "DYLD_CALL_add_image_func"},
{0x1f01002c, "DYLD_CALL_remove_image_func"},
{0x1f010030, "DYLD_CALL_link_object_module_func"},
{0x1f010034, "DYLD_CALL_link_library_module_func"},
{0x1f010038, "DYLD_CALL_link_module_func"},
{0x1f020000, "DYLD_lookup_and_bind_with_hint"},
{0x1f020004, "DYLD_lookup_and_bind_fully"},
{0x1f020008, "DYLD_link_module"},
{0x1f02000c, "DYLD_ulink_module"},
{0x1f020010, "DYLD_bind_objc_module"},
{0x1f020014, "DYLD_bind_fully_image_containing_address"},
{0x1f020018, "DYLD_make_delayed_module_initializer_calls"},
{0x1f02001c, "DYLD_NSNameOfSymbol"},
{0x1f020020, "DYLD_NSAddressOfSymbol"},
{0x1f020024, "DYLD_NSModuleForSymbol"},
{0x1f020028, "DYLD_NSLookupAndBindSymbolWithHint"},
{0x1f02002c, "DYLD_NSLookupSymbolInModule"},
{0x1f020030, "DYLD_NSLookupSymbolInImage"},
{0x1f020034, "DYLD_NSIsSymbolNameDefined"},
{0x1f020038, "DYLD_NSIsSymbolNameDefinedWithHint"},
{0x1f02003c, "DYLD_NSIsSymbolNameDefinedInImage"},
{0x1f020040, "DYLD_NSNameOfModule"},
{0x1f020044, "DYLD_NSLibraryNameForModule"},
{0x1f020048, "DYLD_NSAddLibrary"},
{0x1f02004c, "DYLD_NSAddLibraryWithSearching"},
{0x1f020050, "DYLD_NSAddImage"},
{0x1f030000, "DYLD_lookup_symbol"},
{0x1f030004, "DYLD_bind_lazy_symbol_reference"},
{0x1f030008, "DYLD_bind_symbol_by_name"},
{0x1f03000c, "DYLD_link_in_need_modules"},
{0x1f040000, "DYLD_map_image"},
{0x1f040004, "DYLD_load_executable_image"},
{0x1f040008, "DYLD_load_library_image"},
{0x1f04000c, "DYLD_map_library_image"},
{0x1f040010, "DYLD_map_bundle_image"},
{0x1f040014, "DYLD_load_dependent_libraries"},
{0x1f040018, "DYLD_notify_prebinding_agent"},
{0x1f050000, "DYLD_uuid_map_a"},
{0x1f050004, "DYLD_uuid_map_b"},
{0x1f050008, "DYLD_uuid_map_32_a"},
{0x1f05000c, "DYLD_uuid_map_32_b"},
{0x1f050010, "DYLD_uuid_map_32_c"},
{0x1f050014, "DYLD_uuid_unmap_a"},
{0x1f050018, "DYLD_uuid_unmap_b"},
{0x1f05001c, "DYLD_uuid_unmap_32_a"},
{0x1f050020, "DYLD_uuid_unmap_32_b"},
{0x1f050024, "DYLD_uuid_unmap_32_c"},
{0x1f050028, "DYLD_uuid_shared_cache_a"},
{0x1f05002c, "DYLD_uuid_shared_cache_b"},
{0x1f050030, "DYLD_uuid_shared_cache_32_a"},
{0x1f050034, "DYLD_uuid_shared_cache_32_b"},
{0x1f050038, "DYLD_uuid_shared_cache_32_c"},
{0x1ff10000, "SCROLL_BEGIN_obs"},
{0x1ff10100, "SCROLL_END_obs"},
{0x1ff20000, "BOOT_BEGIN_obs"},
{0x1ff20100, "BOOT_END_obs"},
{0x1ff20400, "APP_DidActivateWindow_obs"},
{0x1ff20500, "TOOL_PRIVATE_1_obs"},
{0x1ff20504, "TOOL_PRIVATE_2_obs"},
{0x1ff20508, "TOOL_PRIVATE_3_obs"},
{0x1ff2050c, "TOOL_PRIVATE_4_obs"},
{0x1fff0000, "LAUNCH_START_FINDER"},
{0x1fff0100, "LAUNCH_START_DOCK"},
{0x1fff0200, "LAUNCH_LSOpen"},
{0x1fff0204, "LAUNCH_LSRegisterItem"},
{0x1fff0208, "LAUNCH_LSGetApplicationAndFlagsForInfo"},
{0x1fff0300, "LAUNCH_CPSLaunch"},
{0x1fff0304, "LAUNCH_CPSRegisterwithServer"},
{0x1fff0308, "LAUNCH_CGSCheckInNewProcess"},
{0x1fff030c, "LAUNCH_CPSExecProcess"},
{0x1fff0310, "LAUNCH_APP_EnterEventLoop"},
{0x1fff0314, "LAUNCH_APP_WillOpenUntitled"},
{0x1fff031c, "LAUNCH_APP_DidOpenUntitled"},
{0x1fff1000, "LAUNCH_END"},
{0x1fffffff, "LAUNCH_END"},
{0x20000004, "RTC_sync_TBR"},
{0x21010000, "SCROLL_BEGIN"},
{0x21020000, "BOOT_BEGIN"},
{0x21040000, "APP_AudioOverload"},
{0x21050000, "TOOL_PRIVATE_1"},
{0x21050004, "TOOL_PRIVATE_2"},
{0x21050008, "TOOL_PRIVATE_3"},
{0x2105000c, "TOOL_PRIVATE_4"},
{0x21060000, "LAUNCH_CPSTraceLineNum"},
{0x21060004, "LAUNCH_CPSLaunch"},
{0x21060008, "LAUNCH_CPSRegisterwithServer"},
{0x2106000c, "LAUNCH_CPSCheckInNewProcess"},
{0x21060010, "LAUNCH_CPSServerSideLaunch"},
{0x21060014, "LAUNCH_CPSExecProcess"},
{0x21070000, "LAUNCH_LSOpen"},
{0x21070004, "LAUNCH_LSRegisterItem"},
{0x21070008, "LAUNCH_LSGetApplicationAndFlagsForInfo"},
{0x21080000, "MCX_DAEMON_START"},
{0x21080004, "MCX_DAEMON_FINISH"},
{0x21080008, "MCX_STARTMCX_START"},
{0x2108000c, "MCX_STARTMCX_FINISH"},
{0x21080010, "MCX_POSTCMP_DOCK_START"},
{0x21080014, "MCX_POSTCMP_DOCK_FINISH"},
{0x21080020, "MCX_POSTCMP_ENERGYSVR_START"},
{0x21080024, "MCX_POSTCMP_ENERGYSVR_FINISH"},
{0x21080030, "MCX_POSTCMP_LOGINITMS_START"},
{0x21080034, "MCX_POSTCMP_LOGINITMS_FINISH"},
{0x21080040, "MCX_CMP_COMPUTERINFO_START"},
{0x21080044, "MCX_CMP_COMPUTERINFO_FINISH"},
{0x21080050, "MCX_CMP_USERINFO_START"},
{0x21080054, "MCX_CMP_USERINFO_FINISH"},
{0x21080060, "MCX_POSTCMP_USER_START"},
{0x21080064, "MCX_POSTCMP_USER_FINISH"},
{0x210800a0, "MCX_MECHANISM_START"},
{0x210800a4, "MCX_MECHANISM_FINISH"},
{0x210800c0, "MCX_MECHANISM_PICKER_START"},
{0x210800c4, "MCX_MECHANISM_PICKER_FINISH"},
{0x21080100, "MCX_APPITEMS_START"},
{0x21080104, "MCX_APPITEMS_FINISH"},
{0x21080200, "MCX_CACHER_START"},
{0x21080204, "MCX_CACHER_FINISH"},
{0x21080300, "MCX_COMPOSITOR_START"},
{0x21080304, "MCX_COMPOSITOR_FINISH"},
{0x21080400, "MCX_DISKSETUP_START"},
{0x21080404, "MCX_DISKSETUP_FINISH"},
{0x21090000, "PHD_DAEMON_START"},
{0x21090004, "PHD_DAEMON_FINISH"},
{0x21090010, "PHD_SYNCNOW_START"},
{0x21090014, "PHD_SYNCNOW_FINISH"},
{0x210b0000, "TAL_APP_LAUNCH_START"},
{0x210b0004, "TAL_APP_LAUNCH_UNSUSPENDED"},
{0x210b0008, "TAL_APP_LAUNCH_UNTHROTTLED"},
{0x210b000c, "TAL_APP_LAUNCH_VISIBLE"},
{0x210b0010, "TAL_APP_LAUNCH_READY"},
{0x210b0014, "TAL_ALL_LAUNCH_READY"},
{0x210c0000, "NSAPPLICATION_RECEIVED_KEYEVENT"},
{0x210c0004, "NSWINDOW_FLUSHED"},
{0x210c0008, "NSTEXTVIEW_PROCESSED_KEYEVENT"},
{0x25000000, "PERF_Event"},
{0x25010000, "PERF_THD_Sample"},
{0x25010004, "PERF_THD_Data"},
{0x25010008, "PERF_THD_XSample"},
{0x2501000c, "PERF_THD_XPend"},
{0x25010010, "PERF_THD_XData"},
{0x25010014, "PERF_THD_CSwitch"},
{0x25010018, "PERF_THD_Sched_Sample"},
{0x2501001c, "PERF_THD_Sched_Data"},
{0x25010020, "PERF_THD_Snap_Sample"},
{0x25010024, "PERF_THD_Snap_Data"},
{0x25010028, "PERF_THD_Disp_Sample"},
{0x2501002c, "PERF_THD_Disp_Data"},
{0x25010030, "PERF_THD_Disp_Pend"},
{0x25010034, "PERF_THD_Snap_Data_32"},
{0x25010038, "PERF_THD_Disp_Data_32"},
{0x2501003c, "PERF_THD_Sched_Data1_32"},
{0x25010040, "PERF_THD_Sched_Data2_32"},
{0x25010044, "PERF_THD_Inscyc_Data"},
{0x25010048, "PERF_THD_Inscyc_Data_32"},
{0x2501004c, "PERF_THD_Sched_Data_2"},
{0x25010050, "PERF_THD_Sched_Data2_32_2"},
{0x25020000, "PERF_STK_KSample"},
{0x25020004, "PERF_STK_USched"},
{0x25020008, "PERF_STK_USample"},
{0x2502000c, "PERF_STK_KData"},
{0x25020010, "PERF_STK_UData"},
{0x25020014, "PERF_STK_KHdr"},
{0x25020018, "PERF_STK_UHdr"},
{0x2502001c, "PERF_STK_Error"},
{0x25020020, "PERF_STK_Backtrace"},
{0x25020024, "PERF_STK_Log"},
{0x25030000, "PERF_TMR_Fire"},
{0x25030004, "PERF_TMR_Schedule"},
{0x25030008, "PERF_TMR_Handler"},
{0x25040000, "PERF_ATS_Thread"},
{0x25040004, "PERF_ATS_Error"},
{0x25040008, "PERF_ATS_Run"},
{0x2504000c, "PERF_ATS_Pause"},
{0x25040010, "PERF_ATS_Idle"},
{0x25040014, "PERF_ATS_Sample"},
{0x25040018, "PERF_PET_Sched"},
{0x2504001c, "PERF_PET_End"},
{0x25040020, "PERF_PET_Sample_Task"},
{0x25040024, "PERF_PET_Sample_Thread"},
{0x25050000, "PERF_AST_Handler"},
{0x25050004, "PERF_AST_Error"},
{0x25060000, "PERF_KPC_Handler"},
{0x25060004, "PERF_KPC_FCounter"},
{0x25060008, "PERF_KPC_Counter"},
{0x2506000c, "PERF_KPC_Data"},
{0x25060010, "PERF_KPC_Config"},
{0x25060014, "PERF_KPC_ConfReg"},
{0x25060018, "PERF_KPC_Data32"},
{0x2506001c, "PERF_KPC_ConfReg32"},
{0x25060020, "PERF_KPC_Data_Thread"},
{0x25060024, "PERF_KPC_Data_Thread32"},
{0x25060028, "PERF_KPC_CPU_Sample"},
{0x2506002c, "PERF_KPC_Thd_Sample"},
{0x25070000, "PERF_KDBG_Handler"},
{0x25080000, "PERF_TK_Snap_Sample"},
{0x25080004, "PERF_TK_Snap_Data1"},
{0x25080008, "PERF_TK_Snap_Data2"},
{0x2508000c, "PERF_TK_Snap_Data1_32"},
{0x25080010, "PERF_TK_Snap_Data2_32"},
{0x250a0000, "PERF_MI_Sample"},
{0x250a0004, "PERF_MI_Data"},
{0x250a0008, "PERF_MI_SysMem_Data"},
{0x26100008, "imp_assertion_hold"},
{0x2610000c, "imp_assertion_hold_ext"},
{0x26100010, "imp_assertion_drop"},
{0x26100014, "imp_assertion_drop_ext"},
{0x26100020, "imp_assertion_externalize"},
{0x26110004, "imp_boost_task"},
{0x26110008, "imp_unboost_task"},
{0x26120004, "imp_msg_send"},
{0x26120008, "imp_msg_delv"},
{0x26130000, "imp_watchport"},
{0x26170000, "imp_suppression_inactive"},
{0x26170004, "imp_suppression_active"},
{0x26180000, "imp_apptype_none"},
{0x26180004, "imp_apptype_int_daemon"},
{0x26180008, "imp_apptype_std_daemon"},
{0x2618000c, "imp_apptype_adapt_daemon"},
{0x26180010, "imp_apptype_bg_daemon"},
{0x26180014, "imp_apptype_default_app"},
{0x26180018, "imp_apptype_tal_app"},
{0x26190010, "imp_update_task"},
{0x26190020, "imp_update_thread"},
{0x261a0000, "imp_usynch_add_override"},
{0x261a0004, "imp_usynch_remove_override"},
{0x261b0000, "imp_donor_update_live_donor"},
{0x261b0004, "imp_donor_init_donor_state"},
{0x261d0000, "imp_sync_ipc_qos_applied"},
{0x261d0004, "imp_sync_ipc_qos_removed"},
{0x261d0008, "imp_sync_ipc_qos_overflow"},
{0x261d000c, "imp_sync_ipc_qos_underflow"},
{0x26210010, "imp_task_int_bg"},
{0x26210014, "imp_task_ext_bg"},
{0x26210020, "imp_thread_int_bg"},
{0x26210024, "imp_thread_ext_bg"},
{0x26220010, "imp_task_int_iopol"},
{0x26220014, "imp_task_ext_iopol"},
{0x26220020, "imp_thread_int_iopol"},
{0x26220024, "imp_thread_ext_iopol"},
{0x26230010, "imp_task_int_io"},
{0x26230014, "imp_task_ext_io"},
{0x26230020, "imp_thread_int_io"},
{0x26230024, "imp_thread_ext_io"},
{0x26240010, "imp_task_int_passive_io"},
{0x26240014, "imp_task_ext_passive_io"},
{0x26240020, "imp_thread_int_passive_io"},
{0x26240024, "imp_thread_ext_passive_io"},
{0x26270018, "imp_task_dbg_iopol"},
{0x26280018, "imp_task_tal"},
{0x26290018, "imp_task_boost"},
{0x262a0018, "imp_task_role"},
{0x262b0018, "imp_task_suppressed_cpu"},
{0x262c0018, "imp_task_terminated"},
{0x262d0018, "imp_task_new_sockets_bg"},
{0x262e0018, "imp_task_lowpri_cpu"},
{0x262f0018, "imp_task_latency_qos"},
{0x26300018, "imp_task_through_qos"},
{0x26310018, "imp_task_watchers_bg"},
{0x26320028, "imp_thread_pidbind_bg"},
{0x26330028, "imp_thread_workq_bg"},
{0x26350028, "imp_thread_qos"},
{0x26360028, "imp_thread_qos_override"},
{0x26380028, "imp_thread_qos_and_relprio"},
{0x263c0028, "imp_thread_qos_promote"},
{0x263d0028, "imp_thread_qos_ipc_override"},
{0x27000000, "PERF_PCEVENT"},
{0x27001000, "PERF_CPU_IDLE"},
{0x27001100, "PERF_CPU_IDLE_TIMER"},
{0x27002000, "PERF_VOLT_CHG_SOC"},
{0x27002010, "PERF_VOLT_CHG_CPU"},
{0x27002020, "PERF_VOLT_CHG_DOM2"},
{0x27002030, "PERF_VOLT_CHG_DOM3"},
{0x27003000, "PERF_PERF_CHG_SOC"},
{0x27003010, "PERF_PERF_CHG_CPU"},
{0x27003020, "PERF_PERF_CHG_DOM2"},
{0x27003030, "PERF_PERF_CHG_DOM3"},
{0x2700a000, "PERF_ARBITER_EVENT"},
{0x2700a100, "PERF_ARBITER_NOTIFY"},
{0x2700a200, "PERF_ARBITER_PERF_SET"},
{0x2700c000, "PERF_CLOCK_GATE"},
{0x2700e000, "PERF_SRAMEMA_DOM0"},
{0x2700e010, "PERF_SRAMEMA_DOM1"},
{0x2700e020, "PERF_SRAMEMA_DOM2"},
{0x2700e030, "PERF_SRAMEMA_DOM3"},
{0x27010100, "PERF_CPU_IDL_ACT_TIME"},
{0x2710a500, "PERF_FB_CONTROLLER"},
{0x2720a500, "PERF_PMC_CONTROLLER"},
{0x2730a500, "PERF_GPU_CONTROLLER"},
{0x2740a500, "PERF_STP_CONTROLLER"},
{0x28100004, "BANK_SETTLE_CPU_TIME"},
{0x28100008, "BANK_SECURE_ORIGINATOR_CHANGED"},
{0x2810000c, "BANK_SETTLE_ENERGY"},
{0x2a100004, "ATM_MIN_CALLED"},
{0x2a100008, "ATM_LINK_LIST_TRIM"},
{0x2a200004, "ATM_VALUE_REPLACED"},
{0x2a200008, "ATM_VALUE_ADDED"},
{0x2a300004, "ATM_VALUE_UNREGISTERED"},
{0x2a300008, "ATM_VALUE_DIFF_MAILBOX"},
{0xff000104, "MSG_mach_notify_port_deleted"},
{0xff000114, "MSG_mach_notify_port_destroyed"},
{0xff000118, "MSG_mach_notify_no_senders"},
{0xff00011c, "MSG_mach_notify_send_once"},
{0xff000120, "MSG_mach_notify_dead_name"},
{0xff0001ec, "MSG_audit_triggers"},
{0xff000320, "MSG_host_info"},
{0xff000324, "MSG_host_kernel_version"},
{0xff000328, "MSG_host_page_size"},
{0xff00032c, "MSG_mach_memory_object_memory_entry"},
{0xff000330, "MSG_host_processor_info"},
{0xff000334, "MSG_host_get_io_master"},
{0xff000338, "MSG_host_get_clock_service"},
{0xff00033c, "MSG_kmod_get_info"},
{0xff000344, "MSG_host_virtual_physical_table_info"},
{0xff000348, "MSG_host_ipc_hash_info"},
{0xff00034c, "MSG_enable_bluebox"},
{0xff000350, "MSG_disable_bluebox"},
{0xff000354, "MSG_processor_set_default"},
{0xff000358, "MSG_processor_set_create"},
{0xff00035c, "MSG_mach_memory_object_memory_entry_64"},
{0xff000360, "MSG_host_statistics"},
{0xff000364, "MSG_host_request_notification"},
{0xff000368, "MSG_host_lockgroup_info"},
{0xff00036c, "MSG_host_statistics64"},
{0xff000370, "MSG_mach_zone_info"},
{0xff000640, "MSG_host_get_boot_info"},
{0xff000644, "MSG_host_reboot"},
{0xff000648, "MSG_host_priv_statistics"},
{0xff00064c, "MSG_host_default_memory_manager"},
{0xff000650, "MSG_vm_wire"},
{0xff000654, "MSG_thread_wire"},
{0xff000658, "MSG_vm_allocate_cpm"},
{0xff00065c, "MSG_host_processors"},
{0xff000660, "MSG_host_get_clock_control"},
{0xff000664, "MSG_kmod_create"},
{0xff000668, "MSG_kmod_destroy"},
{0xff00066c, "MSG_kmod_control"},
{0xff000670, "MSG_host_get_special_port"},
{0xff000674, "MSG_host_set_special_port"},
{0xff000678, "MSG_host_set_exception_ports"},
{0xff00067c, "MSG_host_get_exception_ports"},
{0xff000680, "MSG_host_swap_exception_ports"},
{0xff000684, "MSG_host_load_symbol_table"},
{0xff000688, "MSG_mach_vm_wire"},
{0xff00068c, "MSG_host_processor_sets"},
{0xff000690, "MSG_host_processor_set_priv"},
{0xff000694, "MSG_set_dp_control_port"},
{0xff000698, "MSG_get_dp_control_port"},
{0xff00069c, "MSG_host_set_UNDServer"},
{0xff0006a0, "MSG_host_get_UNDServer"},
{0xff0006a4, "MSG_kext_request"},
{0xff000960, "MSG_host_security_create_task_token"},
{0xff000964, "MSG_host_security_set_task_token"},
{0xff000f9c, "MSG_mach_gss_init_sec_context"},
{0xff000fa0, "MSG_clock_get_time"},
{0xff000fa4, "MSG_clock_get_attributes"},
{0xff000fa8, "MSG_clock_alarm"},
{0xff000fac, "MSG_mach_gss_accept_sec_context_v2"},
{0xff000fb0, "MSG_mach_gss_hold_cred"},
{0xff000fb4, "MSG_mach_gss_unhold_cred"},
{0xff000ffc, "MSG_lockd_request"},
{0xff001000, "MSG_lockd_ping"},
{0xff001004, "MSG_lockd_shutdown"},
{0xff0012c0, "MSG_clock_set_time"},
{0xff0012c4, "MSG_clock_set_attributes"},
{0xff001f40, "MSG_memory_object_get_attributes"},
{0xff001f44, "MSG_memory_object_change_attributes"},
{0xff001f48, "MSG_memory_object_synchronize_completed"},
{0xff001f4c, "MSG_memory_object_lock_request"},
{0xff001f50, "MSG_memory_object_destroy"},
{0xff001f54, "MSG_memory_object_upl_request"},
{0xff001f58, "MSG_memory_object_super_upl_request"},
{0xff001f5c, "MSG_memory_object_cluster_size"},
{0xff001f60, "MSG_memory_object_page_op"},
{0xff001f64, "MSG_memory_object_recover_named"},
{0xff001f68, "MSG_memory_object_release_name"},
{0xff001f6c, "MSG_memory_object_range_op"},
{0xff002008, "MSG_upl_abort"},
{0xff00200c, "MSG_upl_abort_range"},
{0xff002010, "MSG_upl_commit"},
{0xff002014, "MSG_upl_commit_range"},
{0xff002260, "MSG_memory_object_init"},
{0xff002264, "MSG_memory_object_terminate"},
{0xff002268, "MSG_memory_object_data_request"},
{0xff00226c, "MSG_memory_object_data_return"},
{0xff002270, "MSG_memory_object_data_initialize"},
{0xff002274, "MSG_memory_object_data_unlock"},
{0xff002278, "MSG_memory_object_synchronize"},
{0xff00227c, "MSG_memory_object_map"},
{0xff002280, "MSG_memory_object_last_unmap"},
{0xff002284, "MSG_memory_object_data_reclaim"},
{0xff002328, "MSG_memory_object_create"},
{0xff00238c, "MSG_default_pager_object_create"},
{0xff002390, "MSG_default_pager_info"},
{0xff002394, "MSG_default_pager_objects"},
{0xff002398, "MSG_default_pager_object_pages"},
{0xff0023a0, "MSG_default_pager_backing_store_create"},
{0xff0023a4, "MSG_default_pager_backing_store_delete"},
{0xff0023a8, "MSG_default_pager_backing_store_info"},
{0xff0023ac, "MSG_default_pager_add_file"},
{0xff0023b0, "MSG_default_pager_triggers"},
{0xff0023b4, "MSG_default_pager_info_64"},
{0xff0023dc, "MSG_default_pager_space_alert"},
{0xff002584, "MSG_exception_raise"},
{0xff002588, "MSG_exception_raise_state"},
{0xff00258c, "MSG_exception_raise_state_identity"},
{0xff002594, "MSG_mach_exception_raise"},
{0xff002598, "MSG_mach_exception_raise_state"},
{0xff00259c, "MSG_mach_exception_raise_state_identity"},
{0xff002bc0, "MSG_io_object_get_class"},
{0xff002bc4, "MSG_io_object_conforms_to"},
{0xff002bc8, "MSG_io_iterator_next"},
{0xff002bcc, "MSG_io_iterator_reset"},
{0xff002bd0, "MSG_io_service_get_matching_services"},
{0xff002bd4, "MSG_io_registry_entry_get_property"},
{0xff002bd8, "MSG_io_registry_create_iterator"},
{0xff002bdc, "MSG_io_registry_iterator_enter_entry"},
{0xff002be0, "MSG_io_registry_iterator_exit_entry"},
{0xff002be4, "MSG_io_registry_entry_from_path"},
{0xff002be8, "MSG_io_registry_entry_get_name"},
{0xff002bec, "MSG_io_registry_entry_get_properties"},
{0xff002bf0, "MSG_io_registry_entry_get_property_bytes"},
{0xff002bf4, "MSG_io_registry_entry_get_child_iterator"},
{0xff002bf8, "MSG_io_registry_entry_get_parent_iterator"},
{0xff002c00, "MSG_io_service_close"},
{0xff002c04, "MSG_io_connect_get_service"},
{0xff002c08, "MSG_io_connect_set_notification_port"},
{0xff002c0c, "MSG_io_connect_map_memory"},
{0xff002c10, "MSG_io_connect_add_client"},
{0xff002c14, "MSG_io_connect_set_properties"},
{0xff002c18, "MSG_io_connect_method_scalarI_scalarO"},
{0xff002c1c, "MSG_io_connect_method_scalarI_structureO"},
{0xff002c20, "MSG_io_connect_method_scalarI_structureI"},
{0xff002c24, "MSG_io_connect_method_structureI_structureO"},
{0xff002c28, "MSG_io_registry_entry_get_path"},
{0xff002c2c, "MSG_io_registry_get_root_entry"},
{0xff002c30, "MSG_io_registry_entry_set_properties"},
{0xff002c34, "MSG_io_registry_entry_in_plane"},
{0xff002c38, "MSG_io_object_get_retain_count"},
{0xff002c3c, "MSG_io_service_get_busy_state"},
{0xff002c40, "MSG_io_service_wait_quiet"},
{0xff002c44, "MSG_io_registry_entry_create_iterator"},
{0xff002c48, "MSG_io_iterator_is_valid"},
{0xff002c50, "MSG_io_catalog_send_data"},
{0xff002c54, "MSG_io_catalog_terminate"},
{0xff002c58, "MSG_io_catalog_get_data"},
{0xff002c5c, "MSG_io_catalog_get_gen_count"},
{0xff002c60, "MSG_io_catalog_module_loaded"},
{0xff002c64, "MSG_io_catalog_reset"},
{0xff002c68, "MSG_io_service_request_probe"},
{0xff002c6c, "MSG_io_registry_entry_get_name_in_plane"},
{0xff002c70, "MSG_io_service_match_property_table"},
{0xff002c74, "MSG_io_async_method_scalarI_scalarO"},
{0xff002c78, "MSG_io_async_method_scalarI_structureO"},
{0xff002c7c, "MSG_io_async_method_scalarI_structureI"},
{0xff002c80, "MSG_io_async_method_structureI_structureO"},
{0xff002c84, "MSG_io_service_add_notification"},
{0xff002c88, "MSG_io_service_add_interest_notification"},
{0xff002c8c, "MSG_io_service_acknowledge_notification"},
{0xff002c90, "MSG_io_connect_get_notification_semaphore"},
{0xff002c94, "MSG_io_connect_unmap_memory"},
{0xff002c98, "MSG_io_registry_entry_get_location_in_plane"},
{0xff002c9c, "MSG_io_registry_entry_get_property_recursively"},
{0xff002ca0, "MSG_io_service_get_state"},
{0xff002ca4, "MSG_io_service_get_matching_services_ool"},
{0xff002ca8, "MSG_io_service_match_property_table_ool"},
{0xff002cac, "MSG_io_service_add_notification_ool"},
{0xff002cb0, "MSG_io_object_get_superclass"},
{0xff002cb4, "MSG_io_object_get_bundle_identifier"},
{0xff002cb8, "MSG_io_service_open_extended"},
{0xff002cbc, "MSG_io_connect_map_memory_into_task"},
{0xff002cc0, "MSG_io_connect_unmap_memory_from_task"},
{0xff002cc4, "MSG_io_connect_method"},
{0xff002cc8, "MSG_io_connect_async_method"},
{0xff002ccc, "MSG_io_connect_set_notification_port_64"},
{0xff002cd0, "MSG_io_service_add_notification_64"},
{0xff002cd4, "MSG_io_service_add_interest_notification_64"},
{0xff002cd8, "MSG_io_service_add_notification_ool_64"},
{0xff002cdc, "MSG_io_registry_entry_get_registry_entry_id"},
{0xff002ee0, "MSG_processor_start"},
{0xff002ee4, "MSG_processor_exit"},
{0xff002ee8, "MSG_processor_info"},
{0xff002eec, "MSG_processor_control"},
{0xff002ef0, "MSG_processor_assign"},
{0xff002ef4, "MSG_processor_get_assignment"},
{0xff003200, "MSG_mach_port_names"},
{0xff003204, "MSG_mach_port_type"},
{0xff003208, "MSG_mach_port_rename"},
{0xff00320c, "MSG_mach_port_allocate_name"},
{0xff003210, "MSG_mach_port_allocate"},
{0xff003214, "MSG_mach_port_destroy"},
{0xff003218, "MSG_mach_port_deallocate"},
{0xff00321c, "MSG_mach_port_get_refs"},
{0xff003220, "MSG_mach_port_mod_refs"},
{0xff003228, "MSG_mach_port_set_mscount"},
{0xff00322c, "MSG_mach_port_get_set_status"},
{0xff003230, "MSG_mach_port_move_member"},
{0xff003234, "MSG_mach_port_request_notification"},
{0xff003238, "MSG_mach_port_insert_right"},
{0xff00323c, "MSG_mach_port_extract_right"},
{0xff003240, "MSG_mach_port_set_seqno"},
{0xff003244, "MSG_mach_port_get_attributes"},
{0xff003248, "MSG_mach_port_set_attributes"},
{0xff00324c, "MSG_mach_port_allocate_qos"},
{0xff003250, "MSG_mach_port_allocate_full"},
{0xff003254, "MSG_task_set_port_space"},
{0xff003258, "MSG_mach_port_get_srights"},
{0xff00325c, "MSG_mach_port_space_info"},
{0xff003260, "MSG_mach_port_dnrequest_info"},
{0xff003264, "MSG_mach_port_kernel_object"},
{0xff003268, "MSG_mach_port_insert_member"},
{0xff00326c, "MSG_mach_port_extract_member"},
{0xff003270, "MSG_mach_port_get_context"},
{0xff003274, "MSG_mach_port_set_context"},
{0xff003278, "MSG_mach_port_kobject"},
{0xff003520, "MSG_task_create"},
{0xff003524, "MSG_task_terminate"},
{0xff003528, "MSG_task_threads"},
{0xff00352c, "MSG_mach_ports_register"},
{0xff003530, "MSG_mach_ports_lookup"},
{0xff003534, "MSG_task_info"},
{0xff003538, "MSG_task_set_info"},
{0xff00353c, "MSG_task_suspend"},
{0xff003540, "MSG_task_resume"},
{0xff003544, "MSG_task_get_special_port"},
{0xff003548, "MSG_task_set_special_port"},
{0xff00354c, "MSG_thread_create"},
{0xff003550, "MSG_thread_create_running"},
{0xff003554, "MSG_task_set_exception_ports"},
{0xff003558, "MSG_task_get_exception_ports"},
{0xff00355c, "MSG_task_swap_exception_ports"},
{0xff003560, "MSG_lock_set_create"},
{0xff003564, "MSG_lock_set_destroy"},
{0xff003568, "MSG_semaphore_create"},
{0xff00356c, "MSG_semaphore_destroy"},
{0xff003570, "MSG_task_policy_set"},
{0xff003574, "MSG_task_policy_get"},
{0xff003578, "MSG_task_sample"},
{0xff00357c, "MSG_task_policy"},
{0xff003580, "MSG_task_set_emulation"},
{0xff003584, "MSG_task_get_emulation_vector"},
{0xff003588, "MSG_task_set_emulation_vector"},
{0xff00358c, "MSG_task_set_ras_pc"},
{0xff003590, "MSG_task_zone_info"},
{0xff003594, "MSG_task_assign"},
{0xff003598, "MSG_task_assign_default"},
{0xff00359c, "MSG_task_get_assignment"},
{0xff0035a0, "MSG_task_set_policy"},
{0xff0035a4, "MSG_task_get_state"},
{0xff0035a8, "MSG_task_set_state"},
{0xff003840, "MSG_thread_terminate"},
{0xff003844, "MSG_act_get_state"},
{0xff003848, "MSG_act_set_state"},
{0xff00384c, "MSG_thread_get_state"},
{0xff003850, "MSG_thread_set_state"},
{0xff003854, "MSG_thread_suspend"},
{0xff003858, "MSG_thread_resume"},
{0xff00385c, "MSG_thread_abort"},
{0xff003860, "MSG_thread_abort_safely"},
{0xff003864, "MSG_thread_depress_abort"},
{0xff003868, "MSG_thread_get_special_port"},
{0xff00386c, "MSG_thread_set_special_port"},
{0xff003870, "MSG_thread_info"},
{0xff003874, "MSG_thread_set_exception_ports"},
{0xff003878, "MSG_thread_get_exception_ports"},
{0xff00387c, "MSG_thread_swap_exception_ports"},
{0xff003880, "MSG_thread_policy"},
{0xff003884, "MSG_thread_policy_set"},
{0xff003888, "MSG_thread_policy_get"},
{0xff00388c, "MSG_thread_sample"},
{0xff003890, "MSG_etap_trace_thread"},
{0xff003894, "MSG_thread_assign"},
{0xff003898, "MSG_thread_assign_default"},
{0xff00389c, "MSG_thread_get_assignment"},
{0xff0038a0, "MSG_thread_set_policy"},
{0xff003b60, "MSG_vm_region"},
{0xff003b64, "MSG_vm_allocate"},
{0xff003b68, "MSG_vm_deallocate"},
{0xff003b6c, "MSG_vm_protect"},
{0xff003b70, "MSG_vm_inherit"},
{0xff003b74, "MSG_vm_read"},
{0xff003b78, "MSG_vm_read_list"},
{0xff003b7c, "MSG_vm_write"},
{0xff003b80, "MSG_vm_copy"},
{0xff003b84, "MSG_vm_read_overwrite"},
{0xff003b88, "MSG_vm_msync"},
{0xff003b8c, "MSG_vm_behavior_set"},
{0xff003b90, "MSG_vm_map"},
{0xff003b94, "MSG_vm_machine_attribute"},
{0xff003b98, "MSG_vm_remap"},
{0xff003b9c, "MSG_task_wire"},
{0xff003ba0, "MSG_mach_make_memory_entry"},
{0xff003ba4, "MSG_vm_map_page_query"},
{0xff003ba8, "MSG_mach_vm_region_info"},
{0xff003bac, "MSG_vm_mapped_pages_info"},
{0xff003bb4, "MSG_vm_region_recurse"},
{0xff003bb8, "MSG_vm_region_recurse_64"},
{0xff003bbc, "MSG_mach_vm_region_info_64"},
{0xff003bc0, "MSG_vm_region_64"},
{0xff003bc4, "MSG_mach_make_memory_entry_64"},
{0xff003bc8, "MSG_vm_map_64"},
{0xff003bcc, "MSG_vm_map_get_upl"},
{0xff003bd8, "MSG_vm_purgable_control"},
{0xff003e80, "MSG_processor_set_statistics"},
{0xff003e84, "MSG_processor_set_destroy"},
{0xff003e88, "MSG_processor_set_max_priority"},
{0xff003e8c, "MSG_processor_set_policy_enable"},
{0xff003e90, "MSG_processor_set_policy_disable"},
{0xff003e94, "MSG_processor_set_tasks"},
{0xff003e98, "MSG_processor_set_threads"},
{0xff003e9c, "MSG_processor_set_policy_control"},
{0xff003ea0, "MSG_processor_set_stack_usage"},
{0xff003ea4, "MSG_processor_set_info"},
{0xff004b00, "MSG_mach_vm_allocate"},
{0xff004b04, "MSG_mach_vm_deallocate"},
{0xff004b08, "MSG_mach_vm_protect"},
{0xff004b0c, "MSG_mach_vm_inherit"},
{0xff004b10, "MSG_mach_vm_read"},
{0xff004b14, "MSG_mach_vm_read_list"},
{0xff004b18, "MSG_mach_vm_write"},
{0xff004b1c, "MSG_mach_vm_copy"},
{0xff004b20, "MSG_mach_vm_read_overwrite"},
{0xff004b24, "MSG_mach_vm_msync"},
{0xff004b28, "MSG_mach_vm_behavior_set"},
{0xff004b2c, "MSG_mach_vm_map"},
{0xff004b30, "MSG_mach_vm_machine_attribute"},
{0xff004b34, "MSG_mach_vm_remap"},
{0xff004b38, "MSG_mach_vm_page_query"},
{0xff004b3c, "MSG_mach_vm_region_recurse"},
{0xff004b40, "MSG_mach_vm_region"},
{0xff004b44, "MSG__mach_make_memory_entry"},
{0xff004b48, "MSG_mach_vm_purgable_control"},
{0xff004b4c, "MSG_mach_vm_page_info"},
{0xff004e20, "MSG_ledger_create"},
{0xff004e24, "MSG_ledger_terminate"},
{0xff004e28, "MSG_ledger_transfer"},
{0xff004e2c, "MSG_ledger_read"},
{0xff005140, "MSG_mach_get_task_label"},
{0xff005144, "MSG_mach_get_task_label_text"},
{0xff005148, "MSG_mach_get_label"},
{0xff00514c, "MSG_mach_get_label_text"},
{0xff005150, "MSG_mach_set_port_label"},
{0xff005154, "MSG_mac_check_service"},
{0xff005158, "MSG_mac_port_check_service_obj"},
{0xff00515c, "MSG_mac_port_check_access"},
{0xff005160, "MSG_mac_label_new"},
{0xff005164, "MSG_mac_request_label"},
{0xff005dc0, "MSG_UNDExecute_rpc"},
{0xff005dc4, "MSG_UNDDisplayNoticeFromBundle_rpc"},
{0xff005dc8, "MSG_UNDDisplayAlertFromBundle_rpc"},
{0xff005dcc, "MSG_UNDDisplayCustomFromBundle_rpc"},
{0xff005dd0, "MSG_UNDDisplayCustomFromDictionary_rpc"},
{0xff005dd4, "MSG_UNDCancelNotification_rpc"},
{0xff005dd8, "MSG_UNDDisplayNoticeSimple_rpc"},
{0xff005ddc, "MSG_UNDDisplayAlertSimple_rpc"},
{0xff0060e0, "MSG_UNDAlertCompletedWithResult_rpc"},
{0xff0060e4, "MSG_UNDNotificationCreated_rpc"},
{0xff01a5e0, "MSG_check_task_access"},
{0xff01a5e4, "MSG_find_code_signature"},
{0xff04b320, "MSG_kextd_ping"},
{0xff25a8a0, "MSG_lock_acquire"},
{0xff25a8a4, "MSG_lock_release"},
{0xff25a8a8, "MSG_lock_try"},
{0xff25a8ac, "MSG_lock_make_stable"},
{0xff25a8b0, "MSG_lock_handoff"},
{0xff25a8b4, "MSG_lock_handoff_accept"},
{0xff25abc0, "MSG_semaphore_signal"},
{0xff25abc4, "MSG_semaphore_signal_all"},
{0xff25abc8, "MSG_semaphore_wait"},
{0xff25abcc, "MSG_semaphore_signal_thread"},
{0xff25abd0, "MSG_semaphore_timedwait"},
{0xff25abd4, "MSG_semaphore_wait_signal"},
{0xff25abd8, "MSG_semaphore_timedwait_signal"},
{0xffbebdcc, "MSG_clock_alarm_reply"},
};
struct ntptimeval {
struct timespec time;
long maxerror;
long esterror;
long tai;
int time_state;
};
struct timex {
unsigned int modes;
long offset;
long freq;
long maxerror;
long esterror;
int status;
long constant;
long precision;
long tolerance;
long ppsfreq;
long jitter;
int shift;
long stabil;
long jitcnt;
long calcnt;
long errcnt;
long stbcnt;
};
struct mbstat {
u_int32_t m_mbufs;
u_int32_t m_clusters;
u_int32_t m_spare;
u_int32_t m_clfree;
u_int32_t m_drops;
u_int32_t m_wait;
u_int32_t m_drain;
u_short m_mtypes[256];
u_int32_t m_mcfail;
u_int32_t m_mpfail;
u_int32_t m_msize;
u_int32_t m_mclbytes;
u_int32_t m_minclsize;
u_int32_t m_mlen;
u_int32_t m_mhlen;
u_int32_t m_bigclusters;
u_int32_t m_bigclfree;
u_int32_t m_bigmclbytes;
};
struct ombstat {
u_int32_t m_mbufs;
u_int32_t m_clusters;
u_int32_t m_spare;
u_int32_t m_clfree;
u_int32_t m_drops;
u_int32_t m_wait;
u_int32_t m_drain;
u_short m_mtypes[256];
u_int32_t m_mcfail;
u_int32_t m_mpfail;
u_int32_t m_msize;
u_int32_t m_mclbytes;
u_int32_t m_minclsize;
u_int32_t m_mlen;
u_int32_t m_mhlen;
};
typedef struct mb_class_stat {
char mbcl_cname[15 + 1];
u_int32_t mbcl_size;
u_int32_t mbcl_total;
u_int32_t mbcl_active;
u_int32_t mbcl_infree;
u_int32_t mbcl_slab_cnt;
u_int32_t mbcl_pad;
u_int64_t mbcl_alloc_cnt;
u_int64_t mbcl_free_cnt;
u_int64_t mbcl_notified;
u_int64_t mbcl_purge_cnt;
u_int64_t mbcl_fail_cnt;
u_int32_t mbcl_ctotal;
u_int32_t mbcl_release_cnt;
u_int32_t mbcl_mc_state;
u_int32_t mbcl_mc_cached;
u_int32_t mbcl_mc_waiter_cnt;
u_int32_t mbcl_mc_wretry_cnt;
u_int32_t mbcl_mc_nwretry_cnt;
u_int32_t mbcl_peak_reported;
u_int32_t mbcl_reserved[7];
} mb_class_stat_t;
typedef struct mb_stat {
u_int32_t mbs_cnt;
u_int32_t mbs_pad;
mb_class_stat_t mbs_class[1];
} mb_stat_t;
typedef unsigned long msgqnum_t;
typedef unsigned long msglen_t;
struct __msqid_ds_new
{
struct ipc_perm msg_perm;
__int32_t msg_first;
__int32_t msg_last;
msglen_t msg_cbytes;
msgqnum_t msg_qnum;
msglen_t msg_qbytes;
pid_t msg_lspid;
pid_t msg_lrpid;
time_t msg_stime;
__int32_t msg_pad1;
time_t msg_rtime;
__int32_t msg_pad2;
time_t msg_ctime;
__int32_t msg_pad3;
__int32_t msg_pad4[4];
};
struct __msqid_ds_old {
struct __ipc_perm_old msg_perm;
__int32_t msg_first;
__int32_t msg_last;
msglen_t msg_cbytes;
msgqnum_t msg_qnum;
msglen_t msg_qbytes;
pid_t msg_lspid;
pid_t msg_lrpid;
time_t msg_stime;
__int32_t msg_pad1;
time_t msg_rtime;
__int32_t msg_pad2;
time_t msg_ctime;
__int32_t msg_pad3;
__int32_t msg_pad4[4];
};
typedef user_ulong_t user_msgqnum_t;
typedef user64_ulong_t user64_msgqnum_t;
typedef user32_ulong_t user32_msgqnum_t;
typedef user_ulong_t user_msglen_t;
typedef user64_ulong_t user64_msglen_t;
typedef user32_ulong_t user32_msglen_t;
struct user_msqid_ds {
struct ipc_perm msg_perm;
struct msg *msg_first;
struct msg *msg_last;
user_msglen_t msg_cbytes;
user_msgqnum_t msg_qnum;
user_msglen_t msg_qbytes;
pid_t msg_lspid;
pid_t msg_lrpid;
user_time_t msg_stime;
__int32_t msg_pad1;
user_time_t msg_rtime;
__int32_t msg_pad2;
user_time_t msg_ctime;
__int32_t msg_pad3;
__int32_t msg_pad4[4];
};
struct user64_msqid_ds {
struct ipc_perm msg_perm;
__int32_t msg_first;
__int32_t msg_last;
user64_msglen_t msg_cbytes;
user64_msgqnum_t msg_qnum;
user64_msglen_t msg_qbytes;
pid_t msg_lspid;
pid_t msg_lrpid;
user64_time_t msg_stime;
__int32_t msg_pad1;
user64_time_t msg_rtime;
__int32_t msg_pad2;
user64_time_t msg_ctime;
__int32_t msg_pad3;
__int32_t msg_pad4[4];
} ;
struct user32_msqid_ds
{
struct ipc_perm msg_perm;
__int32_t msg_first;
__int32_t msg_last;
user32_msglen_t msg_cbytes;
user32_msgqnum_t msg_qnum;
user32_msglen_t msg_qbytes;
pid_t msg_lspid;
pid_t msg_lrpid;
user32_time_t msg_stime;
__int32_t msg_pad1;
user32_time_t msg_rtime;
__int32_t msg_pad2;
user32_time_t msg_ctime;
__int32_t msg_pad3;
__int32_t msg_pad4[4];
};
struct label;
struct msqid_kernel {
struct user_msqid_ds u;
struct label *label;
};
struct msg {
struct msg *msg_next;
long msg_type;
unsigned short msg_ts;
short msg_spot;
struct label *label;
};
struct mymsg {
long mtype;
char mtext[1];
};
struct msginfo {
int msgmax,
msgmni,
msgmnb,
msgtql,
msgssz,
msgseg;
};
extern struct msginfo msginfo;
struct msgmap {
short next;
};
extern char *msgpool;
extern struct msgmap *msgmaps;
extern struct msg *msghdrs;
extern struct msqid_kernel *msqids;
int select(int, fd_set *, fd_set *,
fd_set *, struct timeval *)

;
struct vnop_advlock_args;
struct vnode;
struct locklist { struct lockf *tqh_first; struct lockf **tqh_last; } ;
struct lockf {
short lf_flags;
short lf_type;
off_t lf_start;
off_t lf_end;
caddr_t lf_id;
struct lockf **lf_head;
struct vnode *lf_vnode;
struct lockf *lf_next;
struct locklist lf_blkhd;
struct { struct lockf *tqe_next; struct lockf **tqe_prev; } lf_block;
struct proc *lf_owner;
};
struct label;
struct pshminfo {
unsigned int pshm_flags;
unsigned int pshm_usecount;
off_t pshm_length;
mode_t pshm_mode;
uid_t pshm_uid;
gid_t pshm_gid;
char pshm_name[31 + 1];
void * pshm_memobject;
struct label * pshm_label;
};
typedef unsigned short shmatt_t;
struct __shmid_ds_new
{
struct ipc_perm shm_perm;
size_t shm_segsz;
pid_t shm_lpid;
pid_t shm_cpid;
shmatt_t shm_nattch;
time_t shm_atime;
time_t shm_dtime;
time_t shm_ctime;
void *shm_internal;
};
struct __shmid_ds_old {
struct __ipc_perm_old shm_perm;
size_t shm_segsz;
pid_t shm_lpid;
pid_t shm_cpid;
shmatt_t shm_nattch;
time_t shm_atime;
time_t shm_dtime;
time_t shm_ctime;
void *shm_internal;
};
int unicode_combinable(u_int16_t character);
int unicode_decomposeable(u_int16_t character);
size_t
utf8_encodelen(const u_int16_t * ucsp, size_t ucslen, u_int16_t altslash,
int flags);
int
utf8_encodestr(const u_int16_t * ucsp, size_t ucslen, u_int8_t * utf8p,
size_t * utf8len, size_t buflen, u_int16_t altslash, int flags);
int
utf8_decodestr(const u_int8_t* utf8p, size_t utf8len, u_int16_t* ucsp,
size_t *ucslen, size_t buflen, u_int16_t altslash, int flags);
int
utf8_normalizestr(const u_int8_t* instr, size_t inlen, u_int8_t* outstr,
size_t *outlen, size_t buflen, int flags);
int
utf8_validatestr(const u_int8_t* utf8p, size_t utf8len);
int xattr_protected(const char *);
int xattr_validatename(const char *);
struct ctl_event_data {
u_int32_t ctl_id;
u_int32_t ctl_unit;
};
struct ctl_info {
u_int32_t ctl_id;
char ctl_name[96];
};
struct sockaddr_ctl {
u_char sc_len;
u_char sc_family;
u_int16_t ss_sysaddr;
u_int32_t sc_id;
u_int32_t sc_unit;
u_int32_t sc_reserved[5];
};
typedef void * kern_ctl_ref;
typedef errno_t (*ctl_connect_func)(kern_ctl_ref kctlref,
struct sockaddr_ctl *sac,
void **unitinfo);
typedef errno_t (*ctl_disconnect_func)(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
typedef errno_t (*ctl_send_func)(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
mbuf_t m, int flags);
typedef errno_t (*ctl_setopt_func)(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
int opt, void *data, size_t len);
typedef errno_t (*ctl_getopt_func)(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
int opt, void *data, size_t *len);
struct kern_ctl_reg
{
char ctl_name[96];
u_int32_t ctl_id;
u_int32_t ctl_unit;
u_int32_t ctl_flags;
u_int32_t ctl_sendsize;
u_int32_t ctl_recvsize;
ctl_connect_func ctl_connect;
ctl_disconnect_func ctl_disconnect;
ctl_send_func ctl_send;
ctl_setopt_func ctl_setopt;
ctl_getopt_func ctl_getopt;
};
errno_t
ctl_register(struct kern_ctl_reg *userkctl, kern_ctl_ref *kctlref);
errno_t
ctl_deregister(kern_ctl_ref kctlref);
errno_t
ctl_enqueuedata(kern_ctl_ref kctlref, u_int32_t unit, void *data, size_t len, u_int32_t flags);
errno_t
ctl_enqueuembuf(kern_ctl_ref kctlref, u_int32_t unit, mbuf_t m, u_int32_t flags);
errno_t
ctl_getenqueuespace(kern_ctl_ref kctlref, u_int32_t unit, size_t *space);
errno_t
ctl_getenqueuereadable(kern_ctl_ref kctlref, u_int32_t unit, u_int32_t *difference);
struct cpu_disklabel {
int cd_dummy;
};
struct disklabel {
u_int32_t d_magic;
u_int16_t d_type;
u_int16_t d_subtype;
char d_typename[16];
union {
char un_d_packname[16];
struct {
char *un_d_boot0;
char *un_d_boot1;
} un_b;
} d_un;
u_int32_t d_secsize;
u_int32_t d_nsectors;
u_int32_t d_ntracks;
u_int32_t d_ncylinders;
u_int32_t d_secpercyl;
u_int32_t d_secperunit;
u_int16_t d_sparespertrack;
u_int16_t d_sparespercyl;
u_int32_t d_acylinders;
u_int16_t d_rpm;
u_int16_t d_interleave;
u_int16_t d_trackskew;
u_int16_t d_cylskew;
u_int32_t d_headswitch;
u_int32_t d_trkseek;
u_int32_t d_flags;
u_int32_t d_drivedata[5];
u_int32_t d_spare[5];
u_int32_t d_magic2;
u_int16_t d_checksum;
u_int16_t d_npartitions;
u_int32_t d_bbsize;
u_int32_t d_sbsize;
struct partition {
u_int32_t p_size;
u_int32_t p_offset;
u_int32_t p_fsize;
u_int8_t p_fstype;
u_int8_t p_frag;
union {
u_int16_t cpg;
u_int16_t sgs;
} __partition_u1;
} d_partitions[8];
};
struct format_op {
char *df_buf;
int df_count;
daddr_t df_startblk;
int df_reg[8];
};
struct partinfo {
struct disklabel *disklab;
struct partition *part;
};
typedef unsigned long tcflag_t;
typedef unsigned char cc_t;
typedef unsigned long speed_t;
struct termios {
tcflag_t c_iflag;
tcflag_t c_oflag;
tcflag_t c_cflag;
tcflag_t c_lflag;
cc_t c_cc[20];
speed_t c_ispeed;
speed_t c_ospeed;
};
typedef __uint64_t user_tcflag_t;
typedef __uint64_t user_speed_t;
struct user_termios {
user_tcflag_t c_iflag;
user_tcflag_t c_oflag;
user_tcflag_t c_cflag;
user_tcflag_t c_lflag;
cc_t c_cc[20];
user_speed_t c_ispeed ;
user_speed_t c_ospeed;
};
struct termios32 {
__uint32_t c_iflag;
__uint32_t c_oflag;
__uint32_t c_cflag;
__uint32_t c_lflag;
cc_t c_cc[20];
__uint32_t c_ispeed;
__uint32_t c_ospeed;
};
struct eventreq {
int er_type;
int er_handle;
void *er_data;
int er_rcnt;
int er_wcnt;
int er_ecnt;
int er_eventbits;
};
typedef struct eventreq *er_t;
struct sockaddr;
enum {
SFLT_GLOBAL = 0x01,
SFLT_PROG = 0x02,
SFLT_EXTENDED = 0x04,
SFLT_EXTENDED_REGISTRY = 0x08
};
typedef u_int32_t sflt_flags;
typedef u_int32_t sflt_handle;
enum {
sock_evt_connecting = 1,
sock_evt_connected = 2,
sock_evt_disconnecting = 3,
sock_evt_disconnected = 4,
sock_evt_flush_read = 5,
sock_evt_shutdown = 6,
sock_evt_cantrecvmore = 7,
sock_evt_cantsendmore = 8,
sock_evt_closing = 9,
sock_evt_bound = 10
};
typedef u_int32_t sflt_event_t;
enum {
sock_data_filt_flag_oob = 1,
sock_data_filt_flag_record = 2
};
typedef u_int32_t sflt_data_flag_t;
typedef void (*sf_unregistered_func)(sflt_handle handle);
typedef errno_t (*sf_attach_func)(void **cookie, socket_t so);
typedef void (*sf_detach_func)(void *cookie, socket_t so);
typedef void (*sf_notify_func)(void *cookie, socket_t so, sflt_event_t event,
void *param);
typedef int (*sf_getpeername_func)(void *cookie, socket_t so,
struct sockaddr **sa);
typedef int (*sf_getsockname_func)(void *cookie, socket_t so,
struct sockaddr **sa);
typedef errno_t (*sf_data_in_func)(void *cookie, socket_t so,
const struct sockaddr *from, mbuf_t *data, mbuf_t *control,
sflt_data_flag_t flags);
typedef errno_t (*sf_data_out_func)(void *cookie, socket_t so,
const struct sockaddr *to, mbuf_t *data, mbuf_t *control,
sflt_data_flag_t flags);
typedef errno_t (*sf_connect_in_func)(void *cookie, socket_t so,
const struct sockaddr *from);
typedef errno_t (*sf_connect_out_func)(void *cookie, socket_t so,
const struct sockaddr *to);
typedef errno_t (*sf_bind_func)(void *cookie, socket_t so,
const struct sockaddr *to);
typedef errno_t (*sf_setoption_func)(void *cookie, socket_t so, sockopt_t opt);
typedef errno_t (*sf_getoption_func)(void *cookie, socket_t so, sockopt_t opt);
typedef errno_t (*sf_listen_func)(void *cookie, socket_t so);
typedef errno_t (*sf_ioctl_func)(void *cookie, socket_t so,
unsigned long request, const char* argp);
typedef errno_t (*sf_accept_func)(void *cookie, socket_t so_listen, socket_t so,
const struct sockaddr *local, const struct sockaddr *remote);
struct sflt_filter {
sflt_handle sf_handle;
int sf_flags;
char *sf_name;
sf_unregistered_func sf_unregistered;
sf_attach_func sf_attach;
sf_detach_func sf_detach;
sf_notify_func sf_notify;
sf_getpeername_func sf_getpeername;
sf_getsockname_func sf_getsockname;
sf_data_in_func sf_data_in;
sf_data_out_func sf_data_out;
sf_connect_in_func sf_connect_in;
sf_connect_out_func sf_connect_out;
sf_bind_func sf_bind;
sf_setoption_func sf_setoption;
sf_getoption_func sf_getoption;
sf_listen_func sf_listen;
sf_ioctl_func sf_ioctl;
struct sflt_filter_ext {
unsigned int sf_ext_len;
sf_accept_func sf_ext_accept;
void *sf_ext_rsvd[5];
} sf_ext;
};
extern errno_t sflt_register(const struct sflt_filter *filter, int domain,
int type, int protocol);
extern errno_t sflt_unregister(sflt_handle handle);
extern errno_t sflt_attach(socket_t socket, sflt_handle handle);
extern errno_t sflt_detach(socket_t socket, sflt_handle handle);
extern errno_t sock_inject_data_in(socket_t so, const struct sockaddr *from,
mbuf_t data, mbuf_t control, sflt_data_flag_t flags);
extern errno_t sock_inject_data_out(socket_t so, const struct sockaddr *to,
mbuf_t data, mbuf_t control, sflt_data_flag_t flags);
enum {
sockopt_get = 1,
sockopt_set = 2
};
typedef u_int8_t sockopt_dir;
extern sockopt_dir sockopt_direction(sockopt_t sopt);
extern int sockopt_level(sockopt_t sopt);
extern int sockopt_name(sockopt_t sopt);
extern size_t sockopt_valsize(sockopt_t sopt);
extern errno_t sockopt_copyin(sockopt_t sopt, void *data, size_t length);
extern errno_t sockopt_copyout(sockopt_t sopt, void *data, size_t length);
off_t ubc_blktooff(struct vnode *, daddr64_t);
daddr64_t ubc_offtoblk(struct vnode *, off_t);
off_t ubc_getsize(struct vnode *);
int ubc_setsize(struct vnode *, off_t);
kauth_cred_t ubc_getcred(struct vnode *);
struct thread;
int ubc_setthreadcred(struct vnode *, struct proc *, struct thread *);
errno_t ubc_msync(vnode_t, off_t, off_t, off_t *, int);
int ubc_pages_resident(vnode_t);
int ubc_page_op(vnode_t, off_t, int, ppnum_t *, int *);
int ubc_range_op(vnode_t, off_t, off_t, int, int *);
int advisory_read(vnode_t, off_t, off_t, int);
int advisory_read_ext(vnode_t, off_t, off_t, int, int (*)(buf_t, void *), void *, int);
int cluster_read(vnode_t, struct uio *, off_t, int);
int cluster_read_ext(vnode_t, struct uio *, off_t, int, int (*)(buf_t, void *), void *);
int cluster_write(vnode_t, struct uio *, off_t, off_t, off_t, off_t, int);
int cluster_write_ext(vnode_t, struct uio *, off_t, off_t, off_t, off_t, int, int (*)(buf_t, void *), void *);
int cluster_pageout(vnode_t, upl_t, upl_offset_t, off_t, int, off_t, int);
int cluster_pageout_ext(vnode_t, upl_t, upl_offset_t, off_t, int, off_t, int, int (*)(buf_t, void *), void *);
int cluster_pagein(vnode_t, upl_t, upl_offset_t, off_t, int, off_t, int);
int cluster_pagein_ext(vnode_t, upl_t, upl_offset_t, off_t, int, off_t, int, int (*)(buf_t, void *), void *);
int cluster_push(vnode_t, int);
int cluster_push_ext(vnode_t, int, int (*)(buf_t, void *), void *);
int cluster_push_err(vnode_t, int, int (*)(buf_t, void *), void *, int *);
int cluster_bp(buf_t);
int cluster_bp_ext(buf_t, int (*)(buf_t, void *), void *);
void cluster_zero(upl_t, upl_offset_t, int, buf_t);
int cluster_copy_upl_data(uio_t, upl_t, int, int *);
int cluster_copy_ubc_data(vnode_t, uio_t, int *, int);
typedef struct cl_direct_read_lock cl_direct_read_lock_t;
cl_direct_read_lock_t *cluster_lock_direct_read(vnode_t vp, lck_rw_type_t exclusive);
void cluster_unlock_direct_read(cl_direct_read_lock_t *lck);
int ubc_create_upl(vnode_t, off_t, int, upl_t *, upl_page_info_t **, int);
int ubc_upl_map(upl_t, vm_offset_t *);
int ubc_upl_unmap(upl_t);
int ubc_upl_commit(upl_t);
int ubc_upl_commit_range(upl_t, upl_offset_t, upl_size_t, int);
int ubc_upl_abort(upl_t, int);
int ubc_upl_abort_range(upl_t, upl_offset_t, upl_size_t, int);
void ubc_upl_range_needed(upl_t, int, int);
upl_page_info_t *ubc_upl_pageinfo(upl_t);
upl_size_t ubc_upl_maxbufsize(void);
int is_file_clean(vnode_t, off_t);
errno_t mach_to_bsd_errno(kern_return_t mach_err);
typedef struct {
u_int8_t sid_kind;
u_int8_t sid_authcount;
u_int8_t sid_authority[6];
u_int32_t sid_authorities[16];
} ntsid_t;
struct kauth_identity_extlookup {
u_int32_t el_seqno;
u_int32_t el_result;
u_int32_t el_flags;
__darwin_pid_t el_info_pid;
u_int64_t el_extend;
u_int32_t el_info_reserved_1;
uid_t el_uid;
guid_t el_uguid;
u_int32_t el_uguid_valid;
ntsid_t el_usid;
u_int32_t el_usid_valid;
gid_t el_gid;
guid_t el_gguid;
u_int32_t el_gguid_valid;
ntsid_t el_gsid;
u_int32_t el_gsid_valid;
u_int32_t el_member_valid;
u_int32_t el_sup_grp_cnt;
gid_t el_sup_groups[16];
};
struct kauth_cache_sizes {
u_int32_t kcs_group_size;
u_int32_t kcs_id_size;
};
extern kauth_cred_t posix_cred_create(posix_cred_t pcred);
extern posix_cred_t posix_cred_get(kauth_cred_t cred);
extern void posix_cred_label(kauth_cred_t cred, posix_cred_t pcred);
extern int posix_cred_access(kauth_cred_t cred, id_t object_uid, id_t object_gid, mode_t object_mode, mode_t mode_req);
extern uid_t kauth_getuid(void);
extern uid_t kauth_getruid(void);
extern gid_t kauth_getgid(void);
extern kauth_cred_t kauth_cred_get(void);
extern kauth_cred_t kauth_cred_get_with_ref(void);
extern kauth_cred_t kauth_cred_proc_ref(proc_t procp);
extern kauth_cred_t kauth_cred_create(kauth_cred_t cred);
extern void kauth_cred_ref(kauth_cred_t _cred);
extern void kauth_cred_unref(kauth_cred_t *_cred);
extern kauth_cred_t kauth_cred_label_update(kauth_cred_t cred, void *label);
extern int kauth_proc_label_update(struct proc *p, void *label);
extern kauth_cred_t kauth_cred_find(kauth_cred_t cred);
extern uid_t kauth_cred_getuid(kauth_cred_t _cred);
extern uid_t kauth_cred_getruid(kauth_cred_t _cred);
extern uid_t kauth_cred_getsvuid(kauth_cred_t _cred);
extern gid_t kauth_cred_getgid(kauth_cred_t _cred);
extern gid_t kauth_cred_getrgid(kauth_cred_t _cred);
extern gid_t kauth_cred_getsvgid(kauth_cred_t _cred);
extern int kauth_cred_pwnam2guid(char *pwnam, guid_t *guidp);
extern int kauth_cred_grnam2guid(char *grnam, guid_t *guidp);
extern int kauth_cred_guid2pwnam(guid_t *guidp, char *pwnam);
extern int kauth_cred_guid2grnam(guid_t *guidp, char *grnam);
extern int kauth_cred_guid2uid(guid_t *_guid, uid_t *_uidp);
extern int kauth_cred_guid2gid(guid_t *_guid, gid_t *_gidp);
extern int kauth_cred_ntsid2uid(ntsid_t *_sid, uid_t *_uidp);
extern int kauth_cred_ntsid2gid(ntsid_t *_sid, gid_t *_gidp);
extern int kauth_cred_ntsid2guid(ntsid_t *_sid, guid_t *_guidp);
extern int kauth_cred_uid2guid(uid_t _uid, guid_t *_guidp);
extern int kauth_cred_getguid(kauth_cred_t _cred, guid_t *_guidp);
extern int kauth_cred_gid2guid(gid_t _gid, guid_t *_guidp);
extern int kauth_cred_uid2ntsid(uid_t _uid, ntsid_t *_sidp);
extern int kauth_cred_getntsid(kauth_cred_t _cred, ntsid_t *_sidp);
extern int kauth_cred_gid2ntsid(gid_t _gid, ntsid_t *_sidp);
extern int kauth_cred_guid2ntsid(guid_t *_guid, ntsid_t *_sidp);
extern int kauth_cred_ismember_gid(kauth_cred_t _cred, gid_t _gid, int *_resultp);
extern int kauth_cred_ismember_guid(kauth_cred_t _cred, guid_t *_guidp, int *_resultp);
extern int kauth_cred_nfs4domain2dsnode(char *nfs4domain, char *dsnode);
extern int kauth_cred_dsnode2nfs4domain(char *dsnode, char *nfs4domain);
extern int groupmember(gid_t gid, kauth_cred_t cred);
extern int kauth_cred_issuser(kauth_cred_t _cred);
extern guid_t kauth_null_guid;
extern int kauth_guid_equal(guid_t *_guid1, guid_t *_guid2);
typedef u_int32_t kauth_ace_rights_t;
struct kauth_ace {
guid_t ace_applicable;
u_int32_t ace_flags;
kauth_ace_rights_t ace_rights;
};
struct kauth_acl {
u_int32_t acl_entrycount;
u_int32_t acl_flags;
struct kauth_ace acl_ace[1];
};
kauth_acl_t kauth_acl_alloc(int size);
void kauth_acl_free(kauth_acl_t fsp);
struct kauth_filesec {
u_int32_t fsec_magic;
guid_t fsec_owner;
guid_t fsec_group;
struct kauth_acl fsec_acl;
};
struct kauth_scope;
typedef struct kauth_scope *kauth_scope_t;
struct kauth_listener;
typedef struct kauth_listener *kauth_listener_t;
typedef int (* kauth_scope_callback_t)(kauth_cred_t _credential,
void *_idata,
kauth_action_t _action,
uintptr_t _arg0,
uintptr_t _arg1,
uintptr_t _arg2,
uintptr_t _arg3);
struct kauth_acl_eval {
kauth_ace_t ae_acl;
int ae_count;
kauth_ace_rights_t ae_requested;
kauth_ace_rights_t ae_residual;
int ae_result;
boolean_t ae_found_deny;
int ae_options;
kauth_ace_rights_t ae_exp_gall;
kauth_ace_rights_t ae_exp_gread;
kauth_ace_rights_t ae_exp_gwrite;
kauth_ace_rights_t ae_exp_gexec;
};
typedef struct kauth_acl_eval *kauth_acl_eval_t;
kauth_filesec_t kauth_filesec_alloc(int size);
void kauth_filesec_free(kauth_filesec_t fsp);
extern kauth_scope_t kauth_register_scope(const char *_identifier, kauth_scope_callback_t _callback, void *_idata);
extern void kauth_deregister_scope(kauth_scope_t _scope);
extern kauth_listener_t kauth_listen_scope(const char *_identifier, kauth_scope_callback_t _callback, void *_idata);
extern void kauth_unlisten_scope(kauth_listener_t _scope);
extern int kauth_authorize_action(kauth_scope_t _scope, kauth_cred_t _credential, kauth_action_t _action,
uintptr_t _arg0, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
extern int kauth_authorize_allow(kauth_cred_t _credential, void *_idata, kauth_action_t _action,
uintptr_t _arg0, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
extern int kauth_authorize_process(kauth_cred_t _credential, kauth_action_t _action,
struct proc *_process, uintptr_t _arg1, uintptr_t _arg2, uintptr_t _arg3);
extern int kauth_authorize_fileop(kauth_cred_t _credential, kauth_action_t _action,
uintptr_t _arg0, uintptr_t _arg1);
extern lck_grp_t *kauth_lck_grp;
void read_random(void* buffer, u_int numBytes);
void read_frandom(void* buffer, u_int numBytes);
int write_random(void* buffer, u_int numBytes);
struct sbuf {
char *s_buf;
void *s_unused;
int s_size;
int s_len;
int s_flags;
};
struct sbuf *sbuf_new(struct sbuf *, char *, int, int);
void sbuf_clear(struct sbuf *);
int sbuf_setpos(struct sbuf *, int);
int sbuf_bcat(struct sbuf *, const void *, size_t);
int sbuf_bcpy(struct sbuf *, const void *, size_t);
int sbuf_cat(struct sbuf *, const char *);
int sbuf_cpy(struct sbuf *, const char *);
int sbuf_printf(struct sbuf *, const char *, ...) ;
int sbuf_vprintf(struct sbuf *, const char *, va_list) ;
int sbuf_putc(struct sbuf *, int);
int sbuf_trim(struct sbuf *);
int sbuf_overflowed(struct sbuf *);
void sbuf_finish(struct sbuf *);
char *sbuf_data(struct sbuf *);
int sbuf_len(struct sbuf *);
int sbuf_done(struct sbuf *);
void sbuf_delete(struct sbuf *);
struct uio;
struct sbuf *sbuf_uionew(struct sbuf *, struct uio *, int *);
int sbuf_bcopyin(struct sbuf *, const void *, size_t);
int sbuf_copyin(struct sbuf *, const void *, size_t);
/*
typedef struct user_ucontext64 {
int uc_onstack;
sigset_t uc_sigmask;
struct user64_sigaltstack uc_stack;
user_addr_t uc_link;
user_size_t uc_mcsize;
user_addr_t uc_mcontext64;
} user_ucontext64_t;
typedef struct user_ucontext32 {
int uc_onstack;
sigset_t uc_sigmask;
struct user32_sigaltstack uc_stack;
user32_addr_t uc_link;
user32_size_t uc_mcsize;
user32_addr_t uc_mcontext;
} user_ucontext32_t;
*/
typedef uint32_t sock_storage[32];
typedef uint32_t xcred[19];
typedef uint8_t nfs_handle[64];
extern
kern_return_t lockd_request
(
mach_port_t server,
uint32_t vers,
uint32_t flags,
uint64_t xid,
int64_t flk_start,
int64_t flk_len,
int32_t flk_pid,
int32_t flk_type,
int32_t flk_whence,
sock_storage sock_address,
xcred cred,
uint32_t fh_len,
nfs_handle fh
);
extern
kern_return_t lockd_ping
(
mach_port_t server
);
extern
kern_return_t lockd_shutdown
(
mach_port_t server
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t vers;
uint32_t flags;
uint64_t xid;
int64_t flk_start;
int64_t flk_len;
int32_t flk_pid;
int32_t flk_type;
int32_t flk_whence;
sock_storage sock_address;
xcred cred;
uint32_t fh_len;
nfs_handle fh;
} __Request__lockd_request_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__lockd_ping_t ;
typedef struct {
mach_msg_header_t Head;
} __Request__lockd_shutdown_t ;
union __RequestUnion__lockd_mach_subsystem {
__Request__lockd_request_t Request_lockd_request;
__Request__lockd_ping_t Request_lockd_ping;
__Request__lockd_shutdown_t Request_lockd_shutdown;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lockd_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lockd_ping_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__lockd_shutdown_t ;
union __ReplyUnion__lockd_mach_subsystem {
__Reply__lockd_request_t Reply_lockd_request;
__Reply__lockd_ping_t Reply_lockd_ping;
__Reply__lockd_shutdown_t Reply_lockd_shutdown;
};
struct pal_efi_registers {
uint64_t rcx;
uint64_t rdx;
uint64_t r8;
uint64_t r9;
uint64_t rax;
};
kern_return_t
pal_efi_call_in_64bit_mode(uint64_t func,
struct pal_efi_registers *efi_reg,
void *stack_contents,
size_t stack_contents_size,
uint64_t *efi_status);
kern_return_t
pal_efi_call_in_32bit_mode(uint32_t func,
struct pal_efi_registers *efi_reg,
void *stack_contents,
size_t stack_contents_size,
uint32_t *efi_status);
boolean_t pal_machine_sleep(uint8_t type_a,
uint8_t type_b,
uint32_t bit_position,
uint32_t disable_mask,
uint32_t enable_mask);
extern _Bool mt_core_supported;
struct mt_cpu {
uint64_t mtc_snaps[3];
uint64_t mtc_counts[3];
uint64_t mtc_counts_last[3];
};
struct mt_thread {
 uint64_t mth_gen;
uint64_t mth_counts[3];
};
struct mt_task {
uint64_t mtk_counts[3];
};
struct mt_cpu *mt_cur_cpu(void);
void mt_mtc_update_fixed_counts(struct mt_cpu *mtc, uint64_t *counts,
uint64_t *counts_since);
uint64_t mt_mtc_update_count(struct mt_cpu *mtc, unsigned int ctr);
uint64_t mt_core_snap(unsigned int ctr);
void mt_core_set_snap(unsigned int ctr, uint64_t snap);
void mt_mtc_set_snap(struct mt_cpu *mtc, unsigned int ctr, uint64_t snap);
uintptr_t pal_hib_map(uintptr_t v, uint64_t p);
void hibernateRestorePALState(uint32_t *src);
void pal_hib_patchup(void);
typedef void (*mach_bridge_regwrite_timestamp_func_t)(uint64_t);
void mach_bridge_register_regwrite_timestamp_callback(mach_bridge_regwrite_timestamp_func_t func);
struct specinfo {
struct vnode **si_hashchain;
struct vnode *si_specnext;
long si_flags;
dev_t si_rdev;
int32_t si_opencount;
daddr_t si_size;
daddr64_t si_lastr;
u_int64_t si_devsize;
u_int8_t si_initted;
u_int8_t si_throttleable;
u_int16_t si_isssd;
u_int32_t si_devbsdunit;
u_int64_t si_throttle_mask;
};
extern struct vnode *speclisth[64];
extern int (**spec_vnodeop_p)(void *);
struct nameidata;
struct componentname;
struct flock;
struct buf;
struct uio;
int spec_ebadf(void *);
int spec_lookup (struct vnop_lookup_args *);
int spec_open (struct vnop_open_args *);
int spec_close (struct vnop_close_args *);
int spec_read (struct vnop_read_args *);
int spec_write (struct vnop_write_args *);
int spec_ioctl (struct vnop_ioctl_args *);
int spec_select (struct vnop_select_args *);
int spec_fsync (struct vnop_fsync_args *);
int spec_strategy (struct vnop_strategy_args *);
int spec_pathconf (struct vnop_pathconf_args *);
void * devfs_make_node_clone(dev_t dev, int chrblk, uid_t uid, gid_t gid,
int perms, int (*clone)(dev_t dev, int action),
const char *fmt, ...);
void * devfs_make_node(dev_t dev, int chrblk, uid_t uid, gid_t gid,
int perms, const char *fmt, ...);
void devfs_remove(void * handle);
int fifo_ebadf(void *);
int fifo_lookup (struct vnop_lookup_args *);
int fifo_open (struct vnop_open_args *);
int fifo_close (struct vnop_close_args *);
int fifo_read (struct vnop_read_args *);
int fifo_write (struct vnop_write_args *);
int fifo_ioctl (struct vnop_ioctl_args *);
int fifo_select (struct vnop_select_args *);
int fifo_inactive (struct vnop_inactive_args *);
int fifo_pathconf (struct vnop_pathconf_args *);
int fifo_advlock (struct vnop_advlock_args *);
struct HFSUniStr255 {
u_int16_t length;
u_int16_t unicode[255];
} ;
typedef struct HFSUniStr255 HFSUniStr255;
typedef const HFSUniStr255 *ConstHFSUniStr255Param;
enum {
kHFSSigWord = 0x4244,
kHFSPlusSigWord = 0x482B,
kHFSXSigWord = 0x4858,
kHFSPlusVersion = 0x0004,
kHFSXVersion = 0x0005,
kHFSPlusMountVersion = 0x31302E30,
kHFSJMountVersion = 0x4846534a,
kFSKMountVersion = 0x46534b21
};
enum {
kHardLinkFileType = 0x686C6E6B,
kHFSPlusCreator = 0x6866732B
};
enum {
kSymLinkFileType = 0x736C6E6B,
kSymLinkCreator = 0x72686170
};
enum {
kHFSMaxVolumeNameChars = 27,
kHFSMaxFileNameChars = 31,
kHFSPlusMaxFileNameChars = 255
};
struct HFSExtentKey {
u_int8_t keyLength;
u_int8_t forkType;
u_int32_t fileID;
u_int16_t startBlock;
} ;
typedef struct HFSExtentKey HFSExtentKey;
struct HFSPlusExtentKey {
u_int16_t keyLength;
u_int8_t forkType;
u_int8_t pad;
u_int32_t fileID;
u_int32_t startBlock;
} ;
typedef struct HFSPlusExtentKey HFSPlusExtentKey;
enum {
kHFSExtentDensity = 3,
kHFSPlusExtentDensity = 8
};
struct HFSExtentDescriptor {
u_int16_t startBlock;
u_int16_t blockCount;
} ;
typedef struct HFSExtentDescriptor HFSExtentDescriptor;
struct HFSPlusExtentDescriptor {
u_int32_t startBlock;
u_int32_t blockCount;
} ;
typedef struct HFSPlusExtentDescriptor HFSPlusExtentDescriptor;
typedef HFSExtentDescriptor HFSExtentRecord[3];
typedef HFSPlusExtentDescriptor HFSPlusExtentRecord[8];
struct FndrFileInfo {
u_int32_t fdType;
u_int32_t fdCreator;
u_int16_t fdFlags;
struct {
int16_t v;
int16_t h;
} fdLocation;
int16_t opaque;
} ;
typedef struct FndrFileInfo FndrFileInfo;
struct FndrDirInfo {
struct {
int16_t top;
int16_t left;
int16_t bottom;
int16_t right;
} frRect;
unsigned short frFlags;
struct {
u_int16_t v;
u_int16_t h;
} frLocation;
int16_t opaque;
} ;
typedef struct FndrDirInfo FndrDirInfo;
struct FndrOpaqueInfo {
int8_t opaque[16];
} ;
typedef struct FndrOpaqueInfo FndrOpaqueInfo;
struct FndrExtendedDirInfo {
u_int32_t document_id;
u_int32_t date_added;
u_int16_t extended_flags;
u_int16_t reserved3;
u_int32_t write_gen_counter;
} ;
struct FndrExtendedFileInfo {
u_int32_t document_id;
u_int32_t date_added;
u_int16_t extended_flags;
u_int16_t reserved2;
u_int32_t write_gen_counter;
} ;
struct HFSPlusForkData {
u_int64_t logicalSize;
u_int32_t clumpSize;
u_int32_t totalBlocks;
HFSPlusExtentRecord extents;
} ;
typedef struct HFSPlusForkData HFSPlusForkData;
struct HFSPlusBSDInfo {
u_int32_t ownerID;
u_int32_t groupID;
u_int8_t adminFlags;
u_int8_t ownerFlags;
u_int16_t fileMode;
union {
u_int32_t iNodeNum;
u_int32_t linkCount;
u_int32_t rawDevice;
} special;
} ;
typedef struct HFSPlusBSDInfo HFSPlusBSDInfo;
enum {
kHFSRootParentID = 1,
kHFSRootFolderID = 2,
kHFSExtentsFileID = 3,
kHFSCatalogFileID = 4,
kHFSBadBlockFileID = 5,
kHFSAllocationFileID = 6,
kHFSStartupFileID = 7,
kHFSAttributesFileID = 8,
kHFSAttributeDataFileID = 13,
kHFSRepairCatalogFileID = 14,
kHFSBogusExtentFileID = 15,
kHFSFirstUserCatalogNodeID = 16
};
struct HFSCatalogKey {
u_int8_t keyLength;
u_int8_t reserved;
u_int32_t parentID;
u_int8_t nodeName[kHFSMaxFileNameChars + 1];
} ;
typedef struct HFSCatalogKey HFSCatalogKey;
struct HFSPlusCatalogKey {
u_int16_t keyLength;
u_int32_t parentID;
HFSUniStr255 nodeName;
} ;
typedef struct HFSPlusCatalogKey HFSPlusCatalogKey;
enum {
kHFSFolderRecord = 0x0100,
kHFSFileRecord = 0x0200,
kHFSFolderThreadRecord = 0x0300,
kHFSFileThreadRecord = 0x0400,
kHFSPlusFolderRecord = 1,
kHFSPlusFileRecord = 2,
kHFSPlusFolderThreadRecord = 3,
kHFSPlusFileThreadRecord = 4
};
enum {
kHFSFileLockedBit = 0x0000,
kHFSFileLockedMask = 0x0001,
kHFSThreadExistsBit = 0x0001,
kHFSThreadExistsMask = 0x0002,
kHFSHasAttributesBit = 0x0002,
kHFSHasAttributesMask = 0x0004,
kHFSHasSecurityBit = 0x0003,
kHFSHasSecurityMask = 0x0008,
kHFSHasFolderCountBit = 0x0004,
kHFSHasFolderCountMask = 0x0010,
kHFSHasLinkChainBit = 0x0005,
kHFSHasLinkChainMask = 0x0020,
kHFSHasChildLinkBit = 0x0006,
kHFSHasChildLinkMask = 0x0040,
kHFSHasDateAddedBit = 0x0007,
kHFSHasDateAddedMask = 0x0080,
kHFSFastDevPinnedBit = 0x0008,
kHFSFastDevPinnedMask = 0x0100,
kHFSDoNotFastDevPinBit = 0x0009,
kHFSDoNotFastDevPinMask = 0x0200,
kHFSFastDevCandidateBit = 0x000a,
kHFSFastDevCandidateMask = 0x0400,
kHFSAutoCandidateBit = 0x000b,
kHFSAutoCandidateMask = 0x0800
};
struct HFSCatalogFolder {
int16_t recordType;
u_int16_t flags;
u_int16_t valence;
u_int32_t folderID;
u_int32_t createDate;
u_int32_t modifyDate;
u_int32_t backupDate;
FndrDirInfo userInfo;
FndrOpaqueInfo finderInfo;
u_int32_t reserved[4];
} ;
typedef struct HFSCatalogFolder HFSCatalogFolder;
struct HFSPlusCatalogFolder {
int16_t recordType;
u_int16_t flags;
u_int32_t valence;
u_int32_t folderID;
u_int32_t createDate;
u_int32_t contentModDate;
u_int32_t attributeModDate;
u_int32_t accessDate;
u_int32_t backupDate;
HFSPlusBSDInfo bsdInfo;
FndrDirInfo userInfo;
FndrOpaqueInfo finderInfo;
u_int32_t textEncoding;
u_int32_t folderCount;
} ;
typedef struct HFSPlusCatalogFolder HFSPlusCatalogFolder;
struct HFSCatalogFile {
int16_t recordType;
u_int8_t flags;
int8_t fileType;
FndrFileInfo userInfo;
u_int32_t fileID;
u_int16_t dataStartBlock;
int32_t dataLogicalSize;
int32_t dataPhysicalSize;
u_int16_t rsrcStartBlock;
int32_t rsrcLogicalSize;
int32_t rsrcPhysicalSize;
u_int32_t createDate;
u_int32_t modifyDate;
u_int32_t backupDate;
FndrOpaqueInfo finderInfo;
u_int16_t clumpSize;
HFSExtentRecord dataExtents;
HFSExtentRecord rsrcExtents;
u_int32_t reserved;
} ;
typedef struct HFSCatalogFile HFSCatalogFile;
struct HFSPlusCatalogFile {
int16_t recordType;
u_int16_t flags;
u_int32_t reserved1;
u_int32_t fileID;
u_int32_t createDate;
u_int32_t contentModDate;
u_int32_t attributeModDate;
u_int32_t accessDate;
u_int32_t backupDate;
HFSPlusBSDInfo bsdInfo;
FndrFileInfo userInfo;
FndrOpaqueInfo finderInfo;
u_int32_t textEncoding;
u_int32_t reserved2;
HFSPlusForkData dataFork;
HFSPlusForkData resourceFork;
} ;
typedef struct HFSPlusCatalogFile HFSPlusCatalogFile;
struct HFSCatalogThread {
int16_t recordType;
int32_t reserved[2];
u_int32_t parentID;
u_int8_t nodeName[kHFSMaxFileNameChars + 1];
} ;
typedef struct HFSCatalogThread HFSCatalogThread;
struct HFSPlusCatalogThread {
int16_t recordType;
int16_t reserved;
u_int32_t parentID;
HFSUniStr255 nodeName;
} ;
typedef struct HFSPlusCatalogThread HFSPlusCatalogThread;
enum {
kHFSPlusAttrInlineData = 0x10,
kHFSPlusAttrForkData = 0x20,
kHFSPlusAttrExtents = 0x30
};
struct HFSPlusAttrForkData {
u_int32_t recordType;
u_int32_t reserved;
HFSPlusForkData theFork;
} ;
typedef struct HFSPlusAttrForkData HFSPlusAttrForkData;
struct HFSPlusAttrExtents {
u_int32_t recordType;
u_int32_t reserved;
HFSPlusExtentRecord extents;
} ;
typedef struct HFSPlusAttrExtents HFSPlusAttrExtents;
struct HFSPlusAttrData {
u_int32_t recordType;
u_int32_t reserved[2];
u_int32_t attrSize;
u_int8_t attrData[2];
} ;
typedef struct HFSPlusAttrData HFSPlusAttrData;
struct HFSPlusAttrInlineData {
u_int32_t recordType;
u_int32_t reserved;
u_int32_t logicalSize;
u_int8_t userData[2];
} ;
typedef struct HFSPlusAttrInlineData HFSPlusAttrInlineData;
union HFSPlusAttrRecord {
u_int32_t recordType;
HFSPlusAttrInlineData inlineData;
HFSPlusAttrData attrData;
HFSPlusAttrForkData forkData;
HFSPlusAttrExtents overflowExtents;
};
typedef union HFSPlusAttrRecord HFSPlusAttrRecord;
enum { kHFSMaxAttrNameLen = 127 };
struct HFSPlusAttrKey {
u_int16_t keyLength;
u_int16_t pad;
u_int32_t fileID;
u_int32_t startBlock;
u_int16_t attrNameLen;
u_int16_t attrName[kHFSMaxAttrNameLen];
} ;
typedef struct HFSPlusAttrKey HFSPlusAttrKey;
enum {
kHFSPlusExtentKeyMaximumLength = sizeof(HFSPlusExtentKey) - sizeof(u_int16_t),
kHFSExtentKeyMaximumLength = sizeof(HFSExtentKey) - sizeof(u_int8_t),
kHFSPlusCatalogKeyMaximumLength = sizeof(HFSPlusCatalogKey) - sizeof(u_int16_t),
kHFSPlusCatalogKeyMinimumLength = kHFSPlusCatalogKeyMaximumLength - sizeof(HFSUniStr255) + sizeof(u_int16_t),
kHFSCatalogKeyMaximumLength = sizeof(HFSCatalogKey) - sizeof(u_int8_t),
kHFSCatalogKeyMinimumLength = kHFSCatalogKeyMaximumLength - (kHFSMaxFileNameChars + 1) + sizeof(u_int8_t),
kHFSPlusCatalogMinNodeSize = 4096,
kHFSPlusExtentMinNodeSize = 512,
kHFSPlusAttrMinNodeSize = 4096
};
enum {
kHFSVolumeHardwareLockBit = 7,
kHFSVolumeUnmountedBit = 8,
kHFSVolumeSparedBlocksBit = 9,
kHFSVolumeNoCacheRequiredBit = 10,
kHFSBootVolumeInconsistentBit = 11,
kHFSCatalogNodeIDsReusedBit = 12,
kHFSVolumeJournaledBit = 13,
kHFSVolumeInconsistentBit = 14,
kHFSVolumeSoftwareLockBit = 15,
kHFSUnusedNodeFixBit = 31,
kHFSContentProtectionBit = 30,
kHFSVolumeHardwareLockMask = 0x00000080,
kHFSVolumeUnmountedMask = 0x00000100,
kHFSVolumeSparedBlocksMask = 0x00000200,
kHFSVolumeNoCacheRequiredMask = 0x00000400,
kHFSBootVolumeInconsistentMask = 0x00000800,
kHFSCatalogNodeIDsReusedMask = 0x00001000,
kHFSVolumeJournaledMask = 0x00002000,
kHFSVolumeInconsistentMask = 0x00004000,
kHFSVolumeSoftwareLockMask = 0x00008000,
kHFSContentProtectionMask = 0x40000000,
kHFSUnusedNodeFixMask = 0x80000000,
kHFSMDBAttributesMask = 0x8380
};
enum {
kHFSUnusedNodesFixDate = 0xc5ef2480
};
struct HFSMasterDirectoryBlock {
u_int16_t drSigWord;
u_int32_t drCrDate;
u_int32_t drLsMod;
u_int16_t drAtrb;
u_int16_t drNmFls;
u_int16_t drVBMSt;
u_int16_t drAllocPtr;
u_int16_t drNmAlBlks;
u_int32_t drAlBlkSiz;
u_int32_t drClpSiz;
u_int16_t drAlBlSt;
u_int32_t drNxtCNID;
u_int16_t drFreeBks;
u_int8_t drVN[kHFSMaxVolumeNameChars + 1];
u_int32_t drVolBkUp;
u_int16_t drVSeqNum;
u_int32_t drWrCnt;
u_int32_t drXTClpSiz;
u_int32_t drCTClpSiz;
u_int16_t drNmRtDirs;
u_int32_t drFilCnt;
u_int32_t drDirCnt;
u_int32_t drFndrInfo[8];
u_int16_t drEmbedSigWord;
HFSExtentDescriptor drEmbedExtent;
u_int32_t drXTFlSize;
HFSExtentRecord drXTExtRec;
u_int32_t drCTFlSize;
HFSExtentRecord drCTExtRec;
} ;
typedef struct HFSMasterDirectoryBlock HFSMasterDirectoryBlock;
struct HFSPlusVolumeHeader {
u_int16_t signature;
u_int16_t version;
u_int32_t attributes;
u_int32_t lastMountedVersion;
u_int32_t journalInfoBlock;
u_int32_t createDate;
u_int32_t modifyDate;
u_int32_t backupDate;
u_int32_t checkedDate;
u_int32_t fileCount;
u_int32_t folderCount;
u_int32_t blockSize;
u_int32_t totalBlocks;
u_int32_t freeBlocks;
u_int32_t nextAllocation;
u_int32_t rsrcClumpSize;
u_int32_t dataClumpSize;
u_int32_t nextCatalogID;
u_int32_t writeCount;
u_int64_t encodingsBitmap;
u_int8_t finderInfo[32];
HFSPlusForkData allocationFile;
HFSPlusForkData extentsFile;
HFSPlusForkData catalogFile;
HFSPlusForkData attributesFile;
HFSPlusForkData startupFile;
} ;
typedef struct HFSPlusVolumeHeader HFSPlusVolumeHeader;
enum BTreeKeyLimits{
kMaxKeyLength = 520
};
union BTreeKey{
u_int8_t length8;
u_int16_t length16;
u_int8_t rawData [kMaxKeyLength+2];
};
typedef union BTreeKey BTreeKey;
struct BTNodeDescriptor {
u_int32_t fLink;
u_int32_t bLink;
int8_t kind;
u_int8_t height;
u_int16_t numRecords;
u_int16_t reserved;
} ;
typedef struct BTNodeDescriptor BTNodeDescriptor;
enum {
kBTLeafNode = -1,
kBTIndexNode = 0,
kBTHeaderNode = 1,
kBTMapNode = 2
};
struct BTHeaderRec {
u_int16_t treeDepth;
u_int32_t rootNode;
u_int32_t leafRecords;
u_int32_t firstLeafNode;
u_int32_t lastLeafNode;
u_int16_t nodeSize;
u_int16_t maxKeyLength;
u_int32_t totalNodes;
u_int32_t freeNodes;
u_int16_t reserved1;
u_int32_t clumpSize;
u_int8_t btreeType;
u_int8_t keyCompareType;
u_int32_t attributes;
u_int32_t reserved3[16];
} ;
typedef struct BTHeaderRec BTHeaderRec;
enum {
kBTBadCloseMask = 0x00000001,
kBTBigKeysMask = 0x00000002,
kBTVariableIndexKeysMask = 0x00000004
};
enum {
kHFSCaseFolding = 0xCF,
kHFSBinaryCompare = 0xBC
};
struct JournalInfoBlock {
u_int32_t flags;
u_int32_t device_signature[8];
u_int64_t offset;
u_int64_t size;
uuid_string_t ext_jnl_uuid;
char machine_serial_num[48];
char reserved[((32*sizeof(u_int32_t)) - sizeof(uuid_string_t) - 48)];
} ;
typedef struct JournalInfoBlock JournalInfoBlock;
enum {
kJIJournalInFSMask = 0x00000001,
kJIJournalOnOtherDeviceMask = 0x00000002,
kJIJournalNeedInitMask = 0x00000004
};
typedef int (* hfs_to_unicode_func_t)(const uint8_t hfs_str[32], uint16_t *uni_str,
u_int32_t maxCharLen, u_int32_t *usedCharLen);
typedef int (* unicode_to_hfs_func_t)(uint16_t *uni_str, u_int32_t unicodeChars,
uint8_t hfs_str[32]);
int hfs_relconverter (u_int32_t encoding);
int hfs_getconverter(u_int32_t encoding, hfs_to_unicode_func_t *get_unicode,
unicode_to_hfs_func_t *get_hfsname);
int hfs_addconverter(int kmod_id, u_int32_t encoding,
hfs_to_unicode_func_t get_unicode,
unicode_to_hfs_func_t get_hfsname);
int hfs_remconverter(int kmod_id, u_int32_t encoding);
u_int32_t hfs_pickencoding(const u_int16_t *src, int len);
u_int32_t hfs_getencodingbias(void);
void hfs_setencodingbias(u_int32_t bias);
int mac_roman_to_utf8(const uint8_t hfs_str[32], uint32_t maxDstLen, uint32_t *actualDstLen,
unsigned char* dstStr);
int utf8_to_mac_roman(uint32_t srcLen, const unsigned char* srcStr, uint8_t dstStr[32]);
int mac_roman_to_unicode(const uint8_t hfs_str[32], uint16_t *uni_str, u_int32_t maxCharLen, u_int32_t *usedCharLen);
int unicode_to_mac_roman(uint16_t *uni_str, u_int32_t unicodeChars, uint8_t hfs_str[32]);
struct hfs_mount_args {
uid_t hfs_uid;
gid_t hfs_gid;
mode_t hfs_mask;
u_int32_t hfs_encoding;
struct timezone hfs_timezone;
int flags;
int journal_tbuffer_size;
int journal_flags;
int journal_disable;
};
typedef uint32_t ipc_pthread_priority_value_t;
typedef unsigned short i386_ioport_t;
static  unsigned char inb(i386_ioport_t port) { unsigned char data; asm volatile ( "in" "b" " %1,%0" : "=a" (data) : "d" (port)); return (data); }
static  unsigned short inw(i386_ioport_t port) { unsigned short data; asm volatile ( "in" "w" " %1,%0" : "=a" (data) : "d" (port)); return (data); }
static  unsigned long inl(i386_ioport_t port) { unsigned long data; asm volatile ( "in" "l" " %1,%0" : "=a" (data) : "d" (port)); return (data); }
static  void outb(i386_ioport_t port, unsigned char data) { asm volatile ( "out" "b" " %1,%0" : : "d" (port), "a" (data)); }
static  void outw(i386_ioport_t port, unsigned short data) { asm volatile ( "out" "w" " %1,%0" : : "d" (port), "a" (data)); }
static  void outl(i386_ioport_t port, unsigned long data) { asm volatile ( "out" "l" " %1,%0" : : "d" (port), "a" (data)); }
extern void cninit(void);
//extern int __builtin___sprintf_chk (char * str, 0, __builtin_object_size (char * str, 2 > 1 ? 1 : 0), const char * format, ...);
int switch_to_serial_console(void);
void switch_to_old_console(int);
boolean_t console_is_serial(void);
int serial_init(void);
void serial_putc(char);
int serial_getc(void);
void cnputc(char);
int cngetc(void);
typedef uint8_t EFI_UINT8;
typedef uint16_t EFI_UINT16;
typedef uint32_t EFI_UINT32;
typedef uint64_t EFI_UINT64;
typedef uint32_t EFI_UINTN;
typedef int8_t EFI_INT8;
typedef int16_t EFI_INT16;
typedef int32_t EFI_INT32;
typedef int64_t EFI_INT64;
typedef int8_t EFI_CHAR8;
typedef int16_t EFI_CHAR16;
typedef int32_t EFI_CHAR32;
typedef int64_t EFI_CHAR64;
typedef uint32_t EFI_STATUS;
typedef uint8_t EFI_BOOLEAN;
typedef void VOID;
typedef uint32_t EFI_PTR32;
typedef uint32_t EFI_HANDLE32;
typedef uint64_t EFI_PTR64;
typedef uint64_t EFI_HANDLE64;
typedef struct {
EFI_UINT32 Data1;
EFI_UINT16 Data2;
EFI_UINT16 Data3;
EFI_UINT8 Data4[8];
} EFI_GUID;
typedef union {
EFI_GUID Guid;
EFI_UINT8 Raw[16];
} EFI_GUID_UNION;
typedef struct {
EFI_UINT16 Year;
EFI_UINT8 Month;
EFI_UINT8 Day;
EFI_UINT8 Hour;
EFI_UINT8 Minute;
EFI_UINT8 Second;
EFI_UINT8 Pad1;
EFI_UINT32 Nanosecond;
EFI_INT16 TimeZone;
EFI_UINT8 Daylight;
EFI_UINT8 Pad2;
} EFI_TIME;
typedef enum {
EfiReservedMemoryType,
EfiLoaderCode,
EfiLoaderData,
EfiBootServicesCode,
EfiBootServicesData,
EfiRuntimeServicesCode,
EfiRuntimeServicesData,
EfiConventionalMemory,
EfiUnusableMemory,
EfiACPIReclaimMemory,
EfiACPIMemoryNVS,
EfiMemoryMappedIO,
EfiMemoryMappedIOPortSpace,
EfiPalCode,
EfiMaxMemoryType
} EFI_MEMORY_TYPE;
typedef struct {
EFI_UINT64 Signature;
EFI_UINT32 Revision;
EFI_UINT32 HeaderSize;
EFI_UINT32 CRC32;
EFI_UINT32 Reserved;
}  EFI_TABLE_HEADER;
typedef EFI_UINT64 EFI_PHYSICAL_ADDRESS;
typedef EFI_UINT64 EFI_VIRTUAL_ADDRESS;
typedef struct {
EFI_UINT32 Type;
EFI_UINT32 Pad;
EFI_PHYSICAL_ADDRESS PhysicalStart;
EFI_VIRTUAL_ADDRESS VirtualStart;
EFI_UINT64 NumberOfPages;
EFI_UINT64 Attribute;
}  EFI_MEMORY_DESCRIPTOR;
typedef
EFI_STATUS
( *EFI_SET_VIRTUAL_ADDRESS_MAP) (
EFI_UINTN MemoryMapSize,
EFI_UINTN DescriptorSize,
EFI_UINT32 DescriptorVersion,
EFI_MEMORY_DESCRIPTOR * VirtualMap
);
typedef
EFI_STATUS
( *EFI_CONVERT_POINTER) (
EFI_UINTN DebugDisposition,
VOID **Address
);
typedef
EFI_STATUS
( *EFI_GET_VARIABLE) (
EFI_CHAR16 * VariableName,
EFI_GUID * VendorGuid,
EFI_UINT32 * Attributes ,
EFI_UINTN * DataSize,
VOID * Data
);
typedef
EFI_STATUS
( *EFI_GET_NEXT_VARIABLE_NAME) (
EFI_UINTN * VariableNameSize,
EFI_CHAR16 * VariableName,
EFI_GUID * VendorGuid
);
typedef
EFI_STATUS
( *EFI_SET_VARIABLE) (
EFI_CHAR16 * VariableName,
EFI_GUID * VendorGuid,
EFI_UINT32 Attributes,
EFI_UINTN DataSize,
VOID * Data
);
typedef struct {
EFI_UINT32 Resolution;
EFI_UINT32 Accuracy;
EFI_BOOLEAN SetsToZero;
}  EFI_TIME_CAPABILITIES;
typedef
EFI_STATUS
( *EFI_GET_TIME) (
EFI_TIME * Time,
EFI_TIME_CAPABILITIES * Capabilities
);
typedef
EFI_STATUS
( *EFI_SET_TIME) (
EFI_TIME * Time
);
typedef
EFI_STATUS
( *EFI_GET_WAKEUP_TIME) (
EFI_BOOLEAN * Enabled,
EFI_BOOLEAN * Pending,
EFI_TIME * Time
);
typedef
EFI_STATUS
( *EFI_SET_WAKEUP_TIME) (
EFI_BOOLEAN Enable,
EFI_TIME * Time
);
typedef enum {
EfiResetCold,
EfiResetWarm,
EfiResetShutdown,
} EFI_RESET_TYPE;
typedef
VOID
( *EFI_RESET_SYSTEM) (
EFI_RESET_TYPE ResetType,
EFI_STATUS ResetStatus,
EFI_UINTN DataSize,
EFI_CHAR16 * ResetData
);
typedef
EFI_STATUS
( *EFI_GET_NEXT_HIGH_MONO_COUNT) (
EFI_UINT32 * HighCount
);
typedef struct {
EFI_TABLE_HEADER Hdr;
EFI_PTR32 GetTime;
EFI_PTR32 SetTime;
EFI_PTR32 GetWakeupTime;
EFI_PTR32 SetWakeupTime;
EFI_PTR32 SetVirtualAddressMap;
EFI_PTR32 ConvertPointer;
EFI_PTR32 GetVariable;
EFI_PTR32 GetNextVariableName;
EFI_PTR32 SetVariable;
EFI_PTR32 GetNextHighMonotonicCount;
EFI_PTR32 ResetSystem;
}  EFI_RUNTIME_SERVICES_32;
typedef struct {
EFI_TABLE_HEADER Hdr;
EFI_PTR64 GetTime;
EFI_PTR64 SetTime;
EFI_PTR64 GetWakeupTime;
EFI_PTR64 SetWakeupTime;
EFI_PTR64 SetVirtualAddressMap;
EFI_PTR64 ConvertPointer;
EFI_PTR64 GetVariable;
EFI_PTR64 GetNextVariableName;
EFI_PTR64 SetVariable;
EFI_PTR64 GetNextHighMonotonicCount;
EFI_PTR64 ResetSystem;
}  EFI_RUNTIME_SERVICES_64;
typedef struct {
EFI_GUID VendorGuid;
EFI_PTR32 VendorTable;
} EFI_CONFIGURATION_TABLE_32;
typedef struct {
EFI_GUID VendorGuid;
EFI_PTR64 VendorTable;
}  EFI_CONFIGURATION_TABLE_64;
typedef struct EFI_SYSTEM_TABLE_32 {
EFI_TABLE_HEADER Hdr;
EFI_PTR32 FirmwareVendor;
EFI_UINT32 FirmwareRevision;
EFI_HANDLE32 ConsoleInHandle;
EFI_PTR32 ConIn;
EFI_HANDLE32 ConsoleOutHandle;
EFI_PTR32 ConOut;
EFI_HANDLE32 StandardErrorHandle;
EFI_PTR32 StdErr;
EFI_PTR32 RuntimeServices;
EFI_PTR32 BootServices;
EFI_UINT32 NumberOfTableEntries;
EFI_PTR32 ConfigurationTable;
}  EFI_SYSTEM_TABLE_32;
typedef struct EFI_SYSTEM_TABLE_64 {
EFI_TABLE_HEADER Hdr;
EFI_PTR64 FirmwareVendor;
EFI_UINT32 FirmwareRevision;
EFI_UINT32 __pad;
EFI_HANDLE64 ConsoleInHandle;
EFI_PTR64 ConIn;
EFI_HANDLE64 ConsoleOutHandle;
EFI_PTR64 ConOut;
EFI_HANDLE64 StandardErrorHandle;
EFI_PTR64 StdErr;
EFI_PTR64 RuntimeServices;
EFI_PTR64 BootServices;
EFI_UINT64 NumberOfTableEntries;
EFI_PTR64 ConfigurationTable;
}  EFI_SYSTEM_TABLE_64;
enum {
kDTPathNameSeparator = '/'
};
enum {
kDTMaxPropertyNameLength=31
};
typedef char DTPropertyNameBuf[32];
enum {
kDTMaxEntryNameLength = 63
};
typedef char DTEntryNameBuf[kDTMaxEntryNameLength+1];
typedef struct DeviceTreeNodeProperty {
char name[32];
uint32_t length;
} DeviceTreeNodeProperty;
typedef struct OpaqueDTEntry {
uint32_t nProperties;
uint32_t nChildren;
} DeviceTreeNode;
typedef DeviceTreeNode *RealDTEntry;
typedef struct DTSavedScope {
struct DTSavedScope * nextScope;
RealDTEntry scope;
RealDTEntry entry;
unsigned long index;
} *DTSavedScopePtr;
typedef struct OpaqueDTEntryIterator {
RealDTEntry outerScope;
RealDTEntry currentScope;
RealDTEntry currentEntry;
DTSavedScopePtr savedScope;
unsigned long currentIndex;
} OpaqueDTEntryIterator, *DTEntryIterator;
typedef struct OpaqueDTPropertyIterator {
RealDTEntry entry;
DeviceTreeNodeProperty *currentProperty;
unsigned long currentIndex;
} OpaqueDTPropertyIterator, *DTPropertyIterator;
typedef struct OpaqueDTEntry* DTEntry;
typedef struct OpaqueDTEntryIterator* DTEntryIterator;
typedef struct OpaqueDTPropertyIterator* DTPropertyIterator;
enum {
kError = -1,
kIterationDone = 0,
kSuccess = 1
};
void DTInit(void *base);
extern int DTEntryIsEqual(const DTEntry ref1, const DTEntry ref2);
extern int DTFindEntry(const char *propName, const char *propValue, DTEntry *entryH);
extern int DTLookupEntry(const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry);
extern int DTInitEntryIterator(const DTEntry startEntry, DTEntryIterator iter);
extern int DTEnterEntry(DTEntryIterator iterator, DTEntry childEntry);
extern int DTExitEntry(DTEntryIterator iterator, DTEntry *currentPosition);
extern int DTIterateEntries(DTEntryIterator iterator, DTEntry *nextEntry);
extern int DTRestartEntryIteration(DTEntryIterator iterator);
extern int DTGetProperty(const DTEntry entry, const char *propertyName, void **propertyValue, unsigned int *propertySize);
extern int DTInitPropertyIterator(const DTEntry entry, DTPropertyIterator iter);
extern int DTIterateProperties(DTPropertyIterator iterator,
char **foundProperty);
extern int DTRestartPropertyIteration(DTPropertyIterator iterator);
typedef float float_t;
typedef double double_t;
extern int __math_errhandling(void);
extern int __fpclassifyf(float);
extern int __fpclassifyd(double);
extern int __fpclassifyl(long double);
inline  int _isfinitef(float);
inline  int _isfinited(double);
inline  int _isfinitel(long double);
inline  int _isinff(float);
inline  int _isinfd(double);
inline  int _isinfl(long double);
inline  int _isnanf(float);
inline  int _isnand(double);
inline  int _isnanl(long double);
inline  int _isnormalf(float);
inline  int _isnormald(double);
inline  int _isnormall(long double);
inline  int _signbitf(float);
inline  int _signbitd(double);
inline  int _signbitl(long double);
inline  int _isfinitef(float __x) {
return __x == __x && __builtin_fabsf(__x) != __builtin_inff();
}
inline  int _isfinited(double __x) {
return __x == __x && __builtin_fabs(__x) != __builtin_inf();
}
inline  int _isfinitel(long double __x) {
return __x == __x && __builtin_fabsl(__x) != __builtin_infl();
}
inline  int _isinff(float __x) {
return __builtin_fabsf(__x) == __builtin_inff();
}
inline  int _isinfd(double __x) {
return __builtin_fabs(__x) == __builtin_inf();
}
inline  int _isinfl(long double __x) {
return __builtin_fabsl(__x) == __builtin_infl();
}
inline  int _isnanf(float __x) {
return __x != __x;
}
inline  int _isnand(double __x) {
return __x != __x;
}
inline  int _isnanl(long double __x) {
return __x != __x;
}
inline  int _signbitf(float __x) {
union { float __f; unsigned int __u; } __u;
__u.__f = __x;
return (int)(__u.__u >> 31);
}
inline  int _signbitd(double __x) {
union { double __f; unsigned long long __u; } __u;
__u.__f = __x;
return (int)(__u.__u >> 63);
}
inline  int _signbitl(long double __x) {
union {
long double __ld;
struct{ unsigned long long __m; unsigned short __sexp; } __p;
} __u;
__u.__ld = __x;
return (int)(__u.__p.__sexp >> 15);
}
inline  int _isnormalf(float __x) {
return _isfinitef(__x) && __builtin_fabsf(__x) >= 1.17549435e-38F;
}
inline  int _isnormald(double __x) {
return _isfinited(__x) && __builtin_fabs(__x) >= 2.2250738585072014e-308;
}
inline  int _isnormall(long double __x) {
return _isfinitel(__x) && __builtin_fabsl(__x) >= 3.36210314311209350626e-4932L;
}
extern float acosf(float);
extern double acos(double);
extern long double acosl(long double);
extern float asinf(float);
extern double asin(double);
extern long double asinl(long double);
extern float atanf(float);
extern double atan(double);
extern long double atanl(long double);
extern float atan2f(float, float);
extern double atan2(double, double);
extern long double atan2l(long double, long double);
extern float cosf(float);
extern double cos(double);
extern long double cosl(long double);
extern float sinf(float);
extern double sin(double);
extern long double sinl(long double);
extern float tanf(float);
extern double tan(double);
extern long double tanl(long double);
extern float acoshf(float);
extern double acosh(double);
extern long double acoshl(long double);
extern float asinhf(float);
extern double asinh(double);
extern long double asinhl(long double);
extern float atanhf(float);
extern double atanh(double);
extern long double atanhl(long double);
extern float coshf(float);
extern double cosh(double);
extern long double coshl(long double);
extern float sinhf(float);
extern double sinh(double);
extern long double sinhl(long double);
extern float tanhf(float);
extern double tanh(double);
extern long double tanhl(long double);
extern float expf(float);
extern double exp(double);
extern long double expl(long double);
extern float exp2f(float);
extern double exp2(double);
extern long double exp2l(long double);
extern float expm1f(float);
extern double expm1(double);
extern long double expm1l(long double);
extern float logf(float);
extern double log(double);
extern long double logl(long double);
extern float log10f(float);
extern double log10(double);
extern long double log10l(long double);
extern float log2f(float);
extern double log2(double);
extern long double log2l(long double);
extern float log1pf(float);
extern double log1p(double);
extern long double log1pl(long double);
extern float logbf(float);
extern double logb(double);
extern long double logbl(long double);
extern float modff(float, float *);
extern double modf(double, double *);
extern long double modfl(long double, long double *);
extern float ldexpf(float, int);
extern double ldexp(double, int);
extern long double ldexpl(long double, int);
extern float frexpf(float, int *);
extern double frexp(double, int *);
extern long double frexpl(long double, int *);
extern int ilogbf(float);
extern int ilogb(double);
extern int ilogbl(long double);
extern float scalbnf(float, int);
extern double scalbn(double, int);
extern long double scalbnl(long double, int);
extern float scalblnf(float, long int);
extern double scalbln(double, long int);
extern long double scalblnl(long double, long int);
extern float fabsf(float);
extern double fabs(double);
extern long double fabsl(long double);
extern float cbrtf(float);
extern double cbrt(double);
extern long double cbrtl(long double);
extern float hypotf(float, float);
extern double hypot(double, double);
extern long double hypotl(long double, long double);
extern float powf(float, float);
extern double pow(double, double);
extern long double powl(long double, long double);
extern float sqrtf(float);
extern double sqrt(double);
extern long double sqrtl(long double);
extern float erff(float);
extern double erf(double);
extern long double erfl(long double);
extern float erfcf(float);
extern double erfc(double);
extern long double erfcl(long double);
extern float lgammaf(float);
extern double lgamma(double);
extern long double lgammal(long double);
extern float tgammaf(float);
extern double tgamma(double);
extern long double tgammal(long double);
extern float ceilf(float);
extern double ceil(double);
extern long double ceill(long double);
extern float floorf(float);
extern double floor(double);
extern long double floorl(long double);
extern float nearbyintf(float);
extern double nearbyint(double);
extern long double nearbyintl(long double);
extern float rintf(float);
extern double rint(double);
extern long double rintl(long double);
extern long int lrintf(float);
extern long int lrint(double);
extern long int lrintl(long double);
extern float roundf(float);
extern double round(double);
extern long double roundl(long double);
extern long int lroundf(float);
extern long int lround(double);
extern long int lroundl(long double);
extern long long int llrintf(float);
extern long long int llrint(double);
extern long long int llrintl(long double);
extern long long int llroundf(float);
extern long long int llround(double);
extern long long int llroundl(long double);
extern float truncf(float);
extern double trunc(double);
extern long double truncl(long double);
extern float fmodf(float, float);
extern double fmod(double, double);
extern long double fmodl(long double, long double);
extern float remainderf(float, float);
extern double remainder(double, double);
extern long double remainderl(long double, long double);
extern float remquof(float, float, int *);
extern double remquo(double, double, int *);
extern long double remquol(long double, long double, int *);
extern float copysignf(float, float);
extern double copysign(double, double);
extern long double copysignl(long double, long double);
extern float nanf(const char *);
extern double nan(const char *);
extern long double nanl(const char *);
extern float nextafterf(float, float);
extern double nextafter(double, double);
extern long double nextafterl(long double, long double);
extern double nexttoward(double, long double);
extern float nexttowardf(float, long double);
extern long double nexttowardl(long double, long double);
extern float fdimf(float, float);
extern double fdim(double, double);
extern long double fdiml(long double, long double);
extern float fmaxf(float, float);
extern double fmax(double, double);
extern long double fmaxl(long double, long double);
extern float fminf(float, float);
extern double fmin(double, double);
extern long double fminl(long double, long double);
extern float fmaf(float, float, float);
extern double fma(double, double, double);
extern long double fmal(long double, long double, long double);
extern float __inff(void) ;
extern double __inf(void) ;
extern long double __infl(void) ;
extern float __nan(void) ;
extern float __exp10f(float) ;
extern double __exp10(double) ;
inline  void __sincosf(float __x, float *__sinp, float *__cosp);
inline  void __sincos(double __x, double *__sinp, double *__cosp);
extern float __cospif(float) ;
extern double __cospi(double) ;
extern float __sinpif(float) ;
extern double __sinpi(double) ;
extern float __tanpif(float) ;
extern double __tanpi(double) ;
inline  void __sincospif(float __x, float *__sinp, float *__cosp);
inline  void __sincospi(double __x, double *__sinp, double *__cosp);
struct __float2 { float __sinval; float __cosval; };
struct __double2 { double __sinval; double __cosval; };
extern struct __float2 __sincosf_stret(float);
extern struct __double2 __sincos_stret(double);
extern struct __float2 __sincospif_stret(float);
extern struct __double2 __sincospi_stret(double);
inline  void __sincosf(float __x, float *__sinp, float *__cosp) {
const struct __float2 __stret = __sincosf_stret(__x);
*__sinp = __stret.__sinval; *__cosp = __stret.__cosval;
}
inline  void __sincos(double __x, double *__sinp, double *__cosp) {
const struct __double2 __stret = __sincos_stret(__x);
*__sinp = __stret.__sinval; *__cosp = __stret.__cosval;
}
inline  void __sincospif(float __x, float *__sinp, float *__cosp) {
const struct __float2 __stret = __sincospif_stret(__x);
*__sinp = __stret.__sinval; *__cosp = __stret.__cosval;
}
inline  void __sincospi(double __x, double *__sinp, double *__cosp) {
const struct __double2 __stret = __sincospi_stret(__x);
*__sinp = __stret.__sinval; *__cosp = __stret.__cosval;
}
extern double j0(double) ;
extern double j1(double) ;
extern double jn(int, double) ;
extern double y0(double) ;
extern double y1(double) ;
extern double yn(int, double) ;
extern double scalb(double, double);
extern int signgam;
extern long int rinttol(double) ;
extern long int roundtol(double) ;
extern double drem(double, double) ;
extern int finite(double) ;
extern double gamma(double) ;
extern double significand(double) ;
struct exception {
int type;
char *name;
double arg1;
double arg2;
double retval;
};
extern int matherr(struct exception *) ;
struct ipc_object ;
typedef struct ipc_object *ipc_object_t;
extern
kern_return_t coalition_notification
(
mach_port_t coalition_port,
uint64_t id,
uint32_t flags
);
extern
boolean_t coalition_notification_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t coalition_notification_server_routine(
mach_msg_header_t *InHeadP);
extern const struct coalition_notification_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} coalition_notification_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint64_t id;
uint32_t flags;
} __Request__coalition_notification_t ;
union __RequestUnion__coalition_notification_subsystem {
__Request__coalition_notification_t Request_coalition_notification;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__coalition_notification_t ;
union __ReplyUnion__coalition_notification_subsystem {
__Reply__coalition_notification_t Reply_coalition_notification;
};
extern
kern_return_t telemetry_notification
(
mach_port_t telemetry_port,
uint32_t flags
);
extern
boolean_t telemetry_notification_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t telemetry_notification_server_routine(
mach_msg_header_t *InHeadP);
extern const struct telemetry_notification_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} telemetry_notification_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t flags;
} __Request__telemetry_notification_t ;
union __RequestUnion__telemetry_notification_subsystem {
__Request__telemetry_notification_t Request_telemetry_notification;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__telemetry_notification_t ;
union __ReplyUnion__telemetry_notification_subsystem {
__Reply__telemetry_notification_t Reply_telemetry_notification;
};
NDR_record_t NDR_record = {
0,
0,
0,
0,
1,
0,
0,
0,
};
extern
kern_return_t upl_abort
(
upl_t upl_object,
integer_t abort_cond
);
extern
kern_return_t upl_abort_range
(
upl_t upl_object,
upl_offset_t offset,
upl_size_t size,
integer_t abort_cond,
boolean_t *empty
);
extern
kern_return_t upl_commit
(
upl_t upl_object,
upl_page_info_array_t page_list,
mach_msg_type_number_t page_listCnt
);
extern
kern_return_t upl_commit_range
(
upl_t upl_object,
upl_offset_t offset,
upl_size_t size,
integer_t cntrl_flags,
upl_page_info_array_t page_list,
mach_msg_type_number_t page_listCnt,
boolean_t *empty
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
integer_t abort_cond;
} __Request__upl_abort_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
upl_offset_t offset;
upl_size_t size;
integer_t abort_cond;
} __Request__upl_abort_range_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t page_listCnt;
upl_page_info_t page_list[256];
} __Request__upl_commit_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
upl_offset_t offset;
upl_size_t size;
integer_t cntrl_flags;
mach_msg_type_number_t page_listCnt;
upl_page_info_t page_list[256];
} __Request__upl_commit_range_t ;
union __RequestUnion__upl_subsystem {
__Request__upl_abort_t Request_upl_abort;
__Request__upl_abort_range_t Request_upl_abort_range;
__Request__upl_commit_t Request_upl_commit;
__Request__upl_commit_range_t Request_upl_commit_range;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__upl_abort_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
boolean_t empty;
} __Reply__upl_abort_range_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__upl_commit_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
boolean_t empty;
} __Reply__upl_commit_range_t ;
union __ReplyUnion__upl_subsystem {
__Reply__upl_abort_t Reply_upl_abort;
__Reply__upl_abort_range_t Reply_upl_abort_range;
__Reply__upl_commit_t Reply_upl_commit;
__Reply__upl_commit_range_t Reply_upl_commit_range;
};
struct shared_file_mapping_np {
mach_vm_address_t sfm_address;
mach_vm_size_t sfm_size;
mach_vm_offset_t sfm_file_offset;
vm_prot_t sfm_max_prot;
vm_prot_t sfm_init_prot;
};
struct shared_region_range_np {
mach_vm_address_t srr_address;
mach_vm_size_t srr_size;
};
extern
kern_return_t memory_object_create
(
memory_object_default_t default_memory_manager,
vm_size_t new_memory_object_size,
memory_object_t *new_memory_object
);
extern
boolean_t memory_object_default_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t memory_object_default_server_routine(
mach_msg_header_t *InHeadP);
extern const struct memory_object_default_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} memory_object_default_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
vm_size_t new_memory_object_size;
} __Request__memory_object_create_t ;
union __RequestUnion__memory_object_default_subsystem {
__Request__memory_object_create_t Request_memory_object_create;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t new_memory_object;
} __Reply__memory_object_create_t ;
union __ReplyUnion__memory_object_default_subsystem {
__Reply__memory_object_create_t Reply_memory_object_create;
};
extern
kern_return_t send_ktrace_background_available
(
mach_port_t ktrace_background_port
);
typedef struct {
mach_msg_header_t Head;
} __Request__ktrace_background_available_t ;
union __RequestUnion__send_ktrace_background_subsystem {
__Request__ktrace_background_available_t Request_send_ktrace_background_available;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__ktrace_background_available_t ;
union __ReplyUnion__send_ktrace_background_subsystem {
__Reply__ktrace_background_available_t Reply_send_ktrace_background_available;
};
extern
kern_return_t receive_sysdiagnose_notification
(
mach_port_t sysdiagnose_port,
uint32_t flags
);
extern
boolean_t sysdiagnose_notification_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t sysdiagnose_notification_server_routine(
mach_msg_header_t *InHeadP);
extern const struct receive_sysdiagnose_notification_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} receive_sysdiagnose_notification_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t flags;
} __Request__sysdiagnose_notification_t ;
union __RequestUnion__receive_sysdiagnose_notification_subsystem {
__Request__sysdiagnose_notification_t Request_sysdiagnose_notification;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__sysdiagnose_notification_t ;
union __ReplyUnion__receive_sysdiagnose_notification_subsystem {
__Reply__sysdiagnose_notification_t Reply_sysdiagnose_notification;
};
extern
kern_return_t check_task_access
(
mach_port_t task_access_port,
int32_t calling_pid,
uint32_t calling_gid,
int32_t target_pid
);
extern
kern_return_t find_code_signature
(
mach_port_t task_access_port,
int32_t new_pid
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int32_t calling_pid;
uint32_t calling_gid;
int32_t target_pid;
} __Request__check_task_access_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int32_t new_pid;
} __Request__find_code_signature_t ;
union __RequestUnion__task_access_subsystem {
__Request__check_task_access_t Request_check_task_access;
__Request__find_code_signature_t Request_find_code_signature;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__check_task_access_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__find_code_signature_t ;
union __ReplyUnion__task_access_subsystem {
__Reply__check_task_access_t Reply_check_task_access;
__Reply__find_code_signature_t Reply_find_code_signature;
};
extern
kern_return_t mach_voucher_extract_attr_content
(
ipc_voucher_t voucher,
mach_voucher_attr_key_t key,
mach_voucher_attr_content_t content,
mach_msg_type_number_t *contentCnt
);
extern
kern_return_t mach_voucher_extract_attr_recipe
(
ipc_voucher_t voucher,
mach_voucher_attr_key_t key,
mach_voucher_attr_raw_recipe_t recipe,
mach_msg_type_number_t *recipeCnt
);
extern
kern_return_t mach_voucher_extract_all_attr_recipes
(
ipc_voucher_t voucher,
mach_voucher_attr_raw_recipe_array_t recipes,
mach_msg_type_number_t *recipesCnt
);
extern
kern_return_t mach_voucher_attr_command
(
ipc_voucher_t voucher,
mach_voucher_attr_key_t key,
mach_voucher_attr_command_t command,
mach_voucher_attr_content_t in_content,
mach_msg_type_number_t in_contentCnt,
mach_voucher_attr_content_t out_content,
mach_msg_type_number_t *out_contentCnt
);
extern
kern_return_t mach_voucher_debug_info
(
ipc_space_t task,
mach_port_name_t voucher_name,
mach_voucher_attr_raw_recipe_array_t recipes,
mach_msg_type_number_t *recipesCnt
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_voucher_attr_key_t key;
mach_msg_type_number_t contentCnt;
} __Request__mach_voucher_extract_attr_content_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_voucher_attr_key_t key;
mach_msg_type_number_t recipeCnt;
} __Request__mach_voucher_extract_attr_recipe_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t recipesCnt;
} __Request__mach_voucher_extract_all_attr_recipes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_voucher_attr_key_t key;
mach_voucher_attr_command_t command;
mach_msg_type_number_t in_contentCnt;
uint8_t in_content[4096];
mach_msg_type_number_t out_contentCnt;
} __Request__mach_voucher_attr_command_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_port_name_t voucher_name;
mach_msg_type_number_t recipesCnt;
} __Request__mach_voucher_debug_info_t ;
union __RequestUnion__mach_voucher_subsystem {
__Request__mach_voucher_extract_attr_content_t Request_mach_voucher_extract_attr_content;
__Request__mach_voucher_extract_attr_recipe_t Request_mach_voucher_extract_attr_recipe;
__Request__mach_voucher_extract_all_attr_recipes_t Request_mach_voucher_extract_all_attr_recipes;
__Request__mach_voucher_attr_command_t Request_mach_voucher_attr_command;
__Request__mach_voucher_debug_info_t Request_mach_voucher_debug_info;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t contentCnt;
uint8_t content[4096];
} __Reply__mach_voucher_extract_attr_content_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t recipeCnt;
uint8_t recipe[4096];
} __Reply__mach_voucher_extract_attr_recipe_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t recipesCnt;
uint8_t recipes[5120];
} __Reply__mach_voucher_extract_all_attr_recipes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t out_contentCnt;
uint8_t out_content[4096];
} __Reply__mach_voucher_attr_command_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t recipesCnt;
uint8_t recipes[5120];
} __Reply__mach_voucher_debug_info_t ;
union __ReplyUnion__mach_voucher_subsystem {
__Reply__mach_voucher_extract_attr_content_t Reply_mach_voucher_extract_attr_content;
__Reply__mach_voucher_extract_attr_recipe_t Reply_mach_voucher_extract_attr_recipe;
__Reply__mach_voucher_extract_all_attr_recipes_t Reply_mach_voucher_extract_all_attr_recipes;
__Reply__mach_voucher_attr_command_t Reply_mach_voucher_attr_command;
__Reply__mach_voucher_debug_info_t Reply_mach_voucher_debug_info;
};
NDR_record_t NDR_record = {
0,
0,
0,
0,
1,
0,
0,
0,
};
extern
kern_return_t mach_voucher_attr_control_get_values
(
ipc_voucher_attr_control_t control,
ipc_voucher_t voucher,
mach_voucher_attr_value_handle_array_t value_handles,
mach_msg_type_number_t *value_handlesCnt
);
extern
kern_return_t mach_voucher_attr_control_create_mach_voucher
(
ipc_voucher_attr_control_t control,
mach_voucher_attr_raw_recipe_array_t recipes,
mach_msg_type_number_t recipesCnt,
ipc_voucher_t *voucher
);
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
NDR_record_t NDR;
mach_msg_type_number_t value_handlesCnt;
} __Request__mach_voucher_attr_control_get_values_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t recipesCnt;
uint8_t recipes[5120];
} __Request__mach_voucher_attr_control_create_mach_voucher_t ;
union __RequestUnion__mach_voucher_attr_control_subsystem {
__Request__mach_voucher_attr_control_get_values_t Request_mach_voucher_attr_control_get_values;
__Request__mach_voucher_attr_control_create_mach_voucher_t Request_mach_voucher_attr_control_create_mach_voucher;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t value_handlesCnt;
mach_voucher_attr_value_handle_t value_handles[4];
} __Reply__mach_voucher_attr_control_get_values_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t voucher;
} __Reply__mach_voucher_attr_control_create_mach_voucher_t ;
union __ReplyUnion__mach_voucher_attr_control_subsystem {
__Reply__mach_voucher_attr_control_get_values_t Reply_mach_voucher_attr_control_get_values;
__Reply__mach_voucher_attr_control_create_mach_voucher_t Reply_mach_voucher_attr_control_create_mach_voucher;
};
extern
kern_return_t audit_triggers
(
mach_port_t audit_port,
int flags
);
extern
boolean_t audit_triggers_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t audit_triggers_server_routine(
mach_msg_header_t *InHeadP);
extern const struct audit_triggers_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[1];
} audit_triggers_subsystem;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
int flags;
} __Request__audit_triggers_t ;
union __RequestUnion__audit_triggers_subsystem {
__Request__audit_triggers_t Request_audit_triggers;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__audit_triggers_t ;
union __ReplyUnion__audit_triggers_subsystem {
__Reply__audit_triggers_t Reply_audit_triggers;
};
typedef unsigned int routine_arg_type;
typedef unsigned int routine_arg_offset;
typedef unsigned int routine_arg_size;
struct rpc_routine_arg_descriptor {
routine_arg_type type;
routine_arg_size size;
routine_arg_size count;
routine_arg_offset offset;
};
typedef struct rpc_routine_arg_descriptor *rpc_routine_arg_descriptor_t;
struct rpc_routine_descriptor {
mig_impl_routine_t impl_routine;
mig_stub_routine_t stub_routine;
unsigned int argc;
unsigned int descr_count;
rpc_routine_arg_descriptor_t
arg_descr;
unsigned int max_reply_msg;
};
typedef struct rpc_routine_descriptor *rpc_routine_descriptor_t;
struct rpc_signature {
struct rpc_routine_descriptor rd;
struct rpc_routine_arg_descriptor rad[1];
};
struct rpc_subsystem {
void *reserved;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t base_addr;
struct rpc_routine_descriptor
routine[1
];
struct rpc_routine_arg_descriptor
arg_descriptor[1
];
};
typedef struct rpc_subsystem *rpc_subsystem_t;
extern
kern_return_t memory_object_get_attributes
(
memory_object_control_t memory_control,
memory_object_flavor_t flavor,
memory_object_info_t attributes,
mach_msg_type_number_t *attributesCnt
);
extern
kern_return_t memory_object_change_attributes
(
memory_object_control_t memory_control,
memory_object_flavor_t flavor,
memory_object_info_t attributes,
mach_msg_type_number_t attributesCnt
);
extern
kern_return_t memory_object_synchronize_completed
(
memory_object_control_t memory_control,
memory_object_offset_t offset,
memory_object_size_t length
);
extern
kern_return_t memory_object_lock_request
(
memory_object_control_t memory_control,
memory_object_offset_t offset,
memory_object_size_t size,
memory_object_offset_t *resid_offset,
integer_t *io_errno,
memory_object_return_t should_return,
integer_t flags,
vm_prot_t lock_value
);
extern
kern_return_t memory_object_destroy
(
memory_object_control_t memory_control,
kern_return_t reason
);
extern
kern_return_t memory_object_upl_request
(
memory_object_control_t memory_control,
memory_object_offset_t offset,
upl_size_t size,
upl_t *upl,
upl_page_info_array_t page_list,
mach_msg_type_number_t *page_listCnt,
integer_t cntrl_flags,
integer_t tag
);
extern
kern_return_t memory_object_super_upl_request
(
memory_object_control_t memory_control,
memory_object_offset_t offset,
upl_size_t size,
upl_size_t super_size,
upl_t *upl,
upl_page_info_array_t page_list,
mach_msg_type_number_t *page_listCnt,
integer_t cntrl_flags,
integer_t tag
);
extern
kern_return_t memory_object_cluster_size
(
memory_object_control_t control,
memory_object_offset_t *start,
vm_size_t *length,
uint32_t *io_streaming,
memory_object_fault_info_t fault_info
);
extern
kern_return_t memory_object_page_op
(
memory_object_control_t memory_control,
memory_object_offset_t offset,
integer_t ops,
uint32_t *phys_entry,
integer_t *flags
);
extern
kern_return_t memory_object_recover_named
(
memory_object_control_t memory_control,
boolean_t wait_on_terminating
);
extern
kern_return_t memory_object_release_name
(
memory_object_control_t memory_control,
integer_t flags
);
extern
kern_return_t memory_object_range_op
(
memory_object_control_t memory_control,
memory_object_offset_t offset_beg,
memory_object_offset_t offset_end,
integer_t ops,
integer_t *range
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_flavor_t flavor;
mach_msg_type_number_t attributesCnt;
} __Request__memory_object_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_flavor_t flavor;
mach_msg_type_number_t attributesCnt;
int attributes[6];
} __Request__memory_object_change_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset;
memory_object_size_t length;
} __Request__memory_object_synchronize_completed_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset;
memory_object_size_t size;
memory_object_return_t should_return;
integer_t flags;
vm_prot_t lock_value;
} __Request__memory_object_lock_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t reason;
} __Request__memory_object_destroy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset;
upl_size_t size;
mach_msg_type_number_t page_listCnt;
integer_t cntrl_flags;
integer_t tag;
} __Request__memory_object_upl_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset;
upl_size_t size;
upl_size_t super_size;
mach_msg_type_number_t page_listCnt;
integer_t cntrl_flags;
integer_t tag;
} __Request__memory_object_super_upl_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_fault_info_t fault_info;
} __Request__memory_object_cluster_size_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset;
integer_t ops;
} __Request__memory_object_page_op_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
boolean_t wait_on_terminating;
} __Request__memory_object_recover_named_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
integer_t flags;
} __Request__memory_object_release_name_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
memory_object_offset_t offset_beg;
memory_object_offset_t offset_end;
integer_t ops;
} __Request__memory_object_range_op_t ;
union __RequestUnion__memory_object_control_subsystem {
__Request__memory_object_get_attributes_t Request_memory_object_get_attributes;
__Request__memory_object_change_attributes_t Request_memory_object_change_attributes;
__Request__memory_object_synchronize_completed_t Request_memory_object_synchronize_completed;
__Request__memory_object_lock_request_t Request_memory_object_lock_request;
__Request__memory_object_destroy_t Request_memory_object_destroy;
__Request__memory_object_upl_request_t Request_memory_object_upl_request;
__Request__memory_object_super_upl_request_t Request_memory_object_super_upl_request;
__Request__memory_object_cluster_size_t Request_memory_object_cluster_size;
__Request__memory_object_page_op_t Request_memory_object_page_op;
__Request__memory_object_recover_named_t Request_memory_object_recover_named;
__Request__memory_object_release_name_t Request_memory_object_release_name;
__Request__memory_object_range_op_t Request_memory_object_range_op;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t attributesCnt;
int attributes[6];
} __Reply__memory_object_get_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__memory_object_change_attributes_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__memory_object_synchronize_completed_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
memory_object_offset_t resid_offset;
integer_t io_errno;
} __Reply__memory_object_lock_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__memory_object_destroy_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t upl;
NDR_record_t NDR;
mach_msg_type_number_t page_listCnt;
upl_page_info_t page_list[256];
} __Reply__memory_object_upl_request_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t upl;
NDR_record_t NDR;
mach_msg_type_number_t page_listCnt;
upl_page_info_t page_list[256];
} __Reply__memory_object_super_upl_request_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
memory_object_offset_t start;
vm_size_t length;
uint32_t io_streaming;
} __Reply__memory_object_cluster_size_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
uint32_t phys_entry;
integer_t flags;
} __Reply__memory_object_page_op_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__memory_object_recover_named_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__memory_object_release_name_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
integer_t range;
} __Reply__memory_object_range_op_t ;
union __ReplyUnion__memory_object_control_subsystem {
__Reply__memory_object_get_attributes_t Reply_memory_object_get_attributes;
__Reply__memory_object_change_attributes_t Reply_memory_object_change_attributes;
__Reply__memory_object_synchronize_completed_t Reply_memory_object_synchronize_completed;
__Reply__memory_object_lock_request_t Reply_memory_object_lock_request;
__Reply__memory_object_destroy_t Reply_memory_object_destroy;
__Reply__memory_object_upl_request_t Reply_memory_object_upl_request;
__Reply__memory_object_super_upl_request_t Reply_memory_object_super_upl_request;
__Reply__memory_object_cluster_size_t Reply_memory_object_cluster_size;
__Reply__memory_object_page_op_t Reply_memory_object_page_op;
__Reply__memory_object_recover_named_t Reply_memory_object_recover_named;
__Reply__memory_object_release_name_t Reply_memory_object_release_name;
__Reply__memory_object_range_op_t Reply_memory_object_range_op;
};
extern
kern_return_t check_task_access
(
mach_port_t task_access_port,
int32_t calling_pid,
uint32_t calling_gid,
int32_t target_pid,
audit_token_t caller_cred
);
extern
kern_return_t find_code_signature
(
mach_port_t task_access_port,
int32_t new_pid
);
extern
boolean_t task_access_server(
mach_msg_header_t *InHeadP,
mach_msg_header_t *OutHeadP);
extern
mig_routine_t task_access_server_routine(
mach_msg_header_t *InHeadP);
extern const struct task_access_subsystem {
mig_server_routine_t server;
mach_msg_id_t start;
mach_msg_id_t end;
unsigned int maxsize;
vm_address_t reserved;
struct routine_descriptor
routine[2];
} task_access_subsystem;
extern
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);
extern
kern_return_t mach_vm_deallocate
(
vm_map_t target,
mach_vm_address_t address,
mach_vm_size_t size
);
extern
kern_return_t mach_vm_protect
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
boolean_t set_maximum,
vm_prot_t new_protection
);
extern
kern_return_t mach_vm_inherit
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_inherit_t new_inheritance
);
extern
kern_return_t mach_vm_read
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_offset_t *data,
mach_msg_type_number_t *dataCnt
);
extern
kern_return_t mach_vm_read_list
(
vm_map_t target_task,
mach_vm_read_entry_t data_list,
natural_t count
);
extern
kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);
extern
kern_return_t mach_vm_copy
(
vm_map_t target_task,
mach_vm_address_t source_address,
mach_vm_size_t size,
mach_vm_address_t dest_address
);
extern
kern_return_t mach_vm_read_overwrite
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
mach_vm_address_t data,
mach_vm_size_t *outsize
);
extern
kern_return_t mach_vm_msync
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_sync_t sync_flags
);
extern
kern_return_t mach_vm_behavior_set
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_behavior_t new_behavior
);
extern
kern_return_t mach_vm_map
(
vm_map_t target_task,
mach_vm_address_t *address,
mach_vm_size_t size,
mach_vm_offset_t mask,
int flags,
mem_entry_name_port_t object,
memory_object_offset_t offset,
boolean_t copy,
vm_prot_t cur_protection,
vm_prot_t max_protection,
vm_inherit_t inheritance
);
extern
kern_return_t mach_vm_machine_attribute
(
vm_map_t target_task,
mach_vm_address_t address,
mach_vm_size_t size,
vm_machine_attribute_t attribute,
vm_machine_attribute_val_t *value
);
extern
kern_return_t mach_vm_remap
(
vm_map_t target_task,
mach_vm_address_t *target_address,
mach_vm_size_t size,
mach_vm_offset_t mask,
int flags,
vm_map_t src_task,
mach_vm_address_t src_address,
boolean_t copy,
vm_prot_t *cur_protection,
vm_prot_t *max_protection,
vm_inherit_t inheritance
);
extern
kern_return_t mach_vm_page_query
(
vm_map_t target_map,
mach_vm_offset_t offset,
integer_t *disposition,
integer_t *ref_count
);
extern
kern_return_t mach_vm_region_recurse
(
vm_map_t target_task,
mach_vm_address_t *address,
mach_vm_size_t *size,
natural_t *nesting_depth,
vm_region_recurse_info_t info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t mach_vm_region
(
vm_map_t target_task,
mach_vm_address_t *address,
mach_vm_size_t *size,
vm_region_flavor_t flavor,
vm_region_info_t info,
mach_msg_type_number_t *infoCnt,
mach_port_t *object_name
);
extern
kern_return_t _mach_make_memory_entry
(
vm_map_t target_task,
memory_object_size_t *size,
memory_object_offset_t offset,
vm_prot_t permission,
mem_entry_name_port_t *object_handle,
mem_entry_name_port_t parent_handle
);
extern
kern_return_t mach_vm_purgable_control
(
vm_map_t target_task,
mach_vm_address_t address,
vm_purgable_t control,
int *state
);
extern
kern_return_t mach_vm_page_info
(
vm_map_t target_task,
mach_vm_address_t address,
vm_page_info_flavor_t flavor,
vm_page_info_t info,
mach_msg_type_number_t *infoCnt
);
extern
kern_return_t mach_vm_page_range_query
(
vm_map_t target_map,
mach_vm_offset_t address,
mach_vm_size_t size,
mach_vm_address_t dispositions,
mach_vm_size_t *dispositions_count
);
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
int flags;
} __Request__mach_vm_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
} __Request__mach_vm_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
boolean_t set_maximum;
vm_prot_t new_protection;
} __Request__mach_vm_protect_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
vm_inherit_t new_inheritance;
} __Request__mach_vm_inherit_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
} __Request__mach_vm_read_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_read_entry_t data_list;
natural_t count;
} __Request__mach_vm_read_list_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
mach_vm_address_t address;
mach_msg_type_number_t dataCnt;
} __Request__mach_vm_write_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t source_address;
mach_vm_size_t size;
mach_vm_address_t dest_address;
} __Request__mach_vm_copy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
mach_vm_address_t data;
} __Request__mach_vm_read_overwrite_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
vm_sync_t sync_flags;
} __Request__mach_vm_msync_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
vm_behavior_t new_behavior;
} __Request__mach_vm_behavior_set_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
mach_vm_offset_t mask;
int flags;
memory_object_offset_t offset;
boolean_t copy;
vm_prot_t cur_protection;
vm_prot_t max_protection;
vm_inherit_t inheritance;
} __Request__mach_vm_map_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
vm_machine_attribute_t attribute;
vm_machine_attribute_val_t value;
} __Request__mach_vm_machine_attribute_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t src_task;
NDR_record_t NDR;
mach_vm_address_t target_address;
mach_vm_size_t size;
mach_vm_offset_t mask;
int flags;
mach_vm_address_t src_address;
boolean_t copy;
vm_inherit_t inheritance;
} __Request__mach_vm_remap_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_offset_t offset;
} __Request__mach_vm_page_query_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
} __Request__mach_vm_region_recurse_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
vm_region_flavor_t flavor;
mach_msg_type_number_t infoCnt;
} __Request__mach_vm_region_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t parent_handle;
NDR_record_t NDR;
memory_object_size_t size;
memory_object_offset_t offset;
vm_prot_t permission;
} __Request___mach_make_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
vm_purgable_t control;
int state;
} __Request__mach_vm_purgable_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_address_t address;
vm_page_info_flavor_t flavor;
mach_msg_type_number_t infoCnt;
} __Request__mach_vm_page_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_vm_offset_t address;
mach_vm_size_t size;
mach_vm_address_t dispositions;
mach_vm_size_t dispositions_count;
} __Request__mach_vm_page_range_query_t ;
union __RequestUnion__mach_vm_subsystem {
__Request__mach_vm_allocate_t Request_mach_vm_allocate;
__Request__mach_vm_deallocate_t Request_mach_vm_deallocate;
__Request__mach_vm_protect_t Request_mach_vm_protect;
__Request__mach_vm_inherit_t Request_mach_vm_inherit;
__Request__mach_vm_read_t Request_mach_vm_read;
__Request__mach_vm_read_list_t Request_mach_vm_read_list;
__Request__mach_vm_write_t Request_mach_vm_write;
__Request__mach_vm_copy_t Request_mach_vm_copy;
__Request__mach_vm_read_overwrite_t Request_mach_vm_read_overwrite;
__Request__mach_vm_msync_t Request_mach_vm_msync;
__Request__mach_vm_behavior_set_t Request_mach_vm_behavior_set;
__Request__mach_vm_map_t Request_mach_vm_map;
__Request__mach_vm_machine_attribute_t Request_mach_vm_machine_attribute;
__Request__mach_vm_remap_t Request_mach_vm_remap;
__Request__mach_vm_page_query_t Request_mach_vm_page_query;
__Request__mach_vm_region_recurse_t Request_mach_vm_region_recurse;
__Request__mach_vm_region_t Request_mach_vm_region;
__Request___mach_make_memory_entry_t Request__mach_make_memory_entry;
__Request__mach_vm_purgable_control_t Request_mach_vm_purgable_control;
__Request__mach_vm_page_info_t Request_mach_vm_page_info;
__Request__mach_vm_page_range_query_t Request_mach_vm_page_range_query;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t address;
} __Reply__mach_vm_allocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_deallocate_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_protect_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_inherit_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t data;
NDR_record_t NDR;
mach_msg_type_number_t dataCnt;
} __Reply__mach_vm_read_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_read_entry_t data_list;
} __Reply__mach_vm_read_list_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_write_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_copy_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_size_t outsize;
} __Reply__mach_vm_read_overwrite_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_msync_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_vm_behavior_set_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t address;
} __Reply__mach_vm_map_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
vm_machine_attribute_val_t value;
} __Reply__mach_vm_machine_attribute_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t target_address;
vm_prot_t cur_protection;
vm_prot_t max_protection;
} __Reply__mach_vm_remap_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
integer_t disposition;
integer_t ref_count;
} __Reply__mach_vm_page_query_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_address_t address;
mach_vm_size_t size;
natural_t nesting_depth;
mach_msg_type_number_t infoCnt;
int info[19];
} __Reply__mach_vm_region_recurse_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_name;
NDR_record_t NDR;
mach_vm_address_t address;
mach_vm_size_t size;
mach_msg_type_number_t infoCnt;
int info[10];
} __Reply__mach_vm_region_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t object_handle;
NDR_record_t NDR;
memory_object_size_t size;
} __Reply___mach_make_memory_entry_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
int state;
} __Reply__mach_vm_purgable_control_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_msg_type_number_t infoCnt;
int info[32];
} __Reply__mach_vm_page_info_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
mach_vm_size_t dispositions_count;
} __Reply__mach_vm_page_range_query_t ;
union __ReplyUnion__mach_vm_subsystem {
__Reply__mach_vm_allocate_t Reply_mach_vm_allocate;
__Reply__mach_vm_deallocate_t Reply_mach_vm_deallocate;
__Reply__mach_vm_protect_t Reply_mach_vm_protect;
__Reply__mach_vm_inherit_t Reply_mach_vm_inherit;
__Reply__mach_vm_read_t Reply_mach_vm_read;
__Reply__mach_vm_read_list_t Reply_mach_vm_read_list;
__Reply__mach_vm_write_t Reply_mach_vm_write;
__Reply__mach_vm_copy_t Reply_mach_vm_copy;
__Reply__mach_vm_read_overwrite_t Reply_mach_vm_read_overwrite;
__Reply__mach_vm_msync_t Reply_mach_vm_msync;
__Reply__mach_vm_behavior_set_t Reply_mach_vm_behavior_set;
__Reply__mach_vm_map_t Reply_mach_vm_map;
__Reply__mach_vm_machine_attribute_t Reply_mach_vm_machine_attribute;
__Reply__mach_vm_remap_t Reply_mach_vm_remap;
__Reply__mach_vm_page_query_t Reply_mach_vm_page_query;
__Reply__mach_vm_region_recurse_t Reply_mach_vm_region_recurse;
__Reply__mach_vm_region_t Reply_mach_vm_region;
__Reply___mach_make_memory_entry_t Reply__mach_make_memory_entry;
__Reply__mach_vm_purgable_control_t Reply_mach_vm_purgable_control;
__Reply__mach_vm_page_info_t Reply_mach_vm_page_info;
__Reply__mach_vm_page_range_query_t Reply_mach_vm_page_range_query;
};
extern mach_port_t master_device_port;
void *alloca(size_t);
typedef struct {
int quot;
int rem;
} div_t;
typedef struct {
long quot;
long rem;
} ldiv_t;
typedef struct {
long long quot;
long long rem;
} lldiv_t;
extern int __mb_cur_max;
void abort(void) ;
int abs(int) ;
int atexit(void (* )(void));
double atof(const char *);
int atoi(const char *);
long atol(const char *);
long long
atoll(const char *);
void *bsearch(const void *__key, const void *__base, size_t __nel,
size_t __width, int (*  __compar)(const void *, const void *));
void *calloc(size_t __count, size_t __size)  ;
div_t div(int, int) ;
void exit(int) ;
void free(void *);
char *getenv(const char *);
long labs(long) ;
ldiv_t ldiv(long, long) ;
long long
llabs(long long);
lldiv_t lldiv(long long, long long);
void *malloc(size_t __size)  ;
int mblen(const char *__s, size_t __n);
size_t mbstowcs(wchar_t * , const char *, size_t);
int mbtowc(wchar_t *, const char *, size_t);
int posix_memalign(void **__memptr, size_t __alignment, size_t __size) ;
void qsort(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *));
int rand(void) ;
void *realloc(void *__ptr, size_t __size)  ;
void srand(unsigned) ;
double strtod(const char *, char **) ;
float strtof(const char *, char **) ;
long strtol(const char *__str, char **__endptr, int __base);
long double
strtold(const char *, char **);
long long
strtoll(const char *__str, char **__endptr, int __base);
unsigned long
strtoul(const char *__str, char **__endptr, int __base);
unsigned long long
strtoull(const char *__str, char **__endptr, int __base);

 
 
int system(const char *) ;
size_t wcstombs(char *, const wchar_t *, size_t);
int wctomb(char *, wchar_t);
void _Exit(int) ;
long a64l(const char *);
double drand48(void);
char *ecvt(double, int, int *restrict, int *restrict);
double erand48(unsigned short[3]);
char *fcvt(double, int, int *restrict, int *restrict);
char *gcvt(double, int, char *);
int getsubopt(char **, char * const *, char **);
int grantpt(int);
char *initstate(unsigned long, char *, long);
long jrand48(unsigned short[3]) ;
char *l64a(long);
void lcong48(unsigned short[7]);
long lrand48(void) ;
char *mktemp(char *);
int mkstemp(char *);
long mrand48(void) ;
long nrand48(unsigned short[3]) ;
int posix_openpt(int);
char *ptsname(int);
int ptsname_r(int fildes, char *buffer, size_t buflen)    ;
int putenv(char *) ;
long random(void) ;
int rand_r(unsigned *) ;
char *realpath(const char *, char *) ;
unsigned short
*seed48(unsigned short[3]);
int setenv(const char * __name, const char * __value, int __overwrite) ;
int setkey(const char *);
char *setstate(const char *);
void srand48(long);
void srandom(unsigned long);
int unlockpt(int);
void unsetenv(const char *);
uint32_t arc4random(void);
void arc4random_addrandom(unsigned char * , int )
 
 
 
 ;
void arc4random_buf(void * __buf, size_t __nbytes) ;
void arc4random_stir(void);
uint32_t
arc4random_uniform(uint32_t __upper_bound) ;
int atexit_b(void (* )(void)) ;
void *bsearch_b(const void *__key, const void *__base, size_t __nel,
size_t __width, int (*  __compar)(const void *, const void *)) ;
char *cgetcap(char *, const char *, int);
int cgetclose(void);
int cgetent(char **, char **, const char *);
int cgetfirst(char **, char **);
int cgetmatch(const char *, const char *);
int cgetnext(char **, char **);
int cgetnum(char *, const char *, long *);
int cgetset(const char *);
int cgetstr(char *, const char *, char **);
int cgetustr(char *, const char *, char **);
int daemon(int, int)    ;
char *devname(dev_t, mode_t);
char *devname_r(dev_t, mode_t, char *buf, int len);
char *getbsize(int *, long *);
int getloadavg(double [], int);
const char
*getprogname(void);
int heapsort(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *));
int heapsort_b(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *)) ;
int mergesort(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *));
int mergesort_b(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *)) ;
void psort(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *)) ;
void psort_b(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *)) ;
void psort_r(void *__base, size_t __nel, size_t __width, void *,
int (*  __compar)(void *, const void *, const void *)) ;
void qsort_b(void *__base, size_t __nel, size_t __width,
int (*  __compar)(const void *, const void *)) ;
void qsort_r(void *__base, size_t __nel, size_t __width, void *,
int (*  __compar)(void *, const void *, const void *));
int radixsort(const unsigned char **__base, int __nel, const unsigned char *__table,
unsigned __endbyte);
void setprogname(const char *);
int sradixsort(const unsigned char **__base, int __nel, const unsigned char *__table,
unsigned __endbyte);
void sranddev(void);
void srandomdev(void);
void *reallocf(void *__ptr, size_t __size) ;
long long
strtoq(const char *__str, char **__endptr, int __base);
unsigned long long
strtouq(const char *__str, char **__endptr, int __base);
extern char *suboptarg;
void *valloc(size_t) ;
typedef const struct _xpc_type_s * xpc_type_t;
typedef void * xpc_object_t;
typedef void (*xpc_handler_t)(xpc_object_t object);

extern 
const struct _xpc_type_s _xpc_type_connection;
typedef struct _xpc_connection_s * xpc_connection_t;
typedef void (*xpc_connection_handler_t)(xpc_connection_t connection);

extern 
const struct _xpc_type_s _xpc_type_endpoint;
typedef struct _xpc_endpoint_s * xpc_endpoint_t;

extern 
const struct _xpc_type_s _xpc_type_null;

extern 
const struct _xpc_type_s _xpc_type_bool;

extern 
const struct _xpc_bool_s _xpc_bool_true;

extern 
const struct _xpc_bool_s _xpc_bool_false;

extern 
const struct _xpc_type_s _xpc_type_int64;

extern 
const struct _xpc_type_s _xpc_type_uint64;

extern 
const struct _xpc_type_s _xpc_type_double;

extern 
const struct _xpc_type_s _xpc_type_date;

extern 
const struct _xpc_type_s _xpc_type_data;

extern 
const struct _xpc_type_s _xpc_type_string;

extern 
const struct _xpc_type_s _xpc_type_uuid;

extern 
const struct _xpc_type_s _xpc_type_fd;

extern 
const struct _xpc_type_s _xpc_type_shmem;

extern 
const struct _xpc_type_s _xpc_type_array;

extern 
const struct _xpc_type_s _xpc_type_dictionary;

extern 
const struct _xpc_type_s _xpc_type_error;

extern 
const char *const _xpc_error_key_description;

extern 
const char *const _xpc_event_key_name;

extern    
xpc_endpoint_t 
xpc_endpoint_create(xpc_connection_t  connection);
 
const char *
xpc_debugger_api_misuse_info(void);

extern 
const struct _xpc_dictionary_s _xpc_error_connection_interrupted;

extern 
const struct _xpc_dictionary_s _xpc_error_connection_invalid;

extern 
const struct _xpc_dictionary_s _xpc_error_termination_imminent;
typedef void (*xpc_finalizer_t)(void *  value);

extern   
xpc_connection_t
xpc_connection_create(const char *  name,
dispatch_queue_t  targetq);

extern    
xpc_connection_t
xpc_connection_create_mach_service(const char *name,
dispatch_queue_t  targetq, uint64_t flags);

extern    
xpc_connection_t
xpc_connection_create_from_endpoint(xpc_endpoint_t endpoint);

extern  
void
xpc_connection_set_target_queue(xpc_connection_t connection,
dispatch_queue_t  targetq);

extern  
void
xpc_connection_set_event_handler(xpc_connection_t connection,
xpc_handler_t handler);
 
 
extern  
void
xpc_connection_activate(xpc_connection_t connection);

extern  
void
xpc_connection_suspend(xpc_connection_t connection);

extern  
void
xpc_connection_resume(xpc_connection_t connection);

extern  
void
xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message);

extern  
void
xpc_connection_send_barrier(xpc_connection_t connection,
dispatch_block_t barrier);

extern    
void
xpc_connection_send_message_with_reply(xpc_connection_t connection,
xpc_object_t message, dispatch_queue_t  replyq,
xpc_handler_t handler);

extern   
xpc_object_t
xpc_connection_send_message_with_reply_sync(xpc_connection_t connection,
xpc_object_t message);

extern  
void
xpc_connection_cancel(xpc_connection_t connection);

extern   
const char * 
xpc_connection_get_name(xpc_connection_t connection);

extern   
uid_t
xpc_connection_get_euid(xpc_connection_t connection);

extern   
gid_t
xpc_connection_get_egid(xpc_connection_t connection);

extern   
pid_t
xpc_connection_get_pid(xpc_connection_t connection);

extern   
au_asid_t
xpc_connection_get_asid(xpc_connection_t connection);

extern  
void
xpc_connection_set_context(xpc_connection_t connection,
void *  context);

extern   
void * 
xpc_connection_get_context(xpc_connection_t connection);

extern  
void
xpc_connection_set_finalizer_f(xpc_connection_t connection,
xpc_finalizer_t  finalizer);

extern 
const char *XPC_ACTIVITY_INTERVAL;

extern 
const char *XPC_ACTIVITY_REPEATING;

extern 
const char *XPC_ACTIVITY_DELAY;

extern 
const char *XPC_ACTIVITY_GRACE_PERIOD;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_1_MIN;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_5_MIN;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_15_MIN;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_30_MIN;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_1_HOUR;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_4_HOURS;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_8_HOURS;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_1_DAY;

extern 
const int64_t XPC_ACTIVITY_INTERVAL_7_DAYS;

extern 
const char *XPC_ACTIVITY_PRIORITY;

extern 
const char *XPC_ACTIVITY_PRIORITY_MAINTENANCE;

extern 
const char *XPC_ACTIVITY_PRIORITY_UTILITY;

extern 
const char *XPC_ACTIVITY_ALLOW_BATTERY;

extern 
const char *XPC_ACTIVITY_REQUIRE_SCREEN_SLEEP;

extern 
const char *XPC_ACTIVITY_REQUIRE_BATTERY_LEVEL;

extern 
const char *XPC_ACTIVITY_REQUIRE_HDD_SPINNING;

extern 
const struct _xpc_type_s _xpc_type_activity;
typedef struct _xpc_activity_s * xpc_activity_t;

typedef void (*xpc_activity_handler_t)(xpc_activity_t activity);

extern 
const xpc_object_t XPC_ACTIVITY_CHECK_IN;

extern    
void
xpc_activity_register(const char *identifier, xpc_object_t criteria,
xpc_activity_handler_t handler);

extern   
xpc_object_t 
xpc_activity_copy_criteria(xpc_activity_t activity);

extern   
void
xpc_activity_set_criteria(xpc_activity_t activity, xpc_object_t criteria);
enum {
XPC_ACTIVITY_STATE_CHECK_IN,
XPC_ACTIVITY_STATE_WAIT,
XPC_ACTIVITY_STATE_RUN,
XPC_ACTIVITY_STATE_DEFER,
XPC_ACTIVITY_STATE_CONTINUE,
XPC_ACTIVITY_STATE_DONE,
};
typedef long xpc_activity_state_t;

extern   
xpc_activity_state_t
xpc_activity_get_state(xpc_activity_t activity);

extern   
_Bool
xpc_activity_set_state(xpc_activity_t activity, xpc_activity_state_t state);

extern   
_Bool
xpc_activity_should_defer(xpc_activity_t activity);

extern  
void
xpc_activity_unregister(const char *identifier);

extern     
int
launch_activate_socket(const char *name,
int *  *  fds, size_t *cnt);
typedef struct _launch_data *launch_data_t;
typedef void (*launch_data_dict_iterator_t)(const launch_data_t lval,
const char *key, void *  ctx);
typedef enum {
LAUNCH_DATA_DICTIONARY = 1,
LAUNCH_DATA_ARRAY,
LAUNCH_DATA_FD,
LAUNCH_DATA_INTEGER,
LAUNCH_DATA_REAL,
LAUNCH_DATA_BOOL,
LAUNCH_DATA_STRING,
LAUNCH_DATA_OPAQUE,
LAUNCH_DATA_ERRNO,
LAUNCH_DATA_MACHPORT,
} launch_data_type_t;

extern   
launch_data_t
launch_data_alloc(launch_data_type_t type);

extern    
launch_data_t
launch_data_copy(launch_data_t ld);

extern   
launch_data_type_t
launch_data_get_type(const launch_data_t ld);

extern  
void
launch_data_free(launch_data_t ld);

extern    
_Bool
launch_data_dict_insert(launch_data_t ldict, const launch_data_t lval,
const char *key);

extern    
launch_data_t 
launch_data_dict_lookup(const launch_data_t ldict, const char *key);

extern   
_Bool
launch_data_dict_remove(launch_data_t ldict, const char *key);

extern   
void
launch_data_dict_iterate(const launch_data_t ldict,
launch_data_dict_iterator_t iterator, void *  ctx);

extern   
size_t
launch_data_dict_get_count(const launch_data_t ldict);

extern   
_Bool
launch_data_array_set_index(launch_data_t larray, const launch_data_t lval,
size_t idx);

extern   
launch_data_t
launch_data_array_get_index(const launch_data_t larray, size_t idx);

extern   
size_t
launch_data_array_get_count(const launch_data_t larray);

extern   
launch_data_t
launch_data_new_fd(int fd);

extern   
launch_data_t
launch_data_new_machport(mach_port_t val);

extern   
launch_data_t
launch_data_new_integer(long long val);

extern   
launch_data_t
launch_data_new_bool(_Bool val);

extern   
launch_data_t
launch_data_new_real(double val);

extern   
launch_data_t
launch_data_new_string(const char *val);

extern   
launch_data_t
launch_data_new_opaque(const void *bytes, size_t sz);

extern  
_Bool
launch_data_set_fd(launch_data_t ld, int fd);

extern  
_Bool
launch_data_set_machport(launch_data_t ld, mach_port_t mp);

extern  
_Bool
launch_data_set_integer(launch_data_t ld, long long val);

extern  
_Bool
launch_data_set_bool(launch_data_t ld, _Bool val);

extern  
_Bool
launch_data_set_real(launch_data_t ld, double val);

extern  
_Bool
launch_data_set_string(launch_data_t ld, const char *val);

extern  
_Bool
launch_data_set_opaque(launch_data_t ld, const void *bytes, size_t sz);

extern   
int
launch_data_get_fd(const launch_data_t ld);

extern   
mach_port_t
launch_data_get_machport(const launch_data_t ld);

extern   
long long
launch_data_get_integer(const launch_data_t ld);

extern   
_Bool
launch_data_get_bool(const launch_data_t ld);

extern   
double
launch_data_get_real(const launch_data_t ld);

extern   
const char *
launch_data_get_string(const launch_data_t ld);

extern   
void *
launch_data_get_opaque(const launch_data_t ld);

extern   
size_t
launch_data_get_opaque_size(const launch_data_t ld);

extern   
int
launch_data_get_errno(const launch_data_t ld);

extern  
int
launch_get_fd(void);

extern    
launch_data_t
launch_msg(const launch_data_t request);

extern  
xpc_object_t
xpc_retain(xpc_object_t object);

extern  
void
xpc_release(xpc_object_t object);

extern   
xpc_type_t
xpc_get_type(xpc_object_t object);

extern   
xpc_object_t 
xpc_copy(xpc_object_t object);

extern    
_Bool
xpc_equal(xpc_object_t object1, xpc_object_t object2);

extern   
size_t
xpc_hash(xpc_object_t object);

extern    
char *
xpc_copy_description(xpc_object_t object);

extern  
xpc_object_t
xpc_null_create(void);

extern  
xpc_object_t
xpc_bool_create(_Bool value);

extern 
_Bool
xpc_bool_get_value(xpc_object_t xbool);

extern   
xpc_object_t
xpc_int64_create(int64_t value);

extern   
int64_t
xpc_int64_get_value(xpc_object_t xint);

extern   
xpc_object_t
xpc_uint64_create(uint64_t value);

extern   
uint64_t
xpc_uint64_get_value(xpc_object_t xuint);

extern   
xpc_object_t
xpc_double_create(double value);

extern   
double
xpc_double_get_value(xpc_object_t xdouble);

extern   
xpc_object_t
xpc_date_create(int64_t interval);

extern   
xpc_object_t
xpc_date_create_from_current(void);

extern   
int64_t
xpc_date_get_value(xpc_object_t xdate);

extern   
xpc_object_t
xpc_data_create(const void *  bytes, size_t length);

extern    
xpc_object_t
xpc_data_create_with_dispatch_data(dispatch_data_t ddata);

extern   
size_t
xpc_data_get_length(xpc_object_t xdata);

extern   
const void * 
xpc_data_get_bytes_ptr(xpc_object_t xdata);

extern    
size_t
xpc_data_get_bytes(xpc_object_t xdata,
void *buffer, size_t off, size_t length);

extern    
xpc_object_t
xpc_string_create(const char *string);

extern    

xpc_object_t
xpc_string_create_with_format(const char *fmt, ...);

extern    

xpc_object_t
xpc_string_create_with_format_and_arguments(const char *fmt, va_list ap);

extern   
size_t
xpc_string_get_length(xpc_object_t xstring);

extern   
const char * 
xpc_string_get_string_ptr(xpc_object_t xstring);

extern    
xpc_object_t
xpc_uuid_create(const uuid_t  uuid);

extern  
const uint8_t * 
xpc_uuid_get_bytes(xpc_object_t xuuid);

extern   
xpc_object_t 
xpc_fd_create(int fd);

extern   
int
xpc_fd_dup(xpc_object_t xfd);

extern    
xpc_object_t
xpc_shmem_create(void *region, size_t length);

extern   
size_t
xpc_shmem_map(xpc_object_t xshmem, void *  *  region);
typedef _Bool (*xpc_array_applier_t)(size_t index, xpc_object_t  value);

extern   
xpc_object_t
xpc_array_create(const xpc_object_t  *  objects, size_t count);

extern   
void
xpc_array_set_value(xpc_object_t xarray, size_t index, xpc_object_t value);

extern   
void
xpc_array_append_value(xpc_object_t xarray, xpc_object_t value);

extern   
size_t
xpc_array_get_count(xpc_object_t xarray);

extern  
xpc_object_t
xpc_array_get_value(xpc_object_t xarray, size_t index);

extern  
_Bool
xpc_array_apply(xpc_object_t xarray,  xpc_array_applier_t applier);

extern  
void
xpc_array_set_bool(xpc_object_t xarray, size_t index, _Bool value);

extern  
void
xpc_array_set_int64(xpc_object_t xarray, size_t index, int64_t value);

extern  
void
xpc_array_set_uint64(xpc_object_t xarray, size_t index, uint64_t value);

extern  
void
xpc_array_set_double(xpc_object_t xarray, size_t index, double value);

extern  
void
xpc_array_set_date(xpc_object_t xarray, size_t index, int64_t value);

extern   
void
xpc_array_set_data(xpc_object_t xarray, size_t index, const void *bytes,
size_t length);

extern   
void
xpc_array_set_string(xpc_object_t xarray, size_t index, const char *string);

extern   
void
xpc_array_set_uuid(xpc_object_t xarray, size_t index,
const uuid_t  uuid);

extern  
void
xpc_array_set_fd(xpc_object_t xarray, size_t index, int fd);

extern   
void
xpc_array_set_connection(xpc_object_t xarray, size_t index,
xpc_connection_t connection);

extern   
_Bool
xpc_array_get_bool(xpc_object_t xarray, size_t index);

extern   
int64_t
xpc_array_get_int64(xpc_object_t xarray, size_t index);

extern   
uint64_t
xpc_array_get_uint64(xpc_object_t xarray, size_t index);

extern   
double
xpc_array_get_double(xpc_object_t xarray, size_t index);

extern   
int64_t
xpc_array_get_date(xpc_object_t xarray, size_t index);

extern   
const void * 
xpc_array_get_data(xpc_object_t xarray, size_t index,
size_t *  length);

extern   
const char * 
xpc_array_get_string(xpc_object_t xarray, size_t index);

extern   
const uint8_t * 
xpc_array_get_uuid(xpc_object_t xarray, size_t index);

extern   
int
xpc_array_dup_fd(xpc_object_t xarray, size_t index);

extern    
xpc_connection_t 
xpc_array_create_connection(xpc_object_t xarray, size_t index);

extern   
xpc_object_t 
xpc_array_get_dictionary(xpc_object_t self, size_t index);

extern   
xpc_object_t 
xpc_array_get_array(xpc_object_t self, size_t index);
typedef _Bool (*xpc_dictionary_applier_t)(const char *  key,
xpc_object_t  value);

extern   
xpc_object_t
xpc_dictionary_create(const char *  const *  keys,
const xpc_object_t  *  values, size_t count);

extern    
xpc_object_t 
xpc_dictionary_create_reply(xpc_object_t original);

extern   
void
xpc_dictionary_set_value(xpc_object_t xdict, const char *key,
xpc_object_t  value);

extern    
xpc_object_t 
xpc_dictionary_get_value(xpc_object_t xdict, const char *key);

extern   
size_t
xpc_dictionary_get_count(xpc_object_t xdict);

extern  
_Bool
xpc_dictionary_apply(xpc_object_t xdict,
 xpc_dictionary_applier_t applier);

extern   
xpc_connection_t 
xpc_dictionary_get_remote_connection(xpc_object_t xdict);

extern   
void
xpc_dictionary_set_bool(xpc_object_t xdict, const char *key, _Bool value);

extern   
void
xpc_dictionary_set_int64(xpc_object_t xdict, const char *key, int64_t value);

extern   
void
xpc_dictionary_set_uint64(xpc_object_t xdict, const char *key, uint64_t value);

extern   
void
xpc_dictionary_set_double(xpc_object_t xdict, const char *key, double value);

extern   
void
xpc_dictionary_set_date(xpc_object_t xdict, const char *key, int64_t value);

extern    
void
xpc_dictionary_set_data(xpc_object_t xdict, const char *key, const void *bytes,
size_t length);

extern    
void
xpc_dictionary_set_string(xpc_object_t xdict, const char *key,
const char *string);

extern    
void
xpc_dictionary_set_uuid(xpc_object_t xdict, const char *key,
const uuid_t  uuid);

extern   
void
xpc_dictionary_set_fd(xpc_object_t xdict, const char *key, int fd);

extern    
void
xpc_dictionary_set_connection(xpc_object_t xdict, const char *key,
xpc_connection_t connection);

extern   
_Bool
xpc_dictionary_get_bool(xpc_object_t xdict, const char *key);

extern   
int64_t
xpc_dictionary_get_int64(xpc_object_t xdict, const char *key);

extern   
uint64_t
xpc_dictionary_get_uint64(xpc_object_t xdict, const char *key);

extern   
double
xpc_dictionary_get_double(xpc_object_t xdict, const char *key);

extern   
int64_t
xpc_dictionary_get_date(xpc_object_t xdict, const char *key);

extern   
const void * 
xpc_dictionary_get_data(xpc_object_t xdict, const char *key,
size_t *  length);

extern   
const char * 
xpc_dictionary_get_string(xpc_object_t xdict, const char *key);

extern    
const uint8_t * 
xpc_dictionary_get_uuid(xpc_object_t xdict, const char *key);

extern   
int
xpc_dictionary_dup_fd(xpc_object_t xdict, const char *key);

extern    
xpc_connection_t 
xpc_dictionary_create_connection(xpc_object_t xdict, const char *key);

extern   
xpc_object_t 
xpc_dictionary_get_dictionary(xpc_object_t self, const char *key);

extern   
xpc_object_t 
xpc_dictionary_get_array(xpc_object_t self, const char *key);

extern   
void
xpc_main(xpc_connection_handler_t handler);

extern 
void
xpc_transaction_begin(void);

extern 
void
xpc_transaction_end(void);

extern   
void
xpc_set_event_stream_handler(const char *stream,
dispatch_queue_t  targetq, xpc_handler_t handler);
extern void *__dso_handle;

static inline void
_os_trace_verify_printf(const char *msg, ...) 
{
}
typedef void (*os_trace_payload_t)(xpc_object_t xdict);

extern   
_Bool
os_trace_info_enabled(void);
   
extern   
_Bool
os_trace_debug_enabled(void);

extern  
size_t
_os_trace_encode(uint8_t *buf, size_t buf_size, const char *format, ...);

extern  
void
_os_trace_internal(void *dso, uint8_t type, const char *format, const uint8_t *buf, size_t buf_size, os_trace_payload_t payload);
   
extern  
void
_os_trace_with_buffer(void *dso, const char *message, uint8_t type, const void *buffer, size_t buffer_size, os_trace_payload_t payload);
extern void *__dso_handle;
 static inline void _os_log_verify_format_str( const char *msg, ...) ;
 static inline void _os_log_verify_format_str( const char *msg, ...) { }
typedef struct os_log_s *os_log_t;

extern 
struct os_log_s _os_log_default;
enum { OS_LOG_TYPE_DEFAULT = 0x00, OS_LOG_TYPE_INFO = 0x01, OS_LOG_TYPE_DEBUG = 0x02, OS_LOG_TYPE_ERROR = 0x10, OS_LOG_TYPE_FAULT = 0x11 }; typedef uint8_t os_log_type_t;

extern   
os_log_t
os_log_create(const char *subsystem, const char *category);
   
extern   
_Bool
os_log_info_enabled(os_log_t log);
   
extern   
_Bool
os_log_debug_enabled(os_log_t log);
   
extern  
void
_os_log_internal(void *dso, os_log_t log, os_log_type_t type, const char *message, ...);
extern
kern_return_t kextd_ping
(
mach_port_t server
);
typedef struct {
mach_msg_header_t Head;
} __Request__kextd_ping_t ;
union __RequestUnion__kextd_kernel_request_subsystem {
__Request__kextd_ping_t Request_kextd_ping;
};
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__kextd_ping_t ;
union __ReplyUnion__kextd_kernel_request_subsystem {
__Reply__kextd_ping_t Reply_kextd_ping;
};
struct nlist {
union {
uint32_t n_strx;
} n_un;
uint8_t n_type;
uint8_t n_sect;
int16_t n_desc;
uint32_t n_value;
};
struct nlist_64 {
union {
uint32_t n_strx;
} n_un;
uint8_t n_type;
uint8_t n_sect;
uint16_t n_desc;
uint64_t n_value;
};
extern int nlist (const char *filename, struct nlist *list);
struct mach_header {
uint32_t magic;
cpu_type_t cputype;
cpu_subtype_t cpusubtype;
uint32_t filetype;
uint32_t ncmds;
uint32_t sizeofcmds;
uint32_t flags;
};
struct mach_header_64 {
uint32_t magic;
cpu_type_t cputype;
cpu_subtype_t cpusubtype;
uint32_t filetype;
uint32_t ncmds;
uint32_t sizeofcmds;
uint32_t flags;
uint32_t reserved;
};
struct load_command {
uint32_t cmd;
uint32_t cmdsize;
};
union lc_str {
uint32_t offset;
};
struct segment_command {
uint32_t cmd;
uint32_t cmdsize;
char segname[16];
uint32_t vmaddr;
uint32_t vmsize;
uint32_t fileoff;
uint32_t filesize;
vm_prot_t maxprot;
vm_prot_t initprot;
uint32_t nsects;
uint32_t flags;
};
struct segment_command_64 {
uint32_t cmd;
uint32_t cmdsize;
char segname[16];
uint64_t vmaddr;
uint64_t vmsize;
uint64_t fileoff;
uint64_t filesize;
vm_prot_t maxprot;
vm_prot_t initprot;
uint32_t nsects;
uint32_t flags;
};
struct section {
char sectname[16];
char segname[16];
uint32_t addr;
uint32_t size;
uint32_t offset;
uint32_t align;
uint32_t reloff;
uint32_t nreloc;
uint32_t flags;
uint32_t reserved1;
uint32_t reserved2;
};
struct section_64 {
char sectname[16];
char segname[16];
uint64_t addr;
uint64_t size;
uint32_t offset;
uint32_t align;
uint32_t reloff;
uint32_t nreloc;
uint32_t flags;
uint32_t reserved1;
uint32_t reserved2;
uint32_t reserved3;
};
struct fvmlib {
union lc_str name;
uint32_t minor_version;
uint32_t header_addr;
};
struct fvmlib_command {
uint32_t cmd;
uint32_t cmdsize;
struct fvmlib fvmlib;
};
struct dylib {
union lc_str name;
uint32_t timestamp;
uint32_t current_version;
uint32_t compatibility_version;
};
struct dylib_command {
uint32_t cmd;
uint32_t cmdsize;
struct dylib dylib;
};
struct sub_framework_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str umbrella;
};
struct sub_client_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str client;
};
struct sub_umbrella_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str sub_umbrella;
};
struct sub_library_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str sub_library;
};
struct prebound_dylib_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str name;
uint32_t nmodules;
union lc_str linked_modules;
};
struct dylinker_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str name;
};
struct thread_command {
uint32_t cmd;
uint32_t cmdsize;
};
struct routines_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t init_address;
uint32_t init_module;
uint32_t reserved1;
uint32_t reserved2;
uint32_t reserved3;
uint32_t reserved4;
uint32_t reserved5;
uint32_t reserved6;
};
struct routines_command_64 {
uint32_t cmd;
uint32_t cmdsize;
uint64_t init_address;
uint64_t init_module;
uint64_t reserved1;
uint64_t reserved2;
uint64_t reserved3;
uint64_t reserved4;
uint64_t reserved5;
uint64_t reserved6;
};
struct symtab_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t symoff;
uint32_t nsyms;
uint32_t stroff;
uint32_t strsize;
};
struct dysymtab_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t ilocalsym;
uint32_t nlocalsym;
uint32_t iextdefsym;
uint32_t nextdefsym;
uint32_t iundefsym;
uint32_t nundefsym;
uint32_t tocoff;
uint32_t ntoc;
uint32_t modtaboff;
uint32_t nmodtab;
uint32_t extrefsymoff;
uint32_t nextrefsyms;
uint32_t indirectsymoff;
uint32_t nindirectsyms;
uint32_t extreloff;
uint32_t nextrel;
uint32_t locreloff;
uint32_t nlocrel;
};
struct dylib_table_of_contents {
uint32_t symbol_index;
uint32_t module_index;
};
struct dylib_module {
uint32_t module_name;
uint32_t iextdefsym;
uint32_t nextdefsym;
uint32_t irefsym;
uint32_t nrefsym;
uint32_t ilocalsym;
uint32_t nlocalsym;
uint32_t iextrel;
uint32_t nextrel;
uint32_t iinit_iterm;
uint32_t ninit_nterm;
uint32_t
objc_module_info_addr;
uint32_t
objc_module_info_size;
};
struct dylib_module_64 {
uint32_t module_name;
uint32_t iextdefsym;
uint32_t nextdefsym;
uint32_t irefsym;
uint32_t nrefsym;
uint32_t ilocalsym;
uint32_t nlocalsym;
uint32_t iextrel;
uint32_t nextrel;
uint32_t iinit_iterm;
uint32_t ninit_nterm;
uint32_t
objc_module_info_size;
uint64_t
objc_module_info_addr;
};
struct dylib_reference {
uint32_t isym:24,
flags:8;
};
struct twolevel_hints_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t offset;
uint32_t nhints;
};
struct twolevel_hint {
uint32_t
isub_image:8,
itoc:24;
};
struct prebind_cksum_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t cksum;
};
struct uuid_command {
uint32_t cmd;
uint32_t cmdsize;
uint8_t uuid[16];
};
struct rpath_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str path;
};
struct linkedit_data_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t dataoff;
uint32_t datasize;
};
struct encryption_info_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t cryptoff;
uint32_t cryptsize;
uint32_t cryptid;
};
struct encryption_info_command_64 {
uint32_t cmd;
uint32_t cmdsize;
uint32_t cryptoff;
uint32_t cryptsize;
uint32_t cryptid;
uint32_t pad;
};
struct version_min_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t version;
uint32_t sdk;
};
struct build_version_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t platform;
uint32_t minos;
uint32_t sdk;
uint32_t ntools;
};
struct build_tool_version {
uint32_t tool;
uint32_t version;
};
struct dyld_info_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t rebase_off;
uint32_t rebase_size;
uint32_t bind_off;
uint32_t bind_size;
uint32_t weak_bind_off;
uint32_t weak_bind_size;
uint32_t lazy_bind_off;
uint32_t lazy_bind_size;
uint32_t export_off;
uint32_t export_size;
};
struct linker_option_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t count;
};
struct symseg_command {
uint32_t cmd;
uint32_t cmdsize;
uint32_t offset;
uint32_t size;
};
struct ident_command {
uint32_t cmd;
uint32_t cmdsize;
};
struct fvmfile_command {
uint32_t cmd;
uint32_t cmdsize;
union lc_str name;
uint32_t header_addr;
};
struct entry_point_command {
uint32_t cmd;
uint32_t cmdsize;
uint64_t entryoff;
uint64_t stacksize;
};
struct source_version_command {
uint32_t cmd;
uint32_t cmdsize;
uint64_t version;
};
struct data_in_code_entry {
uint32_t offset;
uint16_t length;
uint16_t kind;
};
struct tlv_descriptor
{
void* (*thunk)(struct tlv_descriptor*);
unsigned long key;
unsigned long offset;
};
struct note_command {
uint32_t cmd;
uint32_t cmdsize;
char data_owner[16];
uint64_t offset;
uint64_t size;
};
struct relocation_info {
int32_t r_address;
uint32_t r_symbolnum:24,
r_pcrel:1,
r_length:2,
r_extern:1,
r_type:4;
};
struct scattered_relocation_info {
uint32_t
r_address:24,
r_type:4,
r_length:2,
r_pcrel:1,
r_scattered:1;
int32_t r_value;
};
enum reloc_type_generic
{
GENERIC_RELOC_VANILLA,
GENERIC_RELOC_PAIR,
GENERIC_RELOC_SECTDIFF,
GENERIC_RELOC_PB_LA_PTR,
GENERIC_RELOC_LOCAL_SECTDIFF,
GENERIC_RELOC_TLV
};
struct fat_header {
uint32_t magic;
uint32_t nfat_arch;
};
struct fat_arch {
cpu_type_t cputype;
cpu_subtype_t cpusubtype;
uint32_t offset;
uint32_t size;
uint32_t align;
};
typedef char *UNDMessage;
typedef char *UNDLabel;
typedef char *UNDKey;
typedef char *UNDPath;
typedef const char * xmlData_t;
typedef mach_port_t UNDReplyRef;
kern_return_t
KUNCUserNotificationDisplayNotice(
int noticeTimeout,
unsigned flags,
char *iconPath,
char *soundPath,
char *localizationPath,
char *alertHeader,
char *alertMessage,
char *defaultButtonTitle) ;
kern_return_t
KUNCUserNotificationDisplayAlert(
int alertTimeout,
unsigned flags,
char *iconPath,
char *soundPath,
char *localizationPath,
char *alertHeader,
char *alertMessage,
char *defaultButtonTitle,
char *alternateButtonTitle,
char *otherButtonTitle,
unsigned *responseFlags) ;
kern_return_t
KUNCExecute(
char *executionPath,
int openAsUser,
int pathExecutionType) ;
typedef uintptr_t KUNCUserNotificationID;
enum {
kKUNCDefaultResponse = 0,
kKUNCAlternateResponse = 1,
kKUNCOtherResponse = 2,
kKUNCCancelResponse = 3
};
typedef void
(*KUNCUserNotificationCallBack)(
int contextKey,
int responseFlags,
const void *xmlData);
KUNCUserNotificationID KUNCGetNotificationID(void) ;
kern_return_t
KUNCUserNotificationDisplayFromBundle(
KUNCUserNotificationID notificationID,
char *bundleIdentifier,
char *fileName,
char *fileExtension,
char *messageKey,
char *tokenString,
KUNCUserNotificationCallBack callback,
int contextKey) ;
kern_return_t
KUNCUserNotificationCancel(
KUNCUserNotificationID notification) ;
typedef unsigned char vUInt8 ;
typedef signed char vSInt8 ;
typedef unsigned short vUInt16 ;
typedef signed short vSInt16 ;
typedef unsigned int vUInt32 ;
typedef signed int vSInt32 ;
typedef long long vSInt64 ;
typedef unsigned long long vUInt64 ;
typedef float vFloat ;
typedef double vDouble ;
typedef unsigned int vBool32 ;
extern vUInt32
vU64FullMulOdd(
vUInt32 vA,
vUInt32 vB) ;
extern vSInt32
vS64FullMulOdd(
vSInt32 vA,
vSInt32 vB) ;
extern vUInt32
vU128Sub(
vUInt32 vA,
vUInt32 vB) ;
extern vUInt32
vU128SubS(
vUInt32 vA,
vUInt32 vB) ;
extern vSInt32
vS128Sub(
vSInt32 vA,
vSInt32 vB) ;
extern vSInt32
vS64SubS(
vSInt32 vA,
vSInt32 vB) ;
extern vSInt32
vS128SubS(
vSInt32 vA,
vSInt32 vB) ;
extern vUInt32
vU128Add(
vUInt32 vA,
vUInt32 vB) ;
extern vUInt32
vU128AddS(
vUInt32 vA,
vUInt32 vB) ;
extern vSInt32
vS128Add(
vSInt32 vA,
vSInt32 vB) ;
extern vSInt32
vS128AddS(
vSInt32 vA,
vSInt32 vB) ;
extern vUInt32
vLL128Shift(
vUInt32 vA,
vUInt8 vShiftFactor) ;
extern vUInt32
vLR128Shift(
vUInt32 vA,
vUInt8 vShiftFactor) ;
extern vUInt32
vA128Shift(
vUInt32 vA,
vUInt8 vShiftFactor) ;
typedef unsigned long vDSP_Length;
typedef long vDSP_Stride;
typedef struct DSPComplex {
float real;
float imag;
} DSPComplex;
typedef struct DSPDoubleComplex {
double real;
double imag;
} DSPDoubleComplex;
typedef struct DSPSplitComplex {
float *  realp;
float *  imagp;
} DSPSplitComplex;
typedef struct DSPDoubleSplitComplex {
double *  realp;
double *  imagp;
} DSPDoubleSplitComplex;
typedef int FFTDirection;
typedef int FFTRadix;
enum {
kFFTDirection_Forward = +1,
kFFTDirection_Inverse = -1
};
enum {
kFFTRadix2 = 0,
kFFTRadix3 = 1,
kFFTRadix5 = 2
};
enum {
vDSP_HALF_WINDOW = 1,
vDSP_HANN_DENORM = 0,
vDSP_HANN_NORM = 2
};
typedef struct { uint8_t bytes[3]; } vDSP_uint24;
typedef struct { uint8_t bytes[3]; } vDSP_int24;
typedef struct OpaqueFFTSetup *FFTSetup;
typedef struct OpaqueFFTSetupD *FFTSetupD;
typedef struct vDSP_biquad_SetupStruct *vDSP_biquad_Setup;
typedef struct vDSP_biquad_SetupStructD *vDSP_biquad_SetupD;
typedef struct vDSP_biquadm_SetupStruct *vDSP_biquadm_Setup;
typedef struct vDSP_biquadm_SetupStructD *vDSP_biquadm_SetupD;
extern  FFTSetup vDSP_create_fftsetup(
vDSP_Length __Log2n,
FFTRadix __Radix)
;
extern void vDSP_destroy_fftsetup( FFTSetup __setup)
;
extern  vDSP_biquadm_Setup vDSP_biquadm_CreateSetup(
const double *__coeffs,
vDSP_Length __M,
vDSP_Length __N)
;
extern  vDSP_biquadm_SetupD vDSP_biquadm_CreateSetupD(
const double *__coeffs,
vDSP_Length __M,
vDSP_Length __N)
;
extern void vDSP_biquadm_DestroySetup(
vDSP_biquadm_Setup __setup)
;
extern void vDSP_biquadm_DestroySetupD(
vDSP_biquadm_SetupD __setup)
;
extern void vDSP_biquadm_CopyState(
vDSP_biquadm_Setup __dest,
const struct vDSP_biquadm_SetupStruct *__src)
;
extern void vDSP_biquadm_CopyStateD(
vDSP_biquadm_SetupD __dest,
const struct vDSP_biquadm_SetupStructD *__src)
;
extern void vDSP_biquadm_ResetState(vDSP_biquadm_Setup __setup)
;
extern void vDSP_biquadm_ResetStateD(vDSP_biquadm_SetupD __setup)
;
extern void vDSP_biquadm_SetCoefficientsDouble(
vDSP_biquadm_Setup __setup,
const double *__coeffs,
vDSP_Length __start_sec,
vDSP_Length __start_chn,
vDSP_Length __nsec,
vDSP_Length __nchn)
;
extern void vDSP_biquadm_SetTargetsDouble(
vDSP_biquadm_Setup __setup,
const double *__targets,
float __interp_rate,
float __interp_threshold,
vDSP_Length __start_sec,
vDSP_Length __start_chn,
vDSP_Length __nsec,
vDSP_Length __nchn)
;
extern void vDSP_biquadm_SetCoefficientsSingle(
vDSP_biquadm_Setup __setup,
const float *__coeffs,
vDSP_Length __start_sec,
vDSP_Length __start_chn,
vDSP_Length __nsec,
vDSP_Length __nchn)
;
extern void vDSP_biquadm_SetTargetsSingle(
vDSP_biquadm_Setup __setup,
const float *__targets,
float __interp_rate,
float __interp_threshold,
vDSP_Length __start_sec,
vDSP_Length __start_chn,
vDSP_Length __nsec,
vDSP_Length __nchn)
;
extern void vDSP_biquadm_SetActiveFilters(
vDSP_biquadm_Setup __setup,
const _Bool *__filter_states)
;
extern void vDSP_ctoz(
const DSPComplex *__C,
vDSP_Stride __IC,
const DSPSplitComplex *__Z,
vDSP_Stride __IZ,
vDSP_Length __N)
;
extern void vDSP_ztoc(
const DSPSplitComplex *__Z,
vDSP_Stride __IZ,
DSPComplex *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_fft_zrip(
FFTSetup __Setup,
const DSPSplitComplex *__C,
vDSP_Stride __IC,
vDSP_Length __Log2N,
FFTDirection __Direction)
;
extern void vDSP_biquadm(
vDSP_biquadm_Setup __Setup,
const float *  *  __X, vDSP_Stride __IX,
float *  *  __Y, vDSP_Stride __IY,
vDSP_Length __N)
;
extern void vDSP_biquadmD(
vDSP_biquadm_SetupD __Setup,
const double *  *  __X, vDSP_Stride __IX,
double *  *  __Y, vDSP_Stride __IY,
vDSP_Length __N)
;
extern void vDSP_conv(
const float *__A,
vDSP_Stride __IA,
const float *__F,
vDSP_Stride __IF,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N,
vDSP_Length __P)
;
extern void vDSP_zmmul(
const DSPSplitComplex *__A,
vDSP_Stride __IA,
const DSPSplitComplex *__B,
vDSP_Stride __IB,
const DSPSplitComplex *__C,
vDSP_Stride __IC,
vDSP_Length __M,
vDSP_Length __N,
vDSP_Length __P)
;
extern void vDSP_vadd(
const float *__A,
vDSP_Stride __IA,
const float *__B,
vDSP_Stride __IB,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vsub(
const float *__B,
vDSP_Stride __IB,
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vmul(
const float *__A,
vDSP_Stride __IA,
const float *__B,
vDSP_Stride __IB,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vdiv(
const float *__B,
vDSP_Stride __IB,
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_zvdiv(
const DSPSplitComplex *__B,
vDSP_Stride __IB,
const DSPSplitComplex *__A,
vDSP_Stride __IA,
const DSPSplitComplex *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vsmul(
const float *__A,
vDSP_Stride __IA,
const float *__B,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vma(
const float *__A,
vDSP_Stride __IA,
const float *__B,
vDSP_Stride __IB,
const float *__C,
vDSP_Stride __IC,
float *__D,
vDSP_Stride __ID,
vDSP_Length __N)
;
extern void vDSP_zvmul(
const DSPSplitComplex *__A,
vDSP_Stride __IA,
const DSPSplitComplex *__B,
vDSP_Stride __IB,
const DSPSplitComplex *__C,
vDSP_Stride __IC,
vDSP_Length __N,
int __Conjugate)
;
extern void vDSP_vabs(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_zvabs(
const DSPSplitComplex *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vfill(
const float *__A,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vsadd(
const float *__A,
vDSP_Stride __IA,
const float *__B,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_zvmov(
const DSPSplitComplex *__A,
vDSP_Stride __IA,
const DSPSplitComplex *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_deq22(
const float *__A,
vDSP_Stride __IA,
const float *__B,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_maxmgv(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_maxv(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_minv(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_rmsqv(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_svdiv(
const float *__A,
const float *__B,
vDSP_Stride __IB,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_sve(
const float *__A,
vDSP_Stride __I,
float *__C,
vDSP_Length __N)
;
extern void vDSP_svesq(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_sve_svesq(
const float *__A,
vDSP_Stride __IA,
float *__Sum,
float *__SumOfSquares,
vDSP_Length __N)
;
extern void vDSP_svs(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Length __N)
;
extern void vDSP_vclip(
const float *__A,
vDSP_Stride __IA,
const float *__B,
const float *__C,
float *__D,
vDSP_Stride __ID,
vDSP_Length __N)
;
extern void vDSP_vclr(
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vdbcon(
const float *__A,
vDSP_Stride __IA,
const float *__B,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N,
unsigned int __F)
;
extern void vDSP_vmax(
const float *__A,
vDSP_Stride __IA,
const float *__B,
vDSP_Stride __IB,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vmaxmg(
const float *__A,
vDSP_Stride __IA,
const float *__B,
vDSP_Stride __IB,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N)
;
extern void vDSP_vswmax(
const float *__A,
vDSP_Stride __IA,
float *__C,
vDSP_Stride __IC,
vDSP_Length __N,
vDSP_Length __WindowLength)
;
enum {
FFT_FORWARD = kFFTDirection_Forward,
FFT_INVERSE = kFFTDirection_Inverse
};
enum {
FFT_RADIX2 = kFFTRadix2,
FFT_RADIX3 = kFFTRadix3,
FFT_RADIX5 = kFFTRadix5
};
typedef DSPComplex COMPLEX;
typedef DSPSplitComplex COMPLEX_SPLIT;
typedef DSPDoubleComplex DOUBLE_COMPLEX;
typedef DSPDoubleSplitComplex DOUBLE_COMPLEX_SPLIT;
void vvexpf (float * , const float * , const int * ) ;
struct nd_ifinfo {
u_int32_t linkmtu;
u_int32_t maxmtu;
u_int32_t basereachable;
u_int32_t reachable;
u_int32_t retrans;
u_int32_t flags;
int recalctm;
u_int8_t chlim;
u_int8_t receivedra;
u_int8_t randomseed0[8];
u_int8_t randomseed1[8];
u_int8_t randomid[8];
};
struct in6_nbrinfo {
char ifname[16];
struct in6_addr addr;
long asked;
int isrouter;
int state;
int expire;
};
struct in6_drlist {
char ifname[16];
struct {
struct in6_addr rtaddr;
u_char flags;
u_short rtlifetime;
u_long expire;
u_short if_index;
} defrouter[10];
};
struct in6_defrouter {
struct sockaddr_in6 rtaddr;
u_char flags;
u_char stateflags;
u_short rtlifetime;
u_long expire;
u_short if_index;
};
struct in6_prlist {
char ifname[16];
struct {
struct in6_addr prefix;
//struct prf_ra raflags;
struct prf_ra {
u_char onlink : 1;
u_char autonomous : 1;
u_char reserved : 6;
} raflags;
u_char prefixlen;
u_char origin;
u_long vltime;
u_long pltime;
u_long expire;
u_short if_index;
u_short advrtrs;
struct in6_addr advrtr[10];
} prefix[10];
};
struct in6_prefix {
struct sockaddr_in6 prefix;
//struct prf_ra raflags;
struct prf_ra {
u_char onlink : 1;
u_char autonomous : 1;
u_char reserved : 6;
} raflags;
u_char prefixlen;
u_char origin;
u_long vltime;
u_long pltime;
u_long expire;
u_int32_t flags;
int refcnt;
u_short if_index;
u_short advrtrs;
};
struct in6_ondireq {
char ifname[16];
struct {
u_int32_t linkmtu;
u_int32_t maxmtu;
u_int32_t basereachable;
u_int32_t reachable;
u_int32_t retrans;
u_int32_t flags;
int recalctm;
u_int8_t chlim;
u_int8_t receivedra;
} ndi;
};
struct in6_ndireq {
char ifname[16];
struct nd_ifinfo ndi;
};
struct in6_ndifreq {
char ifname[16];
u_long ifindex;
};
extern errno_t nd6_lookup_ipv6(ifnet_t interface,
const struct sockaddr_in6 *ip6_dest, struct sockaddr_dl *ll_dest,
size_t ll_dest_len, route_t hint, mbuf_t packet);
struct ipsecstat {
u_quad_t in_success ;
u_quad_t in_polvio ;
u_quad_t in_nosa ;
u_quad_t in_inval ;
u_quad_t in_nomem ;
u_quad_t in_badspi ;
u_quad_t in_ahreplay ;
u_quad_t in_espreplay ;
u_quad_t in_ahauthsucc ;
u_quad_t in_ahauthfail ;
u_quad_t in_espauthsucc ;
u_quad_t in_espauthfail ;
u_quad_t in_esphist[256] ;
u_quad_t in_ahhist[256] ;
u_quad_t in_comphist[256] ;
u_quad_t out_success ;
u_quad_t out_polvio ;
u_quad_t out_nosa ;
u_quad_t out_inval ;
u_quad_t out_nomem ;
u_quad_t out_noroute ;
u_quad_t out_esphist[256] ;
u_quad_t out_ahhist[256] ;
u_quad_t out_comphist[256] ;
};
struct ipcomp {
u_int8_t comp_nxt;
u_int8_t comp_flags;
u_int16_t comp_cpi;
};
struct rip6stat {
u_quad_t rip6s_ipackets;
u_quad_t rip6s_isum;
u_quad_t rip6s_badsum;
u_quad_t rip6s_nosock;
u_quad_t rip6s_nosockmcast;
u_quad_t rip6s_fullsock;
u_quad_t rip6s_opackets;
};
struct ah {
u_int8_t ah_nxt;
u_int8_t ah_len;
u_int16_t ah_reserve;
u_int32_t ah_spi;
};
struct newah {
u_int8_t ah_nxt;
u_int8_t ah_len;
u_int16_t ah_reserve;
u_int32_t ah_spi;
u_int32_t ah_seq;
};
struct esp {
u_int32_t esp_spi;
};
struct newesp {
u_int32_t esp_spi;
u_int32_t esp_seq;
};
struct esptail {
u_int8_t esp_padlen;
u_int8_t esp_nxt;
};
int random_buf(void *buf, size_t buflen);
typedef struct sha1_ctxt {
union {
u_int8_t b8[20];
u_int32_t b32[5];
} h;
union {
u_int8_t b8[8];
u_int32_t b32[2];
u_int64_t b64[1];
} c;
union {
u_int8_t b8[64];
u_int32_t b32[16];
} m;
u_int8_t count;
} SHA1_CTX;
extern void SHA1Init(SHA1_CTX *);
extern void SHA1Update(SHA1_CTX *, const void *, size_t);
extern void SHA1Final(void *, SHA1_CTX *);
typedef struct __OSMallocTag__ * OSMallocTag;
typedef struct __OSMallocTag__ * OSMallocTag_t;
extern OSMallocTag OSMalloc_Tagalloc(
const char * name,
uint32_t flags);
extern void OSMalloc_Tagfree(OSMallocTag tag);
extern void * OSMalloc(
uint32_t size,
OSMallocTag tag) ;
extern void * OSMalloc_nowait(
uint32_t size,
OSMallocTag tag) ;
extern void * OSMalloc_noblock(
uint32_t size,
OSMallocTag tag) ;
extern void OSFree(
void * addr,
uint32_t size,
OSMallocTag tag);
extern int debug_malloc_size;
extern int debug_iomalloc_size;
extern int debug_container_malloc_size;
extern int debug_ivars_size;
void OSPrintMemory(void);
extern const int version_major;
extern const int version_minor;
extern const char version_variant[];
extern const int version_revision;
extern const int version_stage;
extern const int version_prerelease_level;
extern const char ostype[];
extern const char osrelease[];
extern const char osbuilder[];
extern const char version[];
extern char osversion[];
typedef uint32_t OSKextLoadTag;
OSKextLoadTag OSKextGetCurrentLoadTag(void);
const char * OSKextGetCurrentIdentifier(void);
const char * OSKextGetCurrentVersionString(void);
OSReturn OSKextLoadKextWithIdentifier(const char * kextIdentifier);
OSReturn OSKextRetainKextWithLoadTag(OSKextLoadTag loadTag);
OSReturn OSKextReleaseKextWithLoadTag(OSKextLoadTag loadTag);
typedef uint32_t OSKextRequestTag;
typedef void (* OSKextRequestResourceCallback)(
OSKextRequestTag requestTag,
OSReturn result,
const void * resourceData,
uint32_t resourceDataLength,
void * context);
OSReturn OSKextRequestResource(
const char * kextIdentifier,
const char * resourceName,
OSKextRequestResourceCallback callback,
void * context,
OSKextRequestTag * requestTagOut);
OSReturn OSKextCancelRequest(
OSKextRequestTag requestTag,
void ** contextOut);
int
OSKextGrabPgoData(uuid_t uuid,
uint64_t *pSize,
char *pBuffer,
uint64_t bufferSize,
int wait_for_unload,
int metadata);
void
OSKextResetPgoCountersLock(void);
void
OSKextResetPgoCountersUnlock(void);
void
OSKextResetPgoCounters(void);
extern const void * gOSKextUnresolved;
static 
uint16_t
_OSSwapInt16(
uint16_t data
)
{
return ((__uint16_t)((((__uint16_t)(data) & 0xff00) >> 8) | (((__uint16_t)(data) & 0x00ff) << 8)));
}
static 
uint32_t
_OSSwapInt32(
uint32_t data
)
{
return ((__uint32_t)((((__uint32_t)(data) & 0xff000000) >> 24) | (((__uint32_t)(data) & 0x00ff0000) >> 8) | (((__uint32_t)(data) & 0x0000ff00) << 8) | (((__uint32_t)(data) & 0x000000ff) << 24)));
}
static 
uint64_t
_OSSwapInt64(
uint64_t data
)
{
return ((__uint64_t)((((__uint64_t)(data) & 0xff00000000000000ULL) >> 56) | (((__uint64_t)(data) & 0x00ff000000000000ULL) >> 40) | (((__uint64_t)(data) & 0x0000ff0000000000ULL) >> 24) | (((__uint64_t)(data) & 0x000000ff00000000ULL) >> 8) | (((__uint64_t)(data) & 0x00000000ff000000ULL) << 8) | (((__uint64_t)(data) & 0x0000000000ff0000ULL) << 24) | (((__uint64_t)(data) & 0x000000000000ff00ULL) << 40) | (((__uint64_t)(data) & 0x00000000000000ffULL) << 56)));
}
static 
uint16_t
OSReadSwapInt16(
const volatile void * base,
uintptr_t byteOffset
)
{
uint16_t data = *(volatile uint16_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt16(data);
}
static 
uint32_t
OSReadSwapInt32(
const volatile void * base,
uintptr_t byteOffset
)
{
uint32_t data = *(volatile uint32_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt32(data);
}
static 
uint64_t
OSReadSwapInt64(
const volatile void * base,
uintptr_t byteOffset
)
{
uint64_t data = *(volatile uint64_t *)((uintptr_t)base + byteOffset);
return _OSSwapInt64(data);
}
static 
void
OSWriteSwapInt16(
volatile void * base,
uintptr_t byteOffset,
uint16_t data
)
{
*(volatile uint16_t *)((uintptr_t)base + byteOffset) = _OSSwapInt16(data);
}
static 
void
OSWriteSwapInt32(
volatile void * base,
uintptr_t byteOffset,
uint32_t data
)
{
*(volatile uint32_t *)((uintptr_t)base + byteOffset) = _OSSwapInt32(data);
}
static 
void
OSWriteSwapInt64(
volatile void * base,
uintptr_t byteOffset,
uint64_t data
)
{
*(volatile uint64_t *)((uintptr_t)base + byteOffset) = _OSSwapInt64(data);
}
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef Byte Bytef;
typedef char charf;
typedef int intf;
typedef uInt uIntf;
typedef uLong uLongf;
typedef void const *voidpc;
typedef void *voidpf;
typedef void *voidp;
typedef voidpf (*alloc_func) (voidpf opaque, uInt items, uInt size);
typedef void (*free_func) (voidpf opaque, voidpf address);
struct internal_state;
typedef struct z_stream_s {
Bytef *next_in;
uInt avail_in;
uLong total_in;
Bytef *next_out;
uInt avail_out;
uLong total_out;
char *msg;
struct internal_state *state;
alloc_func zalloc;
free_func zfree;
voidpf opaque;
int data_type;
uLong adler;
uLong reserved;
} z_stream;
typedef z_stream *z_streamp;
typedef struct gz_header_s {
int text;
uLong time;
int xflags;
int os;
Bytef *extra;
uInt extra_len;
uInt extra_max;
Bytef *name;
uInt name_max;
Bytef *comment;
uInt comm_max;
int hcrc;
int done;
} gz_header;
typedef gz_header *gz_headerp;
extern const char * zlibVersion (void);
extern int deflate (z_streamp strm, int flush);
extern int deflateEnd (z_streamp strm);
extern int inflate (z_streamp strm, int flush);
extern int inflateEnd (z_streamp strm);
extern int deflateSetDictionary (z_streamp strm, const Bytef *dictionary, uInt dictLength);
extern int deflateCopy (z_streamp dest, z_streamp source);
extern int deflateReset (z_streamp strm);
extern int deflateParams (z_streamp strm, int level, int strategy);
extern int deflateTune (z_streamp strm, int good_length, int max_lazy, int nice_length, int max_chain);
extern uLong deflateBound (z_streamp strm, uLong sourceLen);
extern int deflatePrime (z_streamp strm, int bits, int value);
extern int deflateSetHeader (z_streamp strm, gz_headerp head);
extern int inflateSetDictionary (z_streamp strm, const Bytef *dictionary, uInt dictLength);
extern int inflateSync (z_streamp strm);
extern int inflateCopy (z_streamp dest, z_streamp source);
extern int inflateReset (z_streamp strm);
extern int inflatePrime (z_streamp strm, int bits, int value);
extern int inflateGetHeader (z_streamp strm, gz_headerp head);
typedef unsigned (*in_func) (void *, unsigned char * *);
typedef int (*out_func) (void *, unsigned char *, unsigned);
extern int inflateBack (z_streamp strm, in_func in, void *in_desc, out_func out, void *out_desc);
extern int inflateBackEnd (z_streamp strm);
extern uLong zlibCompileFlags (void);
extern int compress (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
extern int compress2 (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level);
extern uLong compressBound (uLong sourceLen);
extern int uncompress (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
extern uLong adler32 (uLong adler, const Bytef *buf, uInt len);
extern uLong adler32_combine (uLong adler1, uLong adler2, long len2);
extern uLong z_crc32 (uLong crc, const Bytef *buf, uInt len);
extern uLong z_crc32_combine (uLong crc1, uLong crc2, long len2);
extern int deflateInit_ (z_streamp strm, int level, const char *version, int stream_size);
extern int inflateInit_ (z_streamp strm, const char *version, int stream_size);
extern int deflateInit2_ (z_streamp strm, int level, int method, int windowBits, int memLevel, int strategy, const char *version, int stream_size);
extern int inflateInit2_ (z_streamp strm, int windowBits, const char *version, int stream_size);
extern int inflateBackInit_ (z_streamp strm, int windowBits, unsigned char *window, const char *version, int stream_size);
struct internal_state {int dummy;};
extern const char * zError (int);
extern int inflateSyncPoint (z_streamp z);
extern const uLongf * get_crc_table (void);
extern int log_leaks;
extern void trace_backtrace(unsigned int debugid, unsigned int debugid2, unsigned long size, unsigned long data);
extern void OSReportWithBacktrace(const char *str, ...);
extern unsigned OSBacktrace(void **bt, unsigned maxAddrs);
extern void OSPrintBacktrace(void);
vm_offset_t OSKernelStackRemaining( void );
typedef enum gssd_mechtype {
GSSD_NO_MECH = -1,
GSSD_KRB5_MECH = 0,
GSSD_SPNEGO_MECH,
GSSD_NTLM_MECH,
GSSD_IAKERB_MECH
} gssd_mechtype;
typedef enum gssd_nametype {
GSSD_STRING_NAME = 0,
GSSD_EXPORT,
GSSD_ANONYMOUS,
GSSD_HOSTBASED,
GSSD_USER,
GSSD_MACHINE_UID,
GSSD_STRING_UID,
GSSD_KRB5_PRINCIPAL,
GSSD_KRB5_REFERRAL,
GSSD_NTLM_PRINCIPAL,
GSSD_NTLM_BLOB,
GSSD_UUID
} gssd_nametype;
typedef char *gssd_string;
typedef char *gssd_dstring;
typedef uint8_t *gssd_byte_buffer;
typedef uint32_t *gssd_gid_list;
typedef uint64_t gssd_ctx;
typedef uint64_t gssd_cred;
typedef int32_t *gssd_etype_list;
extern
kern_return_t mach_gss_init_sec_context
(
mach_port_t server,
gssd_mechtype mech,
gssd_byte_buffer intoken,
mach_msg_type_number_t intokenCnt,
uint32_t uid,
gssd_string princ_namestr,
gssd_string svc_namestr,
uint32_t flags,
uint32_t gssd_flags,
gssd_ctx *context,
gssd_cred *cred_handle,
uint32_t *ret_flags,
gssd_byte_buffer *key,
mach_msg_type_number_t *keyCnt,
gssd_byte_buffer *outtoken,
mach_msg_type_number_t *outtokenCnt,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_accept_sec_context
(
mach_port_t server,
gssd_byte_buffer intoken,
mach_msg_type_number_t intokenCnt,
gssd_string svc_namestr,
uint32_t gssd_flags,
gssd_ctx *context,
gssd_cred *cred_handle,
uint32_t *flags,
uint32_t *uid,
gssd_gid_list gids,
mach_msg_type_number_t *gidsCnt,
gssd_byte_buffer *key,
mach_msg_type_number_t *keyCnt,
gssd_byte_buffer *outtoken,
mach_msg_type_number_t *outtokenCnt,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_log_error
(
mach_port_t server,
gssd_string mnt,
uint32_t uid,
gssd_string source,
uint32_t major_stat,
uint32_t minor_stat
);
extern
kern_return_t mach_gss_init_sec_context_v2
(
mach_port_t server,
gssd_mechtype mech,
gssd_byte_buffer intoken,
mach_msg_type_number_t intokenCnt,
uint32_t uid,
gssd_nametype clnt_nt,
gssd_byte_buffer clnt_princ,
mach_msg_type_number_t clnt_princCnt,
gssd_nametype svc_nt,
gssd_byte_buffer svc_princ,
mach_msg_type_number_t svc_princCnt,
uint32_t flags,
uint32_t *gssd_flags,
gssd_ctx *context,
gssd_cred *cred_handle,
uint32_t *ret_flags,
gssd_byte_buffer *key,
mach_msg_type_number_t *keyCnt,
gssd_byte_buffer *outtoken,
mach_msg_type_number_t *outtokenCnt,
gssd_dstring displayname,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_accept_sec_context_v2
(
mach_port_t server,
gssd_byte_buffer intoken,
mach_msg_type_number_t intokenCnt,
gssd_nametype svc_nt,
gssd_byte_buffer svc_princ,
mach_msg_type_number_t svc_princCnt,
uint32_t *gssd_flags,
gssd_ctx *context,
gssd_cred *cred_handle,
uint32_t *flags,
uint32_t *uid,
gssd_gid_list gids,
mach_msg_type_number_t *gidsCnt,
gssd_byte_buffer *key,
mach_msg_type_number_t *keyCnt,
gssd_byte_buffer *outtoken,
mach_msg_type_number_t *outtokenCnt,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_init_sec_context_v3
(
mach_port_t server,
gssd_mechtype mech,
gssd_byte_buffer intoken,
mach_msg_type_number_t intokenCnt,
uint32_t uid,
gssd_nametype clnt_nt,
gssd_byte_buffer clnt_princ,
mach_msg_type_number_t clnt_princCnt,
gssd_nametype svc_nt,
gssd_byte_buffer svc_princ,
mach_msg_type_number_t svc_princCnt,
uint32_t flags,
gssd_etype_list etypes,
mach_msg_type_number_t etypesCnt,
uint32_t *gssd_flags,
gssd_ctx *context,
gssd_cred *cred_handle,
uint32_t *ret_flags,
gssd_byte_buffer *key,
mach_msg_type_number_t *keyCnt,
gssd_byte_buffer *outtoken,
mach_msg_type_number_t *outtokenCnt,
gssd_dstring displayname,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_hold_cred
(
mach_port_t server,
gssd_mechtype mech,
gssd_nametype nt,
gssd_byte_buffer princ,
mach_msg_type_number_t princCnt,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_unhold_cred
(
mach_port_t server,
gssd_mechtype mech,
gssd_nametype nt,
gssd_byte_buffer princ,
mach_msg_type_number_t princCnt,
uint32_t *major_stat,
uint32_t *minor_stat
);
extern
kern_return_t mach_gss_lookup
(
mach_port_t server,
uint32_t uid,
int32_t asid,
mach_port_t *gssd_session_port
);
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t intoken;
NDR_record_t NDR;
gssd_mechtype mech;
mach_msg_type_number_t intokenCnt;
uint32_t uid;
mach_msg_type_number_t princ_namestrOffset;
mach_msg_type_number_t princ_namestrCnt;
char princ_namestr[1024];
mach_msg_type_number_t svc_namestrOffset;
mach_msg_type_number_t svc_namestrCnt;
char svc_namestr[1024];
uint32_t flags;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
} __Request__mach_gss_init_sec_context_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t intoken;
NDR_record_t NDR;
mach_msg_type_number_t intokenCnt;
mach_msg_type_number_t svc_namestrOffset;
mach_msg_type_number_t svc_namestrCnt;
char svc_namestr[1024];
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
} __Request__mach_gss_accept_sec_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
mach_msg_type_number_t mntOffset;
mach_msg_type_number_t mntCnt;
char mnt[1024];
uint32_t uid;
mach_msg_type_number_t sourceOffset;
mach_msg_type_number_t sourceCnt;
char source[1024];
uint32_t major_stat;
uint32_t minor_stat;
} __Request__mach_gss_log_error_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t intoken;
mach_msg_ool_descriptor_t clnt_princ;
mach_msg_ool_descriptor_t svc_princ;
NDR_record_t NDR;
gssd_mechtype mech;
mach_msg_type_number_t intokenCnt;
uint32_t uid;
gssd_nametype clnt_nt;
mach_msg_type_number_t clnt_princCnt;
gssd_nametype svc_nt;
mach_msg_type_number_t svc_princCnt;
uint32_t flags;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
} __Request__mach_gss_init_sec_context_v2_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t intoken;
mach_msg_ool_descriptor_t svc_princ;
NDR_record_t NDR;
mach_msg_type_number_t intokenCnt;
gssd_nametype svc_nt;
mach_msg_type_number_t svc_princCnt;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
} __Request__mach_gss_accept_sec_context_v2_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t intoken;
mach_msg_ool_descriptor_t clnt_princ;
mach_msg_ool_descriptor_t svc_princ;
NDR_record_t NDR;
gssd_mechtype mech;
mach_msg_type_number_t intokenCnt;
uint32_t uid;
gssd_nametype clnt_nt;
mach_msg_type_number_t clnt_princCnt;
gssd_nametype svc_nt;
mach_msg_type_number_t svc_princCnt;
uint32_t flags;
mach_msg_type_number_t etypesCnt;
int32_t etypes[64];
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
} __Request__mach_gss_init_sec_context_v3_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t princ;
NDR_record_t NDR;
gssd_mechtype mech;
gssd_nametype nt;
mach_msg_type_number_t princCnt;
} __Request__mach_gss_hold_cred_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t princ;
NDR_record_t NDR;
gssd_mechtype mech;
gssd_nametype nt;
mach_msg_type_number_t princCnt;
} __Request__mach_gss_unhold_cred_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
uint32_t uid;
int32_t asid;
} __Request__mach_gss_lookup_t ;
union __RequestUnion__gssd_mach_subsystem {
__Request__mach_gss_init_sec_context_t Request_mach_gss_init_sec_context;
__Request__mach_gss_accept_sec_context_t Request_mach_gss_accept_sec_context;
__Request__mach_gss_log_error_t Request_mach_gss_log_error;
__Request__mach_gss_init_sec_context_v2_t Request_mach_gss_init_sec_context_v2;
__Request__mach_gss_accept_sec_context_v2_t Request_mach_gss_accept_sec_context_v2;
__Request__mach_gss_init_sec_context_v3_t Request_mach_gss_init_sec_context_v3;
__Request__mach_gss_hold_cred_t Request_mach_gss_hold_cred;
__Request__mach_gss_unhold_cred_t Request_mach_gss_unhold_cred;
__Request__mach_gss_lookup_t Request_mach_gss_lookup;
};
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t key;
mach_msg_ool_descriptor_t outtoken;
NDR_record_t NDR;
gssd_ctx context;
gssd_cred cred_handle;
uint32_t ret_flags;
mach_msg_type_number_t keyCnt;
mach_msg_type_number_t outtokenCnt;
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_init_sec_context_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t key;
mach_msg_ool_descriptor_t outtoken;
NDR_record_t NDR;
gssd_ctx context;
gssd_cred cred_handle;
uint32_t flags;
uint32_t uid;
mach_msg_type_number_t gidsCnt;
uint32_t gids[16];
mach_msg_type_number_t keyCnt;
mach_msg_type_number_t outtokenCnt;
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_accept_sec_context_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
} __Reply__mach_gss_log_error_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t key;
mach_msg_ool_descriptor_t outtoken;
NDR_record_t NDR;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
uint32_t ret_flags;
mach_msg_type_number_t keyCnt;
mach_msg_type_number_t outtokenCnt;
mach_msg_type_number_t displaynameOffset;
mach_msg_type_number_t displaynameCnt;
char displayname[128];
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_init_sec_context_v2_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t key;
mach_msg_ool_descriptor_t outtoken;
NDR_record_t NDR;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
uint32_t flags;
uint32_t uid;
mach_msg_type_number_t gidsCnt;
uint32_t gids[16];
mach_msg_type_number_t keyCnt;
mach_msg_type_number_t outtokenCnt;
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_accept_sec_context_v2_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_ool_descriptor_t key;
mach_msg_ool_descriptor_t outtoken;
NDR_record_t NDR;
uint32_t gssd_flags;
gssd_ctx context;
gssd_cred cred_handle;
uint32_t ret_flags;
mach_msg_type_number_t keyCnt;
mach_msg_type_number_t outtokenCnt;
mach_msg_type_number_t displaynameOffset;
mach_msg_type_number_t displaynameCnt;
char displayname[128];
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_init_sec_context_v3_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_hold_cred_t ;
typedef struct {
mach_msg_header_t Head;
NDR_record_t NDR;
kern_return_t RetCode;
uint32_t major_stat;
uint32_t minor_stat;
} __Reply__mach_gss_unhold_cred_t ;
typedef struct {
mach_msg_header_t Head;
mach_msg_body_t msgh_body;
mach_msg_port_descriptor_t gssd_session_port;
} __Reply__mach_gss_lookup_t ;
union __ReplyUnion__gssd_mach_subsystem {
__Reply__mach_gss_init_sec_context_t Reply_mach_gss_init_sec_context;
__Reply__mach_gss_accept_sec_context_t Reply_mach_gss_accept_sec_context;
__Reply__mach_gss_log_error_t Reply_mach_gss_log_error;
__Reply__mach_gss_init_sec_context_v2_t Reply_mach_gss_init_sec_context_v2;
__Reply__mach_gss_accept_sec_context_v2_t Reply_mach_gss_accept_sec_context_v2;
__Reply__mach_gss_init_sec_context_v3_t Reply_mach_gss_init_sec_context_v3;
__Reply__mach_gss_hold_cred_t Reply_mach_gss_hold_cred;
__Reply__mach_gss_unhold_cred_t Reply_mach_gss_unhold_cred;
__Reply__mach_gss_lookup_t Reply_mach_gss_lookup;
};
void serial_keyboard_init(void);
void serial_keyboard_start(void);
void serial_keyboard_poll(void);
extern uint32_t serialmode;
extern uint32_t cons_ops_index;
extern const uint32_t nconsops;
extern unsigned int disable_serial_output;
int _serial_getc(int unit, int line, boolean_t wait, boolean_t raw);
struct console_ops {
void (*putc)(int, int, int);
int (*getc)(int, int, boolean_t, boolean_t);
};
boolean_t console_is_serial(void);
int switch_to_serial_console(void);
int switch_to_video_console(void);
void switch_to_old_console(int old_console);
enum
{
kVCDarkReboot = 0x00000001,
kVCAcquireImmediate = 0x00000002,
kVCUsePosition = 0x00000004,
kVCDarkBackground = 0x00000008,
kVCLightBackground = 0x00000010,
};
struct vc_progress_user_options {
uint32_t options;
uint32_t x_pos;
uint32_t y_pos;
uint32_t resv[8];
};
typedef struct vc_progress_user_options vc_progress_user_options;
