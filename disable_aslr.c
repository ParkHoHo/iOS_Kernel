#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>

//14pro 16.6.1
#define off_p_flag 0x25c

#define P_DISABLE_ASLR  0x00001000      /* Disable address space layout randomization */

static void *libjb = NULL;
#define T1SZ_BOOT 17

uint64_t unsign_kptr(uint64_t pac_kaddr) {
    if ((pac_kaddr & 0xFFFFFF0000000000) == 0xFFFFFF0000000000) {
        return pac_kaddr;
    }
    if(T1SZ_BOOT != 0) {
        return pac_kaddr |= ~((1ULL << (64U - T1SZ_BOOT)) - 1U);
    }
    return pac_kaddr;
}

void kwrite64(uint64_t va, uint64_t v) {
	void *libjb_kwrite64 = dlsym(libjb, "kwrite64");
	int (*_kwrite64)(uint64_t va, uint64_t v) = libjb_kwrite64;
	_kwrite64(va, v);
}

void kwrite32(uint64_t va, uint32_t v) {
	void *libjb_kwrite32 = dlsym(libjb, "kwrite32");
	int (*_kwrite32)(uint64_t va, uint32_t v) = libjb_kwrite32;
	_kwrite32(va, v);
}

uint64_t kread64(uint64_t va) {
	void *libjb_kread64 = dlsym(libjb, "kread64");
	uint64_t (*_kread64)(uint64_t va) = libjb_kread64;
	return _kread64(va);
}

uint32_t kread32(uint64_t va) {
	void *libjb_kread32 = dlsym(libjb, "kread32");
	uint32_t (*_kread32)(uint64_t va) = libjb_kread32;
	return _kread32(va);
}


uint64_t proc_self(void)
{
	void *libjb_proc_self = dlsym(libjb, "proc_self");
	uint64_t (*_proc_self)(void) = libjb_proc_self;
	uint64_t ret = _proc_self();
	printf("proc_self = 0x%llx\n", ret);
	return ret;
}

uint64_t proc_find(pid_t pidToFind) {
    void *libjb_proc_find = dlsym(libjb, "proc_find");
	uint64_t (*_proc_find)(pid_t) = libjb_proc_find;
	uint64_t ret = _proc_find(pidToFind);
	return ret;
}

int jbdInitPPLRW(void) {
	void *libjb_jbdInitPPLRW = dlsym(libjb, "jbdInitPPLRW");
	int (*_jbdInitPPLRW)(void) = libjb_jbdInitPPLRW;
	int ret = _jbdInitPPLRW();
	printf("[+] jbdInitPPLRW ret = %d\n", ret);
	if(ret != 0)	return 1;
	return 0;
}

int openLibJB(void) {
	libjb = dlopen("/var/jb/basebin/libjailbreak.dylib", RTLD_NOW);

	if(libjb == NULL)	return -1;
	if(jbdInitPPLRW())	return -1;

    return 0;
}


int closeLibJB(void) {
    dlclose(libjb);
    return 0;
}

int disableASLR(pid_t pid) {
    openLibJB();

    uint64_t proc = proc_find(pid);
    printf("[+] child proc =  0x%llx\n", proc);

    uint32_t p_flag = kread32(proc + off_p_flag);
    printf("[+] child proc->p_flag: 0x%x\n", p_flag);

    kwrite32(proc + off_p_flag, p_flag | P_DISABLE_ASLR);

    closeLibJB();

    return 0;
}

//https://github.com/apple-oss-distributions/xnu/blob/xnu-8019.41.5/bsd/sys/proc_info.h#L63C1-L86C3
struct proc_bsdinfo {
	uint32_t                pbi_flags;              /* 64bit; emulated etc */
	uint32_t                pbi_status;
	uint32_t                pbi_xstatus;
	uint32_t                pbi_pid;
	uint32_t                pbi_ppid;
	uid_t                   pbi_uid;
	gid_t                   pbi_gid;
	uid_t                   pbi_ruid;
	gid_t                   pbi_rgid;
	uid_t                   pbi_svuid;
	gid_t                   pbi_svgid;
	uint32_t                rfu_1;                  /* reserved */
	char                    pbi_comm[MAXCOMLEN];
	char                    pbi_name[2 * MAXCOMLEN];  /* empty if no name is registered */
	uint32_t                pbi_nfiles;
	uint32_t                pbi_pgid;
	uint32_t                pbi_pjobc;
	uint32_t                e_tdev;                 /* controlling tty dev */
	uint32_t                e_tpgid;                /* tty process group id */
	int32_t                 pbi_nice;
	uint64_t                pbi_start_tvsec;
	uint64_t                pbi_start_tvusec;
};

int
proc_pidinfo(int, int, uint64_t, void *, int);

#define PROC_PIDTBSDINFO 3

char* getParentProcessName() {
    pid_t ppid;
    struct kinfo_proc proc;
    size_t proc_info_size = sizeof(proc);
    
    // Get the parent process ID
    int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    if (sysctl(name, 4, &proc, &proc_info_size, NULL, 0) != 0) {
        perror("sysctl");
        return NULL;
    }
    
    ppid = proc.kp_eproc.e_ppid;
    
    // Get the parent process name using the parent process ID
    struct proc_bsdinfo procInfo;
    if (proc_pidinfo(ppid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0) {
        perror("proc_pidinfo");
        return NULL;
    }

	char* ret = malloc(256);
	strcpy(ret, procInfo.pbi_name);
    
    return ret;
}

int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char* arg7, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6, arg7, NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    if (rv) return rv;
    
    kill(pd, SIGCONT); //continue
    
    int a = 0;
    waitpid(pd, &a, 0);
    
    return WEXITSTATUS(a);
}

int main(int argc, char *argv[], char *envp[]) {
	char* parentProcess = getParentProcessName();
	printf("[i] Spawned by \"%s\"\n", parentProcess);
	uint64_t slide = _dyld_get_image_vmaddr_slide(0);
	printf("[i] slide: 0x%llx\n", slide);


	if(strcmp(parentProcess, "ASLRDisableTest") == 0) {

		return 0;
	}

	disableASLR(getpid());	//disable aslr to child process
	launch("/var/jb/usr/local/bin/ASLRDisableTest", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	return 0;
}