#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/kvm.h>
#include <sys/stat.h>
#include <asm/bootparam.h>
#include <pthread.h>
#include <termios.h>



static char rxq[4096];

static uint8_t ier, lcr, mcr, fcr, dll, dlm;
static size_t rxh = 0, rxt = 0;
static int txipnd = 0;
static pthread_mutex_t rxmu = PTHREAD_MUTEX_INITIALIZER;
static int g_vmfd = -1;
size_t ms = 512UL * 1024 * 1024; //mm size



static int ispndg() {
    int pndg;
    pthread_mutex_lock(&rxmu);
    pndg = (rxh != rxt);
    pthread_mutex_unlock(&rxmu);
    return pndg;
}

static void ih(uint8_t *memr, uint32_t ad, uint8_t chr) { //dbg

    uint8_t *p = memr + ad;
    int i = 0;
    p[i++] = 0x60;
    p[i++] = 0x66; p[i++] = 0xBA; p[i++] = 0xF8; p[i++] = 0x3;
    p[i++] = 0xB0; p[i++] = chr;
    p[i++] = 0xEE;
    p[i++] = 0x61;
    p[i++] = 0xFA;
    p[i++] = 0xF4;
}

static void idg(uint8_t *mem, int vec, uint32_t hndl) //dbg
{
    uint32_t off = 0x1100 + vec * 8;
    mem[off + 0] = hndl & 0xff;
    mem[off + 1] = (hndl >> 8) & 0xff;
    mem[off + 2] = 0x10 & 0xff;
    mem[off + 3] = (0x10 >> 8) & 0xff;
    mem[off + 4] = 0;
    mem[off + 5] = 0x8E;
    mem[off + 6] = (hndl >> 16) & 0xff;
    mem[off + 7] = (hndl >> 24) & 0xff;
}


static void st4(int level) {
    struct kvm_irq_level il = { .irq = 4, .level = level };
    (void)ioctl(g_vmfd, KVM_IRQ_LINE, &il);
}

static void up4(void) {

    int pnd = ispndg();

    int wch = 0;
    if ((ier & 0x1) && pnd) wch = 1;
    if ((ier & 0x2) && txipnd) wch = 1;
    st4(wch);
}


static struct termios term;

 void uartin(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    struct termios t;
    if (tcgetattr(STDIN_FILENO, &term) == 0) {
        t = term;
        t.c_lflag &= ~(ICANON | ECHO);
        t.c_iflag &= ~(IXON | ICRNL);
        t.c_oflag &= ~(OPOST);
        t.c_cc[VMIN]  = 1;
        t.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }

    int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (fl >= 0) fcntl(STDIN_FILENO, F_SETFL, fl & ~O_NONBLOCK);
}

static void *thrd(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t c;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n == 1) {
            pthread_mutex_lock(&rxmu);
            rxq[rxt & (sizeof(rxq) - 1)] = c;
            rxt++;
            pthread_mutex_unlock(&rxmu);

            up4();
        }
    }
    return NULL;
}

int kvmrm(int vcpu, void *memr, struct kvm_run *kvr);
int ramfs(void *memr);
int bz(void *memr, size_t sz, uint32_t loc);



int main() {

fprintf(stderr, "starting...\n");
fflush(stderr);

int fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
if (fd < 0) return -errno;

if (ioctl(fd, KVM_GET_API_VERSION, 0) != 12) return 1;

int vmfd = ioctl(fd, KVM_CREATE_VM, 0);

g_vmfd = vmfd;

//fprintf(stderr, "vm created.\n");
//fflush(stderr);


void *memr = mmap(NULL, ms, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
if (memr == MAP_FAILED) return -errno;

struct kvm_userspace_memory_region mmreg = {
    .slot = 0,
    .guest_phys_addr = 0,
    .memory_size = ms,
    .userspace_addr = (uint64_t)memr,
};


int k = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &mmreg);
if (k != 0) return -errno;

//fprintf(stderr, "tss.\n");
//fflush(stderr);

uint64_t tss = ms - 0xD000;
if (ioctl(vmfd, KVM_SET_TSS_ADDR, tss) < 0) return -errno;

uint64_t idmp = ms - 0XE000;
if (ioctl(vmfd, KVM_SET_IDENTITY_MAP_ADDR, &idmp) < 0) return -errno;

//fprintf(stderr, "before irq.\n");
//fflush(stderr);

int irq = ioctl(vmfd, KVM_CREATE_IRQCHIP, 0);
if (irq != 0) return -errno;

//fprintf(stderr, "after irq.\n");
//fflush(stderr);

struct kvm_pit_config pit = {
    .flags = 0,
};

int pit2 = ioctl(vmfd, KVM_CREATE_PIT2, &pit);
if (pit2 != 0) return -errno;

int vcpu = ioctl(vmfd, KVM_CREATE_VCPU, 0);
if (vcpu < 0) return -errno;

//fprintf(stderr, "after vcpu.\n");
//fflush(stderr);

int nent = 100;
size_t sz = sizeof(struct kvm_cpuid2) + nent * sizeof(struct kvm_cpuid_entry2);
struct kvm_cpuid2 *cpuid = malloc(sz);
memset(cpuid, 0, sz);
cpuid->nent = nent;

if (ioctl(fd, KVM_GET_SUPPORTED_CPUID, cpuid) < 0) return -errno;
if (ioctl(vcpu, KVM_SET_CPUID2, cpuid) < 0) return -errno;

free(cpuid);

int mmpsz = ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, 0);
if (mmpsz < 0) return -errno;

struct kvm_run *kvr = mmap(NULL, mmpsz, PROT_READ|PROT_WRITE, MAP_SHARED, vcpu, 0);
if (kvr == MAP_FAILED) return -errno;

fprintf(stderr, "initializing ramfs...");
fflush(stderr);

int err = ramfs(memr);
if (err < 0) return err;

fprintf(stderr, "ramfs initialized...");
fflush(stderr);

uartin();

pthread_t th;
pthread_create(&th, NULL, thrd, NULL);
pthread_detach(th);

err = kvmrm(vcpu, memr, kvr);
if (err < 0) return err;

munmap(kvr, mmpsz);
munmap(memr, ms);

return 0;

}

int kvmrm(int vcpu, void *memr, struct kvm_run *kvr) {
    
    uint64_t gdt[4];
    gdt[0] = (uint64_t)0x0000000000000000;
    gdt[1] = (uint64_t)0x00CF9A000000FFFF; 
    gdt[2] = (uint64_t)0X00CF92000000FFFF;
    
    memset((uint8_t*)memr + 0x8000, 0, 0x68);
    uint32_t bse = 0x8000;
    uint32_t lim = 0x67;
    
    uint64_t tssdsc = 0;
    tssdsc |= (lim & (uint64_t)0xFFFF);
    tssdsc |= ((uint64_t)(bse & 0xFFFF) << 16);
    tssdsc |= ((uint64_t)(bse & 0xFF0000) << 16);
    tssdsc |= ((uint64_t)0x89 << 40);
    tssdsc |= ((uint64_t)(lim & 0x000F0000) << 32);
    tssdsc |= ((uint64_t)(bse & 0xFF000000) << 32);
    
    gdt[3] = tssdsc;

    memcpy((uint8_t*)memr + 0x1000, gdt, sizeof(gdt));
    
    struct kvm_sregs srgs;
    if (ioctl(vcpu, KVM_GET_SREGS, &srgs) < 0) return -errno;

    struct kvm_segment sgmnt = {0}; {
        sgmnt.base = 0;
        sgmnt.limit = 0xFFFFFFFF;
        sgmnt.selector = 0;
        sgmnt.present = 1;
        sgmnt.type = 0;
        sgmnt.dpl = 0;
        sgmnt.db = 1;
        sgmnt.s = 1;
        sgmnt.l = 0;
        sgmnt.g = 1;
    }

    struct boot_params *bp = (struct boot_params *)((uint8_t*)memr + 0x90000);
    uint64_t entr = bp->hdr.code32_start;

    srgs.cs = sgmnt;
    srgs.cs.selector = 0x8;
    srgs.cs.type = 0xA;
    srgs.ds = sgmnt;
    srgs.ds.selector = 0X10;
    srgs.ds.type = 2;
    srgs.gdt.base = 0x1000;
    srgs.gdt.limit = (sizeof(gdt) - 1);
    srgs.es = srgs.ds;
    srgs.fs = srgs.ds;
    srgs.gs = srgs.ds;
    srgs.ss = srgs.ds;
    srgs.cr0 = 0x11;
    srgs.cr4 = 0;
    srgs.efer = 0;
    srgs.idt.base = 0x1100;
    memset((uint8_t*)memr + 0x1100, 0, 256 * 8);
    srgs.idt.limit = (256 * 8) - 1;
    srgs.tr.selector = 0x20;
    srgs.tr.base = 0x8000;
    srgs.tr.limit = 0x67;
    srgs.tr.present = 1;
    srgs.tr.type = 9;
    srgs.tr.s = 0;              
    srgs.tr.dpl = 0;
    srgs.tr.g = 0;
    srgs.tr.db = 0;
    srgs.tr.l = 0;
    srgs.tr.unusable = 0;
    srgs.ldt.unusable = 1;
    srgs.ldt.selector = 0;
    srgs.ldt.base = 0;
    srgs.ldt.limit = 0;


    const uint32_t ud = 0x2000 + 0x00;
    const uint32_t df = 0x2000 + 0x20;
    const uint32_t ts = 0x2000 + 0x40; //dbg
    const uint32_t gp = 0x2000 + 0x60;
    const uint32_t pf = 0x2000 + 0x80;
    const uint32_t rst = 0x2000 + 0x100;

    ih((uint8_t*)memr, ud, 'U');
    ih((uint8_t*)memr, df, 'D');
    ih((uint8_t*)memr, ts, 'T'); //dbg
    ih((uint8_t*)memr, gp, 'G');
    ih((uint8_t*)memr, pf, 'P');
    ih((uint8_t*)memr, rst, 'R');

    for (int v = 0; v < 32; v++) {
    idg((uint8_t*)memr, v, rst);
    } //according to https://docs.amd.com/v/u/en-US/40332-PUB_4.08 (probably should've skipped the reserved ones but whatever)

    idg((uint8_t*)memr, 6,  ud);
    idg((uint8_t*)memr, 8,  df);
    idg((uint8_t*)memr, 10, ts); //dbg
    idg((uint8_t*)memr, 13, gp);
    idg((uint8_t*)memr, 14, pf);






    if (ioctl(vcpu, KVM_SET_SREGS, &srgs) < 0) return -errno;

    struct kvm_regs rgs;
    memset(&rgs, 0, sizeof(rgs));
    rgs.rip = entr;
    rgs.rsp = 0x70000;
    rgs.rflags = 2;
    rgs.rsi = 0x90000;
    rgs.rbx = 0;
    rgs.rbp = 0;
    rgs.rdi = 0;

    if (ioctl(vcpu, KVM_SET_REGS, &rgs) < 0) return -errno;

    fprintf(stderr, "entr=0x%llx cr0=0x%llx cs=0x%x ds=0x%x idt=0x%llx\n", //dbg
    (unsigned long long)entr,
    (unsigned long long)srgs.cr0,
    srgs.cs.selector, srgs.ds.selector,
    (unsigned long long)srgs.idt.base);

    int pnd = ispndg();

    int irql = pnd && (ier & 1);


    struct kvm_irq_level il = {
        .irq = 4,
        .level = irql ? 1 : 0
    };

    if (g_vmfd >= 0) {
        ioctl(g_vmfd, KVM_IRQ_LINE, &il);
    }


    while (1) {
    if (ioctl(vcpu, KVM_RUN, 0) < 0) return -errno;

    switch (kvr->exit_reason) {
    case KVM_EXIT_HLT:
        fprintf(stderr, "HLT\n");
        return 0;

    case KVM_EXIT_SHUTDOWN:
        fprintf(stderr, "SHUTDOWN\n");
        return 1;

    case KVM_EXIT_FAIL_ENTRY:
        fprintf(stderr, "FAIL ENTRY: hardware_entry_failure_reason=0x%llx\n",
        (unsigned long long)kvr->fail_entry.hardware_entry_failure_reason);
        return 1;

    case KVM_EXIT_INTERNAL_ERROR:
        fprintf(stderr, "INTERNAL ERROR: suberror=%u\n", kvr->internal.suberror);
        return 1;

case KVM_EXIT_IO: {
    uint16_t port = kvr->io.port;
    uint8_t *data = (uint8_t*)kvr + kvr->io.data_offset;

    if (port < 0x3F8 || port > 0x3FF) break;
    if (kvr->io.size != 1) break;

    uint8_t off = (uint8_t)(port - 0x3F8); //uart

    if (kvr->io.direction == KVM_EXIT_IO_OUT) {
        uint8_t v = data[0];

        switch (off) {
        case 0:
            if (lcr & 0x80) dll = v;
            else {
                write(STDOUT_FILENO, &v, 1);
                if (ier & 2) txipnd = 1;
                up4();
            }
            break;
        case 1:
            if (lcr & 0x80) dlm = v;
            else ier = v;
            break;
        case 2: fcr = v; break;
        case 3: lcr = v; break;
        case 4: mcr = v; break;
        default: break;
        }

    } else {

        uint8_t v = 0;

        switch (off) {
        case 0:

            if (lcr & 0x80) v = dll;
            else {
                pthread_mutex_lock(&rxmu);
                if (rxh != rxt) {
                    v = rxq[rxh & (sizeof(rxq) - 1)];
                    rxh++;
                } else v = 0;
                pthread_mutex_unlock(&rxmu);
                up4();
            }
            break;

        case 1:
            if (lcr & 0x80) v = dlm;
            else v = ier;
            break;

        case 2:
            pnd = ispndg();

            if (pnd && (ier & 1)) v = 4;
            else if (txipnd && (ier & 2)) {
                v = 2;
                txipnd = 0;
            } else v = 1;
            up4();
            break;

        case 3:
            v = lcr;
            break;

        case 4:
            v = mcr;
            break;

        case 5: {
            v = 0x60;
            pnd = ispndg();

            if (pnd) v |= 1;
            break;
        }

        case 6:
            v = 0;
            break;

        default:
            v = 0;
            break;
        }

        data[0] = v;
    }

    break;
}
}}
return 0;}

int ramfs(void *memr) {

    uint32_t loc = 0x4000000;

    int fd = open("/home/kyo/initramfs.cpio.gz", O_RDONLY); // use your own, this one's just busybox(linked) and /init
    if (fd < 0) return -errno;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 1;
    }

    if (st.st_size == 0) {
        close(fd);
        return 2;
    }

    size_t len = (size_t)st.st_size;

    void *mp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mp == MAP_FAILED) {
        close(fd);
        return 3;
    }

    memcpy((uint8_t*)memr + loc, mp, len);
    munmap(mp, len);
    close(fd);

    int err = bz(memr, len, loc);
    if (err < 0) return err;
    return 0;

}

int bz(void *memr, size_t sz, uint32_t loc) {

    int fd = open("/boot/vmlinuz-6.14.0-35-generic", O_RDONLY); // use your own
    if (fd < 0) return -errno;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 4;
    }

    if (st.st_size == 0) {
        close(fd);
        return 5;
    }

    size_t len = (size_t)st.st_size;

    void *mp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mp == MAP_FAILED) {
        close(fd);
        return 6;
    }

    uint8_t *bz = mp;

    uint8_t stp = (bz[0x1f1]);
    if (stp == 0) stp = 4;
    size_t stpb = (stp+1)*512;

    memcpy((uint8_t*)memr + 0x10000, bz, stpb);
    struct boot_params *bp = (struct boot_params *)((uint8_t*)memr + 0x90000);
    memset(bp, 0, sizeof(*bp));
    memcpy(&bp->hdr, bz + 0x1f1, sizeof(bp->hdr));

    bp->hdr.type_of_loader = 0xFF;
    bp->hdr.cmd_line_ptr = 0x20000;
    if (!bp->hdr.cmdline_size) {
        bp->hdr.cmdline_size = 4096;
    }
    bp->hdr.ramdisk_size = (uint32_t)sz;
    bp->hdr.ramdisk_image = loc;
    bp->e820_entries = 2;

    bp->e820_table[0].addr = (uint64_t)0x00000000;
    bp->e820_table[0].size = (uint64_t)0x0009FC00;
    bp->e820_table[0].type = 1;
 
    bp->e820_table[1].addr = (uint64_t)0x100000;
    bp->e820_table[1].size = (uint64_t)ms - (uint64_t)0x100000;
    bp->e820_table[1].type = 1;
    bp->hdr.loadflags |= 1;

    
    const char *cmd = "console=ttyS0 rdinit=/init earlyprintk=serial,ttyS0,115200 loglevel=7 panic=1";
    memcpy((uint8_t*)memr + 0x20000, cmd, strlen(cmd) + 1);
    
    size_t pmlen = len - stpb;
    memcpy((uint8_t*)memr + 0x100000, bz + stpb, pmlen);

    munmap(mp, len);
    close(fd);
    return 0;

}


