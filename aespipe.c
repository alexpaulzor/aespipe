/*
 *  aespipe.c
 *
 *  Written by Jari Ruusu, June 3 2010
 *
 *  Copyright 2002-2010 by Jari Ruusu.
 *  Redistribution of this file is permitted under the GNU Public License.
 *
 *  AES encrypting or decrypting "pipe", reads from stdin, writes to stdout
 */

#include <stdio.h>
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <string.h>
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <signal.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <errno.h>
#if HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif
#if HAVE_TERMIOS_H
# include <termios.h>
#endif
#if HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#include "aes.h"
#include "md5.h"
#include "sha512.h"
#include "rmd160.h"

#if defined(SUPPORT_CTRMODE)
# include "ctrmode.h"
#endif

#if !defined(AESPIPE_PASSWORD_MIN_LENGTH)
# define  AESPIPE_PASSWORD_MIN_LENGTH   20
#endif

#if WORDS_BIGENDIAN
# define xcpu_to_le32(x) ({u_int32_t __x=(x);((u_int32_t)((((u_int32_t)(__x)&(u_int32_t)0x000000ffUL)<<24)|(((u_int32_t)(__x)&(u_int32_t)0x0000ff00UL)<<8)|(((u_int32_t)(__x)&(u_int32_t)0x00ff0000UL)>>8)|(((u_int32_t)(__x)&(u_int32_t)0xff000000UL)>>24)));})
#else
# define xcpu_to_le32(x) ((u_int32_t)(x))
#endif

#define CBC_MODE 0
#define CTR_MODE 1

char            *progName;
int             ivCounter = 0;
u_int32_t       devSect0 = 0;
u_int32_t       devSect1 = 0;
u_int32_t       devSect2 = 0;
u_int32_t       devSect3 = 0;
int             passFDnumber = -1;
char            *passSeedString = (char *)0;
int             passAskTwice = 0;
char            *gpgKeyFile = (char *)0;
char            *gpgHomeDir = (char *)0;
char            *gpgAgentSocket = (char *)0;
char            *clearTextKeyFile = (char *)0;
char            *passIterThousands = (char *)0;
int             complainWriteErr = 1;
int             verbose = 0;
unsigned int    waitSeconds = 0;
int             multiKeyMode = 0; /* 0=single-key 64=multi-key-v2 65=multi-key-v3 */
char            *multiKeyPass[66];
u_int32_t       partialMD5[4];
int		numThreads = 8;
int		encMode = CBC_MODE;



#define BUFBSIZE    (16*1024)
unsigned char   *bufb;

#define IVBUFSIZE   (4*16)
u_int64_t       *ivbuf;

aes_context     *ctx;
aes_context     *multiKeyCtx[64];

void *specialMalloc(int size, int offs)
{
    unsigned char *p;

    if(!(p = malloc(size + 16 + offs))) {
        fprintf(stderr, "malloc() failed. Aborted.\n");
        exit(1);
    }
    p = (unsigned char *)(((unsigned long)p + 15) & ~((unsigned long)15)) + offs;
    return (void *)p;
}

/*
 * Guessed meanings:
 * int read_write_retry(int file_descriptor, char *buffer, int count, int write)
 * performs a read or write operation to file_descriptor until it succeeeds,
 * gives up after count (int cnt) failures.
 */
int rd_wr_retry(int fd, char *buf, int cnt, int w)
{
    int x, y, z;

    x = 0;
    while(x < cnt) {
        y = cnt - x;
        if(w) {
            z = write(fd, buf + x, y);
        } else {
            z = read(fd, buf + x, y);
            if (!z) return x;
        }
        if(z < 0) {
            if ((errno == EAGAIN) || (errno == ENOMEM) || (errno == EINTR)) {
                continue;
            }
            return x;
        }
        x += z;
    }
    return x;
}

char *get_FD_pass(int fd)
{
    char *p = NULL, *n;
    int x = 0, y = 0;

    do {
        if(y >= (x - 1)) {
            x += 128;
            /* Must enforce some max limit here.      */
            /* This code may have successfully called */
            /* mlockall(MCL_CURRENT | MCL_FUTURE)     */
            if(x > (4*1024)) return(NULL);
            n = malloc(x);
            if(!n) return(NULL);
            if(p) {
                memcpy(n, p, y);
                memset(p, 0, y);
                free(p);
            }
            p = n;
        }
        if(rd_wr_retry(fd, p + y, 1, 0) != 1) break;
        if((p[y] == '\n') || !p[y]) break;
        y++;
    } while(1);
    if(p) p[y] = 0;
    return p;
}

static void warnAboutBadKeyData(int x)
{
    if((x > 1) && (x != 64) && (x != 65)) {
        fprintf(stderr, "Warning: Unknown key data format - using it anyway\n");
    }
}
        
char *do_GPG_pipe(char *pass)
{
    /* pass parameter is NULL pointer in gpgAgentSocket case */
    int     x, pfdi[2], pfdo[2];
    char    str[10], *a[16], *e[3], *h;
    pid_t   gpid;
    struct passwd *p;
    void    *oldSigPipeHandler;

    if(gpgHomeDir) {
        h = gpgHomeDir;
    } else {
        if(!(p = getpwuid(getuid()))) {
            fprintf(stderr, "Error: Unable to detect home directory for uid %d\n", (int)getuid());
            return NULL;
        }
        h = p->pw_dir;
    }
    x = 0;
    if(!(e[x] = malloc(strlen(h) + 6))) {
        nomem1:
        fprintf(stderr, "Error: Unable to allocate memory\n");
        return NULL;
    }
    sprintf(e[x++], "HOME=%s", h);

    if(!pass && gpgAgentSocket) {
        if(!(e[x] = malloc(strlen(gpgAgentSocket) + 16))) {
            goto nomem1;
        }
        sprintf(e[x++], "GPG_AGENT_INFO=%s", gpgAgentSocket);    
    }
    e[x] = 0;

    if(pipe(&pfdi[0])) {
        goto nomem1;
    }
    if(pipe(&pfdo[0])) {
        close(pfdi[0]);
        close(pfdi[1]);
        goto nomem1;
    }

    if((x = open(gpgKeyFile, O_RDONLY)) == -1) {
        fprintf(stderr, "Error: unable to open %s for reading\n", gpgKeyFile);
        close(pfdo[0]);
        close(pfdo[1]);
        close(pfdi[0]);
        close(pfdi[1]);
        return NULL;
    }

    sprintf(str, "%d", pfdi[0]);
    if(!(gpid = fork())) {
        dup2(x, 0);
        dup2(pfdo[1], 1);
        close(x);
        close(pfdi[1]);
        close(pfdo[0]);
        close(pfdo[1]);
        if((x = open("/dev/null", O_WRONLY)) >= 0) {
            dup2(x, 2);
            close(x);
        }
        x = 0;
        a[x++] = "gpg";
        if(gpgHomeDir) {
            a[x++] = "--homedir";
            a[x++] = gpgHomeDir;
        }
        a[x++] = "--no-options";
        a[x++] = "--quiet";
        a[x++] = "--batch";
        a[x++] = "--no-tty";
        if(!pass && gpgAgentSocket) {
            a[x++] = "--use-agent";
        } else {
            a[x++] = "--passphrase-fd";
            a[x++] = str;
        }
        a[x++] = "--decrypt";
        a[x] = 0;
#if defined(PATH_TO_GPG_PROGRAM)
        execve(PATH_TO_GPG_PROGRAM, &a[0], &e[0]);
#endif
        execve("/bin/gpg", &a[0], &e[0]);
        execve("/usr/bin/gpg", &a[0], &e[0]);
        execve("/usr/local/bin/gpg", &a[0], &e[0]);
        /* as last resort try to run gpg from same dir as aespipe */
        x = strlen(progName);
        if((h = malloc(x + 4)) != NULL) {
            strcpy(h, progName);
            while(--x >= 0) {
                if(h[x] == '/') break;
                h[x] = 0;
            }
            if(strlen(h) > 0) {
                strcat(h, "gpg");
                execve(h, &a[0], &e[0]);
            }
        }
        exit(1);
    }
    close(x);
    close(pfdi[0]);
    close(pfdo[1]);
    if(gpid == -1) {
        close(pfdi[1]);
        close(pfdo[0]);
        goto nomem1;
    }

    if(pass) {
        x = strlen(pass);

        /* ignore possible SIGPIPE signal while writing to gpg */
        oldSigPipeHandler = signal(SIGPIPE, SIG_IGN);
        rd_wr_retry(pfdi[1], pass, x, 1);
        rd_wr_retry(pfdi[1], "\n", 1, 1);
        if(oldSigPipeHandler != SIG_ERR) signal(SIGPIPE, oldSigPipeHandler);

        if(x > 0) memset(pass, 0, x);
    }

    close(pfdi[1]);
    x = 0;
    while(x < 66) {
        multiKeyPass[x] = get_FD_pass(pfdo[0]);
        if(!multiKeyPass[x]) {
            /* mem alloc failed - abort */
            multiKeyPass[0] = 0;
            break;
        }
        if(strlen(multiKeyPass[x]) < AESPIPE_PASSWORD_MIN_LENGTH) break;
        x++;
    }
    warnAboutBadKeyData(x);
    if(x >= 65)
        multiKeyMode = 65;
    if(x == 64)
        multiKeyMode = 64;
    close(pfdo[0]);
    waitpid(gpid, &x, 0);
    if(!multiKeyPass[0]) goto nomem1;
    return multiKeyPass[0];
}

#ifndef TCSASOFT
# define TCSASOFT 0
#endif
char *getPass(char *prompt)
{
    int fd, changed = 0;
    struct termios oldt, newt;
    char *p;

    fd = open("/dev/tty", O_RDWR);
    if(fd < 0) return(NULL);
    if(!tcgetattr(fd, &oldt)) {
        newt = oldt;
        newt.c_lflag &= ~(ECHO | ISIG);
        changed = (tcsetattr(fd, TCSAFLUSH | TCSASOFT, &newt) == 0);
    }
    rd_wr_retry(fd, prompt, strlen(prompt), 1);
    p = get_FD_pass(fd);
    if(p) rd_wr_retry(fd, "\n", 1, 1);
    if(changed) tcsetattr(fd, TCSAFLUSH | TCSASOFT, &oldt);
    close(fd);
    return(p);
}

char *sGetPass(int minLen)
{
    char *p = 0, *s, *seed;
    int i, close_psw_fd = 0;

    if(passFDnumber >= 0) {
        contReadFrom_psw:
        if(gpgKeyFile) {
            /* read only one line - this is the gpg passphrase */
            p = get_FD_pass(passFDnumber);
            if(close_psw_fd) close(passFDnumber);
        } else {
            int x = 0;
            /* read many lines from fd */
            while(x < 66) {
                multiKeyPass[x] = get_FD_pass(passFDnumber);
                if(!multiKeyPass[x]) goto nomem;
                if(strlen(multiKeyPass[x]) < AESPIPE_PASSWORD_MIN_LENGTH) break;
                x++;
            }
            if(close_psw_fd) close(passFDnumber);
            warnAboutBadKeyData(x);
            if(x >= 65) {
                multiKeyMode = 65;
                return multiKeyPass[0]; /* got multikey - done now */
            }
            if(x == 64) {
                multiKeyMode = 64;
                return multiKeyPass[0]; /* got multikey - done now */
            }
            p = multiKeyPass[0];        /* got one line passphrase */
        }
        if(!p) goto nomem;

    } else if(clearTextKeyFile) {
        /* reading cleartext passphrase or multikey from file */
        if((passFDnumber = open(clearTextKeyFile, O_RDONLY)) == -1) {
            fprintf(stderr, "Error: unable to open %s for reading\n", clearTextKeyFile);
            return NULL;
        }
        close_psw_fd = 1;
        goto contReadFrom_psw;

    } else if(!gpgAgentSocket) {
        /* get one line passphrase from terminal */
        p = getPass("Password: ");
        if(!p) goto nomem;
        if(passAskTwice) {
            i = strlen(p);
            s = malloc(i + 1);
            if(!s) goto nomem;
            strcpy(s, p);
            p = getPass("Retype password: ");
            if(!p) goto nomem;
            if(strcmp(s, p)) {
                fprintf(stderr, "Error: Passwords are not identical\n");
                return(NULL);
            }
            memset(s, 0, i);
            free(s);
        }
    }

    /* p is still NULL pointer in gpgAgentSocket case */

    if(gpgKeyFile) {
        p = do_GPG_pipe(p);
        if(!p) return(NULL);
        if(!p[0]) {
            fprintf(stderr, "Error: gpg key file decryption failed\n");
            return(NULL);
        }
        if(multiKeyMode) return(p);     /* got multikey - done now */
    }
    if(!p) goto nomem;

    i = strlen(p);
    if(i < minLen) {
        fprintf(stderr, "Error: Password must be at least %d characters.\n", minLen);
        return(NULL);
    }
    seed = passSeedString;
    if(!seed) seed = "";
    s = malloc(i + strlen(seed) + 1);
    if(!s) {
        nomem:
        fprintf(stderr, "Error: Unable to allocate memory\n");
        return(NULL);
    }
    strcpy(s, p);
    memset(p, 0, i);
    strcat(s, seed);
    return(s);
}

/* obsolete */
void unhashed1_hash_buffer(unsigned char *keyStr, int ile, unsigned char *keyBuf, int bufSize) {
    int x, y, z, cnt = ile;
    unsigned char *kp;

    memset(keyBuf, 0, bufSize);
    kp = keyStr;

    for (x = 0; x < (bufSize * 8); x += 6) {
        y = *kp++;

        if (--cnt <= 0) {
            kp = keyStr;
            cnt = ile;
        }

        if ((y >= '0') && (y <= '9')) y -= '0';
        else if((y >= 'A') && (y <= 'Z')) y -= ('A' - 10);
        else if((y >= 'a') && (y <= 'z')) y -= ('a' - 36);
        else if((y == '.') || (y == '/')) y += (62 - '.');
        else y &= 63;

        z = x >> 3;

        if (z < bufSize) {
            keyBuf[z] |= y << (x & 7);
        }

        z++;

        if (z < bufSize) {
            keyBuf[z] |= y >> (8 - (x & 7));
        }
    }
}

/* obsolete */
void unhashed2_hash_buffer(unsigned char *keyStr, int ile, unsigned char *keyBuf, int bufSize) {
    memset(keyBuf, 0, bufSize);
    strncpy((char *)keyBuf, (char *)keyStr, bufSize - 1);
    keyBuf[bufSize - 1] = 0;
}

void rmd160HashTwiceWithA(unsigned char *ib, int ile, unsigned char *ob, int ole)
{
    unsigned char tmpBuf[20 + 20];
    unsigned char pwdCopy[130];

    if(ole < 1) return;
    memset(ob, 0, ole);
    if(ole > 40) ole = 40;
    rmd160_hash_buffer(&tmpBuf[0], ib, ile);
    pwdCopy[0] = 'A';
    if(ile > sizeof(pwdCopy) - 1) ile = sizeof(pwdCopy) - 1;
    memcpy(pwdCopy + 1, ib, ile);
    rmd160_hash_buffer(&tmpBuf[20], pwdCopy, ile + 1);
    memcpy(ob, tmpBuf, ole);
    memset(tmpBuf, 0, sizeof(tmpBuf));
    memset(pwdCopy, 0, sizeof(pwdCopy));
}

static void compute_sector_iv(u_int32_t *ivout)
{
    ivout[0] = xcpu_to_le32(devSect0);
    ivout[1] = xcpu_to_le32(devSect1);
    ivout[2] = xcpu_to_le32(devSect2);
    ivout[3] = xcpu_to_le32(devSect3);
    /* Update the sector number for next sector */
    /* All references to current sector number must be made before this function is called */
    if(!++devSect0 && !++devSect1 && !++devSect2) devSect3++;
}

static void compute_md5_iv_v3(u_int32_t *ivout, u_int32_t *data)
{
    int         x;
#if WORDS_BIGENDIAN
    int         y, e;
#endif
    u_int32_t   sbuf[16];

#if WORDS_BIGENDIAN
    y = 7;
    e = 16;
    do {
        if (!y) {
            e = 12;
            /* md5_transform_CPUbyteorder wants data in CPU byte order */
            /* devSect{0,1} are already in CPU byte order -- no need to convert */
            /* use only 56 bits of sector number */
            sbuf[12] = devSect0;
            sbuf[13] = (devSect1 & 0xFFFFFF) | 0x80000000;
            /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
            /* For version 3 on-disk format this really should be 4536 bits, but can't be */
            /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
            sbuf[14] = 4024;
            sbuf[15] = 0;
        }
        x = 0;
        do {
            sbuf[x    ] = xcpu_to_le32(data[0]);
            sbuf[x + 1] = xcpu_to_le32(data[1]);
            sbuf[x + 2] = xcpu_to_le32(data[2]);
            sbuf[x + 3] = xcpu_to_le32(data[3]);
            x += 4;
            data += 4;
        } while (x < e);
        md5_transform_CPUbyteorder(&ivout[0], &sbuf[0]);
    } while (--y >= 0);
    ivout[0] = xcpu_to_le32(ivout[0]);
    ivout[1] = xcpu_to_le32(ivout[1]);
    ivout[2] = xcpu_to_le32(ivout[2]);
    ivout[3] = xcpu_to_le32(ivout[3]);
#else
    x = 6;
    do {
        md5_transform_CPUbyteorder(&ivout[0], data);
        data += 16;
    } while (--x >= 0);
    memcpy(sbuf, data, 48);
    /* md5_transform_CPUbyteorder wants data in CPU byte order */
    /* devSect{0,1} are already in CPU byte order -- no need to convert */
    /* use only 56 bits of sector number */
    sbuf[12] = devSect0;
    sbuf[13] = (devSect1 & 0xFFFFFF) | 0x80000000;
    /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
    /* For version 3 on-disk format this really should be 4536 bits, but can't be */
    /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
    sbuf[14] = 4024;
    sbuf[15] = 0;
    md5_transform_CPUbyteorder(&ivout[0], &sbuf[0]);
#endif
    /* Update the sector number for next sector */
    /* All references to current sector number must be made before this function is called */
    if(!++devSect0) devSect1++;
}

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
/*
 * This 2x code is currently only available on little endian AMD64
 * This 2x code assumes little endian byte order
 * Context A input data is at zero offset, context B at data + 512 bytes
 * Context A ivout at zero offset, context B at ivout + 16 bytes
 */
static void compute_md5_iv_v3_2x(u_int32_t *ivout, u_int32_t *data)
{
    int         x;
    u_int32_t   sbuf[2*16];

    x = 6;
    do {
        md5_transform_CPUbyteorder_2x(&ivout[0], data, data + (512/4));
        data += 16;
    } while (--x >= 0);
    memcpy(&sbuf[0], data, 48);
    memcpy(&sbuf[16], data + (512/4), 48);
    /* md5_transform_CPUbyteorder wants data in CPU byte order */
    /* devSect{0,1} are already in CPU byte order -- no need to convert */
    /* use only 56 bits of sector number */
    sbuf[12] = devSect0;
    sbuf[13] = (devSect1 & 0xFFFFFF) | 0x80000000;
    if(!++devSect0) devSect1++;     /* Update the sector number for next sector */
    sbuf[16 + 12] = devSect0;
    sbuf[16 + 13] = (devSect1 & 0xFFFFFF) | 0x80000000;
    /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
    /* For version 3 on-disk format this really should be 4536 bits, but can't be */
    /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
    sbuf[16 + 14] = sbuf[14] = 4024;
    sbuf[16 + 15] = sbuf[15] = 0;
    md5_transform_CPUbyteorder_2x(&ivout[0], &sbuf[0], &sbuf[16]);
    /* Update the sector number for next sector */
    /* All references to current sector number must be made before this function is called */
    if(!++devSect0) devSect1++;
}
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */

static void generic_multikey_decrypt(int size)
{
    aes_context     *acpa[2];
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#6) */
    while(size >= (2*512)) {
        /* multi-key mode, decrypt 2 sectors at a time */
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        /* decrypt using fake all-zero IV, first sector */
        memset(ivbuf, 0, 16);
        x = 15;
        do {
            memcpy(&ivbuf[2], bfp, 16);
            aes_decrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[0];
            bfp[1] ^= ivbuf[1];
            bfp += 2;
            memcpy(ivbuf, bfp, 16);
            aes_decrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[2];
            bfp[1] ^= ivbuf[3];
            bfp += 2;
        } while(--x >= 0);
        /* decrypt using fake all-zero IV, second sector */
        memset(ivbuf, 0, 16);
        x = 15;
        do {
            memcpy(&ivbuf[2], bfp, 16);
            aes_decrypt(acpa[1], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[0];
            bfp[1] ^= ivbuf[1];
            bfp += 2;
            memcpy(ivbuf, bfp, 16);
            aes_decrypt(acpa[1], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[2];
            bfp[1] ^= ivbuf[3];
            bfp += 2;
        } while(--x >= 0);
        /* compute correct IV */
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        compute_md5_iv_v3_2x((u_int32_t *)ivbuf, (u_int32_t *)(bfp - 126));
        /* XOR with correct IV now */
        *(bfp - 128) ^= ivbuf[0];
        *(bfp - 127) ^= ivbuf[1];
        *(bfp - 64) ^= ivbuf[2];
        *(bfp - 63) ^= ivbuf[3];
        size -= 2*512;
    }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
    while(size > 0) {
        /* decrypt one sector at a time */
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        /* decrypt using fake all-zero IV */
        memset(ivbuf, 0, 16);
        x = 15;
        do {
            memcpy(&ivbuf[2], bfp, 16);
            aes_decrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[0];
            bfp[1] ^= ivbuf[1];
            bfp += 2;
            memcpy(ivbuf, bfp, 16);
            aes_decrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[2];
            bfp[1] ^= ivbuf[3];
            bfp += 2;
        } while (--x >= 0);
        /* multi-key mode, compute correct IV */
        memcpy(ivbuf, &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)ivbuf, (u_int32_t *)(bfp - 62));
        /* XOR with correct IV now */
        *(bfp - 64) ^= ivbuf[0];
        *(bfp - 63) ^= ivbuf[1];
        size -= 512;
    }
}

static void generic_singlekey_decrypt(int size)
{
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    while(size > 0) {
        /* decrypt using fake all-zero IV */
        memset(ivbuf, 0, 16);
        x = size >> 4;
        if(x > 32) x = 32;
        while(--x >= 0) {
            memcpy(&ivbuf[2], bfp, 16);
            aes_decrypt(ctx, (unsigned char *)bfp, (unsigned char *)bfp);
            bfp[0] ^= ivbuf[0];
            bfp[1] ^= ivbuf[1];
            bfp += 2;
            memcpy(ivbuf, &ivbuf[2], 16);
        }
        /* single-key mode, compute correct IV  */
        compute_sector_iv((u_int32_t *)ivbuf);
        /* XOR with correct IV now */
        *(bfp - 64) ^= ivbuf[0];
        *(bfp - 63) ^= ivbuf[1];
        size -= 512;
    }
}

static void generic_multikey_encrypt(int size)
{
    aes_context     *acpa[2];
    int             x;
    u_int64_t       *dip;
    u_int64_t       *bfp = (u_int64_t *)bufb;

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#5) */
    while(size >= (2*512)) {
        /* multi-key mode, encrypt 2 sectors at a time */
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        compute_md5_iv_v3_2x((u_int32_t *)ivbuf, (u_int32_t *)(bfp + 2));
        /* first sector */
        dip = &ivbuf[0];
        x = 15;
        do {
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
        } while(--x >= 0);
        /* second sector */
        dip = &ivbuf[2];
        x = 15;
        do {
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[1], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[1], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
        } while(--x >= 0);
        size -= 2*512;
    }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
    while(size > 0) {
        /* encrypt one sector at a time */
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        /* multi-key mode encrypt */
        memcpy(ivbuf, &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)ivbuf, (u_int32_t *)(bfp + 2));
        dip = ivbuf;
        x = 15;
        do {
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
            bfp[0] ^= dip[0];
            bfp[1] ^= dip[1];
            aes_encrypt(acpa[0], (unsigned char *)bfp, (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
        } while(--x >= 0);
        size -= 512;
    }
}

static void generic_singlekey_encrypt(int size)
{
    int             x;
    u_int64_t       *dip;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    while(size > 0) {
        /* single-key mode encrypt */
        compute_sector_iv((u_int32_t *)ivbuf);
        dip = ivbuf;
        x = size >> 4;
        if(x > 32) x = 32;
        while(--x >= 0) {
            ivbuf[2] = bfp[0] ^ dip[0];
            ivbuf[3] = bfp[1] ^ dip[1];
            aes_encrypt(ctx, (unsigned char *)(&ivbuf[2]), (unsigned char *)bfp);
            dip = bfp;
            bfp += 2;
        }
        size -= 512;
    }
}

static void (*generic_workFunc[4])(int) = {
    generic_singlekey_decrypt,
    generic_singlekey_encrypt,
    generic_multikey_decrypt,
    generic_multikey_encrypt
};

#if defined(SUPPORT_CTRMODE)

static void generic_ctr_singlekey_decrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode requires Intel AES\n");
    exit(1);
}

static void generic_ctr_singlekey_encrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode requires Intel AES\n");
    exit(1);
}

static void generic_ctr_multikey_decrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode requires Intel AES\n");
    exit(1);
}

static void generic_ctr_multikey_encrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode requires Intel AES\n");
    exit(1);
}

static void (*generic_ctr_workFunc[4])(int) = {
    generic_ctr_singlekey_decrypt,
    generic_ctr_singlekey_encrypt,
    generic_ctr_multikey_decrypt,
    generic_ctr_multikey_encrypt
};
#endif //SUPPORT_CTRMODE

#if defined(SUPPORT_PADLOCK) && (defined(X86_ASM) || defined(AMD64_ASM))
static __inline__ void padlock_flush_key_context(void)
{
    __asm__ __volatile__("pushf; popf" : : : "cc");
}

static __inline__ void padlock_rep_xcryptcbc(void *cw, void *k, void *s, void *d, void *iv, unsigned long cnt)
{
    __asm__ __volatile__(".byte 0xF3,0x0F,0xA7,0xD0"
                         : "+a" (iv), "+c" (cnt), "+S" (s), "+D" (d) /*output*/
                         : "b" (k), "d" (cw) /*input*/
                         : "cc", "memory" /*modified*/ );
}

static u_int32_t    padlock_cw_e;
static u_int32_t    padlock_cw_d;
static u_int32_t    *padlock_cwBuf;

static void padlock_multikey_decrypt(int size)
{
    aes_context     *acpa[2];
    u_int64_t       *bfp = (u_int64_t *)bufb;

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#4) */
    while(size >= (2*512)) {
        /* decrypt using fake all-zero IV */
        memset(&ivbuf[0], 0, 2*16);
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        padlock_flush_key_context();
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[0]->aes_d_key[0], bfp,      bfp,      &ivbuf[0], 32);
        padlock_flush_key_context();
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[1]->aes_d_key[0], bfp + 64, bfp + 64, &ivbuf[2], 32);
        /* compute correct IV */
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        compute_md5_iv_v3_2x((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 2));
        /* XOR with correct IV now */
        bfp[0] ^= ivbuf[0];
        bfp[1] ^= ivbuf[1];
        bfp[64] ^= ivbuf[2];
        bfp[65] ^= ivbuf[3];
        size -= 2*512;
        bfp += 2*64;
    }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
    while(size > 0) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        padlock_flush_key_context();
        /* decrypt using fake all-zero IV */
        memset(&ivbuf[0], 0, 16);
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[0]->aes_d_key[0], bfp, bfp, &ivbuf[0], 32);
        /* compute correct IV */
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 2));
        /* XOR with correct IV now */
        bfp[0] ^= ivbuf[0];
        bfp[1] ^= ivbuf[1];
        size -= 512;
        bfp += 64;
    }
}

static void padlock_singlekey_decrypt(int size)
{
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    while(size > 0) {
        padlock_flush_key_context();
        compute_sector_iv((u_int32_t *)(&ivbuf[0]));
        x = size >> 4;
        if(x > 32) x = 32;
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &ctx->aes_d_key[0], bfp, bfp, &ivbuf[0], x);
        size -= 512;
        bfp += 64;
    }
}

static void padlock_multikey_encrypt(int size)
{
    aes_context     *acpa[2];
    u_int64_t       *bfp = (u_int64_t *)bufb;

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#3) */
    while(size >= (2*512)) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        compute_md5_iv_v3_2x((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 2));
        padlock_flush_key_context();
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[0]->aes_e_key[0], bfp,      bfp,      &ivbuf[0], 32);
        padlock_flush_key_context();
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[1]->aes_e_key[0], bfp + 64, bfp + 64, &ivbuf[2], 32);
        size -= 2*512;
        bfp += 2*64;
    }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
    while(size > 0) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        padlock_flush_key_context();
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 2));
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &acpa[0]->aes_e_key[0], bfp, bfp, &ivbuf[0], 32);
        size -= 512;
        bfp += 64;
    }
}

static void padlock_singlekey_encrypt(int size)
{
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    while(size > 0) {
        padlock_flush_key_context();
        compute_sector_iv((u_int32_t *)(&ivbuf[0]));
        x = size >> 4;
        if(x > 32) x = 32;
        padlock_rep_xcryptcbc(&padlock_cwBuf[0], &ctx->aes_e_key[0], bfp, bfp, &ivbuf[0], x);
        size -= 512;
        bfp += 64;
    }
}

static void (*padlock_workFunc[4])(int) = {
    padlock_singlekey_decrypt,
    padlock_singlekey_encrypt,
    padlock_multikey_decrypt,
    padlock_multikey_encrypt
};
#endif

#if defined(SUPPORT_INTELAES) && (defined(X86_ASM) || defined(AMD64_ASM))
extern void intel_aes_cbc_encrypt(const aes_context *, void *src, void *dst, size_t len, void *iv);
extern void intel_aes_cbc_decrypt(const aes_context *, void *src, void *dst, size_t len, void *iv);
extern void intel_aes_cbc_enc_4x512(aes_context **, void *src, void *dst, void *iv);

static void intelaes_multikey_decrypt(int size)
{
    aes_context     *acpa[2];
    u_int64_t       *bfp = (u_int64_t *)bufb;

#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#2) */
    while(size >= (2*512)) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        /* decrypt using fake all-zero IV */
        memset(ivbuf, 0, 2*16);
        intel_aes_cbc_decrypt(acpa[0], bfp,      bfp,      512, &ivbuf[0]);
        intel_aes_cbc_decrypt(acpa[1], bfp + 64, bfp + 64, 512, &ivbuf[2]);
        /* compute correct IV, use 2x parallelized version */
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        compute_md5_iv_v3_2x((u_int32_t *)ivbuf, (u_int32_t *)(bfp + 2));
        /* XOR with correct IV now */
        bfp[0] ^= ivbuf[0];
        bfp[1] ^= ivbuf[1];
        bfp[64] ^= ivbuf[2];
        bfp[65] ^= ivbuf[3];
        size -= 2*512;
        bfp += 2*64;
    }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
    while(size > 0) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        /* decrypt using fake all-zero IV */
        memset(ivbuf, 0, 16);
        intel_aes_cbc_decrypt(acpa[0], bfp, bfp, 512, ivbuf);
        /* compute correct IV */
        memcpy(ivbuf, &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)ivbuf, (u_int32_t *)(bfp + 2));
        /* XOR with correct IV now */
        bfp[0] ^= ivbuf[0];
        bfp[1] ^= ivbuf[1];
        size -= 512;
        bfp += 64;
    }
}

static void intelaes_singlekey_decrypt(int size)
{
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    while(size > 0) {
        compute_sector_iv((u_int32_t *)ivbuf);
        x = size;
        if(x > 512) x = 512;
        intel_aes_cbc_decrypt(ctx, bfp, bfp, x, ivbuf);
        size -= 512;
        bfp += 64;
    }
}

static void intelaes_multikey_encrypt(int size)
{
    aes_context     *acpa[4];
    u_int64_t       *bfp = (u_int64_t *)bufb;

    /* if possible, use faster 4-chains at a time encrypt implementation (#1) */
    while(size >= (4*512)) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0    ) & 0x3F];
        acpa[1] = multiKeyCtx[((unsigned)devSect0 + 1) & 0x3F];
        acpa[2] = multiKeyCtx[((unsigned)devSect0 + 2) & 0x3F];
        acpa[3] = multiKeyCtx[((unsigned)devSect0 + 3) & 0x3F];
        memcpy(&ivbuf[0], &partialMD5[0], 16);
        memcpy(&ivbuf[2], &partialMD5[0], 16);
        memcpy(&ivbuf[4], &partialMD5[0], 16);
        memcpy(&ivbuf[6], &partialMD5[0], 16);
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
        /* use 2x parallelized version */
        compute_md5_iv_v3_2x((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 0x02));
        compute_md5_iv_v3_2x((u_int32_t *)(&ivbuf[4]), (u_int32_t *)(bfp + 0x82));
#else
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[0]), (u_int32_t *)(bfp + 0x02));
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[2]), (u_int32_t *)(bfp + 0x42));
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[4]), (u_int32_t *)(bfp + 0x82));
        compute_md5_iv_v3((u_int32_t *)(&ivbuf[6]), (u_int32_t *)(bfp + 0xC2));
#endif
        intel_aes_cbc_enc_4x512(&acpa[0], bfp, bfp, ivbuf);
        size -= 4*512;
        bfp += 4*64;
    }
    /* encrypt the rest (if any) using slower 1-chain at a time implementation */
    while(size > 0) {
        acpa[0] = multiKeyCtx[((unsigned)devSect0) & 0x3F];
        memcpy(ivbuf, &partialMD5[0], 16);
        compute_md5_iv_v3((u_int32_t *)ivbuf, (u_int32_t *)(bfp + 2));
        intel_aes_cbc_encrypt(acpa[0], bfp, bfp, 512, ivbuf);
        size -= 512;
        bfp += 64;
    }
}

static void intelaes_singlekey_encrypt(int size)
{
    aes_context     *acpa[4];
    int             x;
    u_int64_t       *bfp = (u_int64_t *)bufb;

    acpa[3] = acpa[2] = acpa[1] = acpa[0] = ctx;
    /* if possible, use faster 4-chains at a time encrypt implementation (#0) */
    while(size >= (4*512)) {
        compute_sector_iv((u_int32_t *)(&ivbuf[0]));
        compute_sector_iv((u_int32_t *)(&ivbuf[2]));
        compute_sector_iv((u_int32_t *)(&ivbuf[4]));
        compute_sector_iv((u_int32_t *)(&ivbuf[6]));
        intel_aes_cbc_enc_4x512(&acpa[0], bfp, bfp, ivbuf);
        size -= 4*512;
        bfp += 4*64;
    }
    /* encrypt the rest (if any) using slower 1-chain at a time implementation */
    while(size > 0) {
        compute_sector_iv((u_int32_t *)ivbuf);
        x = size;
        if(x > 512) x = 512;
        intel_aes_cbc_encrypt(acpa[0], bfp, bfp, x, ivbuf);
        size -= 512;
        bfp += 64;
    }
}

static void (*intelaes_workFunc[4])(int) = {
    intelaes_singlekey_decrypt,
    intelaes_singlekey_encrypt,
    intelaes_multikey_decrypt,
    intelaes_multikey_encrypt
};

#if defined(SUPPORT_CTRMODE)

static void intelaes_ctr_singlekey_decrypt(int size)
{
    enqueue_data(bufb, size);
}

static void intelaes_ctr_singlekey_encrypt(int size)
{
    enqueue_data(bufb, size);
}

static void intelaes_ctr_multikey_decrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode multikey encryption is not supported");
    exit(1);
}

static void intelaes_ctr_multikey_encrypt(int size)
{
    //TODO: implement
    fprintf(stderr, "Counter mode multikey encryption is not supported");
    exit(1);
}

static void (*intelaes_ctr_workFunc[4])(int) = {
    intelaes_ctr_singlekey_decrypt,
    intelaes_ctr_singlekey_encrypt,
    intelaes_ctr_multikey_decrypt,
    intelaes_ctr_multikey_encrypt
};
#endif	//SUPPORT_CTRMODE
#endif

#if (defined(SUPPORT_PADLOCK) || defined(SUPPORT_INTELAES)) && defined(X86_ASM)
/*
 * flag_is_changeable_p() function was copied from linux kernel source.
 * No copyright info on that linux source file - assuming GPL license
 */
/* Standard macro to see if a specific flag is changeable */
static inline int flag_is_changeable_p(u_int32_t flag)
{
	u_int32_t f1, f2;

	__asm__ __volatile__("pushfl		\n\t"
			     "pushfl		\n\t"
			     "popl %0		\n\t"
			     "movl %0, %1	\n\t"
			     "xorl %2, %0	\n\t"
			     "pushl %0		\n\t"
			     "popfl		\n\t"
			     "pushfl		\n\t"
			     "popl %0		\n\t"
			     "popfl		\n\t"

			     : "=&r" (f1), "=&r" (f2)
			     : "ir" (flag));

	return ((f1^f2) & flag) != 0;
}
#endif

#if defined(SUPPORT_PADLOCK) && (defined(X86_ASM) || defined(AMD64_ASM))
static int padlock_check_cpuid(void)
{
    unsigned int eax, ebx, ecx, edx;

#if defined(X86_ASM)
    /* check that processor supports cpuid instruction */
    if(!flag_is_changeable_p(0x00200000)) return 0;
#endif

    /* check for "CentaurHauls" ID string, and enabled ACE */
    __asm__ __volatile__("cpuid" : "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0), "b" (0), "c" (0), "d" (0));
    if((ebx != 0x746e6543) || (edx != 0x48727561) || (ecx != 0x736c7561)) return 0;
    __asm__ __volatile__("cpuid" : "=a" (eax) : "a" (0xC0000000), "b" (0), "c" (0), "d" (0));
    if(eax < 0xC0000001) return 0;
    __asm__ __volatile__("cpuid" : "=d" (edx) : "a" (0xC0000001), "b" (0), "c" (0), "d" (0));
    if((edx & 0xC0) != 0xC0) return 0;
    return 1;
}
#endif

#if defined(SUPPORT_INTELAES) && (defined(X86_ASM) || defined(AMD64_ASM))
static int intelaes_check_cpuid(void)
{
    unsigned int ecx;

#if defined(X86_ASM)
    /* check that processor supports cpuid instruction */
    if(!flag_is_changeable_p(0x00200000)) return 0;
#endif

    /* check for enabled Intel AES */
    __asm__ __volatile__("cpuid" : "=c" (ecx) : "a" (1), "b" (0), "c" (0), "d" (0));
    if((ecx & 0x02000000) != 0x02000000) return 0;
    return 1;
}
#endif

int main(int argc, char **argv)
{
    int x, encrypt = 1, bits, ret, bMask;
    void (*hf)(unsigned char *, int, unsigned char *, int);
    union {
        u_int32_t     hw[16];
        unsigned char hb[64];
    } hbu;
    char *pass, *hfn = (char *)0, *efn = (char *)0;
    unsigned int y;
    void (*workFunc)(int);
    char *hardware;

#if defined(MCL_CURRENT) && defined(MCL_FUTURE) && HAVE_MLOCKALL
    /* try to lock all memory to prevent key leak to swap */
    mlockall(MCL_CURRENT | MCL_FUTURE);
    /* drop possible suid-root privileges */
    if(getuid() != geteuid()) setuid(getuid());
#endif

    progName = *argv;

    for(argc--, argv++; argc > 0; argc--, argv++) {
        if(!strcmp(*argv, "-") || (**argv != '-')) {
            usage:
            fprintf(stderr, "usage: %s [options] <inputfile >outputfile\n"
                            "version 2.4b  Copyright (c) 2002-2010 Jari Ruusu, (c) 2001 Dr Brian Gladman\n"
                            "options:  -e aes128|aes192|aes256          =  set key length\n"
                            "          -H sha256|sha384|sha512|rmd160   =  set password hash function\n"
			    "          -m cbc|ctr 			=  set encryption mode [default: cbc]\n"
			    "          -t num     =  set number of threads to use (implies -m ctr)\n"
                            "          -d         =  decrypt\n"
                            "          -p num     =  read password from file descriptor num\n"
                            "          -P file    =  read password from file\n"
                            "          -S pseed   =  set password seed\n"
                            "          -T         =  ask password twice\n"
                            "          -q         =  don't complain about write errors\n"
                            "          -w num     =  wait num seconds before asking password\n"
                            "          -O num     =  set IV offset (value 1 == 512 byte offset)\n"
                            "          -K file    =  file contains gpg encrypted keys\n"
                            "          -G dir     =  home directory for gpg\n"
                            "          -A socket  =  socket for gpg-agent\n"
                            "          -C num     =  iterate key num thousand times through AES-256\n"
                            "          -v         =  prints some diagnostics to stderr\n"
                            , progName);
            exit(1);
        } else {
            while(*++(*argv)) {
                switch(**argv) {
                case 'e':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    efn = *argv;
                    goto nextArg;
                case 'H':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    hfn = *argv;
                    goto nextArg;
		case 'm':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
		    if (strcmp(*argv, "cbc") == 0) encMode = CBC_MODE;
		    else if (strcmp(*argv, "ctr") == 0) encMode = CTR_MODE;
		    else goto usage;
		    goto nextArg;
		case 't':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    if(sscanf(*argv, "%d", &numThreads) != 1) goto usage;
		    encMode = CTR_MODE;
                    goto nextArg;
                case 'd':
                    encrypt = 0;
                    break;
                case 'p':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    if(sscanf(*argv, "%d", &passFDnumber) != 1) goto usage;
                    goto nextArg;
                case 'P':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    clearTextKeyFile = *argv;
                    goto nextArg;
                case 'S':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    passSeedString = *argv;
                    goto nextArg;
                case 'T':
                    passAskTwice = 1;
                    break;
                case 'q':
                    complainWriteErr = 0;
                    break;
                case 'w':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    if(sscanf(*argv, "%u", &waitSeconds) != 1) goto usage;
                    goto nextArg;
                case 'O':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    if(sscanf(*argv, "%u", &y) != 1) goto usage;
                    devSect0 = y;
                    goto nextArg;
                case 'K':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    gpgKeyFile = *argv;
                    if(!gpgKeyFile[0]) gpgKeyFile = 0;
                    goto nextArg;
                case 'G':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    gpgHomeDir = *argv;
                    if(!gpgHomeDir[0]) gpgHomeDir = 0;
                    goto nextArg;
                case 'A':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    gpgAgentSocket = *argv;
                    if(!gpgAgentSocket[0]) gpgAgentSocket = 0;
                    goto nextArg;
                case 'C':
                    if(!(*++(*argv) || (--argc && *++argv))) goto usage;
                    passIterThousands = *argv;
                    goto nextArg;
                case 'v':
                    verbose = 1;
                    break;
                default:
                    goto usage;
                }
            }
        }
        nextArg: continue;
    }

    /* sort out conflicting options */
    if(gpgAgentSocket && !gpgKeyFile) {
        gpgAgentSocket = 0;
    }
    if(passFDnumber >= 0) {     /* -p wins -P and -A and -T */
        clearTextKeyFile = 0;
        gpgAgentSocket = 0;
        passAskTwice = 0;
    }
    if(clearTextKeyFile) {      /* -P wins -A and -T */
        gpgAgentSocket = 0;
        passAskTwice = 0;
    }
    if(gpgAgentSocket) {        /* -A wins -T */
        passAskTwice = 0;
    }

    /* 16 byte alignment for these */
    bufb = specialMalloc(BUFBSIZE, 0);
    ivbuf = specialMalloc(IVBUFSIZE, 0);

    /* offset 8 is needed here to align expanded key data at 16 byte boundary */
    ctx = specialMalloc(sizeof(aes_context), 8);
    for(x = 0; x < 64; x++) {
        multiKeyCtx[x] = specialMalloc(sizeof(aes_context), 8);
    }

    bits = 128;
    hf = sha256_hash_buffer;
    if(efn) {
        if(!strcasecmp(efn, "aes256")) {
            bits = 256;
            hf = sha512_hash_buffer;
        } else if(!strcasecmp(efn, "aes192")) {
            bits = 192;
            hf = sha384_hash_buffer;
        } else if(strcasecmp(efn, "aes128") && strcasecmp(efn, "aes")) {
            goto usage;
        }
    }
    x = AESPIPE_PASSWORD_MIN_LENGTH;
    if(hfn) {
        if(!strcasecmp(hfn, "sha256")) hf = sha256_hash_buffer;
        else if(!strcasecmp(hfn, "sha384")) hf = sha384_hash_buffer;
        else if(!strcasecmp(hfn, "sha512")) hf = sha512_hash_buffer;
        else if(!strcasecmp(hfn, "rmd160")) hf = rmd160HashTwiceWithA, x = 1;
        else if(!strcasecmp(hfn, "unhashed1")) hf = unhashed1_hash_buffer;
        else if(!strcasecmp(hfn, "unhashed2")) hf = unhashed2_hash_buffer, x = 1;
        else goto usage;
    }

    if(waitSeconds) sleep(waitSeconds);
    pass = sGetPass(x);
    if(!pass) exit(1);
    x = strlen(pass);
    if(hf == unhashed1_hash_buffer) { /* obsolete compat */
        bits = 128;
        if(x >= 32) bits = 192;
        if(x >= 43) bits = 256;
    }
    (*hf)((unsigned char *)pass, x, &hbu.hb[0], 32);
    if(multiKeyMode) {
        int r = 0, t;
        partialMD5[0] = 0x67452301;
        partialMD5[1] = 0xefcdab89;
        partialMD5[2] = 0x98badcfe;
        partialMD5[3] = 0x10325476;
        while(r < multiKeyMode) {
            t = strlen(multiKeyPass[r]);
            (*hf)((unsigned char *)multiKeyPass[r], t, &hbu.hb[0], 32);
            memset(multiKeyPass[r], 0, t);
            /*
             * MultiKeyMode uses md5 IV. One key mode uses sector IV. Sector IV
             * and md5 IV v2 and v3 are all computed differently. This first key
             * byte XOR with 0x55/0xF4 is needed to cause complete decrypt failure
             * in cases where data is encrypted with one type of IV and decrypted
             * with another type IV. If identical key was used but only IV was
             * computed differently, only first plaintext block of 512 byte CBC
             * chain would decrypt incorrectly and rest would decrypt correctly.
             * Partially correct decryption is dangerous. Decrypting all blocks
             * incorrectly is safer because file system mount will simply fail.
             */
            if(multiKeyMode == 65) {
                hbu.hb[0] ^= 0xF4; /* version 3 */
            } else {
                hbu.hb[0] ^= 0x55; /* version 2 */
            }
            if(r < 64) {
                aes_set_key(multiKeyCtx[r], &hbu.hb[0], bits, 0);
            } else {
                /* only first 128 bits of iv-key is used */
#if WORDS_BIGENDIAN
                hbu.hw[0] = xcpu_to_le32(hbu.hw[0]);
                hbu.hw[1] = xcpu_to_le32(hbu.hw[1]);
                hbu.hw[2] = xcpu_to_le32(hbu.hw[2]);
                hbu.hw[3] = xcpu_to_le32(hbu.hw[3]);
#endif
                memset(&hbu.hb[16], 0, 48);
                md5_transform_CPUbyteorder(&partialMD5[0], &hbu.hw[0]);
            }
            r++;
        }
    } else if(passIterThousands) {
        unsigned long iter = 0;
        union {
            u_int32_t     w[8]; /* needed for 4 byte alignment of tempkey[] */
            unsigned char tempkey[32];
        } tku;
        /*
         * Set up AES-256 encryption key using same password and hash function
         * as before but with password bit 0 flipped before hashing. That key
         * is then used to encrypt actual encryption key N thousand times.
         */
        pass[0] ^= 1;
        (*hf)((unsigned char *)pass, x, &tku.tempkey[0], 32);
        aes_set_key(ctx, &tku.tempkey[0], 256, 0);
        sscanf(passIterThousands, "%lu", &iter);
        iter *= 1000;
        while(iter > 0) {
            /* encrypt both 128bit blocks with AES-256 */
            aes_encrypt(ctx, &hbu.hb[ 0], &hbu.hb[ 0]);
            aes_encrypt(ctx, &hbu.hb[16], &hbu.hb[16]);
            /* exchange upper half of first block with lower half of second block */
            memcpy(&tku.tempkey[0], &hbu.hb[8], 8);
            memcpy(&hbu.hb[8], &hbu.hb[16], 8);
            memcpy(&hbu.hb[16], &tku.tempkey[0], 8);
            iter--;
        }
        memset(&tku.tempkey[0], 0, sizeof(tku.tempkey));
    }
    aes_set_key(ctx, &hbu.hb[0], bits, 0);
    memset(&hbu.hb[0], 0, sizeof(hbu.hb));
    memset(pass, 0, x);

    x = (multiKeyMode ? 2 : 0) + encrypt;  /* index to xxxxx_workFunc[], 0...3 */
#if defined(SUPPORT_PADLOCK) && (defined(X86_ASM) || defined(AMD64_ASM))
    if(padlock_check_cpuid()) {
        workFunc = padlock_workFunc[x];
        hardware = "VIA padlock hardware AES";
        switch(bits) {
        case 256:
            /* 14 rounds, AES, software key gen, normal oper, encrypt, 256-bit key */
            padlock_cw_e = 14 | (1<<7) | (2<<10);
            /* 14 rounds, AES, software key gen, normal oper, decrypt, 256-bit key */
            padlock_cw_d = 14 | (1<<7) | (1<<9) | (2<<10);
            break;
        case 192:
            /* 12 rounds, AES, software key gen, normal oper, encrypt, 192-bit key */
            padlock_cw_e = 12 | (1<<7) | (1<<10);
            /* 12 rounds, AES, software key gen, normal oper, decrypt, 192-bit key */
            padlock_cw_d = 12 | (1<<7) | (1<<9) | (1<<10);
            break;
        default:
            /* 10 rounds, AES, software key gen, normal oper, encrypt, 128-bit key */
            padlock_cw_e = 10 | (1<<7);
            /* 10 rounds, AES, software key gen, normal oper, decrypt, 128-bit key */
            padlock_cw_d = 10 | (1<<7) | (1<<9);
            break;
        }
        padlock_cwBuf = specialMalloc(4*4, 0);
        padlock_cwBuf[0] = encrypt ? padlock_cw_e : padlock_cw_d;
        padlock_cwBuf[3] = padlock_cwBuf[2] = padlock_cwBuf[1] = 0;
    } else
#endif
#if defined(SUPPORT_INTELAES) && (defined(X86_ASM) || defined(AMD64_ASM))
    if(intelaes_check_cpuid()) {
        workFunc = intelaes_workFunc[x];
        hardware = "Intel hardware AES";
    } else
#endif
    {
        workFunc = generic_workFunc[x];
#if defined(X86_ASM)
        hardware = "x86 assembler AES";
#else
#if defined(AMD64_ASM)
        hardware = "amd64 assembler AES";
#else
        hardware = "C-language AES";
#endif
#endif
    }
    if(verbose) {
        char *mode;
        switch(multiKeyMode) {
        case 65:
            mode = "multi-key-v3";
            break;
        case 64:
            mode = "multi-key-v2";
            break;
        default:
            mode = "single-key";
            break;
        }
        fprintf(stderr, "%s: %s, %d key bits, %s, %s mode\n", progName, hardware,
                        bits, encrypt ? "encrypting" : "decrypting", mode);
    }

    bMask = multiKeyMode ? 511 : 15;
#if defined(SUPPORT_CTRMODE)
    if (encMode == CTR_MODE) ctr_setup(numThreads, ctx -> aes_e_key, ctx -> aes_Nkey, passSeedString);
#endif
    ret = 0;
    while(1) {
        x = rd_wr_retry(0, (char *)(&bufb[0]), BUFBSIZE, 0);
        if(x < 1) break;
        while(x & bMask) bufb[x++] = 0;
        (*workFunc)(x);
        if(encMode != CTR_MODE && rd_wr_retry(1, (char *)(&bufb[0]), x, 1) != x) {
            if(complainWriteErr) fprintf(stderr, "%s: write failed\n", progName);
            ret = 1;
            break;
        }
    }
#if defined(SUPPORT_CTRMODE)
    if (encMode == CTR_MODE) ctr_finish();
#endif

    memset(ctx, 0, sizeof(aes_context));
    for(x = 0; x < 64; x++) {
        memset(multiKeyCtx[x], 0, sizeof(aes_context));
    }
    memset(&ivbuf[0], 0, IVBUFSIZE);
    memset(&bufb[0], 0, BUFBSIZE);
    memset(&partialMD5[0], 0, sizeof(partialMD5));
    exit(ret);
}
