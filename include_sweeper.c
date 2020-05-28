// Copyright 2020 Mihail Mladenov
//
// IncludeSweeper is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// IncludeSweeper is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with IncludeSweeper.  If not, see <http://www.gnu.org/licenses/>.


// Detect word size of the CPU architecture
#if defined __x86_64__ && !defined __ILP32__
    #define WORDSIZE 64
#else
    #define WORDSIZE 32
#endif

#if WORDSIZE == 64
typedef unsigned long int u64;
typedef long int i64;
#else
typedef unsigned long long int u64;
typedef unsigned long long i64;
#endif

typedef unsigned int u32;
typedef int i32;
typedef unsigned short u16;
typedef short i16;
typedef unsigned char u8;
typedef char i8;

#define FORCE_INLINE __attribute__((always_inline)) inline
#define FORCE_CALL __attribute__((noinline))

// Implement mechanism for making syscalls
#if defined __x86_64__ && !defined __ILP32__
FORCE_INLINE i64 syscall1(i64 n, i64 a0)
{
    register i64 rax __asm__("rax") = n;
    register i64 rdi __asm__("rdi") = a0;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE i64 syscall3(i64 n, i64 a0, i64 a1, i64 a2)
{
    register i64 rax __asm__("rax") = n;
    register i64 rdi __asm__("rdi") = a0;
    register i64 rsi __asm__("rsi") = a1;
    register i64 rdx __asm__("rdx") = a2;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE i64 syscall4(i64 n, i64 a0, i64 a1, i64 a2, i64 a3)
{
    register i64 rax __asm__("rax") = n;
    register i64 rdi __asm__("rdi") = a0;
    register i64 rsi __asm__("rsi") = a1;
    register i64 rdx __asm__("rdx") = a2;
    register i64 r10 __asm__("r10") = a3;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}
#else
    // TODO: Implement for other architectures
    #error "Unsupported system."
#endif


#define SYSCALL_NUMBER_SOCKET 41
#define SYSCALL_NUMBER_CONNECT 42
#define SYSCALL_NUMBER_EXIT 60


FORCE_INLINE int socket(int domain, int type, int protocol)
{
    return syscall3(SYSCALL_NUMBER_SOCKET, domain, type, protocol);
}


typedef u16 sa_family_t;
typedef struct sockaddr_un {
    sa_family_t sun_family;
    char sun_path[108]; 
} sockaddr_un;


FORCE_INLINE int connect(int fd, sockaddr_un* addr, i64 addrlen)
{
    syscall3(SYSCALL_NUMBER_CONNECT, (i64)fd, (i64)addr, addrlen);
}


FORCE_INLINE i64 write(i32 fd, const void *buf, u64 size)
{
    return syscall3(1, fd, (i64)buf, size);
}


FORCE_INLINE void exit(int status)
{
    syscall1(SYSCALL_NUMBER_EXIT, status);
}


FORCE_CALL int main_function(int argc, char** argv, char** envp);


int _start()
{
    i64* stack_pointer;
    register i64 rsp __asm__("rsp");
    __asm__ __volatile__ ("mov %1, %0" : "=memory"(stack_pointer) : "r"(rsp));
    int argc = *stack_pointer;
    char** argv = stack_pointer + 1;
    char** envp = argv + argc + 1; 
                         
    exit(main_function(argc, argc, envp));
}


#define AF_UNIX 1
#define SOCK_STREAM 1

void copystr(char* dst, const char* src)
{
    u32 i;
    for(i = 0; src[i]; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = 0;
}


struct global_state_t
{
    int x_socket;
} global_state;


int connect_to_x()
{
    // TODO: Take the DISPLAY env variable in mind, dont just pick the first display
    static const char* x_socket_path = "/tmp/.X-unix/X0";

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    copystr(addr.sun_path, x_socket_path);
    global_state.x_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    
    return connect(global_state.x_socket, &addr, sizeof(addr));
}


FORCE_CALL int main_function(int argc, char** argv, char** envp)
{
    if (connect_to_x() < -1)
    {
        return 1;
    }
    
    write(1, envp[0], 4);

    return 0;
}
