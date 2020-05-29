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
typedef u64 size_t;
typedef i64 offset_t;
#else
typedef unsigned long long int u64;
typedef unsigned long long i64;
typedef u64 size_t;
typedef i64 offset_t;
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
FORCE_INLINE u64 syscall1(u64 n, u64 a0)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE u64 syscall2(u64 n, u64 a0, u64 a1)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;
    register u64 rsi __asm__("rsi") = a1;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE u64 syscall3(u64 n, u64 a0, u64 a1, u64 a2)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;
    register u64 rsi __asm__("rsi") = a1;
    register u64 rdx __asm__("rdx") = a2;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE u64 syscall4(u64 n, u64 a0, u64 a1, u64 a2, u64 a3)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;
    register u64 rsi __asm__("rsi") = a1;
    register u64 rdx __asm__("rdx") = a2;
    register u64 r10 __asm__("r10") = a3;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE u64 syscall5(u64 n, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;
    register u64 rsi __asm__("rsi") = a1;
    register u64 rdx __asm__("rdx") = a2;
    register u64 r10 __asm__("r10") = a3;
    register u64 r8 __asm__("r8") = a4;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}


FORCE_INLINE u64 syscall6(u64 n, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5)
{
    register u64 rax __asm__("rax") = n;
    register u64 rdi __asm__("rdi") = a0;
    register u64 rsi __asm__("rsi") = a1;
    register u64 rdx __asm__("rdx") = a2;
    register u64 r10 __asm__("r10") = a3;
    register u64 r8 __asm__("r8") = a4;
    register u64 r9 __asm__("r9") = a5;

    __asm__ __volatile__ (
                           "syscall"
                           : "+r"(rax)
                           : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
                           : "rcx", "r11", "memory"
                         );

    return rax;
}
#define PAGE_SIZE 4096
#else
    // TODO: Implement for other architectures
    #error "Unsupported system."
#endif

#define SYSCALL_NUMBER_WRITE 1
#define SYSCALL_NUMBER_MMAP 9
#define SYSCALL_NUMBER_MUNMAP 11
#define SYSCALL_NUMBER_SOCKET 41
#define SYSCALL_NUMBER_CONNECT 42
#define SYSCALL_NUMBER_EXIT 60


FORCE_INLINE int socket(int domain, int type, int protocol)
{
    return syscall3(SYSCALL_NUMBER_SOCKET, domain, type, protocol);
}


typedef u16 sa_family_t;
typedef struct sockaddr_un
{
    sa_family_t sun_family;
    char sun_path[108]; 
} sockaddr_un;


FORCE_INLINE int connect(int fd, sockaddr_un* addr, size_t addrlen)
{
    syscall3(SYSCALL_NUMBER_CONNECT, (size_t)fd, (size_t)addr, addrlen);
}


FORCE_INLINE size_t write(int fd, const void *buf, size_t size)
{
    return syscall3(SYSCALL_NUMBER_WRITE, fd, (size_t)buf, size);
}


FORCE_INLINE void exit(int status)
{
    syscall1(SYSCALL_NUMBER_EXIT, status);
}


void* mmap(void *addr, size_t length, int prot, int flags, int fd, offset_t offset)
{
    (void*) syscall6(SYSCALL_NUMBER_MMAP, (i64) addr, (i64) length, prot, flags, fd, offset);
}


int munmap(void *addr, size_t length)
{
    return syscall2(SYSCALL_NUMBER_MUNMAP, (i64) addr, (i64) length);
}


FORCE_CALL int main_function(int argc, char** argv, char** envp);


int _start()
{
#if defined __x86_64__ && !defined __ILP32__
    i64* stack_pointer;
    register i64 rsp __asm__("rsp");
    __asm__ __volatile__ ("mov %1, %0" : "=memory"(stack_pointer) : "r"(rsp));
#else
    #error "Unsupported system!"
#endif
    int argc = *stack_pointer;
    char** argv = (char**)(stack_pointer + 1);
    char** envp = argv + argc + 1; 
                         
    exit(main_function(argc, argv, envp));
}

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_ANONYMOUS 0x20


void* allocate_pages(size_t page_count)
{
    return mmap(0, page_count * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
}

void deallocate_pages(void* pages, size_t page_count)
{
    munmap(pages, page_count * PAGE_SIZE);
}

typedef struct
{
    u8* memory;
    u32 pages;
    u32 current_pointer;
} stack_allocator_t;


void init_stack_allocator(stack_allocator_t* alloc, u32 pages)
{
    alloc->pages = pages;
    alloc->current_pointer = 0;
    alloc->memory = allocate_pages(pages);
}


void* sa_allocate(stack_allocator_t* alloc, u32 size)
{
    void* memory = alloc->memory + alloc->current_pointer;
    alloc->current_pointer += size;
    return memory;
}


void sa_deallocate(stack_allocator_t* alloc, u32 size)
{
    alloc->current_pointer -= size;
}


struct global_state_t
{
    stack_allocator_t stack_allocator;
    int x11_socket;
} global_state;


void copystr(char* dst, const char* src)
{
    u32 i;
    for(i = 0; src[i]; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = 0;
}


#define AF_UNIX 1
#define SOCK_STREAM 1

int connect_to_x11()
{
    // TODO: Take the DISPLAY env variable in mind, dont just pick the first display
    static const char* x11_socket_path = "/tmp/.X-unix/X0";

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    copystr(addr.sun_path, x11_socket_path);
    global_state.x11_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    
    return connect(global_state.x11_socket, &addr, sizeof(addr));
}

void init_global_state()
{
    static const u32 stack_allocator_initial_pages = 2;
    init_stack_allocator(&global_state.stack_allocator, stack_allocator_initial_pages);
}



FORCE_CALL int main_function(int argc, char** argv, char** envp)
{
    if (connect_to_x11() < -1)
    {
        return 1;
    }
    
    write(1, envp[0], 4);

    return 0;
}
