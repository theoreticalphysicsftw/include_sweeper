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

#define SYSCALL_NUMBER_READ 0
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


int connect(int fd, sockaddr_un* addr, size_t addrlen)
{
    return syscall3(SYSCALL_NUMBER_CONNECT, (size_t)fd, (size_t)addr, addrlen);
}


size_t write(int fd, const void *buf, size_t size)
{
    return syscall3(SYSCALL_NUMBER_WRITE, fd, (size_t)buf, size);
}


size_t read(int fd, const void *buf, size_t size)
{
    return syscall3(SYSCALL_NUMBER_READ, fd, (size_t)buf, size);
}
  

FORCE_INLINE void exit(int status)
{
    syscall1(SYSCALL_NUMBER_EXIT, status);
}


void* mmap(void *addr, size_t length, int prot, int flags, int fd, offset_t offset)
{
    return (void*) syscall6(SYSCALL_NUMBER_MMAP, (size_t) addr, length, prot, flags, fd, offset);
}


int munmap(void *addr, size_t length)
{
    return syscall2(SYSCALL_NUMBER_MUNMAP, (size_t) addr, (size_t) length);
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
#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x20


void* allocate_pages(size_t page_count)
{
    return mmap(0, page_count * PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
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
stack_allocator_t g_stack_allocator;


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


void* sa_alloc(u32 size)
{
    return sa_allocate(&g_stack_allocator, size);
}


void sa_dealloc(u32 size)
{
    sa_deallocate(&g_stack_allocator, size);
}


void copystr(char* dst, const char* src)
{
    u32 i;
    for(i = 0; src[i]; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = 0;
}


void fill_memory(void* memory, u32 size, u8 value)
{
    for(u32 i = 0; i < size; ++i)
    {
        ((u8*)memory)[i] = value;
    }
}


#define LOGGER_BUFFER_SIZE PAGE_SIZE
typedef struct
{
    char* buffer;
    u16 current_size;
} logger_t;
logger_t g_logger;


void init_logger()
{
    g_logger.buffer = (char*) allocate_pages(1);
    g_logger.current_size = 0;
}

#define STDOUT_FD 1
void flush_logger()
{
    write(STDOUT_FD, g_logger.buffer, LOGGER_BUFFER_SIZE);
    g_logger.current_size = 0;
}


void log_string(const char* str)
{
    for(u32 i = 0; str[i]; ++i)
    {
        if (g_logger.current_size == LOGGER_BUFFER_SIZE)
        {
            flush_logger(g_logger);
        }
        g_logger.buffer[g_logger.current_size++] = str[i];
        
    }
}


void destroy_logger()
{
    flush_logger();
    deallocate_pages(g_logger.buffer, 1);
}


#define AF_UNIX 1
#define SOCK_STREAM 1

// Generic responses can be either Errors, Events or Replies. This is a minimal
// struct that we can use to peak on what exactly is going on.
typedef struct
{
    u8 code;
    u8 detail;
    u16 seq_number;
    u32 length;
    u32 _pad0[6];
} x11_generic_response_header_t;


struct
{
    int socket_fd;
} g_x11_state;


int connect_to_x11()
{
    // TODO: Take the DISPLAY env variable in mind, dont just pick the first display
    static const char* x11_socket_path = "/tmp/.X-unix/X0";

    sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    copystr(addr.sun_path, x11_socket_path);
    g_x11_state.socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    
    int status = connect(g_x11_state.socket_fd, &addr, sizeof(addr));
    if (status < 0)
    {
        return status;
    }

    typedef struct
    {
        u8 byte_order;
        u8 _pad0;
        u16 protocol_major_version;
        u16 protocol_minor_version;
        u16 auth_proto_name_len;
        u16 auth_proto_data_len;
        u16 _pad1;
    } handshake_request_t;

    handshake_request_t handshake_request;
    fill_memory(&handshake_request, sizeof(handshake_request_t), 0);
    handshake_request.byte_order = 'l';
    handshake_request.protocol_major_version = 11;
    handshake_request.protocol_minor_version = 0;

    write(g_x11_state.socket_fd, &handshake_request, sizeof(handshake_request_t));

    struct
    {
        u8 success;
        u8 _pad0;
        u16 major_version;
        u16 minor_version;
        u16 additional_data_length;
    } handshake_response_header;
    read(g_x11_state.socket_fd, &handshake_response_header, sizeof(handshake_response_header));

    if (handshake_response_header.success != 1)
    {
        log_string("Failed to handshake with X11!\n");
        return -1;
    }
}

void init_global_state()
{
    static const u32 stack_allocator_initial_pages = 2;
    init_stack_allocator(&g_stack_allocator, stack_allocator_initial_pages);
    init_logger(&g_logger);
}

void destroy_global_state()
{
    destroy_logger(&g_logger);
}


FORCE_CALL int main_function(int argc, char** argv, char** envp)
{
    init_global_state();

    if (connect_to_x11() < 0)
    {
        return 1;
    }

    while(1)
    {
        log_string("Log this!\n");
    }


    destroy_global_state();
    return 0;
}
