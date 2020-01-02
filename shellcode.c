#include <sys/mman.h>
#include <stdint.h>
#include <stdlib.h>

char shellcode []= "\x48\xb8\x63\x75\x6c\x61\x74\x6f"
                   "\x72\x00\x50\x48\xb8\x6e\x6f\x6d"
                   "\x65\x2d\x63\x61\x6c\x50\x48\xb8"
                   "\x61\x70\x2f\x62\x69\x6e\x2f\x67"
                   "\x50\x48\xb8\x2f\x2f\x2f\x2f\x2f"
                   "\x2f\x73\x6e\x50\x48\x89\xe7\xb8"
                   "\x3a\x30\x00\x00\x50\x48\xb8\x44"
                   "\x49\x53\x50\x4c\x41\x59\x3d\x50"
                   "\x48\x89\xe1\xb8\x00\x00\x00\x00"
                   "\x50\x51\x48\x89\xe2\x50\x57\x48"
                   "\x89\xe6\xb8\x3b\x00\x00\x00\x0f"
                   "\x05";"
                  
                   /*
                   0x48b863756c61746f
                   0x72005048b86e6f6d
                   0x652d63616c5048b8
                   0x61702f62696e2f67
                   0x5048b82f2f2f2f2f
                   0x2f736e504889e7b8
                   0x3a3000005048b844
                   0x4953504c41593d50
                   0x4889e1b800000000
                   0x50514889e2505748
                   0x89e6b83b0000000f
                   0x05
                  */

int main(){
  mprotect((void *)((long long)shellcode & 0xffffffffffffff00), 0x10000, 7|PROT_EXEC);
  void (*fp) (void);
  fp = (void *)shellcode;
  fp();
}

