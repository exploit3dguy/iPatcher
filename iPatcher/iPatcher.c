// made by @exploit3dguy

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../patchfinder64/patchfinder64.c"

#define GET_OFFSET(buf1, buf2) (buf1 - buf2)
#define bswap32(x) __builtin_bswap32(x)

void *find;
addr_t ref;
char *args = NULL;
bool ibss;

int iboot_check(void* buf, size_t len) {
    void *iboot_ver_addr = buf + 0x280;
    char iboot_ver[0x20];

    memcpy(iboot_ver, iboot_ver_addr, sizeof(iboot_ver));
    if(memcmp(iboot_ver, "iBoot", 0x5) == 0) {
        printf("inputted: %s\n", iboot_ver);
    } else {
        printf("Invalid image. Make sure image is extracted, iPatcher doesn't support IM4P/IMG4\n");
        exit(1);
    }

    void *build_type_addr = buf + 0x200;
    char build_type[0x4];
    memcpy(build_type, build_type_addr, sizeof(build_type));
    if (strcmp(build_type, "iBSS") == 0 || strcmp(build_type, "LLB ") == 0) {
        ibss = true;
    }

	return 0;
}

int get_iboot_version(void* buf, size_t len) {
	char version[5];
	void *version_string = memmem(buf, len, "iBoot-", strlen("iBoot-"));
	strncpy(version, version_string + 6, 4);
	return atoi(version);
}

 int get_rsa_patch(void* buf, size_t len) {
	int iboot_version = get_iboot_version(buf, len);
	printf("getting %s()\n", __FUNCTION__);

    // iOS 9.x and later
    if (iboot_version == 2817) {
        find = memmem(buf,len,"\x08\x69\x88\x72", 0x4);
        if (!find) {
            printf("[-] Failed to find MOVK W8, #0x4348\n");
            exit(1);
        }
    }

    // iOS 8.x
    else if (iboot_version == 2261){
        find = memmem(buf,len,"\x0A\x69\x88\x72", 0x4);
        if (!find) {
            printf("[-] Failed to find MOVK W10, #0x4348\n");
            exit(1);
        }
    }

    // iOS 7.x
    else if (iboot_version == 1940){
        find = memmem(buf,len,"\x0B\x69\x88\x72", 0x4);
        if (!find) {
            printf("[-] Failed to find MOVK W11, #0x4348\n");
            exit(1);
        }
    }

    //any other version
    else {
        printf("Version not supported\n");
        exit(1);
    }

    ref = bof64(buf, 0, (addr_t)GET_OFFSET(find, buf));
    if (!ref) {
        printf("failed to find bof\n");
    }
    *(uint32_t *) (buf + ref) = bswap32(0x000080D2); // mov x0, #0
    *(uint32_t *) (buf + ref + 0x4) = bswap32(0xC0035FD6); // ret

    printf("[+] Patched RSA signature checks\n");
    return 0;
}   

static uint32_t make_bl(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x94000000 + (to - from) / 4;
}

int get_securerom_patch(void *buf, size_t len) {

    int iboot_version = get_iboot_version(buf, len);

    if (iboot_version == 2817) {
        printf("iOS 9 iBoots aren't supported by SecureROM patch\n");
        return -1;
       }
    printf("getting %s()\n", __FUNCTION__);

    addr_t prepare_and_jump;
    addr_t tramp_init;
    /*
    BL tramp_init
    MOV X1, X0
    MOV W0, #7 @ BOOT_TARGET = BOOT_SECUREROM
    MOV X2, #0x100000000
    MOV X3, #0
    BL prepare_and_jump
    */

    find = memmem(buf,len,"jumping into image at",strlen("jumping into image at"));
    if (!find) {
        printf("[-] Failed to find prepare_and_jump\n");
        return -1;
    }
        ref = xref64(buf,0,len,(addr_t)GET_OFFSET(find, buf));
        if (!ref) {
         printf("failed to find xref\n");
        }
        if (iboot_version == 1940) {
        prepare_and_jump = follow_call64(buf, ref + 0x1c);
        tramp_init = follow_call64(buf, ref + 0x8);
       }

       if (iboot_version == 2261) {
        prepare_and_jump = follow_call64(buf, ref + 0x28);
        tramp_init = follow_call64(buf, ref + 0x10);
       }
    find = memmem(buf,len,"cebilefctmbrtlhptreprmmh",strlen("cebilefctmbrtlhptreprmmh"));
    if (!find) {
        printf("[-] Failed to find go cmd\n");
        return -1;
    }

    ref = xref64(buf,0,len,(addr_t)GET_OFFSET(find, buf));
    if (!ref) {
        printf("failed to find xref\n");
    }

    if (iboot_version == 1940) {
        ref = ref - 0x44;
    }

    if (iboot_version == 2261) {
        ref = ref - 0x30;
    }

    *(uint32_t *) (buf + ref) = make_bl((uintptr_t)buf + ref,(uintptr_t)tramp_init + (uintptr_t)buf); // BL tramp_init
    *(uint32_t *) (buf + ref + 0x4) = bswap32(0xE10300AA); // MOV X1, X0
    *(uint32_t *) (buf + ref + 0x8) = bswap32(0xE0008052); // MOV W0, #7
    *(uint32_t *) (buf + ref + 0xC) = bswap32(0x2200C0D2); // MOV X2, #0x100000000
    *(uint32_t *) (buf + ref + 0x10) = bswap32(0x030080D2); // MOV X3, #0
    *(uint32_t *) (buf + ref + 0x14) = make_bl((uintptr_t)buf + ref + 0x14,(uintptr_t)prepare_and_jump + (uintptr_t)buf); // BL prepare_and_jump
    printf("[+] Applied patch to boot SecureROM\n");

    return 0;
}

int get_debugenabled_patch(void* buf, size_t len) {
	printf("getting %s()\n", __FUNCTION__);

	find = memmem(buf,len,"debug-enabled", 13);
    if (!find) {
        printf("[-] Failed to find debug-enabled string\n");
        return -1;
    }

    ref = xref64(buf,0,len,(addr_t)GET_OFFSET(find, buf));
    if (!ref) {
        printf("failed to find xref\n");
    }
    *(uint32_t *) (buf + ref + 0x28) = bswap32(0x200080D2); // mov x0, #1

    printf("[+] Enabled kernel debug\n");
	return 0;
}

uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); } // tihmstar stuff
uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));} // tihmstar stuff

// https://github.com/dayt0n/kairos/blob/add747e062a36893de012d507d4586266954a09c/instructions.c#L36
uint32_t new_insn_adr(addr_t offset,uint8_t rd, int64_t addr) {
    uint32_t opcode = 0;
    opcode |= SET_BITS(0x10,24); // set adr
    opcode |= (rd % (1<<5)); // set rd
    // we have a pc rel address
    // do difference validations
    int64_t diff = addr - offset; // addr - offset to get pc rel
    if(diff > 0) {
        if(diff > (1LL<<20)) // diff is too long, won't be able to fit
            return -1;
        else if(-diff > (1LL<<20)) // again, diff is too long but it is a signed int
            return -1;
    }
    opcode |= SET_BITS(BIT_RANGE(diff,0,1),29); // set pos 30-29 to immlo
    opcode |= SET_BITS(BIT_RANGE(diff,2,20),5); // set pos 23-5  to immhi
    return opcode;
}

int get_bootargs_patch(void *buf, size_t len, char *args) {
    int iboot_version = get_iboot_version(buf, len);
	if (strlen(args) > 200) {
	 printf("[-] boot-args too long\n");
         return -1;
        }
	
	printf("getting %s(%s)\n", __FUNCTION__, args);
    
    find = memmem(buf,len,"rd=md0 nand-enable-reformat=1", 28);
    if (!find) {
    	printf("[-] Failed to find boot-args string\n");
    	return -1;
    }
    
    ref = xref64(buf,0,len,(addr_t)GET_OFFSET(find, buf));
    if (!ref) {
        printf("failed to find xref\n");
    }
    
    void *findcertarea = memmem(buf,len,"Reliance on this certificate by",strlen("Reliance on this certificate by"));
    if (!findcertarea) {
        printf("[-] Failed to cert area for new boot-args\n");
        return -1;
    }
    
    *(uint32_t *) (buf + ref) = new_insn_adr(ref,8,GET_OFFSET(findcertarea,buf));
    if (iboot_version == 1940) {
        *(uint32_t *) (buf + ref - 0x4) = bswap32(0x1F2003D5);
    }
    
    args = strcat(args,"\n");
    strcpy(findcertarea, args);

    printf("[+] Set xnu boot-args to %s", args);
	return 0;
}

int main(int argc, char* argv[]) {
    if(argc < 3) {
   	printf("iPatcher - tool to patch lower versions of iBoot64 by @exploit3dguy\n");
        printf("Usage: ibec.raw ibec.pwn [-b]\n");
        printf("       -b set custom boot-args\n");
	printf("       -s SecureROM boot patch\n");
        return 0;
    }

    printf("%s: Starting...\n", __FUNCTION__);

    char *in = argv[1];
    char *out = argv[2];

    void* buf;
    size_t len;

    FILE* fp = fopen(in, "rb");
    if (!fp) {
        printf("[-] Failed to open iBoot image\n");
        return -1;
    }
    

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    buf = malloc(len);
    if(!buf) {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
    }

    fread(buf, 1, len, fp);
    fclose(fp);

    iboot_check(buf,len);	
    get_rsa_patch(buf,len);

    if (!ibss) {
        get_debugenabled_patch(buf,len);

        for(int i = 1; i < argc; i++) {
	    if(strncmp(argv[i],"-s",2) == 0) {
              get_securerom_patch(buf,len);
           }
            if(strncmp(argv[i],"-b",2) == 0) {
                get_bootargs_patch(buf,len,argv[i+1]);
            }
        }
    }

    printf("[*] Writing out patched file to %s\n", out);
    fp = fopen(out, "wb+");
    fwrite(buf, 1, len, fp);
    fflush(fp);
    fclose(fp);
    free(buf);
    printf("%s: Quitting...\n", __FUNCTION__);
    return 0;
}
