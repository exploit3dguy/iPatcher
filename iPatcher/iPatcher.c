// made by @exploit3dguy

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../patchfinder64/patchfinder64.c"

#define GET_OFFSET(len, x) (x - (uintptr_t) buf) // Thanks to @Ralph0045 for this 

void *find;
addr_t beg_func;
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

    beg_func = bof64(buf, 0, (addr_t)GET_OFFSET(len, find));
    *(uint32_t *) (buf + beg_func) = 0xD2800000;
    *(uint32_t *) (buf + beg_func + 0x4) = 0xD65F03C0;

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


    // find funcs

    find = memmem(buf,len,"jumping into image at",strlen("jumping into image at"));
    if (!find) {
        printf("[-] Failed to find prepare_and_jump\n");
        return -1;
    }

        beg_func = xref64(buf,0,len,(addr_t)GET_OFFSET(len, find));
          

        if (iboot_version == 1940) {
        prepare_and_jump = follow_call64(buf, beg_func + 0x1c);
        tramp_init = follow_call64(buf, beg_func + 0x8);
       }

       if (iboot_version == 2261) {
        prepare_and_jump = follow_call64(buf, beg_func + 0x28);
        tramp_init = follow_call64(buf, beg_func + 0x10);
       }

 
       
  
   
    
    
    
    

    find = memmem(buf,len,"cebilefctmbrtlhptreprmmh",strlen("cebilefctmbrtlhptreprmmh"));
    if (!find) {
        printf("[-] Failed to find go cmd\n");
        return -1;
    }

    beg_func = xref64(buf,0,len,(addr_t)GET_OFFSET(len, find));

    



    if (iboot_version == 1940) {
        beg_func = beg_func - 0x44;
    }

    if (iboot_version == 2261) {
        beg_func = beg_func - 0x30;
    }

  


    // write the payload

    


    *(uint32_t *) (buf + beg_func) = make_bl((uintptr_t)buf + beg_func,(uintptr_t)tramp_init + (uintptr_t)buf); // BL tramp_init
    *(uint32_t *) (buf + beg_func + 0x4) = 0xAA0003E1; // MOV X1, X0
    *(uint32_t *) (buf + beg_func + 0x8) = 0x528000E0; // MOV W0, #7
    *(uint32_t *) (buf + beg_func + 0xC) = 0xD2C00022; // MOV X2, #0x100000000
    *(uint32_t *) (buf + beg_func + 0x10) = 0xD2800003; // MOV X3, #0
    *(uint32_t *) (buf + beg_func + 0x14) = make_bl((uintptr_t)buf + beg_func + 0x14,(uintptr_t)prepare_and_jump + (uintptr_t)buf); // BL prepare_and_jump
    
   
    

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

    beg_func = xref64(buf,0,len,(addr_t)GET_OFFSET(len, find));
    beg_func = beg_func + 0x28;
    *(uint32_t *) (buf + beg_func) = 0xD2800020;

    printf("[+] Enabled kernel debug\n");
	return 0;
}

int get_bootargs_patch(void *buf, size_t len, char *args) {
	
	if (strlen(args) > 35) {
	 printf("[-] boot-args too long\n");
         return -1;
        }
	
	printf("getting %s(%s)\n", __FUNCTION__, args);
    
    find = memmem(buf,len,"rd=md0 nand-enable-reformat=1", 28);
    if (!find) {
    	printf("[-] Failed to find boot-args string\n");
    	return -1;
    }
    
    
    char *args2 = strcat(args, "                    ");
    strcpy(find, args2);

    printf("[+] Set xnu boot-args to %s\n", args);
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

    buf = (void*)malloc(len);
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

    fp = fopen(out, "wb+");
    fwrite(buf, 1, len, fp);
    fflush(fp);
    fclose(fp);
    
    free(buf);

    printf("[*] Writing out patched file to %s\n", out);
    printf("%s: Quitting...\n", __FUNCTION__);
	return 0;
}
