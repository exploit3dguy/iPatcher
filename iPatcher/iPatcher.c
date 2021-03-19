// made by @exploit3dguy

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../patchfinder64/patchfinder64.c"

#define GET_OFFSET(len, x) (x - (uintptr_t) buf) // Thanks to @Ralph0045 for this 

void *str_stuff;
addr_t beg_func;
char *args = NULL;
void *lolz;

int iBoot_check(void* buf, size_t len) {
     lolz = buf + 0x280;
     str_stuff =  buf + 0x285;

     void *coco = buf + 0x160;
     size_t size = 0x20;

     memcpy(coco, lolz, size);

     *(uint32_t *) (str_stuff) = 0x00000000000000000000000000000000;
     
     char *str = "iBoot";

     if(strcmp(lolz, str) == 0) {
     	 memcpy(lolz, coco, size);
     	*(uint32_t *) (coco) = 0x00000000000000000000000000000000;
     	*(uint32_t *) (coco + 4) = 0x00000000000000000000000000000000;
        *(uint32_t *) (coco + 8) = 0x00000000000000000000000000000000;
        *(uint32_t *) (coco + 12) = 0x00000000000000000000000000000000;
        *(uint32_t *) (coco + 16) = 0x00000000000000000000000000000000;
        *(uint32_t *) (coco + 20) = 0x00000000000000000000000000000000;
     	printf("inputted: %s\n", lolz);
     	return 0;
     }
     else {
     	printf("Invalid image. Make sure image is extracted, iPatcher doesn't support IM4P/IMG4\n");
     	exit(1);
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
	int iboot_version = 0;
	iBoot_check(buf,len);

	printf("getting %s()\n", __FUNCTION__);

    iboot_version = get_iboot_version(buf, len);

    // iOS 9.x + and later
    if (iboot_version >= 2817) {
        str_stuff = memmem(buf,len,"\x08\x69\x88\x72", 0x4);
        if (!str_stuff) {
            printf("[-] Failed to find MOVK W8, #0x4348\n");
            exit(1);
        }
    }

    // iOS 7.x
    else if (iboot_version == 1940){
        str_stuff = memmem(buf,len,"\x0B\x69\x88\x72", 0x4);
        if (!str_stuff) {
            printf("[-] Failed to find MOVK W11, #0x4348\n");
            exit(1);
        }
    }
	
    // anything else (iOS 8.x)
    else {
        str_stuff = memmem(buf,len,"\x0A\x69\x88\x72", 0x4);
        if (!str_stuff) {
            printf("[-] Failed to find MOVK W10, #0x4348\n");
            exit(1);
        }
    }

    beg_func = (addr_t)GET_OFFSET(len, str_stuff);
    beg_func = bof64(buf,0,beg_func);

    *(uint32_t *) (buf + beg_func) = 0xD2800000;
    *(uint32_t *) (buf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched RSA signature checks\n");
    printf("%s: quitting\n", __FUNCTION__);
    
	return 0;
}

int get_debugenabled_patch(void* buf, size_t len) {
	printf("getting %s()\n", __FUNCTION__);

	str_stuff = memmem(buf,len,"debug-enabled", 13);
    if (!str_stuff) {
        printf("[-] Failed to find debug-enabled string\n");
        exit(1);
    }

    beg_func = xref64(buf,0,len,(addr_t)GET_OFFSET(len, str_stuff));
    beg_func = beg_func + 0x28;

    *(uint32_t *) (buf + beg_func) = 0xD2800020;

    printf("[+] Enabled kernel debug\n");
    printf("%s: quitting\n", __FUNCTION__);

	return 0;
}

int get_bootargs_patch(void *buf, size_t len, char *args) {
	printf("getting %s(%s)\n", __FUNCTION__, args);
    
    str_stuff = memmem(buf,len,"rd=md0 nand-enable-reformat=1", 28);
    if (!str_stuff) {
    	printf("[-] Failed to find boot-args string\n");
    	exit(1);
    }
    
    char *args2 = strcat(args, "                    ");
    strcpy(str_stuff, args2);

    printf("[+] Set xnu boot-args to %s\n", args);
    printf("%s: quitting\n", __FUNCTION__);

	return 0;
}

int main(int argc, char* argv[]) {

    if(argc < 3) {
   	    printf("iPatcher - tool to patch lower versions of iBoot64 by @exploit3dguy\n");
        printf("Usage: ibec.raw ibec.pwn [-b]\n");
        printf("       -b set custom boot-args\n");
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

    get_rsa_patch(buf,len);
    get_debugenabled_patch(buf,len);
    
    for(int i = 1; i < argc; i++) {
        if(strncmp(argv[i],"-b",2) == 0) {
            args = argv[i+1];
        }
    }
    
    if (args) {
        get_bootargs_patch(buf,len,args);
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

