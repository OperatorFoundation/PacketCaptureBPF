#include <stdint.h>
#include <net/if_utun.h>
#include <net/if_dl.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <errno.h>
#include <strings.h>
#include <stdio.h>
#include <sys/sockio.h>
#include <net/bpf.h>

int main(void)
{
    // You can use a spreadsheet program and the below formula to easily generate the below print statements.
    // ="printf(""let "&A2&": UInt = %lu\n"", "&A2&");"
    // Where A2 is the macro name
    
    printf("Hello Operator\n");
    printf("let BIOCGBLEN: UInt = %lu\n", BIOCGBLEN);
    printf("let BIOCSBLEN: UInt = %lu\n", BIOCSBLEN);
    printf("let BIOCGDLT: UInt = %lu\n", BIOCGDLT);
    printf("let BIOCGDLTLIST: UInt = %lu\n", BIOCGDLTLIST);
    printf("let BIOCSDLT: UInt = %lu\n", BIOCSDLT);
    printf("let BIOCPROMISC: UInt = %lu\n", BIOCPROMISC);
    printf("let BIOCFLUSH: UInt = %lu\n", BIOCFLUSH);
    printf("let BIOCSETIF: UInt = %lu\n", BIOCSETIF);
    printf("let BIOCSRTIMEOUT: UInt = %lu\n", BIOCSRTIMEOUT);
    printf("let BIOCGRTIMEOUT: UInt = %lu\n", BIOCGRTIMEOUT);
    printf("let BIOCGSTATS: UInt = %lu\n", BIOCGSTATS);
    printf("let BIOCIMMEDIATE: UInt = %lu\n", BIOCIMMEDIATE);
    printf("let BIOCSETF: UInt = %lu\n", BIOCSETF);
    printf("let BIOCSETFNR: UInt = %lu\n", BIOCSETFNR);
    printf("let BIOCVERSION: UInt = %lu\n", BIOCVERSION);
    printf("let BIOCSHDRCMPLT: UInt = %lu\n", BIOCSHDRCMPLT);
    printf("let BIOCSSEESENT: UInt = %lu\n", BIOCSSEESENT);
    printf("let BIOCGSEESENT: UInt = %lu\n", BIOCGSEESENT);
    printf("let BIOCGRSIG: UInt = %lu\n", BIOCGRSIG);
    printf("let BIOCSRSIG: UInt = %lu\n", BIOCSRSIG);
    printf("let SIGIO: UInt = %lu\n", SIGIO);
    printf("let FIONREAD: UInt = %lu\n", FIONREAD);
    printf("let SIOCGIFADDR: UInt = %lu\n", SIOCGIFADDR);
    return 0;
}
