#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void main() {
	execl("/home/jiangxd/src/flashapp/ziproxy/ziproxy-flashapp-src/ziproxy-3.2.0-flashapp/src/ziproxy_killtimeout","-d","3600","7200",NULL);
}
