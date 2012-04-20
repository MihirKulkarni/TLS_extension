#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

extern char* get_ip()
{

int fd;
struct if_nameindex *curif, *ifs;
struct ifreq req;
char ip[16];
if((fd = socket(PF_INET, SOCK_DGRAM, 0)) != -1) {
ifs = if_nameindex();
if(ifs) {
for(curif = ifs; curif && curif->if_name; curif++) {
strncpy(req.ifr_name, curif->if_name, IFNAMSIZ);
req.ifr_name[IFNAMSIZ] = 0;
if (ioctl(fd, SIOCGIFADDR, &req) >= 0 && !strcmp(curif->if_name,"eth2")){
sprintf(ip,"%s",inet_ntoa(((struct sockaddr_in*) &req.ifr_addr)->sin_addr));
}
}
if_freenameindex(ifs);
if(close(fd)!=0)
perror("close");
} else
perror("if_nameindex");
} else
perror("socket");
return ip;
}

extern int get_ip_int(char *p)
{
int ip=0;
int i=0;
char x[3]={};
int cur=0;
while(i!=strlen(p)+1){
if(p[i]!='.' && p[i]!='\0'){
	x[cur++]=p[i];
}
else{
x[cur++]='\0';
cur=0;
ip=ip|atoi(x);
if(p[i]!='\0')
ip=ip<<4;
}
i++;
}
return ip;
}

extern void get_ip_str(int ip,char* ip_str1){
int i=0;
char ip_str[20]="";
char tempc[4][4];
while(i<4){
	int temp=(ip>>4);
	temp=temp<<4;
	if(i==0)
		sprintf(tempc[i],"%d",temp^ip);
	else
		sprintf(tempc[i],"%d.",temp^ip);
	ip=ip>>4;
	i++;
}
for(i=3;i>=0;i--)
strcat(ip_str,tempc[i]);
strcpy(ip_str1,ip_str);
return ip_str;
}

