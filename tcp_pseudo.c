/************************tcp_pseudo.c********************/
/** Author :cbchen. */
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#define INTERFACE "eth0"
#define IP""
/*Prototype area*/
int Open_Packet_Socket();
int Open_Raw_Socket();
int Set_Promisc(char *interface, int sock);
void send_tcp_ack(int sockfd,struct sockaddr_in *addr);
unsigned short check_sum(unsigned short *addr,int len);
struct ip *iprecv;
struct tcphdr *tcprecv;
struct sockaddr_in addr;

int main() 
{
int sockfd,sendfd,bytes_recieved;

char buffer[1518];
u_char *buf2;
charsaddr[20],daddr[20];

sockfd=Open_Packet_Socket();
sendfd=Open_Raw_Socket();
//printf("sockfd:%d/tsendfd:%d/n",sockfd,sendfd);

int on=1;
/******** 设置IP数据包格式,告诉系统内核模块IP数据包由我们自己来填写 ***/
setsockopt(sendfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
Set_Promisc(INTERFACE, sockfd);
int count=1;

while(1)
{

 bytes_recieved = recvfrom(sockfd, buffer, 1518, 0, NULL, NULL);

 buf2=buffer;
 buf2+=14;
 iprecv=(struct ip *)buf2;
 //iprecv+=sizeof(struct ethhdr*);
/*See if this is a TCP packet*/
 if(iprecv->ip_v == 4&iprecv->ip_p == 6) {
 printf("---------------------------Number %d packet-----------------------------------------------/n",count);
 count++;
 printf("/nBytes received ::: %5d/n",bytes_recieved);
printf("ip version:%u/n",iprecv->ip_v);

 printf("IP包头解码:/n");
 printf("Source ip:%s/t",inet_ntoa(iprecv->ip_src));
 printf("Dest ip:%s/t",inet_ntoa(iprecv->ip_dst));
 printf("proto:%u/n",iprecv->ip_p);
 buf2+=iprecv->ip_hl<<2;
 printf("TCP包头解码:/n");
tcprecv = (struct tcphdr*)buf2;
 //tcprecv = (struct tcphdr *)(buffer + (iprecv->ip_hl<<2));
 printf("Source port :::%d/n",ntohs(tcprecv->source));
 printf("Dest port :::%d/n",ntohs(tcprecv->dest));
 printf("seq num:%u/n",ntohl(tcprecv->seq));
 printf("ack num:%u/n",ntohl(tcprecv->ack_seq));
 printf("urg:%x/tack:%x/tpsh:%x/trst:%x/tsyn:%x/tfin:%x/n",tcprecv->urg,tcprecv->ack,tcprecv->psh,tcprecv->rst,tcprecv->syn,tcprecv->fin);
 bzero(&addr,sizeof(struct sockaddr_in));
addr.sin_family=AF_INET;
                        //addr2.sin_port=htons(thdr->source);
addr.sin_port=tcprecv->source;
//addr2.sin_addr=iphdr->ip_src;
        addr.sin_addr=iprecv->ip_src;

/********* 发送阻隔包了!!!! ****/
if(tcprecv->syn==1&tcprecv->urg!=1&tcprecv->ack!=1&tcprecv->psh!=1&tcprecv->rst!=1&tcprecv->fin!=1)
{
//send_tcp_ack(sendfd,&addr);
//printf("It's a syn pocket!/n");
}
}
}
 close(sockfd);
 close(sendfd);
}
//end main

/******* 发送阻隔包的实现 *********/
/*
void send_tcp_ack(int sockfd,struct sockaddr_in *addr)
{
struct send_tcp
   {
      struct iphdr ip;
      struct tcphdr tcp;
   } send_tcp;

struct pseudo_header
   {
      unsigned int source_address;
      unsigned int dest_address;
      unsigned char placeholder;
      unsigned char protocol;
      unsigned short tcp_length;
      struct tcphdr tcp;
   } pseudo_header;

int tcp_socket;
   struct sockaddr_in sin;
   int sinlen;

   // form ip packet 
   send_tcp.ip.ihl = 5;
   send_tcp.ip.version = 4;
   send_tcp.ip.tos = 0;
   send_tcp.ip.tot_len = htons(40);
   send_tcp.ip.frag_off = 0;
   send_tcp.ip.ttl = 64;
   send_tcp.ip.protocol = IPPROTO_TCP;
   send_tcp.ip.check = 0;
   send_tcp.ip.saddr = iprecv->ip_dst.s_addr;
   send_tcp.ip.daddr = addr->sin_addr.s_addr;

   // form tcp packet 
   send_tcp.tcp.dest = addr->sin_port;
send_tcp.tcp.source = tcprecv->dest;
   send_tcp.tcp.ack_seq = htonl(ntohl(tcprecv->seq)+0x01);
   send_tcp.tcp.res1 = 0;
   send_tcp.tcp.doff = 5;
   send_tcp.tcp.fin = 0;
   send_tcp.tcp.syn = 1;
   send_tcp.tcp.rst = 0;
   send_tcp.tcp.psh = 0;
   send_tcp.tcp.ack = 1;
   send_tcp.tcp.urg = 0;
   send_tcp.tcp.res2 = 0;
   send_tcp.tcp.window = htons(512);
   send_tcp.tcp.check = 0;
   send_tcp.tcp.urg_ptr = 0;
     send_tcp.tcp.seq = tcprecv->seq;

      // set fields that need to be changed 
      //send_tcp.tcp.source++;
      send_tcp.ip.id = 0 ;
      //send_tcp.tcp.seq++;
      send_tcp.tcp.check = 0;
      send_tcp.ip.check = 0;

      // calculate the ip checksum 
      send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);

      // set the pseudo header fields 
      pseudo_header.source_address = send_tcp.ip.saddr;
     pseudo_header.dest_address = send_tcp.ip.daddr;
      pseudo_header.placeholder = 0;
      pseudo_header.protocol = IPPROTO_TCP;
      pseudo_header.tcp_length = htons(20);
      bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
      send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32);
      sinlen = sizeof(sin);
int count;
for(count=0;count<2;count++){
      if(sendto(sockfd, &send_tcp, 40, 0, (struct sockaddr *)addr,sizeof(struct sockaddr))<0)
{
printf("sendto error!/n");
}
else
{
printf("send packet ok!/n");
}


}
*/


/* 下面是首部校验和的算法 */
unsigned short in_cksum(unsigned short *addr, int len)    /* function is from ping.c */
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer =0;

    while (nleft > 1)
       {
       sum += *w++;
       nleft -= 2;
      }
    if (nleft == 1)
     {      
       *(u_char *)(&answer) = *(u_char *)w;
        sum += answer;
     }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}
int Open_Packet_Socket()
{
    int sock;
    sock=socket(AF_INET,SOCK_PACKET,htons(ETH_P_ALL));
    if (sock==-1) 
    {
        perror("socket");
        exit(errno);
    }
    printf("sockfd:%d/n",sock);
    return(sock);
}
int Open_Raw_Socket()
{
int sock;
sock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
if (sock==-1) 
{
perror("socket");
exit(errno);
}
printf("sendfd:%d/n",sock);
return(sock);
}


int Set_Promisc(char *interface, int sockfd ) 
{
struct ifreq ifr;
 strncpy(ifr.ifr_name,interface,strnlen(interface)+1);
if (ioctl(sockfd,SIOCGIFFLAGS,&ifr)==-1) 
{
perror("ioctl1");
exit(errno);
}
ifr.ifr_flags |= IFF_PROMISC;
if (ioctl(sockfd,SIOCSIFFLAGS,&ifr)) 
{
perror("ioctl2");
exit(errno);
}

// printf("Setting interface ::: %s ::: to promisc...ok..../n", interface);
 return(1);
}
