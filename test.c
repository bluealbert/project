// nlasp.c

/* this file is just used to test communication with the kernel module */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "time.hh"
#include <time.h>



#define ETH_ALEN 6
#define CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
//#include "ulog.h"
#include "omcap.h"

struct hijack_info *pinfo = NULL;
unsigned char *data_to_user;
//static FILE *rx_log_file = NULL;
//static FILE *tx_log_file = NULL;

unsigned short sport = 4000;
unsigned short dport = 80;

//char srcip[]="10.2.0.13";
//char dstip[]="10.1.0.14";

char srcip[16];
char dstip[16];
char mac_str[18];
u_char mac_20[ETH_ALEN];

int trail = 50;
int recved=0;
// char *nl_inet_ntoa(const unsigned int addr, char *buf)
// {
//   u_char s1 = (addr & 0xFF000000) >> 24;
//   u_char s2 = (addr & 0x00FF0000) >> 16;
//   u_char s3 = (addr & 0x0000FF00) >> 8;
//   u_char s4 = (addr & 0x000000FF);
//   sprintf(buf, "%d.%d.%d.%d", s4, s3, s2, s1);
//   return buf;
// }


//static double start=0.0;
//static double ent=0.0;
//static long pktnum=0;
unsigned int pkts = 0, bytes = 0;
struct timeval tv_start, tv_end; 
int ip_process(char *data, struct timespec tv_rx, unsigned int len, unsigned long id) {
  struct iphdr  *iph = NULL;
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
 // struct timeval now;
  char buf1[16], buf2[16];

  iph = (struct iphdr *)data;
//  if(len != ntohs(iph->tot_len))
//  {
//    printf("%4d received uncomplete packet(%d %d)\n", iph->id, len, ntohs(iph->tot_len));
//    return -1;    
//  }
  //printf("%4d received packet(%d %d)\n", iph->id, len, ntohs(iph->tot_len));
  // log
 // gettimeofday(&now);
	switch(iph->protocol){
		case IPPROTO_UDP:
		/*	udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));
			if(ntohs(udph->dest) > 10000 && ntohs(udph->dest) < 10010){
				if(pkts == 0){
					tv_start = now;
					printf("start: %d.%d\n", now.tv_sec, now.tv_usec);
				}
				pkts++;
				bytes += (len + 14);
				tv_end = now;*/
	// printf("%d: %d\n", ntohs(iph->id), len);
			//}
			break;      
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
			//if(ntohs(tcph->source) != 80){
				//rule_del_ker(pinfo, id);
			//}
			
			if ((tcph->rst==1)){
				printf("recd,%u,%u,%u,%u.%09lu\n", ntohs(iph->tot_len),ntohs(tcph->source), ntohs(tcph->dest),tv_rx.tv_sec, tv_rx.tv_nsec);
				//recved++;
			}
			//if (recved>=trail){
					//omcapexit(pinfo);
			//}
      break;
    case IPPROTO_ICMP:
      break;
    default:
      break;     
  }
  return 0;
}

int ip_sent_process(char *data, struct timespec tv_rx, unsigned int len, unsigned long id) {
	struct iphdr  *iph = NULL;
	struct tcphdr *tcph = NULL;
	iph = (struct iphdr *)data;
	tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
	printf("sent,%u,%u,%u,%u.%09lu\n", ntohs(iph->tot_len), ntohs(tcph->source), ntohs(tcph->dest),tv_rx.tv_sec, tv_rx.tv_nsec);
	return 0;
}

uint16_t csum(u_char *addr, int count)
{
  /* Compute Internet Checksum for "count" bytes
   *         beginning at location "addr".
   */
  register long sum = 0;
  while( count > 1 )  {
    /*  This is the inner loop */
    sum += *((unsigned short *)addr);
    addr += 2;
    count -= 2;    
  }
  /*  Add left-over byte, if any */
  if( count > 0 )
    sum += *(unsigned char *) addr;
  /*  Fold 32-bit sum to 16 bits */
  while (sum>>16)
    sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
} 

struct psd_header
{
  in_addr_t saddr; // sip
  in_addr_t daddr; // dip
  u_char mbz;// 0
  u_char ptcl; // protocol
  unsigned short tcpl; //TCP length

};

int in_cksum_(uint16_t *addr, int len) {
    int sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint16_t *)addr;
    }
    return (sum);
}

uint16_t tcp_chksum(uint16_t * ip_src_ptr, uint16_t * tcp_ptr, uint16_t ip_payloadlen){
	int sum=0;  
	sum = in_cksum_(ip_src_ptr, 8);
	sum += ntohs(IPPROTO_TCP + ip_payloadlen);
	sum += in_cksum_(tcp_ptr, ip_payloadlen);
 return CKSUM_CARRY(sum);
}

uint16_t tcp_csum(in_addr_t saddr, in_addr_t daddr, u_char *tcppkt, uint16_t len)
{
  u_char buf[1600], *pkt;
  uint16_t rst;
  struct psd_header *psdh;
  int count = sizeof(struct psd_header) + len;
  TRACE_ENTRY;
  memset(buf, 0, count);
  psdh = (struct psd_header *)buf;
  pkt = buf + sizeof(struct psd_header);
  psdh->saddr = saddr;
  psdh->daddr = daddr;
  psdh->mbz = 0;
  psdh->ptcl = IPPROTO_TCP;
  psdh->tcpl = htons(len);
  memcpy(pkt, tcppkt, len);
  rst = csum(buf, count);


  TRACE_EXIT;
  return rst;  
}

static int seq = 1;
int ip_packets_tx(int pkts, int pkt_len, struct timespec delay)
{
  int pktlen = pkt_len + sizeof(struct iphdr) + sizeof(struct tcphdr);
  char *ip_buf = NULL;//kmalloc(pktlen, GFP_KERNEL);
  struct iphdr *iph = NULL;//(struct iphdr *)ip_buf;
  struct tcphdr *tcph = NULL;//(struct tcphdr *)(ip_buf + sizeof(struct iphdr));
  char *data = NULL;
  //, buf1[16], buf2[16];
  //ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);
//  struct timeval now;
  int res = 0;
  if (pktlen<=0){
  	return 0;
  }
//  if(pktlen < sizeof(struct timeval))
//    pktlen = sizeof(struct timeval);
  ip_buf = malloc(pktlen);
  iph = (struct iphdr *)ip_buf;
  tcph = (struct tcphdr *)(ip_buf + sizeof(struct iphdr));
  data = ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);

  if(!ip_buf)
  {
    printf("malloc ip packet buff (%d) failure\n", pktlen);
    return 0;
  }

//  TRACE_ENTRY;
//  printk("0001\n");
  memset(ip_buf, 0, pktlen);

  iph->version = 4;
  iph->ihl = sizeof(struct iphdr) >> 2;
  iph->frag_off = 0;
  iph->protocol = IPPROTO_TCP;
  iph->tos = 0;
  iph->daddr = inet_addr(dstip);
  iph->saddr = inet_addr(srcip);
  //printf("%s  --> %s\n",nl_inet_ntoa(iph->saddr, buf1),nl_inet_ntoa(iph->daddr, buf2)); 
  iph->ttl = 0x40;

  iph->tot_len = htons(pktlen);
  iph->check = 0;
  

  
  tcph->source = htons(sport);
  tcph->dest = htons(dport);

  tcph->ack_seq = 0;
  tcph->doff = 5;
  tcph->psh = 1;
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst=0;
  tcph->ack = 1;
  tcph->check = 0;
  tcph->window = htons(5840);
//  printk("data address %x\n", data);
  
  iph->id = htons(1234);
  tcph->seq = htonl(seq);
  memset(data, 0x01, pkt_len); 
  iph->check = csum((void *)iph, iph->ihl * 4);
  tcph->check = tcp_chksum((uint16_t*) &iph->saddr, (uint16_t*)tcph, (pktlen-20));
  //tcph->check = tcp_csum(iph->saddr, iph->daddr, (u_char *)tcph, pkt_len + sizeof(struct tcphdr));
  //tcph->check = tcp_csum(inet_addr(srcip), inet_addr(dstip), (u_char *)tcph, (pktlen-(iph->ihl * 4)));
   //tcph->check = htons(0x4bcc);
  
  if(pkts > 1)
  {
    pkt_train_tx(pinfo, ip_buf, pktlen, pkts, delay);  // SCHEDULE PACKET TRAIN
    return 1;
  }
  
  res = pkt_schedule(pinfo, ip_buf, pktlen, delay); // SCHDEULE PACKET

//  TRACE_EXIT;
  return res;
};


int soc_ip_packets_tx(int fd, int pkt_len)
{
  int pktlen = pkt_len + sizeof(struct iphdr) + sizeof(struct tcphdr);
  char *ip_buf = NULL;//kmalloc(pktlen, GFP_KERNEL);
  struct iphdr *iph = NULL;//(struct iphdr *)ip_buf;
  struct tcphdr *tcph = NULL;//(struct tcphdr *)(ip_buf + sizeof(struct iphdr));
  char *data = NULL;
  // buf1[16], buf2[16];
  //ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);
  struct timespec current_time;
  struct sockaddr_in sin;
//  struct timeval now;
  //int res = 0;
//  if(pktlen < sizeof(struct timeval))
//    pktlen = sizeof(struct timeval);
  ip_buf = malloc(pktlen);
  iph = (struct iphdr *)ip_buf;
  tcph = (struct tcphdr *)(ip_buf + sizeof(struct iphdr));
  data = ip_buf + sizeof(struct iphdr) + sizeof(struct tcphdr);

  if(!ip_buf)
  {
    printf("malloc ip packet buff (%d) failure\n", pktlen);
    return 0;
  }
  sin.sin_family = AF_INET;
  sin.sin_port = htons(80);
  sin.sin_addr.s_addr = inet_addr(dstip);
     

//  TRACE_ENTRY;
//  printk("0001\n");
  memset(ip_buf, 0, pktlen);

  iph->version = 4;
  iph->ihl = sizeof(struct iphdr) >> 2;
  iph->frag_off = 0;
  iph->protocol = IPPROTO_TCP;
  iph->tos = 0;
  iph->daddr = inet_addr(dstip);
  iph->saddr = inet_addr(srcip);
  //printf("%s  --> %s\n",nl_inet_ntoa(iph->saddr, buf1),nl_inet_ntoa(iph->daddr, buf2)); 
  iph->ttl = 0x40;

  iph->tot_len = htons(pktlen);
  iph->check = 0;
  

  
  tcph->source = htons(sport);
  tcph->dest = htons(dport);

  tcph->ack_seq = 0;
  tcph->doff = 5;
  tcph->psh = 1;
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst=0;
  tcph->ack = 1;
  tcph->check = 0;
  tcph->window = htons(5840);
//  printk("data address %x\n", data);
  
  iph->id = htons(1234);
  tcph->seq = htonl(seq);
  memset(data, 0x01, pkt_len); 
  iph->check = csum((void *)iph, iph->ihl * 4);
  tcph->check = tcp_chksum((uint16_t*) &iph->saddr, (uint16_t*)tcph, (pktlen-20));
  //tcph->check = tcp_csum(iph->saddr, iph->daddr, (u_char *)tcph, pkt_len + sizeof(struct tcphdr));
  //tcph->check = tcp_csum(inet_addr(srcip), inet_addr(dstip), (u_char *)tcph, (pktlen-(iph->ihl * 4)));
   //tcph->check = htons(0x4bcc);
	clock_gettime(CLOCK_REALTIME,&current_time);
	printf("usnd,%d,%u.%06u\n",seq-1, current_time.tv_sec, current_time.tv_nsec);
	if (sendto (fd, ip_buf, pktlen ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0){
  	printf("sendto failed\n");
	}

//  TRACE_EXIT;
  return 0;
};

void pktloss()
{
  struct timespec gap;
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
  
  ip_packets_tx(100,200,gap);
  usleep(1000*10);
  ip_packets_tx(100,800,gap);
  usleep(1000*10);
  ip_packets_tx(100,1400,gap);
  usleep(1000*10);
  printf("finisth\n");
}
void pkt_schedule_test(unsigned int ustime, unsigned int size)
{
  int i = 0;
//  int j;
  unsigned long timegap;
  struct timespec gap, pre_period;
  struct timespec current_time, interval_ts, sc_ts, pre_ts;
  
  //tx_log_file = ulog_init("tx.log");
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
 // ip_packets_tx(5, 1000, gap);
  //sleep(15);
  interval_ts.tv_sec=0;
  interval_ts.tv_nsec=ustime*1000;
	pre_period.tv_sec = 0;
	pre_period.tv_nsec = 50000;
	printf("intv: %u\n",interval_ts.tv_nsec);
  //gettimeofday(&current_time,NULL);
  clock_gettime(CLOCK_MONOTONIC,&current_time);
  sc_ts=current_time;
  for(i=0; i<trail; i++){
    ts_add(&sc_ts,interval_ts);
    gap=sc_ts;
    
    printf("schd,%d,%u.%06u\n",seq-1, gap.tv_sec, gap.tv_nsec);
    //printf("sleep until %u.%06u\n",pre_ts.tv_sec, pre_ts.tv_nsec);
    rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport), htons(dport));
    //clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&pre_ts,NULL);
    ip_packets_tx(1,size,gap);
    seq+=1;
    sport+=1;
    
    //usleep(timegap*10*2);
  }
	pre_ts = gap;
	pre_ts.tv_sec+=1;
	clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&pre_ts,NULL);
	omcapexit(pinfo); 
 // printf("finish\n");
  return;
}

void pkt_schedule_test_sleep(unsigned int ustime, unsigned int size, unsigned int usgap)
{
  int i = 0;
//  int j;
  unsigned long timegap;
  struct timespec gap, pre_period;
  struct timespec current_time, interval_ts, sc_ts, pre_ts;
  
  //tx_log_file = ulog_init("tx.log");
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
 // ip_packets_tx(5, 1000, gap);
  //sleep(15);
  interval_ts.tv_sec=0;
  interval_ts.tv_nsec=ustime*1000;
	pre_period.tv_sec = 0;
	pre_period.tv_nsec = usgap*1000;
	printf("intv: %u\n",interval_ts.tv_nsec);
  //gettimeofday(&current_time,NULL);
  clock_gettime(CLOCK_MONOTONIC,&current_time);
  sc_ts=current_time;
  for(i=0; i<trail; i++){
    ts_add(&sc_ts,interval_ts);
    gap=sc_ts;
    pre_ts = sc_ts;
    ts_sub(&pre_ts, pre_period);
    printf("schd,%d,%u.%06u\n",seq-1, gap.tv_sec, gap.tv_nsec);
    //printf("sleep until %u.%06u\n",pre_ts.tv_sec, pre_ts.tv_nsec);
    rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport), htons(dport));
    clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&pre_ts,NULL);
    ip_packets_tx(1,size,gap);
    seq+=1;
    sport+=1;
    
    //usleep(timegap*10*2);
  }
	pre_ts = gap;
	pre_ts.tv_sec+=1;
	clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&pre_ts,NULL);
	omcapexit(pinfo); 

 // printf("finish\n");
  return;
}

void pkt_usleep_test(unsigned int ustime, unsigned int size){
	unsigned int interval = ustime;
	int i;
	struct timespec gap;
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
  
	for (i=0; i<trail; i++){
		rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport), htons(dport));
		usleep(interval);
    ip_packets_tx(1,size,gap);
    seq+=1;
    sport+=1;
	}
	sleep(1);
	omcapexit(pinfo); 
}

void pkt_nsleep_test(unsigned int ustime, unsigned int size){
	unsigned int interval = ustime;
	int i;
	struct timespec gap, sinv;
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
  sinv.tv_sec = 0;
  sinv.tv_nsec = ustime*1000;
	for (i=0; i<trail; i++){
		rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport), htons(dport));
		clock_nanosleep(CLOCK_MONOTONIC,0,&sinv,NULL);
    ip_packets_tx(1,size,gap);
    seq+=1;
    sport+=1;
	}
	sleep(1);
	omcapexit(pinfo); 
}

void socket_test(unsigned int ustime, unsigned int size){
	int i;
	struct timespec sinv;
	int one = 1;
  const int *val = &one;
  sinv.tv_sec = 0;
  sinv.tv_nsec = ustime*1000;
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (s==-1){
		printf ("fail to create socket\n");
		exit(1);
	}
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0){
		printf("Error setting IP_HDRINCL");
		exit(1);
	}
	for (i=0; i<trail; i++){
		rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport), htons(dport));
		clock_nanosleep(CLOCK_MONOTONIC,0,&sinv,NULL);
		//usleep(ustime);
    soc_ip_packets_tx(s,size);
    seq+=1;
    sport+=1;
	}
	sleep(1);
	close (s);
	omcapexit(pinfo); 
}

void delaytest(void)
{
  int i,j;
  struct timespec gap;
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
  //for(i=0; i < 147;i++)
  for(i=0; i < 10;i++)
  {
    //for(j=0;j<10;j++)
    //{
      ip_packets_tx(1, 500, gap);
      usleep(10000);
    //}
  }
}
void test(void)
{
  char test[1024];
//  struct timeval ti;
  sprintf(test, "data");

 // nl_send_data(pinfo, test, strlen(test)+1, MSG_TEST_DATA);
  printf("send data(%d): %s\n",strlen(test), test);

}

void rule_test(int numrule, int period){
	int i;
	for (i=0; i<numrule; i++){
		rule_add(pinfo, inet_addr(srcip), inet_addr(dstip), htons(sport+i), htons(dport-i));
		printf ("rule %d added\n",i);
	}
	sleep(period);
	omcapexit(pinfo);
}

void print_rx_res()
{
  double d=0.0, prate = 0.0, rbytes = 0.0;
  int sec, usec;
  
  sec = tv_end.tv_sec - tv_start.tv_sec;
  usec = tv_end.tv_usec - tv_start.tv_usec;
  d = (double)sec + ((double)usec/1000000.0);
  rbytes = (double)bytes/d;
  prate = (double)pkts/d;
  
  printf("duration: %d.%d - %d.%d\n", tv_start.tv_sec, tv_start.tv_usec, tv_end.tv_sec, tv_end.tv_usec);
  printf("process ID: %d\n", pinfo->pid);
  printf("total time: %f s\n", d);
  printf("total packets: %d\n", pkts);
  printf("total bytes: %d\n", bytes);
  printf("byte rate: %f Kbit/s\n", rbytes * 8.0 / 1000.0);
  printf("packet rate: %f pkts/s\n", prate);

}
void pkt_train_test()
{
  int i = 0;
  struct timespec gap;
  gap.tv_sec = 0;
  gap.tv_nsec = 0;
  for(i=0; i<147;i++)
  {
    ip_packets_tx(100, i*10, gap);
    usleep(1000*100);
  }
  
}

void terminate(int signo) 
{
    //printf("exit\n");
    //print_rx_res();
    omcapexit(pinfo); 
   // ulog_exit(rx_log_file);
   // exit(0);
}

void str_to_mac(char * mchar, u_char* mac_hex){
	unsigned int tmp_mac[ETH_ALEN];
	int i;
	sscanf(mchar, "%2x:%2x:%2x:%2x:%2x:%2x", &tmp_mac[0],&tmp_mac[1],&tmp_mac[2],&tmp_mac[3],&tmp_mac[4],&tmp_mac[5]);
	for (i=0; i<ETH_ALEN; i++){
		mac_hex[i] = tmp_mac[i]&0xff;
	}
	//&mac_hex[1],&mac_hex[2],&mac_hex[3],&mac_hex[4],&mac_hex[5]);
}

int main(int argc, char *argv[])
{
 // int i = 10;
 //u_char mac_20[ETH_ALEN] = {0x00,0x11,0x25,0xb4,0x37,0x1d};
 //u_char mac_20[ETH_ALEN] = {0xd4,0xca,0x6d,0x8f,0x27,0x93};
  char eth[8];
  int cmd = 0;
  if(argc > 1){
    strcpy(eth, argv[1]);
  }else{
    strcpy(eth, "eth0");
  }
  if(argc >= 5){
    cmd = atoi(argv[2]);
    str_to_mac(argv[3], mac_20);
    strcpy(srcip, argv[4]);
    strcpy(dstip, argv[5]);
  }else{
    cmd = 0; // test for packets capture capacity 
  }
  printf ("mac: %x:%x:%x:%x:%x:%x; srcip: %s; dstip: %s \n",mac_20[0],mac_20[1],mac_20[2],mac_20[3],mac_20[4],mac_20[5],srcip,dstip);
  //printf("Capture %s, sport=%d\n", eth, sport);
  signal(SIGINT, terminate);
  pinfo = omcapinit(eth,mac_20);
  if( !pinfo)
    return 0;
  //printf("Initinal successfully. \n");
  
  if(pkt_capture(pinfo, (void *)ip_process, (void *)ip_sent_process) < 0)
    return 0;
  if(cmd == 1) // packet delay
    delaytest();
  if(cmd == 2)
    pkt_schedule_test((unsigned int)atol(argv[6]), atoi(argv[7]));
  if(cmd == 3){
    //pkt_train_test();
  	pkt_schedule_test_sleep((unsigned int)atol(argv[6]), atoi(argv[7]),(unsigned int)atol(argv[8]));
  }
  if(cmd == 4){
    //rule_add(pinfo, inet_addr("220.181.111.148"), inet_addr("192.168.1.207"), htons(80), htons(8001));
    //rule_add(pinfo, inet_addr("220.181.112.143"), inet_addr("192.168.1.207"), htons(80), htons(8001));
    pkt_usleep_test((unsigned int)atol(argv[6]), atoi(argv[7]));
  }
  if (cmd==5){
  	socket_test((unsigned int)atol(argv[6]), atoi(argv[7]));
  }
  if (cmd==6){
  	pkt_nsleep_test((unsigned int)atol(argv[6]), atoi(argv[7]));
  }
  if (cmd==7){
  	rule_test(atoi(argv[6]), atoi(argv[7]));
  }
  pthread_join(pinfo->nl_thread_rcv, NULL);
  //printf("ready for exiting\n");
  omcapexit(pinfo); 
  // ulog_exit(rx_log_file);
  return 0;
}
