//'Hello world' netfilter hooks example
//For any packet, we drop it, and log fact to /var/log/messages

#undef _KERNEL_

#include <linux/kernel.h> //required for any kernel modules 
#include <linux/module.h>
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>

#include <linux/module.h> 	//This is a kernel module.
#include <linux/kernel.h> 	//This is a kernel module.
#include <linux/proc_fs.h> 	//Since we are using proc file system.
#include<linux/sched.h>		//For scheduling.
#include <asm/uaccess.h>	//copy_to_user(), copy_from_user().
#include <linux/slab.h>		//for kmalloc() and kfree()

#include <linux/skbuff.h>  
#include <linux/ip.h>         // for IP header

#include <linux/string.h>
#define _KERNEL_


//initialize to unblock
bool block = false;

// initialize to monitor
bool monitor = false;


static struct nf_hook_ops nfho; //struct holding set of hook function options
static struct nf_hook_ops nfho2;

struct sk_buff *sock_buff;
struct iphdr *ip_header;

//function to be called by hook2
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	
	if(block){
		printk(KERN_INFO "packet dropped\n");
		return NF_DROP;
	} else {
		printk(KERN_INFO "packet accpted\n");
		return NF_ACCEPT;
	}
}


char *msg1;

// get source and destination IP address of a packet caught in the hook function
unsigned int hook_func2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *)) {
	
	if (monitor) {
	
		unsigned int src_ip;
		unsigned int dest_ip;
		char source[16];
		char dest[16];
		int count = 0;

		sock_buff = skb;		
		// grad network header using accessor
		ip_header = (struct iphdr *) skb_network_header(sock_buff);
		// get the source address
		src_ip = (unsigned int) ip_header->saddr;
		// get the destination address
		dest_ip = (unsigned int) ip_header->daddr;

		// convert the source and destination IP addresses to character buffers
		
		snprintf(source, 16, "%pI4", &src_ip);
		
		snprintf(dest, 16, "%pI4", &dest_ip);

		// (****DEBUGGING STATEMENT) check function
		if (len1 <= 16) {
			while (count < len1 && msg1[count] == source[count]) {
				count++;	
			}
		} else {
			while (count < 16 && msg1[count] == source[count]) {
				count++;
			}
		}

		printk(KERN_INFO "%p", source);
		printk(KERN_INFO "\n%p", msg1);



		if (count == 16) {
			printk(KERN_INFO "equal");
		}


		if (strcmp(&msg1, source) == 0) {
			printk(KERN_INFO "two are comparable and are equal");
		} else {
			printk(KERN_INFO "two are comparable and not equal");
		}
		
		// compare the ip address from the packet with user input
		if (strcmp(&msg1, source) == 0) {
			printk(KERN_INFO "got an ip packet with matching address \n");
			// if it is the same, output address, timestamp, and size to logfile
			printk(KERN_INFO "Soure address: %s", source);
			printk(KERN_INFO "Destination address %s", dest);
			printk(KERN_INFO "Packet was received at time ");

		}	

	}	

	return NF_ACCEPT;

}


//global int variable of length and tmp.
//len: the number of bytes in msg. (proc entry)
//temp: the number of bytes to be read. Will be set back to len everytime after each read finishes.
int len0,temp0;

//String buffer in the kernel space
//msg = char[10];
char *msg0;

//transfer the data from user space to kernel space 
ssize_t write_proc0(struct file *filp,const char *buf,size_t count,loff_t *offp)
{

	//copy the data from the buffer to msg (in the proc entry).
	copy_from_user(msg0,buf,count);

	//Update len and temp for msg.
	len0=count;
	temp0=len0;

	if(count > 0){
	   block = !block;
	}

	//return the number of bytes copied.
	return count;
}

int len00, temp00;

// character buffer that holds the ip address you want to block
char *msg00;


// write a proc file for blocking a specific ip address
ssize_t write_proc00(struct file *filp, const char *buf, size_t count, loff_t *offp)
{
	copy_from_user(msg00, buf, count);
	len00 = count;
	temp00 = len00;

	// need to parse it in some way to separate the ip address from block/unblock
	// the second to last element in msg00 will be 0 or 1
	// from index 0..msg00.size-2, will be the ip address

	return count;
}


int len1,temp1;

//String buffer in the kernel space
//msg = char[10];


ssize_t write_proc1(struct file *filp,const char *buf,size_t count,loff_t *offp)
{

	//copy the data from the buffer to msg (in the proc entry).
	copy_from_user(msg1,buf,count);
	// msg1 has already been modified, so you don't need to return it, do you?

	//Update len and temp for msg.
	len1=count;
	temp1=len1;

	// redundant?
	if (count > 0) {
	   monitor = !monitor;	
	}

	//***check to make sure the character buffers are comparable

	//return the number of bytes copied.
	return count;
}

struct file_operations proc_fops0 = {

	//Those are both callback functions
	write: write_proc0
};

struct file_operations proc_fops1 = {

	//Those are both callback functions
	write: write_proc1,
};

void create_new_proc_entry(void) 
{

	//Here we pass the file_operations struct toe create the proc entry.
	//NULL: means it's proc/hello 
	proc_create("blockAll",0,NULL,&proc_fops0);

	//GFP_KERNEL: most reliable, will sleep or swap if out of memory.
	msg0=kmalloc(10*sizeof(char),GFP_KERNEL);

	//For entering IP4 address.
	proc_create("monitor",0,NULL,&proc_fops1);

	//GFP_KERNEL: most reliable, will sleep or swap if out of memory.
	msg1=kmalloc(20*sizeof(char),GFP_KERNEL);
}



//Called when module loaded using "insmod"
int init_module(){

	//setup nf_hook_ops:
	
	nfho.hook = hook_func; //function to call when conditions below met
	nfho.hooknum = NF_INET_PRE_ROUTING;   //called right after packet received, first hook in Netfilter 
	nfho.pf = PF_INET;  //IPV4 packets. (ignore IPV6)
	nfho.priority = NF_IP_PRI_FIRST; //set to highest priority over all other hook functions
	nf_register_hook(&nfho); //register hook
	
	nfho2.hook = hook_func2;
	nfho2.hooknum = NF_INET_PRE_ROUTING; // ?
	nfho2.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; // ?
	nf_register_hook(&nfho2); // register hook2

	//Create two proc_entries: one for blockAll and the other one for monitoring.
	create_new_proc_entry();

	return 0;
}

//Called when module unloaded using "rmmod"
void cleanup_module(){
	
	nf_unregister_hook(&nfho); //cleanup -- unregister hook.
	nf_unregister_hook(&nfho);

	//remove blockAll
	remove_proc_entry("blockAll",NULL);
 	kfree(msg0); //free the dynamically allocated memory.

	//remove monitor
	remove_proc_entry("monitor",NULL);
 	kfree(msg1); //free the dynamically allocated memory.

}