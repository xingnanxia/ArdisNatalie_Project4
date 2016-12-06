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

#define _KERNEL_

//initialize to unblock
bool block = false;


static struct nf_hook_ops nfho; //struct holding set of hook function options

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff*)){
	
	if(block){

		printk(KERN_INFO "packet dropped\n");
		return NF_DROP;
	} else {
		printk(KERN_INFO "packet accpted\n");
		return NF_ACCEPT;
	}
}


// get source and destination IP address of a packet caught in the hook function
unsigned int hook_func_2(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff*)) {
	
	// get the source and destination IP address of a packet caught in hook_func_2
	struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
	unsigned int src_ip = (unsigned int) ip_header -> saddr;
	unsigned int dest_ip = (unsigned int) ip_header->daddr;

	char source[16];
	snprintf(source, 16, "%pI4", &ip_header -> saddr);

	// compare the ip address from the packet with user input

	// if it is the same, then print it out using printk
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


int len1,temp1;

//String buffer in the kernel space
//msg = char[10];
char *msg1;

ssize_t write_proc1(struct file *filp,const char *buf,size_t count,loff_t *offp)
{

	//copy the data from the buffer to msg (in the proc entry).
	copy_from_user(msg1,buf,count);

	//Update len and temp for msg.
	len1=count;
	temp1=len1;



	//return the number of bytes copied.
	return count;
}



struct file_operations proc_fops0 = {

	//Those are both callback functions
	write: write_proc0,
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

	//Create two proc_entries: one for blockAll and the other one for monitoring.
	create_new_proc_entry();

	return 0;
}

//Called when module unloaded using "rmmod"
void cleanup_module(){
	
	nf_unregister_hook(&nfho); //cleanup -- unregister hook.

	//remove blockAll
	remove_proc_entry("blockAll",NULL);
 	kfree(msg0); //free the dynamically allocated memory.

	//remove monitor
	remove_proc_entry("monitor",NULL);
 	kfree(msg1); //free the dynamically allocated memory.

}