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

struct sk_buff *sock_buff;
struct iphdr *ip_header;

char *msg1;
int len1,temp1;

//function to be called by hook2
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	
	if(block){
		printk(KERN_INFO "packet dropped\n");
		return NF_DROP;
	} 
		
	else if(monitor){

		unsigned int src_ip;
		unsigned int dest_ip;
		char source[16];
		char dest[16];

		sock_buff = skb;		
		// grad network header using accessor
		ip_header = (struct iphdr *) skb_network_header(sock_buff);
		// get the source address
		src_ip = (unsigned int) ip_header -> saddr;
		// get the destination address
		dest_ip = (unsigned int) ip_header -> daddr;

		// convert the source and destination IP addresses to character buffers
		
		snprintf(source, 16, "%pI4", &src_ip);
		
		snprintf(dest, 16, "%pI4", &dest_ip);
		
		/*
		printk(KERN_INFO "slen = %d\n",slen);
		printk(KERN_INFO "dlen = %d\n",dlen);
		
		printk(KERN_INFO "buffer length = %d\n",len1); 
		
		printk(KERN_INFO "buffer address = %s\n",msg1);
		*/
	
		//Now it matches address that does not even match the target!
		if (strstr(source,msg1) == 0) {
			printk(KERN_INFO "Source address match the target");
			printk(KERN_INFO "source address = %s\n",source);
			printk(KERN_INFO "dest address = %s\n",dest);
			
			
		} 
		else if (strstr(dest,msg1) == 0){
			printk(KERN_INFO "Destination address match the target");
			printk(KERN_INFO "source address = %s\n",source);
			printk(KERN_INFO "dest address = %s\n",dest);
			
		}
		
		else {
			printk(KERN_INFO "two are NOT equal");
		}
		
		
		return NF_ACCEPT;
	}

	else {
		printk(KERN_INFO "packet accpted\n");
		
		return NF_ACCEPT;
	}
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
	//here we need to allocate more space to entry the message.
	msg0=kmalloc(100*sizeof(char),GFP_KERNEL);

	//For entering IP4 address.
	proc_create("monitor",0,NULL,&proc_fops1);

	//GFP_KERNEL: most reliable, will sleep or swap if out of memory.
	msg1=kmalloc(100*sizeof(char),GFP_KERNEL);
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