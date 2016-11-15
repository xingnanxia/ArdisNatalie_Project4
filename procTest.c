//This example creates a proc entry that can read from and write to the user space.

#include <linux/module.h> 	//This is a kernel module.
#include <linux/kernel.h> 	//This is a kernel module.
#include <linux/proc_fs.h> 	//Since we are using proc file system.
#include<linux/sched.h>		//For scheduling.
#include <asm/uaccess.h>	//page default.
#include <linux/slab.h>		//

//global int variable of length and tmp.
//len: the number of bytes in msg. (proc entry)
//temp: the number of bytes to be read. Will be set back to len everytime after each read finishes.
int len,temp;

//String buffer in the kernel space
char *msg;

//transfer data from kernel space to user space.

//offp is the offset: loff: long offset type.
//buf: buffer in the user space to write to.
//count: number of bytes to copy to the buffer.
//If the return value is not 0, this function is called again! This function will be called recursively, moving the offset downwards everytime, until this is nothing more to read. 
//filp is the file pointer pointing to our proc entry. 
ssize_t read_proc(struct file *filp,char *buf,size_t count,loff_t *offp ) 
{

//If we want to read more bytes than there is, set the count to the number of bytes there is.
if(count>temp)
{
count=temp;
}

//temp is the following bytes to be read.
temp=temp-count;

//copy the count number of bytes to the user space.
copy_to_user(buf,msg, count);

//If we finish reading this time, set temp back to len, so that the whole things can be read again the next time.
if(count==0)
temp=len;
   
return count;
}

//transfer data from user space  to kernel space.
//filp is the file pointer pointing to our proc entry.
//buf is the buffer in kernel space.
//offp is the offset in the buffer. 
ssize_t write_proc(struct file *filp,const char *buf,size_t count,loff_t *offp)
{

//copy the data from the buffer to msg (in the proc entry).
copy_from_user(msg,buf,count);

//Update len and temp for msg.
len=count;
temp=len;

//return the number of bytes copied.
return count;
}


struct file_operations proc_fops = {

//Those are both callback functions
read: read_proc,
write: write_proc
};


void create_new_proc_entry(void) 
{

//Here we pass the file_operations struct toe create the proc entry.
//NULL: means it's proc/hello 
proc_create("hello",0,NULL,&proc_fops);
msg=kmalloc(10*sizeof(char),GFP_KERNEL);
}


int proc_init (void) {
 create_new_proc_entry();
 return 0;
}

void proc_cleanup(void) {
 remove_proc_entry("hello",NULL);
 kfree(msg);
}

MODULE_LICENSE("GPL"); 
module_init(proc_init);
module_exit(proc_cleanup);
