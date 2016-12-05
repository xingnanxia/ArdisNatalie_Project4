# ArdisNatalie_Project4
Build a kernel module that monitors network traffic

Nov, 30, 2016

*How to use BlockAllTrafficOnDemand?*

1) sudo insmod BlockAllTrafficOnDemand.ko (insert the module)

2) ping www.google.com (should print out network info) 

3) write anything to the /proc/blockAll proc file: if bytes read in > 0, the module will basically toggle between block and unblock. 
    eg. echo "1" | sudo tee /proc/blockAll 
    
4) ping www.google.com (should not print out anything now) 

5) echo "1" | sudo tee /proc/blockAll

6) ping www.google.com (should print out network info again) 

7) sudo rmmod BlockAllTrafficOnDemand (inject the module) 


Dec. 4, 2016

*How to monitor network traffic*

1) sudo insmod BlockAllTrafficOnDemand.ko (insert the module)

2) in order to activate ipt_LOG for IPv4 (=printk-based logging), type
   echo "ipt_LOG" > /proc/sys/net/netfilter/nf_log/2

3) write the IPv4 address you want to monitor: eg. echo "172.16.254.1" | sudo tee /proc/monitor
