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
   
