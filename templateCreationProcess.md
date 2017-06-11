# Template Creation Process
Steps to create an un-hindered image for use across various cloud services

##### Tools Setup
1.  Download your base image - I have used Centos7x64-minimal
2.  Install VirtualBox
3.  Create new VM  
    a.  2c / 4 GiB / 15 GiB / Thin provisioned / x64 Linux kernel 3.x  
    b. Attach Centos7 iso  
    c. Boot to install  
    d. US English / US Keyboard / UTC Timezone  
    e. Automatic Partitioning / Hostname to vanillabox.hortonworks.com / SecPol to Centos Standard  
    f. Hit Install  
    g. set root to StrongPassword / create user 'centos' as an administrator with password StrongPassword  
    h. Done and reboot

4.  Login as centos/StrongPassword
```bash
sudo yum update -y

```
    