## Book Exercises 
- book name: << windowskernelprogramming >>
- book link: https://www.amazon.com/Windows-Kernel-Programming-Pavel-Yosifovich-ebook/dp/B07TJT1GTF

## Project Prerequisites
- wil: https://github.com/microsoft/wil
- kernel library from Pavel Yosifovich, https://github.com/zodiacon/ndcoslo2019.git 

## Chapter8 Exercises:  
- Create a driver that monitors process creation and allows a client application to configure executable paths that should not be allowed to execute.  
- Write a driver (or add to the SysMon driver) the ability to detect remote thread creations - threads created in processes other than their own. Hint: the first thread in a process is always created “remotely”. Notify the user mode client when this occurs. Write a test application that uses CreateRemoteThread to test your detection. 

## Chapter9 Exercises:  
- Implement a driver that will not allow thread injection into other processes unless the target process is being debugged.  
- Implement a driver that protects a registry key from modifications. A client can send the driver registry keys to protect or unprotect.  
- Implement a driver that redirects registry write operations coming from selected processes (configured by a client application) to their own private key if they access HKEY_LOCAL_MACHINE. If the app is writing data, it goes to its private store. If it’s reading data, first check the private store, and if no value is there go to the real registry key. This is one facet of application sandboxing.  

## Chapter10 Exercises:  
- Write a file system mini-filter that captures delete operations from cmd.exe and instead of deleting them, moves the files to the recycle bin.  