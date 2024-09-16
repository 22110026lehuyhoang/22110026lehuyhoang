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
1. **Vulnerabilities:** the `get() function` is unsafe because it does not perform any bounds checking on the input. If the user provides input larger than the buffer (which is `char array[200]` in this case), it will overwrite adjacent memory locations, potentially including the return address of the `vuln() function`.
2. **Goal:** You want to overflow the array buffer in such a way that the return address is overwritten with the address of secretFunc()

- Step 1: Indentify the buffer size and offsets
  - The buffer `array` is 200 bytes, but you need to determine where the return address is stored relative to the start of the buffer.
  - This can be done by trial and error, injecting a large enough input to identify when the overflow occurs.
- Step 2: Find the Address of `secretFunc()`
  - You can use a debugger (e.g., `gdb`) to find the address of `secretFunc()`. The address of this function will be injected into the return address location. Use `gdb` to compile and load the program:
    ```ruby
    gcc -g bof1.c -o bof1
    gdb ./bof1
    ```
  - Inside `gdb`, find the address of `secretFunc()`
    ```ruby
    (gdb) disassemble secretFunc
    ```
  - This will give you the memory address where `secretFunc()` is stored.
