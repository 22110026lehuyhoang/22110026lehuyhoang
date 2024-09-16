# 22110026, Lê Huy Hoàng
**Lab#1: Conduct buffer overflow attack on _bof1.c_, _bof2.c_, _bof3.c_ programs.**
## bo1.c
### Conduct a buffer overflow attack on _bof1.c_ 
```
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
<!--
**22110026lehuyhoang/22110026lehuyhoang** is a ✨ _special_ ✨ repository because its `README.md` (this file) appears on your GitHub profile.

Here are some ideas to get you started:

- 🔭 I’m currently working on ...
- 🌱 I’m currently learning ...
- 👯 I’m looking to collaborate on ...
- 🤔 I’m looking for help with ...
- 💬 Ask me about ...
- 📫 How to reach me: ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...
-->
