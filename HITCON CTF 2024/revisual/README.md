# Writeup for Revisual 


## Challenge Descriptions

```
Try to break into this beautiful starry vault.

http://revisual.chal.hitconctf.com/

Attachment: https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/revisual/revisual-8acf90164f9aed0ce5e4018b3e9ea66a203022e5.tar.gz

Author: bronson113

Solves: 30 solves / 255 pts
```


## Idea

- Reverse the js file to find the shader string
- Figure out that the shader is doing float to bytes conversion
- See that a varying variable is used, and figure out that the calc function is doing a form of linear intepolation with sbox.
- Reverse the process and solve the linear equation
- Solve the system of quadratic equation (or just bruteforce since 25^3 is not a lot of options).

