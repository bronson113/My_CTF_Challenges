# Writeup for PCBC Revenge by bronson113


```plaintext
I see what I did wrong last time, now it's fixed.

[Link to the original challenge](https://github.com/bronson113/My_CTF_Challenges/tree/main/b01lersCTF2024/counter_block_chaining)

`nc pcbcrevenge.chal.hitconctf.com 3000`

Attachment: https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/pcbcrevenge/pcbcrevenge-8acf90164f9aed0ce5e4018b3e9ea66a203022e5.tar.gz

Author: bronson113

Solves: 7 solves / 360 pts
```


## Idea

Using pt-ct pair as building block and so GF(2) linear combination to craft the last block that we want.



