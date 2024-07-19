# Gleamering


## Challenge Descriptions

```
# Gleamering Star

Like a star in the sky, gleamering, remembering all the things we've done.

Instancer: http://gleamering.chal.hitconctf.com/

Attachment: https://storage.googleapis.com/hitcon-ctf-2024-qual-attachment/gleamering/gleamering-8acf90164f9aed0ce5e4018b3e9ea66a203022e5.tar.gz

Author: bronson113

Solves: 7 solves / 360 pts
```

```
# Gleamering Hope

At last, when all sights of light disappear, only the hope gleamering within you.

PS. This is part 2 to Gleamering Star

Author: bronson113

Solves: 4 solves / 400 pts

```


## Dist File

Everything is src except source for gleamering\_hope\_ffi.so

## Environment

To start local version of the service, run `PORT=1234 docker compose up` to specify the port to connect to the service.


## Idea 

Gleamering light is run with js while Gleamering star is run with erlang.
Therefore, even though they shared the library of gleamering hope, their behavior can differ.
In particular, when encrypting the post, gleamering star encrypts the post id to `user_id+post_id+secret_key` in erlang.
But when the user try to read said post from gleamering light, the same calculation is done in js.
According to gleam.run, gleam's int is implemented differently accross js and erlang.
In particular, gleam implements int as double for js target, but implements as full percision int for erlang target.
This discrapency can be exploited to extract the secret key.

Now when gleam is running a function, it'll try to see if the function has been implemented externally if the extern modifier is added to the function before falling back to gleam implementation.
In gleamering hope you can see that the encrypt functions are all extern to an erlang ffi.
Then in the erlang source, you can see that the stream\_xor function is further implemented using a nif, a natively implemented function. ]
The so file is loaded from the priv folder.

With some reversing, you can find a backdoor in the priv folder.
You can craft a message using the secret key leaked from part 1 and gain RCE through ROP in the nif.
With no stack canary and the pie position of the main beam.smp binary, you have a plethora of options to do what ever you want.
You can send the flag out through internet by executing wget (Like what I did in my exploit).
You can also return cleanly after reading the flag so it gets added to the database.
