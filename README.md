Banning End-to-End Encryption is Stupid
=======================================

Various lawmakers in different countries are proposing to require messaging services to provide a mechanism for law enforcement to decrypt end-to-end encrypted messages.
This kind of legislation fundamentally misunderstands how easy it is for bad people to build their own end-to-end encryption layers on top of other messaging systems.

Requiring Signal, WhatsApp, and so on to introduce vulnerabilities into their products does not make life much harder for criminals.
Criminals can easily build or buy an extra layer of encryption on top and exchange messages that can't be decrypted.

It does make everyone else less safe.
If a backdoor exists and is usable by authorised people, it will eventually be exploited and used by malicious people.

This repository contains a trivial demonstration of this.
It builds a simple tool that allows sending end-to-end encrypted messages over any messaging service, including plain old SMS (though message-length limits may cause problems there).
It is 186 lines of code (and depends on a load of off-the-shelf open-source libraries) and took about an hour to write.

Imagine that Alice wants to send a message to Bob, as she often does in cryptography texts.
She needs a secret passphrase, which will be used to derive some keys:

```
$ cat pass 
Alice has a totally secret passphrase.
```

This is the only thing that we need to keep secret to be able to build end-to-end encrypted messaging.
Don't worry about how it's used, just remember that this is some secret that no one should be able to guess.

She then runs the following command:

```
$ banning-e2ee-is-stupid -k pass -u bob
```

The program notices that this is the first time that Alice has sent a message to Bob and so asks for his public key and asks Alice to send Bob her public key.
These are written out as a set of English words:

```
You have not exchanged keys with this user.  You must send them your public key:
celan fiona tasmanian bloomer terminological elca glamis fenceposts troilus ramapo premeditation meth chairpersons addictiveness bergman beauregard 
Please enter their key:
```

At the same time, Bob is preparing to receive his first message from Alice and so ensures that he has a completely unguessable key phrase and runs the tool to decrypt a message:

```
$ cat pass 
Bob also has a completely unguessable passphrase
$ ../banning-e2ee-is-stupid -k pass -u alice -d
You have not exchanged keys with this user.  You must send them your public key:
luxuriantly hensel soper chinny kilts esai downpours dissimulation adroitly widmann striven breastbone clonmel forecastle abascal barstools 
Please enter their key:
```

Alice and Bob must now send each other their public keys.
The easiest way to do this is to send it as a text message or email and then have a phone call where they read it out.
This isn't secret: it doesn't matter if someone else reads the key (you can put it on your website, Facebook profile, whatever), only if they are able to tamper with it.

This key-exchange process is handled by apps like Signal automatically.
Doing it well is the hard part of building an end-to-end encrypted messaging app.
Once Alice and Bob have both pasted each others' public key, they can start exchanging messages.
They won't be asked for keys again.
Alice now sees something like this:


```
Please enter the message to encrypt:
Hi Bob!

Send the following message to the other person:
anomaly forceful amongst ralphie gia ponds scandalous movies ungracious candidate absolution honan lima lambent cutaways embroider locos computers disqualify boehm naik brimming schrieber glebe 
```

This message is now encrypted in such a way that Bob (and only Bob) can decrypt it.
Alice can now send this message in email, or in her favourite messaging program.
She can even paste it into something public like a GitHub Gist or a Pastebin.
No one else can decrypt it and Bob can detect if it's tampered with.
In fact, Alice can paste a load of random messages in different places and Bob can try decrypting them all to find the one that's intended for him.

Bob just needs to paste the message from Alice into the program:

```
Please enter the message to decrypt:
anomaly forceful amongst ralphie gia ponds scandalous movies ungracious candidate absolution honan lima lambent cutaways embroider locos computers disqualify boehm naik brimming schrieber glebe

Decrypted message:
Hi Bob! 
```

This will report 'Decryption failed' if the message has been tampered with, was not from Alice, or was not intended for Bob (these three conditions are indistinguishable).

With this simple program (remember, about an hour's quick coding), it is possible for Alice and Bob to exchange messages over any insecure channel.

This is intended as a toy demonstration of how simple it is to build encrypted messaging over an unencrypted messaging service.
Over a decade ago, [TextSecure](https://en.wikipedia.org/wiki/TextSecure) built a product that did this (using much more clever crypto!) that gave a polished user interface.

Frequently asked questions
--------------------------

*How do I build this thing?*

You probably shouldn't (see disclaimers below).
If you really want to, run:

```
$ mkdir build
$ cd build
$ cmake .. -G Ninja
$ ninja
```

This will give you a program called `banning-e2ee-is-stupid`.
This will store public keys in a database in the directory that you run it from.

*Isn't this too complex for end users to use?  It requires using a command line and stuff.*

I wrote this in about an hour, much of which was spent learning how to use libraries.
It is absolutely not a polished end-user product.
Something with a half decent UI, better key storage, and so on, would probably be a whole afternoon's effort.

*What happens if someone intercepts the key-exchange messages?*

Nothing bad.
Each message is encrypted using both the sender's secret key and the receiver's public key.
Decrypting it requires the sender's public key and the receiver's secret key.
Both encrypting and decrypting a message require that you have a secret key, and these are never sent anywhere.


*What happens if an attacker uses the attack from [XKCD 538](https://xkcd.com/538/)?*

![XKCD 538](https://imgs.xkcd.com/comics/security.png)

They get your messages.
Sorry.

*Isn't it easy to spot messages like "aggarwal ashwell kalter stephenville compounders carleton somatic bks sanada airspaces brees lamb's fossilization wadsworth composit downey's arkansans advanta diffferent hewlitt henne rowed airlifts corba fortune's"?*

Yes.
This doesn't apply any [Steganography](https://en.wikipedia.org/wiki/Steganography) to the output and so traffic analysis (including scanning in the client device) would probably find it easily.
That said, if your heuristic is 'words used in strange ways' then you will get false positives from all teenagers.

*Where do all of these words come from?*

The encrypted message is pile of binary data.
A lot of messaging apps will be unhappy if you try to send raw binary data and break it in annoying ways.
This program uses one of [Keith Vertanen's big word lists](https://www.keithv.com/software/wlist/), truncated to 2^16 entries.
This means that for every two bytes of binary data, we have one word.
The words are all in the top 84K most commonly used English words and so totally indistinguishable from the kind of piffle that might be generated by the kind of politician that thinks banning encryption is remotely feasible.

*What does this use?*

This uses libsodium for all of the cryptography.
The passhprase hashed using Argon2id, which is intended to be slow (this is where the startup pause comes from) for a brute force attacker.
The encryption uses libsodium's crypto box construction, which uses X25519, XSalsa20, and Poly1305.
If you know what these are, you understand enough about cryptography to not need to read this page.
If you do not know what these are, you should not be voting on legislation about cryptography without talking to an expert.

**DO NOT USE THIS**
-------------------

This code is intended to show that it's easy to write something that does end-to-end encryption without the cooperation of the underlying messaging service.
As such, it is intentionally brief.
It does not follow best practices for encryption, in a number of ways:

 - It does not try to make the pass phrase storage secure.
   Good code would use the operating system's key storage APIs.
 - It does not provide a mechanism for rolling over keys.
   A good system would periodically re-key to handle cases where the key is leaked.
 - It does not provide forward security.
   If your key is leaked, an attacker can impersonate you and can read all messages that you've received.
 - It does not protect keys in memory.
   Keys may show up in core dumps, swap, and so on.
 - No one has reviewed the use of crypto.
   I am not a cryptographer, I probably did something stupid.
 - It uses random dependencies.
   The SQLite and libsodium wrappers were chosen because they were the first results in a DuckDuckGo search.
   This is not how you do supply-chain security.


