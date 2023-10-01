## Overview

this is a stream cipher. and this is not implementation of other cipher.
if other cipher have equality with this cipher, I am sorry for that. 
this cipher algorithm is easy to implement,
because the algorithm of this cipher is simple but not very simple.


## Docs


#### Installation
```
go get github.com/Rian-wahid/rcipher
```


#### Example

```go
package main
import (
  "fmt"
  "bytes"
  "github.com/Rian-wahid/rcipher"
)

func encrypt(key, nonce, data []byte)[]byte{
   var buf bytes.Buffer
   cipher,err:=rcipher.NewCipher(key,nonce,&buf)
   if err!=nil {
     panic(err.Error())
   }
   cipher.Write(data)
   cipher.End()
   return buf.Bytes()
}
func decrypt(key, nonce, data []byte)[]byte{
   var buf bytes.Buffer
   decipher,err:=rcipher.NewDecipher(key,nonce,&buf)
   if err!=nil {
     panic(err.Error())
   }
   decipher.Write(data)
   decipher.End()
   return buf.Bytes()
}

func main(){
   key:=make([]byte,32)
   nonce:=make([]byte,16)
   copy(key,[]byte("some key"))
   copy(nonce,[]byte("some nonce"))
   plaintext:=[]byte("a plaintext")

   ciphertext:=encrypt(key,nonce,plaintext)
   fmt.Printf("%x\n",ciphertext)
   
   decrypted:=decrypt(key,nonce,ciphertext)
   fmt.Printf("%x\n",decrypted)

   fmt.Println(string(decrypted))
}

```

## Notes

this is not thread safe.
I cannot guarantee the security (how safe this cipher). but like other stream ciphers if the same nonce is used to encrypt more than once with the same key, it is dangerous.
By default this has a simple authentication mechanism with a sha256 hash so the ciphertext length is equal to the plaintext length plus 32 bytes.
This uses a combination of key and nonce which is hashed and then used to create a key stream.
Previously it used AES S-Box and some steps from chacha (before the LICENSE file was added), but now it uses neither.

