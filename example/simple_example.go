package main

import (
  "fmt"
  "github.com/Rian-wahid/rcipher"
  "bytes"
)

func main(){
  key,nonce:=make([]byte,32),make([]byte,16)
  copy(key,[]byte("some secret key"))
  copy(nonce,[]byte("nonce"))
  msg:=[]byte("some secret message")
  var encryptedBuf bytes.Buffer
  cipher,err:=rcipher.NewCipher(key,nonce,&encryptedBuf)
  if err!=nil {
    panic(err.Error())
  }
  _,err=cipher.Write(msg)
  if err!=nil {
    panic(err.Error())
  }
  _,err=cipher.End()
  if err!=nil {
    panic(err.Error())
  }
  encrypted:=encryptedBuf.Bytes()
  fmt.Printf("message    : %s\n",msg)
  fmt.Printf("message    : %x (in hexadecimal)\n",msg)
  fmt.Printf("ciphertext : %x (in hexadecimal)\n",encrypted[:len(msg)])
  fmt.Printf("authtag    : %x\n",encrypted[len(msg):])

  var decryptedBuf bytes.Buffer
  decipher,err:=rcipher.NewDecipher(key,nonce,&decryptedBuf)
  if err!=nil {
    panic(err.Error())
  }
  decipher.Write(encrypted)
  decipher.End()
  fmt.Printf("decrypted  : %s\n",decryptedBuf.Bytes())
}
