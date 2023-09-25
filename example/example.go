package main

import (
  "os"
  "github.com/Rian-wahid/rcipher"
  "fmt"
  "bytes"
  "crypto/rand"
)

func main(){
  key:=make([]byte,32)
  nonce:=make([]byte,16)
  rand.Read(nonce)
  rand.Read(key)
  var encrypted bytes.Buffer
  cipher,err:=rcipher.NewCipher(key,nonce,&encrypted)
  if err!=nil {
    panic(err.Error())
  }
  decipher,err:=rcipher.NewDecipher(key,nonce,os.Stdout)
  if err!=nil {
    panic(err.Error())
  }
  msg:=[]byte("Hello ")
  cipher.Write(msg)
  enc:=encrypted.Next(len(msg))
  decipher.Write(enc)
  fmt.Printf("message hex  : %x\nencrypted hex: %x\n",msg,enc)
  msg=[]byte("world\n")
  cipher.Write(msg)
  enc=encrypted.Next(len(msg))
  decipher.Write(enc)
  fmt.Printf("message hex  : %x\nencrypted hex: %x\n",msg,enc)
  cipher.End()
  authTag:=encrypted.Next(64)
  fmt.Printf("authtag      : %x\n",authTag)
  fmt.Print("decrypted    : ")
  decipher.Write(authTag)
  _,err=decipher.End()
  if err!=nil {
    panic(err.Error())
  }
}
