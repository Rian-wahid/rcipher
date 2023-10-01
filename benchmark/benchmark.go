package main

import (
  "time"
  "fmt"
  "github.com/Rian-wahid/rcipher"
  "bytes"
)

func main(){
  key:=make([]byte,32)
  nonce:=make([]byte,16)
  copy(key,[]byte("some key"))
  copy(nonce,[]byte("some nonce"))
  var encrypted bytes.Buffer
  cipher,err:=rcipher.NewCipher(key,nonce,&encrypted)
  if err!=nil {
    panic(err.Error())
  }
  totalTime:=int64(0)

  l:=int64(1000000)
  b:=make([]byte,16)
  for i:=int64(0); i<l; i++ {
    st:=time.Now().UnixMilli()
    _,err:=cipher.Write(b)
    totalTime+=time.Now().UnixMilli()-st
    if err!=nil {
      panic(err.Error())
    }
  }
  
  fmt.Printf("encryption speed is %dKB/s\n",((int64(len(b))*l)/1000)/(totalTime/1000))
}

