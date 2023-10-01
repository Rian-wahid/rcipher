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
