package rcipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
  "fmt"
  "crypto/rand"
  "bytes"
  "encoding/hex"
)

func TestCipherUniqueXORKey(t *testing.T){
  key,nonce:=make([]byte,32),make([]byte,16)
  var buf bytes.Buffer
  rand.Read(key)
  rand.Read(nonce)
  cipher,err:=NewCipher(key,nonce,&buf)
  assert.Nil(t,err)
  uniqueXorKey:=make(map[string]bool)
  size:=2
  round:=65000
  for i:=0; i<round; i++{
    b:=make([]byte,size)
    n,err:=cipher.Write(b)
    assert.Nil(t,err)
    enc:=buf.Next(n)
    assert.NotEqual(t,hex.EncodeToString(b),hex.EncodeToString(enc))
    uniqueXorKey[string(enc)]=true
  }
  n,err:=cipher.End()
  assert.Nil(t,err)
  assert.Equal(t,32,n)
  assert.Equal(t,n,len(buf.Next(n)))
  fmt.Printf("INFO total unique %d byte XOR key ",size)
  fmt.Printf("in %d round: %d\n",round,len(uniqueXorKey))
}

func TestDecipher(t *testing.T){
  key,nonce:=make([]byte,32),make([]byte,16)
  rand.Read(key)
  rand.Read(nonce)
  var buf bytes.Buffer
  decipher,err:=NewDecipher(key,nonce,&buf)
  assert.Nil(t,err)
  msg:=make([]byte,32)
  rand.Read(msg)
  cipher,_:=NewCipher(key,nonce,decipher)
  cipher.Write(msg)
  _,err=cipher.End()
  assert.Nil(t,err)
  _,err=decipher.End()
  assert.Nil(t,err)
  assert.Equal(t,hex.EncodeToString(msg),hex.EncodeToString(buf.Bytes()))
}

func TestDifferent1BitInKey(t *testing.T){
  msg,key,nonce:=make([]byte,10),make([]byte,32),make([]byte,16)
  rand.Read(msg)
  rand.Read(key)
  rand.Read(nonce)
  key[31]=1
  key2:=make([]byte,32)
  copy(key2,key)
  key2[31]=3
  var buf1 bytes.Buffer
  var buf2 bytes.Buffer
  cipher1,err:=NewCipher(key,nonce,&buf1)
  assert.Nil(t,err)
  cipher2,err:=NewCipher(key2,nonce,&buf2)
  assert.Nil(t,err)
  n1,err:=cipher1.Write(msg)
  assert.Nil(t,err)
  n2,err:=cipher2.Write(msg)
  assert.Nil(t,err)
  assert.Equal(t,n1,n2)
  result1:=buf1.Next(n1)
  result2:=buf2.Next(n2)
  fmt.Printf("INFO message %x\n",msg)
  fmt.Printf("INFO result1 %x\n",result1)
  fmt.Printf("INFO result2 %x\n",result2)
  assert.NotEqual(t,
    hex.EncodeToString(result1),
    hex.EncodeToString(result2),
    )
  cipher1.End()
  cipher2.End()
}

/*func TestIrreversibleLogic(t *testing.T){
  i:=0
  for a:=0; a<256; a++{
    for b:=0; b<256; b++{
      n:=(sbox[a]>>3)|(sbox[b]<<3)
      n=sbox[n]
      n+=1
      if n!=byte(a)&&n!=byte(b) && sbox[n]!=byte(a) &&sbox[n]!=byte(b) && n^byte(a)!=byte(b) && sbox[n] ^byte(b)!=byte(a) && sbox[a]^n!=byte(b) && sbox[b]^n!=byte(a) && sbox[b]!=n && sbox[a]!=n{
        fmt.Println(n,a,b)
        i++
      }
    }
  }
  fmt.Println(i)
}*/
