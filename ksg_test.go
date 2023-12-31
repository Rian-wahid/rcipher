package rcipher

import (
  "testing"
  "github.com/stretchr/testify/assert"
  "fmt"
  "crypto/rand"
  "sync"
)

var wg sync.WaitGroup

func ksgTestHelperUniqueKey(t *testing.T,round,size int){
  key,nonce:=make([]byte,32),make([]byte,16)
  rand.Read(key)
  rand.Read(nonce)
  keyGen,err:=newKeyGenerator(key,nonce)
  assert.Nil(t,err)
  uniqueKey:=make(map[string]bool)
  for i:=0; i<round; i++{
    k:=make([]byte,size)
    for j:= range k{
      k[j]=keyGen.getKey()
    }
    uniqueKey[string(k)]=true
  }
  fmt.Printf("INFO total unique %d byte key",size)
  fmt.Printf(" generated in %d round: %d\n",round,len(uniqueKey))
  wg.Done()
}
func TestKeyGenerator(t *testing.T){
  key,nonce:=make([]byte,31),make([]byte,16)
  _,err:=newKeyGenerator(key,nonce)
  assert.NotNil(t,err)
  key,nonce=make([]byte,32),make([]byte,15)
  _,err=newKeyGenerator(key,nonce)
  assert.NotNil(t,err)
  wg.Add(10)
  go ksgTestHelperUniqueKey(t,256,2)
  go ksgTestHelperUniqueKey(t,1000,2)
  go ksgTestHelperUniqueKey(t,10000,2)
  go ksgTestHelperUniqueKey(t,50000,2)

  go ksgTestHelperUniqueKey(t,50000,3)
  go ksgTestHelperUniqueKey(t,100000,3)
  go ksgTestHelperUniqueKey(t,500000,4)
  go ksgTestHelperUniqueKey(t,750000,5)

  go ksgTestHelperUniqueKey(t,2000000,6)
  go ksgTestHelperUniqueKey(t,4000000,8)
  wg.Wait()
}
