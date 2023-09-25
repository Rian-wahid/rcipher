package rcipher

import (
  "errors"
  "math/bits"
)

type keyGenerator struct{
  keys *ringInt8
  counter uint8
}

var initP = byte(255)

var keysSize = 128

func (t *keyGenerator) getKey(p byte)byte{
  key:=t.keys
  t.counter++
  t.keys=t.keys.next

  a:=mix2byte(key.value,p)
  b:=mix2byte(t.keys.value,t.counter)
  c:=mix3byte(t.keys.next.value,a,b)
  d:=mix3byte(t.keys.next.next.value,b,c)

  key.value=mix2byte(key.value,c)
  t.keys.value=mix2byte(t.keys.value,d)
  
  a+=b
  d^=a
  d=bits.RotateLeft8(d,4)
  c+=d
  b^=c
  b=bits.RotateLeft8(b,3)

  t.keys.next.value=mix2byte(t.keys.next.value,c)
  t.keys.next.next.value=mix2byte(t.keys.next.next.value,d)
  t.keys=t.keys.next.next.next
   
  return nsbox[mix4byte(a,b,c,d)]
}



func newKeyGenerator(key,nonce []byte)(*keyGenerator,error){
  if len(key)!=32 {
    return nil,errors.New("key size must be 32 bytes")
  }
  if len(nonce)!=16 {
    return nil,errors.New("nonce size must be 16 bytes")
  }
  keys:=genKeys(key,nonce)
  keyGen:=&keyGenerator{
    keys:keys,
    counter:1,
  }
  // mix the keys
  p:=initP
  for i:=0; i<2*keysSize; i++{
    p=mix4byte(p,keyGen.getKey(p),key[i%32],nonce[i%16])
  }
  keyGen.counter=1
  return keyGen,nil
}

func genKeys(key, nonce []byte) *ringInt8{
  _ = key[31]
  _ = nonce[15]
  keys:=newRingInt8(keysSize)
  kn:=append(key,nonce...)
  kk:=uint8(255)
  
  for i:= range kn{
    kk=mix2byte(kk,kn[i])
  }
  
  for i:=0; i<keysSize; i++{
    k:=kn[i%48]
    kk=mix3byte(kk,k,uint8(i))
    kn[i%48]=mix2byte(kn[i%48],kk)
    keys.value=kk
    keys=keys.next
  } 
  return keys
}
