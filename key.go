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

  a:=key.value^p
  b:=t.keys.value^sbox[a^t.counter]
  c:=t.keys.next.value^sbox[b]
  d:=t.keys.next.next.value^sbox[c]


  key.value=sbox[(key.value>>4)|(c<<4)]
  t.keys.value=sbox[(t.keys.value>>4)|(d<<4)]
  
  a+=b
  d^=a
  d=bits.RotateLeft8(d,4)
  c+=d
  b^=c
  b=bits.RotateLeft8(b,3)

  t.keys.next.value=sbox[(c>>4)|(d<<4)]
  t.keys.next.next.value=sbox[(d>>4)|(c<<4)]
  t.keys=t.keys.next.next.next
  a=sbox[a^c]
  b=sbox[b^d]
 
  return nsbox[a^b]
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
    p^=sbox[keyGen.getKey(p)^sbox[key[i%32]^nonce[i%16]]]
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
  
  for i:= range key{
    kk^=sbox[kn[i]]^bits.RotateLeft8(kk,4)
  }
  
  for i:=0; i<keysSize; i++{
    k:=kn[i%48]
    kk^=sbox[k+uint8(i)]
    kn[i%48]^=sbox[kk]
    keys.value=kk^k^bits.RotateLeft8(k,4)
    keys=keys.next
  } 
  return keys
}
