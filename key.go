package rcipher

import (
  "errors"
)

type keyGenerator struct{
  keys *ringInt8
  counter1 uint8
  counter2 uint8
  tmpKey []byte
}


var keysSize = 127
func (t *keyGenerator) getKey()byte{
  t.counter1++
  if len(t.tmpKey)!=0 {
    r:=nsbox[t.tmpKey[0]]
    if len(t.tmpKey)==1 {
      t.tmpKey=[]byte{}
      return r
    }
    t.tmpKey=t.tmpKey[1:]
    return r
  }
  t.counter2++
  k:=make([]byte,5)
  k1:=t.keys
  k2:=k1.next
  k3:=k2.next
  k4:=k3.next
  k5:=k4.next
  a:=mix2byte(k1.value,t.counter1)
  b:=mix2byte(k2.value,t.counter2)
  c:=mix2byte(k3.value,a)
  d:=mix2byte(k4.value,b)
  e:=mix2byte(k5.value,c)
  k[0],k[1],k[2],k[3],k[4]=a,b,c,d,e
  n:=mix2byte(a,mix4byte(b,c,d,e))
  k1.value=mix2byte(n,a)
  k2.value=mix2byte(b,n)
  k3.value=mix2byte(n,c)
  k4.value=mix2byte(d,n)
  k5.value=mix2byte(n,e)
  t.keys=k5.next
  t.tmpKey=k[1:]
  return nsbox[k[0]]
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
    counter1:1,
    counter2:1,
    tmpKey:[]byte{},
  }
  //mix key
  for i:=0; i<keysSize; i++{
    keyGen.getKey()
  }
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
