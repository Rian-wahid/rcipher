package rcipher

import (
  "errors"
  "crypto/sha512"
)

type keyGenerator struct{
  keys *ringInt8
  tmpKey []byte
}


var keysSize = 257
func (t *keyGenerator) getKey()byte{
  if len(t.tmpKey)!=0 {
    r:=t.tmpKey[0]
    if len(t.tmpKey)==1 {
      t.tmpKey=[]byte{}
      return r
    }
    t.tmpKey=t.tmpKey[1:]
    return r
  }

  k:=make([]byte,8)
  k1:=t.keys
  k2:=k1.next
  k3:=k2.next
  k4:=k3.next
  k5:=k4.next
  k6:=k5.next
  k7:=k6.next
  k8:=k7.next
  n:=mix4byte(k1.value,k2.value,k3.value,k4.value)
  n2:=mix4byte(k5.value,k6.value,k7.value,k8.value)
  x:=nsbox[n^n2]
  x2:=nsbox[x^n2]
  k[0]=nsbox[k1.value-x]
  k[1]=nsbox[k2.value-x2] 
  k[2]=nsbox[k3.value-x]
  k[3]=nsbox[k4.value-x2]
  k[4]=nsbox[k5.value-x]
  k[5]=nsbox[k6.value-x2]
  k[6]=nsbox[k7.value-x]
  k[7]=nsbox[k8.value-x2]
  k1.value=mix2byte(n,k1.value)
  k2.value=mix2byte(n2,k2.value)
  k3.value=mix2byte(n,k3.value)
  k4.value=mix2byte(n2,k4.value)
  k5.value=mix2byte(n,k5.value)
  k6.value=mix2byte(n2,k6.value)
  k7.value=mix2byte(n,k7.value)
  k8.value=mix2byte(n2,k8.value)
  t.keys=k5
  t.tmpKey=k[1:]
  return k[0]
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
    tmpKey:[]byte{},
  }
  return keyGen,nil
}

func genKeys(key, nonce []byte) *ringInt8{
  h:=sha512.New()
  h.Write(append(key,nonce...))
  kn:=h.Sum(nil)
  h.Reset()
  h.Write(append(nonce,key...))
  kn=append(kn,h.Sum(nil)...)
  keys:=newRingInt8(keysSize)
  prev:=byte(255)
  for i:=0; i<keysSize; i++{
    keys.value=kn[i%128]^prev
    prev=kn[i%128]
    keys=keys.next
  } 
  return keys
}
