package rcipher

import (
  "errors"
  "crypto/sha512"
)

type keyGenerator struct{
  keys *ringInt8
  tmpKey []byte
}


var keysSize = 127
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
  key:=t.keys
  k0v:=key.value
  nextKey:=key.next.next.next.next
  n:=byte(1)
  for i:=0; i<8; i++{
    by:=n
    if i+1<8 {
      by=key.next.value-by
    }else{
      by=k0v-by
    }
    k[i]=(key.value^by)-((key.value>>4)|(key.value<<4))
    if k[i]+1>k[i]{
     k[i]+=1
    }
    key.value=key.value-((by>>4)|(by<<4))
    key=key.next
    n++
  }
  t.keys=nextKey
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
  for i:=0; i<keysSize; i++{
    keys.value=kn[i]
    keys=keys.next
  } 
  return keys
}
