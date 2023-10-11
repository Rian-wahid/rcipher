package rcipher

import (
  "errors"
  "crypto/sha512"
  "encoding/binary"
  "math/bits"
)

type keyGenerator struct{
  keys *ringUint32
  tmpKey []byte
}

func zeroByteHelper(b byte)byte{
  r:=b+1
  if r<b{
    r=b-1
  }
  return r
}

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

  k:=make([]byte,16)
  key:=t.keys
  k0v:=key.value
  nextKey:=key.next.next.next
  for i:=0; i<16; i+=4{
    var a uint32
    if i+4<16 {
      a=key.next.value
    }else{
      a=k0v
    }
    b:=(key.value^a)-bits.RotateLeft32(key.value,8)
    k[i]=zeroByteHelper(byte(b))
    k[i+1]=zeroByteHelper(byte(b>>8))
    k[i+2]=zeroByteHelper(byte(b>>16))
    k[i+3]=zeroByteHelper(byte(b>>24))
    key.value=key.value-bits.RotateLeft32(a^b,24)
    key=key.next
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

func genKeys(key, nonce []byte) *ringUint32{
  h:=sha512.New()
  h.Write(append(key,nonce...))
  kn:=h.Sum(nil)
  h.Reset()
  h.Write(append(nonce,key...))
  kn=append(kn,h.Sum(nil)...)
  keys:=newRingUint32(32)  
  for i:=0; i<32; i++{
    ind:=i*4
    keys.value=binary.BigEndian.Uint32(kn[ind:ind+4])
    keys=keys.next
  } 
  return keys
}
