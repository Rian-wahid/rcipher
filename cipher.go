package rcipher

import (
  "crypto/sha256"
  "hash"
  "io"
  "errors"
)

type Cipher struct {
  hash hash.Hash
  keyGen *keyGenerator
  writer io.Writer
  key []byte
  nonce []byte
  p byte
  start bool
}

type Decipher struct{
  cipher *Cipher
  temp []byte
}

func NewDecipher(key ,nonce []byte,w io.Writer)(*Decipher,error){
  cipher,err:=NewCipher(key,nonce,w)
  if err!=nil {
  return nil,err
  }
  return &Decipher{
    cipher: cipher,
    temp: []byte{},
  },nil
}

func (t *Decipher) Write(p []byte)(n int,err error){
  t.cipher.start=true
  if len(p)==0 {
    return 0,nil
  }
  for i:= range p {
    xk:=(*t.cipher.keyGen).getKey(t.cipher.p)
    d:=p[i]^xk
    t.cipher.p=sbox[(sbox[xk]>>3)|(sbox[d]<<3)]
    t.temp=append(t.temp, d)
  }
  tmpLen:=len(t.temp)
  n=0
  if tmpLen>32 {
    bb:=t.temp[:tmpLen-32]
    _,err:=t.cipher.hash.Write(bb)
    if err!=nil {
      return 0,err
    }
    n,err=t.cipher.writer.Write(bb)
    if err!=nil{
      return n,err
    }
    t.temp=t.temp[tmpLen-32:]
  }
  return n,nil
}

func (t *Decipher) end()error{
  t.cipher.hash.Reset()
  err:=initHash(t.cipher.key,&t.cipher.hash)  
  if err!= nil {
    return err
  }
  t.cipher.p=initP
  t.temp=[]byte{}
  keyGen,err:=newKeyGenerator(t.cipher.key,t.cipher.nonce)
  if err!=nil {
    return err
  }
  t.cipher.keyGen=keyGen
  return nil
}

func (t *Decipher) End()(n int,err error){
  if !t.cipher.start{
    return 0,nil
  }

  if len(t.temp)<32{
    err:=t.end()
    if err!=nil {
      return 0,err
    }
    return 0,errors.New("authentication failed, missing bytes?")
  }
  hashResult:=t.cipher.hash.Sum(nil)
  match:=0
  for i:=range hashResult{
    if hashResult[i]==t.temp[i] {
      match++
    }
  }
  err=t.end()
  if err!=nil {
    return 0,err
  }
  if match!=len(hashResult) {
    return 0,errors.New("authentication failed")
  }
  return 0,nil
}

func (t *Cipher) Write(p []byte)(n int,err error){
  t.start=true
  if len(p)==0 {
    return 0,nil
  }
  _,err=t.hash.Write(p)
  if err!=nil {
    return 0,err
  }
  result:=make([]byte,len(p))
  for i:= range p {
    xk:=t.keyGen.getKey(t.p)
    e:=p[i]^xk
    t.p=sbox[(sbox[xk]>>3)|(sbox[p[i]]<<3)]
    result[i]=e
  }
  n,err=t.writer.Write(result)
  
  if err!=nil {
    return n,err
  }
  return n,nil
}

func (t *Cipher) End()(n int, err error){
  if !t.start {
    return 0,nil
  }
  
  n,err=t.Write(t.hash.Sum(nil))
  if err!= nil {
    return n,err
  }
  t.hash.Reset()
  err=initHash(t.key,&t.hash)
  if err!=nil {
    return n,err
  }
  keyGen,err:=newKeyGenerator(t.key,t.nonce)

  if err!=nil {
    return n,err
  }
  t.keyGen=keyGen
  t.p=initP
  return n,nil
}

func NewCipher(key,nonce []byte, w io.Writer)(*Cipher,error){
  keyGen,err:=newKeyGenerator(key,nonce)
  if err!=nil{
    return nil,err
  }
  h:=sha256.New()
  err=initHash(key,&h)
  if err!=nil {
    return nil,err
  }
  return &Cipher{
    p:initP,
    keyGen: keyGen,
    hash: h,
    writer: w,
    key:append([]byte{},key...),
    nonce:append([]byte{},nonce...),
  },nil
}

func initHash(key []byte,h *hash.Hash)error{
  _,err:=(*h).Write(key)
  if err!=nil {
    return err
  }
  (*h).Reset()
  in:=(*h).Sum(nil)
  _,err=(*h).Write(in)
  if err!=nil {
    return err
  }
  return nil
}
