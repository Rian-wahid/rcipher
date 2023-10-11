package rcipher

import (
  "crypto/sha256"
  "crypto/hmac"
  "hash"
  "io"
  "errors"
)

type Cipher struct {
  hmac hash.Hash
  keyGen *keyGenerator
  writer io.Writer
  start bool
  end bool
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
  if t.cipher.end {
    return 0,errors.New("cannot use this, you must be create new 'object' decipher")
  }
  t.cipher.start=true
  if len(p)==0 {
    return 0,nil
  }
  n=0
  for i:= range p {
    xk:=(*t.cipher.keyGen).getKey()
    d:=p[i]^xk
    t.temp=append(t.temp, d)
  }
  tmpLen:=len(t.temp)
  if tmpLen>32 {
    bb:=t.temp[:tmpLen-32]
    t.cipher.hmac.Write(bb)
    n,err:=t.cipher.writer.Write(bb)
    if err!=nil{
      return n,err
    }
    t.temp=t.temp[tmpLen-32:]
  }
  return n,nil
}



func (t *Decipher) End()(n int,err error){
  if !t.cipher.start{
    return 0,nil
  }
  t.cipher.end=true

  if len(t.temp)<32{
    return 0,errors.New("authentication failed, missing bytes?")
  }

  match:=hmac.Equal(t.temp,t.cipher.hmac.Sum(nil))
  if !match {
    return 0,errors.New("authentication failed")
  }
  return 0,nil
}

func (t *Cipher) Write(p []byte)(n int,err error){
  if t.end {
    return 0,errors.New("cannot use this. you must be create new 'object' cipher")
  }
  t.start=true
  if len(p)==0 {
    return 0,nil
  }
  t.hmac.Write(p)
  result:=make([]byte,len(p))
  for i:= range p {
    xk:=t.keyGen.getKey()
    e:=p[i]^xk
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
  n,err=t.Write(t.hmac.Sum(nil))
  t.end=true
  if err!= nil {
    return n,err
  }
  return n,nil
}

func NewCipher(key,nonce []byte, w io.Writer)(*Cipher,error){
  keyGen,err:=newKeyGenerator(key,nonce)
  if err!=nil{
    return nil,err
  }
  
  h:=sha256.New()
  
  h.Write(key)
  in:=h.Sum(nil)
  return &Cipher{
    keyGen: keyGen,
    hmac: hmac.New(sha256.New,in),
    writer: w,
    start: false,
    end: false,
  },nil
}

