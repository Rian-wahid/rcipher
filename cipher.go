package rcipher

import (
  "crypto/sha256"
  "hash"
  "io"
  "errors"
  "sync"
)

type Cipher struct {
  hash hash.Hash
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
    var wg sync.WaitGroup
    wg.Add(1)
    bb:=t.temp[:tmpLen-32]
    go func(){
      t.cipher.hash.Write(bb)
      wg.Done()
    }()
    n,err:=t.cipher.writer.Write(bb)
    wg.Wait()
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
  hashResult:=t.cipher.hash.Sum(nil)
  match:=0
  for i:=range hashResult{
    if hashResult[i]==t.temp[i] {
      match++
    }
  }
  if match!=len(hashResult) {
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
  var wg sync.WaitGroup
  wg.Add(1)
  go func ()  {
    t.hash.Write(p)
    wg.Done()
  }()
  result:=make([]byte,len(p))
  for i:= range p {
    xk:=t.keyGen.getKey()
    e:=p[i]^xk
    result[i]=e
  }
  n,err=t.writer.Write(result)
  wg.Wait()
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
  h.Reset()
  h.Write(in)
  
  return &Cipher{
    keyGen: keyGen,
    hash: h,
    writer: w,
    start: false,
    end: false,
  },nil
}

