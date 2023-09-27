package rcipher

type ringInt8 struct{
  next *ringInt8
  value uint8
}
func newRingInt8(size int)*ringInt8{
  if size<=0 {
    return nil
  }
  initial:=&ringInt8{}
  initial.next=initial
  prev:=initial
  for i:=1; i<size; i++{
    r:=&ringInt8{}
    prev.next=r
    prev=r
  }
  prev.next=initial
  return initial
}

func mix2byte(a,b byte)byte{
  n:= sbox[a^b]^((b<<4)|(b>>4))
  if n!=a && n!=b{
    return n
  }
  return sbox[n]
}

func mix3byte(a,b,c byte)byte{
  n:=mix2byte(a,mix2byte(b,c))
  if n!=a && n!=b && n!=c {
    return n
  }
  n=mix2byte(n,n)
  if n!=a && n!=b && n!=c {
    return n
  }
  n=sbox[n]
  if n!=a && n!=b && n!=c {
    return n
  }
  return sbox[n]
}

func mix4byte(a,b,c,d byte)byte{
  return mix2byte(a,mix3byte(b,c,d))
}
