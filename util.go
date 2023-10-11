package rcipher

type ringUint32 struct{
  next *ringUint32
  value uint32
}
func newRingUint32(size int)*ringUint32{
  if size<=0 {
    return nil
  }
  initial:=&ringUint32{}
  initial.next=initial
  prev:=initial
  for i:=1; i<size; i++{
    r:=&ringUint32{}
    prev.next=r
    prev=r
  }
  prev.next=initial
  return initial
}

