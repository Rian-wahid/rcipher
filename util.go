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
