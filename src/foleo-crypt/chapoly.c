#include "chacha20.c"
#include "poly1305.c"

/*
todo:

generate key from block=0
this returns 64-bytes, discard the second 32 and keep the first 32
split the first 32 into (16,16) byte blocks to be used for (r,s) respectively.
start the actual chacha cipher at block=1


 Key:
  000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
  016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................

   Nonce:
   000  00 00 00 00 00 01 02 03 04 05 06 07              ............

   The ChaCha state setup with key, nonce, and block counter zero:
         61707865  3320646e  79622d32  6b206574
         83828180  87868584  8b8a8988  8f8e8d8c
         93929190  97969594  9b9a9998  9f9e9d9c
         00000000  00000000  03020100  07060504

   The ChaCha state after 20 rounds:
         8ba0d58a  cc815f90  27405081  7194b24a
         37b633a8  a50dfde3  e2b8db08  46a6d1fd
         7da03782  9183a233  148ad271  b46773d1
         3cc1875a  8607def1  ca5c3086  7085eb87

*/
