#ifndef _BASE64_H  
#define _BASE64_H  
  
#include <stdlib.h>  
#include <string.h>  
  
unsigned char *base64_encode(unsigned char *str, long str_size);  
  
unsigned char *base64_decode(unsigned char *code, long code_size);  
  
#endif  
