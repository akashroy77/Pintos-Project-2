#ifndef __LIB_KERNEL_FIXED_POINT_H
#define __LIB_KERNEL_FIXED_POINT_H

// Creating a 17.14 fixed point structure
#define SCALING_FACTOR 14
#define FACTOR 16384
#define INT2LL(val) ((long long int)val)
#define FP_ONE ((fixed_point_t) FACTOR)
#define N59OF60  (fixed_point_t) 16110

typedef int fixed_point_t;

fixed_point_t int_to_fp(int num);
int fp_to_int (fixed_point_t fixed_point);

fixed_point_t int_div (int a, int b);

fixed_point_t fp_add (fixed_point_t a,fixed_point_t b);
fixed_point_t fp_sub (fixed_point_t a,fixed_point_t b);
fixed_point_t fp_mul (fixed_point_t a,fixed_point_t b);
fixed_point_t fp_div (fixed_point_t a,fixed_point_t b);

fixed_point_t fp_int_mul (fixed_point_t a, int b);
fixed_point_t fp_int_div (fixed_point_t a, int b);

#endif /* lib/fixed_point.h */
