#include "fixed_point.h"

fixed_point_t 
int_to_fp (int num)
{
    return num * FACTOR;
}

/* rounds the fixed point number down to the nearest integer f(3.6) = 3 */

int
fp_to_int (fixed_point_t fixed_point)
{
    return fixed_point / FACTOR;
}

fixed_point_t
int_div (int a, int b)
{
	return (fixed_point_t) a * FACTOR / b;
}

fixed_point_t
fp_add (fixed_point_t a,fixed_point_t b)
{
    return a + b;
}

fixed_point_t
fp_sub (fixed_point_t a,fixed_point_t b)
{
    return a - b;
}

fixed_point_t
fp_mul (fixed_point_t a,fixed_point_t b)
{
    return INT2LL(a) * b / FACTOR;
}

fixed_point_t
fp_div (fixed_point_t a,fixed_point_t b)
{
    return INT2LL(a) * FACTOR / b;
}

fixed_point_t
fp_int_mul(fixed_point_t a, int b)
{
    return a * b;
}

fixed_point_t
fp_int_div(fixed_point_t a, int b)
{
    return a / b;
}