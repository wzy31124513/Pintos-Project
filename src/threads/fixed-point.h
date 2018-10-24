#ifndef FIXED_POINT_H
#define FIXED_POINT_H
#include <stdio.h>

#define f 16384

int itf(int x);
int ftinearest(int x );
int fti(int x);
int add(int x,int y);
int sub(int x,int y);
int addxn(int x,int n);
int subxn(int x,int n);
int mul(int x,int y);
int mulxn(int x,int n);
int div(int x,int y);
int divxn(int x,int n);

int itf(int x){
	return x*f;
}

int fti(int x){
	return x/f;
}

int ftinearest(int x ){
	if(x>=0){
		return (x+f/2)/f;
	}else{
		return (x-f/2)/f;
	}
}

int add(int x,int y){
	return x+y;
}

int sub(int x,int y){
	return x-y;
}

int addxn(int x,int n){
	return x+n*f;
}

int subxn(int x,int n){
	return x-n*f;
}

int mul(int x,int y){
	return ((int64_t)x)*y/f;
}

int mulxn(int x,int n){
	return x*n;
}

int div(int x,int y){
	return ((int64_t)x)*f/y;
}

int divxn(int x,int n){
	return x/n;
}

#endif
