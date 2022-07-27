// This is a simple Set implementation based on array.
// The time complexity will be linear

#ifndef _SIMPLE_SET_H
#define _SIMPLE_SET_H 

// ET is shortfor ElementType
typedef char ET[20];
typedef struct SetRecord *SimpleSet;

struct SetRecord {
    int Capacity; // the maximum number of elements in the SimpleSet
    int Size;     // the current number of elements in the SimpleSet
    ET *Array;
    int (*isFull)(SimpleSet);
    void (*add)(ET, SimpleSet);
    int (*find)(ET, SimpleSet);
    void (*removeElement)(ET, SimpleSet);
};
void newSimpleSet(SimpleSet*);
SimpleSet createSimpleSet(int);
void printSimpleSet(SimpleSet);
void disposeSimpleSet(SimpleSet);
#endif 

