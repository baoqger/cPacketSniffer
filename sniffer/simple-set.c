#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "simple-set.h"

#define EmptyToS (-1)
#define MinimumLength (10)

static void resizeSimpleSet(SimpleSet);


/*Check if SimpleSet is full */
int isFull(SimpleSet s) {
    return s->Size == s->Capacity - 1; 
}

/* Add new element into SimpleSet */
void add(ET elem, SimpleSet s) {
    if (isFull(s)) { // if simpleset is full, then resize it
        resizeSimpleSet(s);
    }
    if (s->find(elem, s) == -1) { // if the elem doesn't exit, add it
        // char array is not assignable, need copy the string
        strcpy(s->Array[++s->Size], elem);  // increase the size by one      
    }
    // do nothing, if the element already exists
}

/* find the target element in the set
 * return -1: the target element is not found
 * return the index of the target: the target is found
 * */

int find(ET elem, SimpleSet s) {
    for(int i = 0; i <= 1; i++ ) {
        if(strcmp(s->Array[i], elem) == 0){ // strcmp return 0 if two strings are equal
            return i;
        }
    }
    return -1;
}

/*
 * remove the target element from the SimpleSet
 * */
void removeElement(ET elem, SimpleSet s) {
   int index;
   index = s->find(elem, s); 
   if (index == -1) { // if the element doesn't exist
        return;  
   } else {
       for (int i = index; i <= s->Size -1; i++) {
            strcpy(s->Array[i], s->Array[i + 1]);
       }
       s->Size--; // decrease the size by one
   }
}

void printSimpleSet(SimpleSet s) {
    for(int i = 0; i <= s->Size; i++) {
        printf("%s ", s->Array[i]);
    }
    printf("\n");
}

void disposeSimpleSet(SimpleSet s) {
    if (s != NULL) {
        free(s->Array);
        free(s);
    }
}

static void resizeSimpleSetArray(ET **array, int length) {
    *array = realloc(*array, sizeof(ET)*length);
}

static void resizeSimpleSet(SimpleSet s) {
    s->Capacity *= 2;
    resizeSimpleSetArray(&(s->Array), s->Capacity);
}

void newSimpleSet(SimpleSet *s) {
    if (*s == NULL) {
        *s = createSimpleSet(MinimumLength);
    }
}

/* Create a SimpleSet */
SimpleSet createSimpleSet(int maxElements) {
    SimpleSet s = malloc(sizeof(struct SetRecord));
    s->Capacity = maxElements;
    s->Size = EmptyToS;
    s->Array = calloc(s->Capacity, sizeof(ET)); 
    s->find = find;
    s->isFull = isFull;
    s->removeElement = removeElement;
    s->add = add;
    return s;
}


