// NOTE: We implement a dictionary ADT with <Key, Value> pair using
//       hashTable open addressing with quadratic probing


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#ifndef _DICT_H
#define _DICT_H

typedef unsigned int Index;
typedef Index Position;

struct data;
typedef struct data ET;
struct HashEntry;
typedef struct HashEntry Cell;
struct HashTbl;
typedef struct HashTbl *HashTable;

HashTable initializeTable(int TableSize);
void DestroyTable(HashTable H);
/* NOTE: if the key is already in the table, then we will update the value
 *       to the given one.
 */
HashTable put(char *key, void* value, HashTable H);
HashTable removeKey(char *key, HashTable H);
/* We retrieve the corresponding value from the given key
 */
void* retrieve(char *key, HashTable H);
void printDictionary(HashTable H, char* (*printvalue)(void*));
Position hash(char *key, int TableSize);
Position simpleHash(char *key,int TableSize);

int keyExist(char *key, HashTable H);
int keyDeleted(char *key, HashTable H);
#endif
