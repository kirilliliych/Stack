#ifndef STACK_H_INCLUDE

#define STACK_H_INCLUDE

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int type;
static double Poison = 666;

struct Stack_t
{
    #ifdef CANARY_LEVEL_PROTECTION

    canary_t left_struct_canary = 0;

    const char *name = nullptr;

    int error = 0;

    #endif

    size_t capacity = 0;
    size_t size = 0;
    type *data = nullptr;

    #ifdef HASH_LEVEL_PROTECTION

    unsigned int stack_hash  = 0;
    unsigned int struct_hash = 0;

    #endif

    #ifdef CANARY_LEVEL_PROTECTION

    canary_t right_struct_canary = 0;

    #endif
};

void StackCtor(Stack_t *stack, int capacity);
void StackDtor(Stack_t *stack);
void StackPush(Stack_t *stack, const type *value);
type StackPop(Stack_t *stack);
type StackTop(Stack_t *stack);
void StackMemoryRealloc(Stack_t *stack);
void StackBackwardMemoryRealloc(Stack_t *stack);

#endif
