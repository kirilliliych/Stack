#ifndef PROTECTION_H_INCLUDE

#define PROTECTION_H_INCLUDE

#include "ProtectionLevels.h"
#include "Stack.h"

enum Errors
{
    SIZE_OUT_OF_CAPACITY = 1,
    OUT_OF_MEMORY,
    NEGATIVE_SIZE,
    NEGATIVE_CAPACITY,
    NULLPTR_TO_ARRAY,
    NULL_POP,
    EMPTY_TOP_ATTEMPT,
    WRONG_SIZE,
    STACK_IS_DESTRUCTED,
    WRONG_LEFT_ARRAY_CANARY,
    WRONG_RIGHT_ARRAY_CANARY,
    WRONG_LEFT_STRUCT_CANARY,
    WRONG_RIGHT_STRUCT_CANARY,
    WRONG_STACK_HASH,
    WRONG_STRUCT_HASH
};

void StackNullCheck(Stack_t *stack);

void FillingPoison(Stack_t *stack);

int  IsValid(Stack_t *stack);

void StackDump(FILE* file, Stack_t *stack);

bool  IfStackDestructed(Stack_t *stack);

const char *TextError(Stack_t *stack);

void PrintArray(FILE *file, Stack_t *stack);

void PlacingCanary(Stack_t *stack, void *temp);

unsigned int StackHashFAQ6(Stack_t *stack);

unsigned int StructHashFAQ6(Stack_t *stack);

#endif
