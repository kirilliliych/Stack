#include "Protection.h"

void StackNullCheck(Stack_t *stack)
{
    if (stack == nullptr)
    {
        FILE *logs = fopen("logs.txt", "a");

        fprintf(logs, "Stack (ERROR NULLPTR) [0x000000]\n");

        fflush(logs);
        fclose(logs);

        abort();
    }
}

void FillingPoison(Stack_t *stack)
{
    assert(stack != nullptr);

    for (size_t poisoner = stack->size; poisoner < stack->capacity; ++poisoner)
    {
        stack->data[poisoner] = Poison;
    }
}

#ifdef CANARY_LEVEL_PROTECTION

int IsValid(Stack_t *stack)
{
    StackNullCheck(stack);

    if (stack->error != 0)
    {
        return stack->error;
    }
    else
    {
        if (IfStackDestructed(stack))
        {
            stack->error = STACK_IS_DESTRUCTED;
            return STACK_IS_DESTRUCTED;
        }

        if (stack->size >= stack->capacity)
        {
            stack->error = SIZE_OUT_OF_CAPACITY;
            return SIZE_OUT_OF_CAPACITY;
        }

        if (stack->size > 10000000)
        {
            stack->error = NEGATIVE_SIZE;
            return NEGATIVE_SIZE;
        }

        if (stack->capacity > 10000000)
        {
            stack->error = NEGATIVE_CAPACITY;
            return NEGATIVE_CAPACITY;
        }

        if (stack->data == nullptr)
        {
            stack->error = NULLPTR_TO_ARRAY;
            return NULLPTR_TO_ARRAY;
        }

        if (((canary_t *) stack->data)[-1] != Canary)
        {
            stack->error = WRONG_LEFT_ARRAY_CANARY;
            return WRONG_LEFT_ARRAY_CANARY;
        }

        if (*((canary_t *) &stack->data[stack->capacity]) != Canary)
        {
            stack->error = WRONG_RIGHT_ARRAY_CANARY;
            return WRONG_RIGHT_ARRAY_CANARY;
        }

        if (stack->left_struct_canary != Canary)
        {
            stack->error = WRONG_LEFT_STRUCT_CANARY;
            return WRONG_LEFT_STRUCT_CANARY;
        }

        if (stack->right_struct_canary != Canary)
        {
            stack->error = WRONG_RIGHT_STRUCT_CANARY;
            return WRONG_RIGHT_STRUCT_CANARY;
        }

        #ifdef HASH_LEVEL_PROTECTION

        for (size_t poison_checker = stack->size; poison_checker < stack->capacity; ++poison_checker)
        {
            if (stack->data[poison_checker] != Poison)
            {
                stack->error = WRONG_SIZE;
                return WRONG_SIZE;
            }
        }

        if (stack->struct_hash != StructHashFAQ6(stack))
        {
            stack->error = WRONG_STRUCT_HASH;
            return WRONG_STRUCT_HASH;
        }

        if (stack->stack_hash  != StackHashFAQ6(stack))
        {
            stack->error = WRONG_STACK_HASH;
            return WRONG_STACK_HASH;
        }

        #endif

        return 0;
    }
}

void StackDump(FILE* file, Stack_t *stack)
{
    assert(file != nullptr);
    StackNullCheck(stack);

    const char *error_code = TextError(stack);

    if (stack->error == STACK_IS_DESTRUCTED)
    {
        fprintf(file, "Stack (ERROR #%d: %s [%p] \"%s\") \n\n\n", stack->error, error_code, stack, stack->name);

        return;
    }

    fprintf(file, "Stack (ERROR #%d: %s [%p] \"%s\") \n"
                  "{\n"
                  "\tsize = %u\n"
                  "\tcapacity = %u\n"
                  "\tleft_struct_canary  = %llx\n"
                  "\tright_struct_canary = %llx\n"
                  "\tleft_array_canary   = %llx\n"
                  "\tright_array_canary  = %llx\n"

                  #ifdef HASH_LEVEL_PROTECTION

                  "\tstruct_hash = %x\n"
                  "\tstack_hash = %x\n"

                  #endif

                  "\tdata[%p]\n"
                  "\t{\n",

                  stack->error,
                  error_code,
                  stack,
                  stack->name,
                  stack->size,
                  stack->capacity,
                  stack->left_struct_canary,
                  stack->right_struct_canary,
                  ((canary_t *) stack->data)[-1],
                  *((canary_t *) &stack->data[stack->capacity]),

                  #ifdef HASH_LEVEL_PROTECTION

                  stack->struct_hash,
                  stack->stack_hash,

                  #endif

                  stack->data);

    if ((stack->data != nullptr) && (stack->error != NEGATIVE_CAPACITY))
    {
        PrintArray(file, stack);
    }

    fprintf(file, "\t}\n"
                  "}\n\n\n");

    fflush(file);
    fclose(file);
}

bool IfStackDestructed(Stack_t *stack)
{
    StackNullCheck(stack);

    if ((stack->data         == nullptr)              &&
        (stack->error        ==  0)                   &&
        (stack->size         == -1)                   &&
        (stack->capacity     == -1)                   &&
        (stack->left_struct_canary  == -1)            &&
        (stack->right_struct_canary == -1)            &&

        #ifdef HASH_LEVEL_PROTECTION

        (stack->stack_hash   ==  -1)                  &&
        (stack->struct_hash  ==  -1))

        #endif

        #ifndef HASH_LEVEL_PROTECTION

        (1))

        #endif

    {
        return 1;
    }

    return 0;
}

const char *TextError(Stack_t *stack)
{
    StackNullCheck(stack);

    switch (stack->error)
    {
        case 0: return "OK";
        switch_case(SIZE_OUT_OF_CAPACITY);
        switch_case(OUT_OF_MEMORY);
        switch_case(NEGATIVE_SIZE);
        switch_case(NEGATIVE_CAPACITY);
        switch_case(NULLPTR_TO_ARRAY);
        switch_case(NULL_POP);
        switch_case(WRONG_SIZE);
        switch_case(STACK_IS_DESTRUCTED);
        switch_case(WRONG_LEFT_ARRAY_CANARY);
        switch_case(WRONG_RIGHT_ARRAY_CANARY);
        switch_case(WRONG_LEFT_STRUCT_CANARY);
        switch_case(WRONG_RIGHT_STRUCT_CANARY);
        switch_case(WRONG_STACK_HASH);
        switch_case(WRONG_STRUCT_HASH);
        default: return "UNKNOWN ERROR";
    }
}

void PrintArray(FILE *file, Stack_t *stack)
{
    StackNullCheck(stack);

    for (size_t cur_elem = 0; cur_elem < stack->size; ++cur_elem)
    {
        fprintf(file, "\t\t*[%d] = %lg\n", cur_elem, stack->data[cur_elem]);
    }

    for (size_t cur_elem = stack->size; cur_elem < stack->capacity; ++cur_elem)
    {
        fprintf(file, "\t\t[%d] = %lg (Poison!)\n", cur_elem, stack->data[cur_elem]);
    }
}

void PlacingCanary(Stack_t *stack, void *temp)
{
    StackNullCheck(stack);
    assert(temp != nullptr);

    canary_t *left_canary = (canary_t *) temp;
    *left_canary = Canary;

    stack->data = (type *) &left_canary[1];

    canary_t *right_canary = (canary_t *) &(stack->data[stack->capacity]);
    *right_canary = Canary;
}

#endif

#ifdef HASH_LEVEL_PROTECTION

unsigned int StructHashFAQ6(Stack_t *stack)
{
    StackNullCheck(stack);

    unsigned int hash = 0;

    size_t bytes_to_hash = 2 * sizeof(size_t) + sizeof(char *) + sizeof(type *) + sizeof(canary_t) + sizeof(int);

    for (int cur_byte = 0; cur_byte < bytes_to_hash; ++cur_byte)
    {
        hash += (unsigned char) (*((char *) stack + cur_byte));
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    for (int cur_byte = 0; cur_byte < sizeof(canary_t); ++cur_byte)
    {
        hash += (unsigned char) (*((char *) stack + bytes_to_hash + 2 * sizeof(unsigned int) + cur_byte));
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash ^= (hash << 15);

    unsigned int stack_address = (unsigned int) stack;

    hash ^= stack_address;

    return hash;
}

unsigned int StackHashFAQ6(Stack_t *stack)
{
    StackNullCheck(stack);

    unsigned int hash = 0;

    size_t bytes_to_hash = stack->capacity * sizeof(type) + 2 * sizeof(canary_t);

    for (size_t cur_byte = 0; cur_byte < bytes_to_hash; ++cur_byte)
    {
        hash += (unsigned char) (*((char *) &((canary_t *) stack->data)[-1] + cur_byte));
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash ^= (hash << 15);

    unsigned int array_address = (unsigned int) &((canary_t *) stack->data)[-1];
    hash ^= array_address;

    return hash;
}

#endif
