#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LEVEL_PROTECTION

#ifdef HASH_LEVEL_PROTECTION
    #define CANARY_LEVEL_PROTECTION
    #define LIGHT_LEVEL_PROTECTION
#endif

#ifdef CANARY_LEVEL_PROTECTION
    #define LIGHT_LEVEL_PROTECTION
#endif

#define ASSERT_OK(stack) if (IsValid(stack))                                                                  \
                     {                                                                                        \
                        FILE *logs = fopen("logs.txt", "a");                                                  \
                        assert(logs != nullptr);                                                              \
                        fprintf(logs, "ERROR: file %s line %d function %s\n", __FILE__, __LINE__, __func__);  \
                        StackDump(logs, stack);                                                               \
                        printf("ERROR: exiting programme, check logs.txt");                                   \
                        fclose(logs);                                                                         \
                        abort();                                                                              \
                     }

#define STACK_CONSTRUCT(stack, capacity) stack.name = #stack;                                                 \
                                         StackCtor(&stack, capacity)

#define switch_case(error_line) case  error_line:                                                             \
                                return #error_line
#define INT_T

#ifdef DOUBLE_T
    const int      code_t = 1;
    const double   Poison = NAN;
    typedef double type;

#endif

#ifdef INT_T
    const int   code_t = 2;
    const int   Poison = 0xBADDED;
    typedef int type;

#endif

#ifdef CHAR_T
    const int   code_t = 3;
    const char  Poison = '\0';
    typedef char type;

#endif

#ifdef CANARY_LEVEL_PROTECTION
    typedef unsigned long long canary_t;

    const canary_t Canary = 0xBADF00DDEADBEAF;

#endif

enum Errors
{
    SIZE_OUT_OF_CAPACITY = 1,
    OUT_OF_MEMORY,
    NEGATIVE_SIZE,
    NEGATIVE_CAPACITY,
    NULLPTR_TO_ARRAY,
    NULL_POP,
    INVALID_PUSH,
    WRONG_SIZE,
    STACK_IS_DESTRUCTED,
    WRONG_LEFT_ARRAY_CANARY,
    WRONG_RIGHT_ARRAY_CANARY,
    WRONG_LEFT_STRUCT_CANARY,
    WRONG_RIGHT_STRUCT_CANARY,
    WRONG_STACK_HASH,
    WRONG_STRUCT_HASH
};

struct Stack_t
{
    #ifdef CANARY_LEVEL_PROTECTION

        canary_t left_struct_canary = 0;

    #endif

    const char *name = nullptr;
    size_t capacity = 0;
    size_t size = 0;
    type *data = nullptr;

    int error;

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
void StackPush(Stack_t *stack, type value);
type StackPop(Stack_t *stack);
void StackNullCheck(Stack_t *stack);
void FillingPoison(Stack_t *stack, size_t start, size_t end);
void StackMemoryRealloc(Stack_t *stack);
void StackBackwardMemoryRealloc(Stack_t *stack);
int  IfPoison(type value);
int  IsValid(Stack_t *stack);
void StackDump(FILE* file, Stack_t *stack);
bool  IfStackDestructed(Stack_t *stack);
const char *TextError(Stack_t *stack);
void PrintArray(FILE *file, Stack_t *stack);
void PlacingCanary(Stack_t *stack, void *temp);
void PrintStack(Stack_t *stack);
unsigned int StackHashFAQ6(Stack_t *stack);
unsigned int StructHashFAQ6(Stack_t *stack);

int main()
{
    Stack_t stack = {};

    STACK_CONSTRUCT(stack, 1);

    return 0;
}

void StackCtor(Stack_t *stack, int capacity)
{
    StackNullCheck(stack);

    if (capacity < 0)
    {
        stack->error = NEGATIVE_CAPACITY;
        ASSERT_OK(stack);
    }
    else
    {
        if (capacity == 0)
        {
            stack->capacity = capacity + 1;
        }

        if (capacity > 0)
        {
            stack->capacity = capacity;
        }

        #ifndef CANARY_LEVEL_PROTECTION

            void *temp = calloc(stack->capacity, sizeof(type));

            if (temp == nullptr)
            {
                stack->error = OUT_OF_MEMORY;
                ASSERT_OK(stack);
            }

            stack->data = (type *) temp;

        #endif

        #ifdef CANARY_LEVEL_PROTECTION

            stack->left_struct_canary  = Canary;
            stack->right_struct_canary = Canary;

            void *temp = malloc(stack->capacity * sizeof(type) + 2 * sizeof(canary_t));

            if (temp == nullptr)
            {
                stack->error = OUT_OF_MEMORY;
                ASSERT_OK(stack);
            }

            PlacingCanary(stack, temp);

        #endif

        stack->size  = 0;
        stack->error = 0;

        FillingPoison(stack, stack->size, stack->capacity);

        #ifdef HASH_LEVEL_PROTECTION

            stack->stack_hash  = StackHashFAQ6(stack);
            stack->struct_hash = StructHashFAQ6(stack);

        #endif
    }
}

void StackPush(Stack_t *stack, type value)
{
    StackNullCheck(stack);
    ASSERT_OK(stack);

    if (stack->capacity - 1 == stack->size)
    {
        StackMemoryRealloc(stack);
    }

    ASSERT_OK(stack);

    if (IfPoison(value))
    {
        stack->error = INVALID_PUSH;
        ASSERT_OK(stack);
    }

    stack->data[stack->size++] = value;

    #ifdef HASH_LEVEL_PROTECTION

        stack->stack_hash  = StackHashFAQ6(stack);
        stack->struct_hash = StructHashFAQ6(stack);

    #endif

    ASSERT_OK(stack);
}

type StackPop(Stack_t *stack)
{
    StackNullCheck(stack);

    ASSERT_OK(stack);

    if (stack->size == 0)
    {
        stack->error = NULL_POP;
        ASSERT_OK(stack);
    }

    if ((stack->capacity >= 4) && (stack->size < ((stack->capacity) / 4)))
    {
        StackBackwardMemoryRealloc(stack);
    }

    ASSERT_OK(stack);

    type temp = stack->data[--(stack->size)];

    stack->data[stack->size] = Poison;

    #ifdef HASH_LEVEL_PROTECTION

    stack->stack_hash  = StackHashFAQ6(stack);
    stack->struct_hash = StructHashFAQ6(stack);

    #endif

    return temp;
}

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

void FillingPoison(Stack_t *stack, size_t start, size_t end)
{
    for (size_t poisoner = start; poisoner < end; ++poisoner)
    {
        stack->data[poisoner] = Poison;
    }
}

void StackMemoryRealloc(Stack_t *stack)
{
    StackNullCheck(stack);

    void *temp = nullptr;

    #ifdef CANARY_LEVEL_PROTECTION

        temp = realloc(&((canary_t *) stack->data)[-1], 2 * stack->capacity * sizeof(type) + 2 * sizeof(canary_t));

    #else

        temp = realloc(stack->data, 2 * stack->capacity * sizeof(type));

    #endif

    if (temp == nullptr)
    {
        #ifdef CANARY_LEVEL_PROTECTION

            temp = realloc(&((canary_t *) stack->data)[-1], (size_t) 1.5 * stack->capacity * sizeof(type) + 2 * sizeof(canary_t));

        #else

            temp = realloc(stack->data, (size_t) 1.5 * stack->capacity * sizeof(type));

        #endif

        if (temp == nullptr)
        {
            #ifdef CANARY_LEVEL_PROTECTION

                temp = realloc(&((canary_t *) stack->data)[-1], (stack->capacity + 1) * sizeof(type) + 2 * sizeof(canary_t));

            #else

                temp = realloc(stack->data, (stack->capacity + 1) * sizeof(type));

            #endif

            if (temp == nullptr)
            {
                stack->error = OUT_OF_MEMORY;
            }
            else
            {
                ++stack->capacity;

                #ifdef CANARY_LEVEL_PROTECTION

                    PlacingCanary(stack, temp);

                #else

                    stack->data = (type *) temp;

                #endif

                stack->data[stack->capacity - 1] = Poison;

                #ifdef HASH_LEVEL_PROTECTION

                    stack->stack_hash  = StackHashFAQ6(stack);
                    stack->struct_hash = StructHashFAQ6(stack);

                #endif
            }
        }
        else
        {
            stack->capacity *= (size_t) 1.5 * stack->capacity;

            #ifdef CANARY_LEVEL_PROTECTION

                PlacingCanary(stack, temp);

            #else

                stack->data = (type *) temp;

            #endif

            FillingPoison(stack, stack->size + 1, stack->capacity);

            #ifdef HASH_LEVEL_PROTECTION

                stack->stack_hash  = StackHashFAQ6(stack);
                stack->struct_hash = StructHashFAQ6(stack);

            #endif
        }
    }
    else
    {
        stack->capacity *= 2;

        #ifdef CANARY_LEVEL_PROTECTION

            PlacingCanary(stack, temp);

        #else

            stack->data = (type *) temp;

        #endif

        FillingPoison(stack, stack->size + 1, stack->capacity);

        #ifdef HASH_LEVEL_PROTECTION

            stack->stack_hash  = StackHashFAQ6(stack);
            stack->struct_hash = StructHashFAQ6(stack);

        #endif
    }
}

void StackBackwardMemoryRealloc(Stack_t *stack)
{
    StackNullCheck(stack);

    stack->capacity /= 4;

    #ifdef CANARY_LEVEL_PROTECTION

        void *temp = realloc(&((canary_t *) stack->data)[-1], (stack->capacity + 1) * sizeof(type) + 2 * sizeof(canary_t));

        PlacingCanary(stack, temp);

    #else

        void *temp = realloc(stack->data, (stack->capacity + 1) * sizeof(type));

        stack->data = (type *) temp;

    #endif

    #ifdef HASH_LEVEL_PROTECTION

        stack->stack_hash  = StackHashFAQ6(stack);
        stack->struct_hash = StructHashFAQ6(stack);

    #endif

    ASSERT_OK(stack);
}

void StackDtor(Stack_t *stack)
{
    StackNullCheck(stack);

    if (stack->data != nullptr)
    {
        #ifdef CANARY_LEVEL_PROTECTION

            free(&(((canary_t *) stack->data)[-1]));

        #else

            free(stack->data);

        #endif
    }

    stack->data     = nullptr;
    stack->size     = -1;
    stack->error    =  0;
    stack->capacity = -1;
    stack = nullptr;

    #ifdef CANARY_LEVEL_PROTECTION

        stack->left_struct_canary  = -1;
        stack->right_struct_canary = -1;

    #endif

    #ifdef HASH_LEVEL_PROTECTION

        stack->stack_hash   = -1;
        stack->struct_hash  = -1;

    #endif
}

int IfPoison(type value)
{
    switch (code_t)
    {
        case 1:  return isnan(value);
        case 2:  return value == 0xBADDED;
        case 3:  return value == '\0';
    }
}

int IsValid(Stack_t *stack)
{
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

        if ((stack->size == 0) && (!IfPoison(stack->data[stack->size])))
        {
            stack->error = WRONG_SIZE;
            return WRONG_SIZE;
        }

        #ifdef CANARY_LEVEL_PROTECTION

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

        #endif

        #ifdef HASH_LEVEL_PROTECTION

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
    StackNullCheck(stack);

    const char *error_code = TextError(stack);

    fprintf(file, "Stack (ERROR #%d: %s [%p] \"%s\") \n"
                  "{\n"
                  "\tsize = %lu\n"
                  "\tcapacity = %lu\n"

                  #ifdef CANARY_LEVEL_PROTECTION

                      "\tleft_struct_canary  = %x\n"
                      "\tright_struct_canary = %x\n"
                      "\tleft_array_canary   = %x\n"
                      "\tright_array_canary  = %x\n"

                  #endif

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

                  #ifdef CANARY_LEVEL_PROTECTION

                      stack->left_struct_canary,
                      stack->right_struct_canary,
                      ((canary_t *) stack->data)[-1],
                      *((canary_t *) &stack->data[stack->capacity]),

                  #endif

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
    if ((stack->data         == nullptr)              &&
        (stack->size         == -1)                   &&
        (stack->error        ==  0)                   &&
        (stack->capacity     == -1)                   &&

        #ifdef CANARY_LEVEL_PROTECTION

            (stack->left_struct_canary  == -1)        &&
            (stack->right_struct_canary == -1)        &&

        #endif

        #ifdef HASH_LEVEL_PROTECTION

            (stack->stack_hash   ==  -1)              &&
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
    switch (stack->error)
    {
        case 0: return "OK";
        switch_case(SIZE_OUT_OF_CAPACITY);
        switch_case(OUT_OF_MEMORY);
        switch_case(NEGATIVE_SIZE);
        switch_case(NEGATIVE_CAPACITY);
        switch_case(NULLPTR_TO_ARRAY);
        switch_case(NULL_POP);
        switch_case(INVALID_PUSH);
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
    switch (code_t)
    {
        case 1:
            for (size_t cur_elem = 0; cur_elem < stack->size; ++cur_elem)
            {
                if (isnan(stack->data[cur_elem]))
                {
                    fprintf(file, "\t\t*[%d] = NAN (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t*[%d] = %lg\n", cur_elem, stack->data[cur_elem]);
                }
            }

            for (size_t cur_elem = stack->size; cur_elem < stack->capacity; ++cur_elem)
            {
                if (isnan(stack->data[cur_elem]))
                {
                    fprintf(file, "\t\t [%d] = NAN (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t [%d] = %lg\n", cur_elem, stack->data[cur_elem]);
                }
            }

            break;


        case 2:
            for (size_t cur_elem = 0; cur_elem < stack->size; ++cur_elem)
            {
                if (stack->data[cur_elem] == Poison)
                {
                    fprintf(file, "\t\t*[%d] = 0xBADDED (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t*[%d] = %d\n", cur_elem, stack->data[cur_elem]);
                }
            }

            for (size_t cur_elem = stack->size; cur_elem < stack->capacity; ++cur_elem)
            {
                if (stack->data[cur_elem] == Poison)
                {
                    fprintf(file, "\t\t [%d] = 0XBADDED (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t [%d] = %d\n", cur_elem, stack->data[cur_elem]);
                }
            }

            break;

        case 3:
            for (size_t cur_elem = 0; cur_elem < stack->size; ++cur_elem)
            {
                if (stack->data[cur_elem] == Poison)
                {
                    fprintf(file, "\t\t*[%d] = \\0 (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t*[%d] = %c\n", cur_elem, stack->data[cur_elem]);
                }
            }

            for (size_t cur_elem = stack->size; cur_elem < stack->capacity; ++cur_elem)
            {
                if (stack->data[cur_elem] == Poison)
                {
                    fprintf(file, "\t\t [%d] = \\0 (Poison!)\n", cur_elem);
                }
                else
                {
                    fprintf(file, "\t\t [%d] = %c\n", cur_elem, stack->data[cur_elem]);
                }
            }

            break;

        default:
            fprintf(file, "\t\tUnknown type element\n");

            break;
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

unsigned int StructHashFAQ6(Stack_t *stack)
{
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

    unsigned long long stack_address = (unsigned long long) stack;

    hash ^= stack_address;

    return hash;
}

unsigned int StackHashFAQ6(Stack_t *stack)
{
    unsigned int hash = 0;

    size_t bytes_to_hash = stack->capacity * sizeof(type) + 2 * sizeof(canary_t);

    for (int cur_byte = 0; cur_byte < bytes_to_hash; ++cur_byte)
    {
        hash += (unsigned char) (*((char *) &((canary_t *) stack->data)[-1] + cur_byte));
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash ^= (hash << 15);

    unsigned long long array_address = (unsigned long long) &((canary_t *) stack->data)[-1];

    hash ^= array_address;

    return hash;
}

void PrintStack(Stack_t *stack)
{
    for (int i = 0; i < stack->size; ++i)
    {
        printf("%d\n", stack->data[i]);
    }

    printf("\n");
}
