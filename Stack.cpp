#include "Protection.h"

void StackCtor(Stack_t *stack, int capacity)
{
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);

    if (capacity < 0)
    {
        stack->error = NEGATIVE_CAPACITY;

        ASSERT_OK(stack);
    }

    if (capacity == 0)
    {
        stack->capacity = capacity + 1;
    }

    if (capacity > 0)
    {
        stack->capacity = capacity;
    }

    #endif

    #ifndef CANARY_LEVEL_PROTECTION

    stack->capacity = capacity;

    void *temp = calloc(stack->capacity, sizeof(type));

    stack->data = (type *) temp;

    #endif

    #ifdef CANARY_LEVEL_PROTECTION

    stack->left_struct_canary  = Canary;
    stack->right_struct_canary = Canary;

    void *temp = calloc(stack->capacity * sizeof(type) + 2 * sizeof(canary_t), 1);

    if (temp == nullptr)
    {
        stack->error = OUT_OF_MEMORY;
        ASSERT_OK(stack);
    }

    PlacingCanary(stack, temp);

    stack->error = 0;

    #endif

    stack->size  = 0;

    FillingPoison(stack);

    #ifdef HASH_LEVEL_PROTECTION

    stack->stack_hash  = StackHashFAQ6(stack);
    stack->struct_hash = StructHashFAQ6(stack);

    #endif
}

void StackPush(Stack_t *stack, const type *value)
{
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);
    ASSERT_OK(stack);

    #endif

    if (stack->capacity - 1 == stack->size)
    {
        StackMemoryRealloc(stack);
    }

    ASSERT_OK(stack);

    stack->data[stack->size++] = *value;

    #ifdef HASH_LEVEL_PROTECTION

    stack->stack_hash  = StackHashFAQ6(stack);
    stack->struct_hash = StructHashFAQ6(stack);

    #endif

    ASSERT_OK(stack);
}

type StackPop(Stack_t *stack)
{
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);
    ASSERT_OK(stack);

    #endif

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

type StackTop(Stack_t *stack)
{
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);
    ASSERT_OK(stack);

    if (stack->size == 0)
    {
        stack->error = EMPTY_TOP_ATTEMPT;
        ASSERT_OK(stack);
    }

    #endif

    return stack->data[stack->size - 1];
}

void StackMemoryRealloc(Stack_t *stack)
{
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);

    void *temp = realloc(&((canary_t *) stack->data)[-1], 2 * stack->capacity * sizeof(type) + 2 * sizeof(canary_t));

    if (temp == nullptr)
    {
        stack->error = OUT_OF_MEMORY;
        ASSERT_OK(stack);
    }

    #else

    void *temp = realloc(stack->data, 2 * stack->capacity * sizeof(type));

    #endif

    stack->capacity *= 2;

    #ifdef CANARY_LEVEL_PROTECTION

    PlacingCanary(stack, temp);

    #else

    stack->data = (type *) temp;

    #endif

    FillingPoison(stack);

    #ifdef HASH_LEVEL_PROTECTION

    stack->stack_hash  = StackHashFAQ6(stack);
    stack->struct_hash = StructHashFAQ6(stack);

    #endif
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
    #ifdef CANARY_LEVEL_PROTECTION

    StackNullCheck(stack);

    free(&(((canary_t *) stack->data)[-1]));

    #else

    free(stack->data);

    #endif

    stack->data     = nullptr;
    stack->size     = -1;
    stack->capacity = -1;

    #ifdef CANARY_LEVEL_PROTECTION

    stack->error = 0;

    stack->left_struct_canary  = -1;
    stack->right_struct_canary = -1;

    #endif

    #ifdef HASH_LEVEL_PROTECTION

    stack->stack_hash   = -1;
    stack->struct_hash  = -1;

    #endif
}
