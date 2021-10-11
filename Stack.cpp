#include "Protection.h"

void StackCtor(Stack_t *stack, int capacity)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);

        if (capacity < 0)
        {
            stack->error = NEGATIVE_CAPACITY;
            ASSERT_OK(stack);
        }
        else
        {
            stack->capacity = capacity;

            if (capacity == 0)
            {
                stack->data = nullptr;
            }
            else
            {
                stack->left_struct_canary  = Canary;
                stack->right_struct_canary = Canary;

                void *memory = calloc(stack->capacity * sizeof(stack_element_t) + 2 * sizeof(canary_t), 1);

                if (memory == nullptr)
                {
                    stack->error = OUT_OF_MEMORY;
                    ASSERT_OK(stack);
                }

                PlacingCanary(stack, memory);
            }

            stack->error = 0;
            stack->status = CONSTRUCTED;
        }
    )

    IF_NO_PROTECTION
    (
        stack->capacity = capacity;

        if (capacity == 0)
        {
            stack->data == nullptr;
        }
        else
        {
            stack->data = (stack_element_t *) calloc(stack->capacity, sizeof(stack_element_t));
        }
    )

    stack->size = 0;

    IF_HASH_LEVEL_PROTECTION
    (
        if (stack->capacity != 0)
        {
            FillingPoison(stack);

            stack->array_hash = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                                  sizeof(stack_element_t) + 2 * sizeof(canary_t));

            stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                                2 * sizeof(canary_t) + 2 * sizeof(int));
        }
    )
}

void StackPush(Stack_t *stack, const stack_element_t *value)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);
    )

    if (stack->capacity == 0)
    {
        ++stack->capacity;

        IF_NO_PROTECTION
        (
            stack->data = (stack_element_t *) calloc(stack->capacity, sizeof(stack_element_t));
        )

        IF_CANARY_LEVEL_PROTECTION
        (
            stack->left_struct_canary  = Canary;
            stack->right_struct_canary = Canary;

            void *memory = calloc(stack->capacity * sizeof(stack_element_t) + 2 * sizeof(canary_t), 1);

            if (memory == nullptr)
            {
                stack->error = OUT_OF_MEMORY;
                ASSERT_OK(stack);
            }

            PlacingCanary(stack, memory);

            stack->error = 0;
            stack->status = CONSTRUCTED;

            IF_HASH_LEVEL_PROTECTION
            (
                FillingPoison(stack);

                stack->array_hash = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                                      sizeof(stack_element_t) + 2 * sizeof(canary_t));

                stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                                    2 * sizeof(canary_t) + 2 * sizeof(int));
            )
        )
    }

    IF_CANARY_LEVEL_PROTECTION
    (
        ASSERT_OK(stack);
    )

    if (stack->capacity - 1 == stack->size)
    {
        StackMemoryRealloc(stack);
    }

    ASSERT_OK(stack);

    stack->data[stack->size++] = *value;

    IF_HASH_LEVEL_PROTECTION
    (
        stack->array_hash  = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                               sizeof(stack_element_t) + 2 * sizeof(canary_t));

        stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                            2 * sizeof(canary_t) + 2 * sizeof(int));
    )

    ASSERT_OK(stack);
}

stack_element_t StackPop(Stack_t *stack)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);

        if (stack->size == 0)
        {
            stack->error = NULL_POP;
        }

        ASSERT_OK(stack);
    )

    if ((stack->capacity >= 4) && (stack->size < ((stack->capacity) / 4)))
    {
        StackBackwardMemoryRealloc(stack);
    }

    ASSERT_OK(stack);

    stack_element_t popped_element = stack->data[--(stack->size)];
    stack->data[stack->size] = Poison;

    IF_HASH_LEVEL_PROTECTION
    (
        stack->array_hash = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                               sizeof(stack_element_t) + 2 * sizeof(canary_t));

        stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                            2 * sizeof(canary_t) + 2 * sizeof(int));
    )

    return popped_element;
}

stack_element_t StackTop(Stack_t *stack)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);
        ASSERT_OK(stack);

        if (stack->size == 0)
        {
            stack->error = EMPTY_TOP_ATTEMPT;
            ASSERT_OK(stack);
        }
    )

    return stack->data[stack->size - 1];
}

void StackMemoryRealloc(Stack_t *stack)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);

        void *memory = realloc(((canary_t *) stack->data) - 1, EXPAND_MEMORY_COEF * stack->capacity * sizeof(stack_element_t) + 2 * sizeof(canary_t));

        if (memory == nullptr)
        {
            stack->error = OUT_OF_MEMORY;
            ASSERT_OK(stack);
        }
    )

    IF_NO_PROTECTION
    (
        void *memory = realloc(stack->data, EXPAND_MEMORY_COEF * stack->capacity * sizeof(stack_element_t));
    )

    stack->capacity *= EXPAND_MEMORY_COEF;

    IF_CANARY_LEVEL_PROTECTION
    (
        PlacingCanary(stack, memory);
    )

    IF_NO_PROTECTION
    (
        stack->data = (stack_element_t *) memory;
    )

    IF_HASH_LEVEL_PROTECTION
    (
        FillingPoison(stack);

        stack->array_hash = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                               sizeof(stack_element_t) + 2 * sizeof(canary_t));

        stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                            2 * sizeof(canary_t) + 2 * sizeof(int));
    )
}

void StackBackwardMemoryRealloc(Stack_t *stack)
{
    StackNullCheck(stack);

    stack->capacity /= 4;

    IF_CANARY_LEVEL_PROTECTION
    (
        void *memory = realloc(((canary_t *) stack->data) - 1, (stack->capacity + 1) * sizeof(stack_element_t) + 2 * sizeof(canary_t));

        PlacingCanary(stack, memory);
    )

    IF_NO_PROTECTION
    (
        void *memory = realloc(stack->data, (stack->capacity + 1) * sizeof(stack_element_t));
        stack->data = (stack_element_t *) memory;
    )

    IF_HASH_LEVEL_PROTECTION
    (
        stack->array_hash = CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                               sizeof(stack_element_t) + 2 * sizeof(canary_t));

        stack->stack_hash = CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                            2 * sizeof(canary_t) + 2 * sizeof(int));
    )

    ASSERT_OK(stack);
}

void StackDtor(Stack_t *stack)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);
        ASSERT_OK(stack);

        free(((canary_t *) stack->data) - 1);
    )

    IF_NO_PROTECTION
    (
        free(stack->data);
    )

    stack->data     = nullptr;
    stack->size     = -1;
    stack->capacity = -1;

    IF_CANARY_LEVEL_PROTECTION
    (
        stack->error = 0;
        stack->status = DESTRUCTED;
        stack->left_struct_canary  = -1;
        stack->right_struct_canary = -1;
    )

    IF_HASH_LEVEL_PROTECTION
    (
        stack->array_hash  = -1;
        stack->stack_hash  = -1;
    )
}

void StackDump(FILE* out, Stack_t *stack, location_t location)
{
    assert(out != nullptr);

    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);

        const char *error_code = TextError(stack);

        fprintf(out, "ERROR: file %s line %d function %s\n"
                     "Stack (ERROR #%d: %s [%p] \"%s\")\n",

                     location.file, location.line, location.func,
                     stack->error, error_code, stack, stack->name);

        if ((stack->error == STACK_IS_DESTRUCTED) || (stack->error == USING_STACK_ZERO_CAPACITY))
        {
            return;
        }
    )

    IF_NO_PROTECTION
    (
        fprintf(out, "Stack\n");
    )

    fprintf(out, "{\n"
                 "\tsize = %u\n"
                 "\tcapacity = %u\n",

                 stack->size,
                 stack->capacity);

    IF_CANARY_LEVEL_PROTECTION
    (
        fprintf(out, "\tleft_struct_canary  = %llx\n"
                     "\tright_struct_canary = %llx\n",

                     stack->left_struct_canary,
                     stack->right_struct_canary);

        if (stack->data != nullptr)
        {
            fprintf(out, "\tleft_array_canary   = %llx\n"
                         "\tright_array_canary  = %llx\n",

                         ((canary_t *) stack->data)[-1],
                         *((canary_t *) (stack->data + stack->capacity)));
        }
    )

    IF_HASH_LEVEL_PROTECTION
    (
        fprintf(out, "\tstack_hash = %x\n"
                     "\tarray_hash = %x\n",

                     stack->stack_hash,
                     stack->array_hash);
    )

    fprintf(out, "\tdata[%p]\n",

                 stack->data);

    if (stack->data != nullptr)
    {
        if (stack->error != NEGATIVE_CAPACITY)
        {
            fprintf(out, "\t{\n");
            PrintArray(out, stack);
            fprintf(out, "\t}\n");
        }
    }

    fprintf(out, "}\n\n\n");

    fclose(out);
}
