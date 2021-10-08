#include "Protection.h"

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

void PrintArray(FILE *file, Stack_t *stack)
{
    IF_CANARY_LEVEL_PROTECTION
    (
        StackNullCheck(stack);
    )

    for (size_t cur_elem = 0; cur_elem < stack->size; ++cur_elem)
    {
        fprintf(file, "\t\t*[%d] = %lg\n", cur_elem, stack->data[cur_elem]);
    }

    IF_CANARY_LEVEL_PROTECTION
    (
        for (size_t cur_elem = stack->size; cur_elem < stack->capacity; ++cur_elem)
        {
            fprintf(file, "\t\t[%d] = %lg (Poison!)\n", cur_elem, stack->data[cur_elem]);
        }
    )
}

IF_CANARY_LEVEL_PROTECTION
(
    void StackNullCheck(Stack_t *stack)
    {
        if (stack == nullptr)
        {
            FILE *logs = fopen(DUMPFILE, "a");

            fprintf(logs, "Stack (ERROR NULLPTR) [0x000000], file %s line %d function %s\n\n\n", __FILE__, __LINE__, __func__);

            printf("ERROR: exiting programme, check logs.txt\n");

            fclose(logs);

            abort();
        }
    }

    int UsingStackZeroCapacity(Stack_t *stack)
    {
        if ((stack->data == nullptr) &&
            (stack->capacity == 0)   &&
            (stack->size == 0))
        {
            return USING_STACK_ZERO_CAPACITY;
        }

        return 0;
    }

    int IsValid(Stack_t *stack)
    {
        StackNullCheck(stack);

        if (stack->error != 0)
        {
            return stack->error;
        }
        else
        {
            if (UsingStackZeroCapacity(stack))
            {
                stack->error = USING_STACK_ZERO_CAPACITY;
                return USING_STACK_ZERO_CAPACITY;
            }

            if (stack->status == DESTRUCTED)
            {
                stack->error = STACK_IS_DESTRUCTED;
                return STACK_IS_DESTRUCTED;
            }

            if (stack->status != CONSTRUCTED)
            {
                stack->error = STACK_IS_NOT_CONSTRUCTED;
                return STACK_IS_NOT_CONSTRUCTED;
            }

            if (stack->size >= stack->capacity)
            {
                stack->error = SIZE_OUT_OF_CAPACITY;
                return SIZE_OUT_OF_CAPACITY;
            }

            if (stack->size > NEGATIVE_SIZE_T)
            {
                stack->error = NEGATIVE_SIZE;
                return NEGATIVE_SIZE;
            }

            if (stack->capacity > NEGATIVE_SIZE_T)
            {
                stack->error = NEGATIVE_CAPACITY;
                return NEGATIVE_CAPACITY;
            }

            if (stack->data == nullptr)
            {
                stack->error = NULLPTR_TO_ARRAY;
                return NULLPTR_TO_ARRAY;
            }

            if (*(((canary_t *) stack->data) - 1) != Canary)
            {
                stack->error = WRONG_LEFT_ARRAY_CANARY;
                return WRONG_LEFT_ARRAY_CANARY;
            }

            if (*((canary_t *) (stack->data + stack->capacity)) != Canary)
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

            IF_HASH_LEVEL_PROTECTION
            (
                for (size_t poison_checker = stack->size; poison_checker < stack->capacity; ++poison_checker)
                {
                    if (stack->data[poison_checker] != Poison)
                    {
                        stack->error = WRONG_SIZE;
                        return WRONG_SIZE;
                    }
                }

                if (stack->array_hash != CalculatingHash(((canary_t *) stack->data) - 1, stack->capacity *
                                                            sizeof(stack_element_t) + 2 * sizeof(canary_t)))
                {
                    stack->error = WRONG_ARRAY_HASH;
                    return WRONG_ARRAY_HASH;
                }

                if (stack->stack_hash != CalculatingHash(stack, 2 * sizeof(size_t) + sizeof(char *) + sizeof(stack_element_t *) +
                                                         2 * sizeof(canary_t) + 2 * sizeof(int)))
                {
                    stack->error = WRONG_STACK_HASH;
                    return WRONG_STACK_HASH;
                }
            )

            return 0;
        }
    }

    const char *TextError(Stack_t *stack)
    {
        StackNullCheck(stack);

        #define SWITCH_CASE_(error_line) case   error_line:   \
                                         return #error_line
        switch (stack->error)
        {
            case 0: return "NO_ERRORS";
            SWITCH_CASE_(SIZE_OUT_OF_CAPACITY);
            SWITCH_CASE_(OUT_OF_MEMORY);
            SWITCH_CASE_(NEGATIVE_SIZE);
            SWITCH_CASE_(NEGATIVE_CAPACITY);
            SWITCH_CASE_(USING_STACK_ZERO_CAPACITY);
            SWITCH_CASE_(NULLPTR_TO_ARRAY);
            SWITCH_CASE_(NULL_POP);
            SWITCH_CASE_(EMPTY_TOP_ATTEMPT);
            SWITCH_CASE_(WRONG_SIZE);
            SWITCH_CASE_(STACK_IS_DESTRUCTED);
            SWITCH_CASE_(STACK_IS_NOT_CONSTRUCTED);
            SWITCH_CASE_(WRONG_LEFT_ARRAY_CANARY);
            SWITCH_CASE_(WRONG_RIGHT_ARRAY_CANARY);
            SWITCH_CASE_(WRONG_LEFT_STRUCT_CANARY);
            SWITCH_CASE_(WRONG_RIGHT_STRUCT_CANARY);
            SWITCH_CASE_(WRONG_ARRAY_HASH);
            SWITCH_CASE_(WRONG_STACK_HASH);
            default: return "UNKNOWN ERROR";
        }

        //#undef SWITCH_CASE_(error_line)

    }

    void PlacingCanary(Stack_t *stack, void *memory)
    {
        StackNullCheck(stack);
        assert(memory != nullptr);

        canary_t *left_canary = (canary_t *) memory;
        *left_canary = Canary;

        stack->data = (stack_element_t *) (left_canary + 1);

        canary_t *right_canary = (canary_t *) (stack->data + stack->capacity);
        *right_canary = Canary;
    }
)

IF_HASH_LEVEL_PROTECTION
(
    void FillingPoison(Stack_t *stack)
    {
        assert(stack != nullptr);

        for (size_t poisoner = stack->size; poisoner < stack->capacity; ++poisoner)
        {
            stack->data[poisoner] = Poison;
        }
    }

    unsigned int CalculatingHash(const void *hash_from, size_t bytes_to_hash)
    {
        assert(hash_from != nullptr);

        unsigned int hash = 0;

        for (size_t cur_byte = 0; cur_byte < bytes_to_hash; ++cur_byte)
        {
            hash += (unsigned char) (*((char *) hash_from + cur_byte));
            hash += (hash << 10);
            hash ^= (hash >> 6);
        }

        hash += (hash << 3);
        hash ^= (hash >> 11);
        hash ^= (hash << 15);

        unsigned int stack_address = (unsigned int) hash_from;

        hash ^= stack_address;

        return hash;
    }
)
