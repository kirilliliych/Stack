#include "Protection.h"

int main()
{
    Stack_t stack = {};

    STACK_CONSTRUCT(stack, 1);

    int value = 20;

    for (int i = 0; i < 11; ++i)
    {
        StackPush(&stack, &i);
    }

    for (int i = 0; i < 12; i++)
    {
        StackPop(&stack);
    }

    StackDtor(&stack);

    return 0;
}
