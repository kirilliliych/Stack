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

    for (int i = 0; i < 9; i++)
    {
        StackPop(&stack);
    }

    StackDtor(&stack);

    printf("ALL");
    return 0;
}
