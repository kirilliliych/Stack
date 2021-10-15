#include "Protection.h"

int main()
{
    Stack_t stack = {};

    STACK_CONSTRUCT(stack, 0);

    int value = 20;

    for (int i = 0; i < 10; i++)
    {
        StackPush(&stack, &i);
    }

    for (int i = 0; i < 9; i++)
    {
        StackPop(&stack);
    }

    StackDtor(&stack);

    printf("Programme finished successfully");

    return 0;
}
