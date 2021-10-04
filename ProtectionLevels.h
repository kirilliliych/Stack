#ifndef PROTECTIONLEVELS_H

#define PROTECTIONLEVELS_H

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_LEVEL_PROTECTION

#ifdef HASH_LEVEL_PROTECTION

#undef NO_PROTECTION
#define CANARY_LEVEL_PROTECTION

#endif

#ifdef CANARY_LEVEL_PROTECTION

#undef NO_PROTECTION
#define ASSERT_OK(stack) if (IsValid(stack))                                                                       \
                         {                                                                                         \
                             FILE *logs = fopen("logs.txt", "a");                                                  \
                             assert(logs != nullptr);                                                              \
                             fprintf(logs, "ERROR: file %s line %d function %s\n", __FILE__, __LINE__, __func__);  \
                             StackDump(logs, stack);                                                               \
                             printf("ERROR: exiting programme, check logs.txt\n");                                 \
                             fclose(logs);                                                                         \
                             abort();                                                                              \
                         }

#define STACK_CONSTRUCT(stack, capacity) stack.name = #stack;                                                      \
                                         StackCtor(&stack, capacity)

#endif

#ifdef NO_PROTECTION

#undef HASH_LEVEL_PROTECTION
#undef CANARY_LEVEL_PROTECTION

#define ASSERT_OK(stack)
#define STACK_CONSTRUCT(stack, capacity) StackCtor(&stack, capacity)

#endif

#define switch_case(error_line) case  error_line:                                                                  \
                                return #error_line

#ifdef CANARY_LEVEL_PROTECTION

typedef unsigned long long canary_t;
const canary_t Canary = 0xBADF00DDEADBEAF;

#endif
#endif
