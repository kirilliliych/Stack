#ifndef LOGS_H

#define LOGS_H

static const char *DUMPFILE = "logs.txt";
static FILE *logs = fopen(DUMPFILE, "a");
static const int LOG_FILE_NULLPTR = -1;

int PrintToLogs(const char *format ...);

void CloseLogs();

#endif
