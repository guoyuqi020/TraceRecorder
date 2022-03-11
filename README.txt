# TraceRecorder
================================

## Usage: 
```
clang -fsanitize=trace ./a.cpp -o a.out
TREC_TRACE_DIR=</path/to/your/directory> ./a.out
```
The trace files will be placed under the folder specified by TREC_TRACE_DIR.
Please remember to use the absolute path.
