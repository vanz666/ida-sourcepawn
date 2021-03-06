# ida-sourcepawn
A processor module for IDA that allows disassembling SMX binaries.

Supports cross-referencing, recognition of stack and global variables, displaying the value of the stack pointer, and instruction comments.

Written for Python 2.7 and tested on IDA Pro 6.8 and 7.2 with IDAPython plugin, it may not work on recent IDA versions.

Parsing of debug symbols is not yet implemented, but it may be implemented in the future.

![ida-sourcepawn](https://user-images.githubusercontent.com/63844820/110215147-554b9b80-7eb9-11eb-8ea2-c36781eb3ba1.png)

### Problems
- If the branching instruction refers to a lower address, the stack pointer may not be traced correctly.
- Subroutine calling instructions may also incorrectly recognize a stack pointer change if the previous instruction did not specify the number of arguments passed to the function.
- Pointers vs Constants is a problem because the executable does not contain a relocation table, and the code and data are in different memory segments, so pointers can start at zero. If you are sure that the immediate value of the operand is a pointer, you can mark it as offset to the data segment.

## Installation
Open the ida69 directory for IDA Pro 6.xx, or ida70 for IDA Pro 7.xx, and copy the contents to the root folder with the IDA Pro installed.
