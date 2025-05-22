# Contributing guidelines

Thank you for taking your time to improve TCPDirect. We would appreciate if you
follow the contributing guidelines to make review of changes easier.

## Submitting changes

1. Fork TCPDirect repository on https://github.com/Xilinx-CNS/tcpdirect
2. Make local short-lived branch off of public master.
3. Develop on branch locally. Please describe the changes you have made in
the commit messages.
4. Try to follow the coding conventions used in the files you edit.
5. Check that the TCPDirect Unit Tests pass. See
[DEVELOPING.md # How to run unit tests](./DEVELOPING.md#how-to-run-unit-tests)
for further instructions.
6. Push branch to your fork of TCPDirect repository.
7. Create a new Pull Request. Please describe what feature testing you have done.
8. Address review comments.
9. You need to get sign-off of two other developers before the Pull Request
can be merged.

## Summary of coding conventions

In general try to follow the style that is used in the file.
Most of the files use:

1. Line length limit of 79 characters.
2. Two space indentation.
3. C style comments (no C++ style comments).
4. Opening braces are not put on their own line.
5. No space between keyword and bracket.

For instance,

```c
/* This is a comment */
if( ! conditional_expr ) {
  statement1;
  statement2;
}
```

## Footnotes

```yaml
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: Copyright (C) 2020-2024 Advanced Micro Devices, Inc.
```
