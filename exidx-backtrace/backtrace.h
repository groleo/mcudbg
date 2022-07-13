/*
 * Copyright 2022 NXP
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __BACKTRACE_H__
#define __BACKTRACE_H__

#include <stdint.h>

int btexidx_unwind(uint32_t functions[], uint32_t addresses[], unsigned nb_elem);
const char *btexidx_function_name(uint32_t pc);

// PC - r15 : program counter
// LR - r14 : the return address
// SP - r13 : stack pointer
// FP - r7 : frame pointer
#define getPC(regval) asm volatile ("mov %0, r15" : "=r" (regval))
#define getLR(regval) asm volatile ("mov %0, r14" : "=r" (regval))
#define getSP(regval) asm volatile ("mov %0, r13" : "=r" (regval))
#define getFP(regval) asm volatile ("mov %0, r7" : "=r" (regval))

#endif /* __BACKTRACE_H__ */
