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

#include "backtrace.h"
#include <stdlib.h>
#include <string.h>

// IHI0038B_ehabi.pdf

typedef struct backtrace_frame_regs
{
    uint32_t fp;
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
} backtrace_frame_regs_t;

typedef struct unwind_control_block
{
    uint32_t vrs[16];
    const uint32_t *current;
    int remaining;
    int byte;
} unwind_control_block_t;

// Exceptions Index Table
typedef struct eit
{
    uint32_t fnoffset; //prel31 offset (see §4.4.2) to the start of a function, with bit 31 clear
    uint32_t insn;
} eit_t;

// use readelf -u to dump the ARM.exidx
#define EXIDX_CANTUNWIND 0x00000001
#define REG_PC 15
#define REG_LR 14
#define REG_SP 13
#define REG_FP 7
void gcoOS_Print(const char*, ...);

/* These symbols point to the unwind index and should be provided by the linker script */
extern const uint32_t __exidx_start;
extern const uint32_t __exidx_end;

const eit_t* btexidx_start = (eit_t*)&__exidx_start;
const eit_t* btexidx_end = (eit_t*)&__exidx_end;


typedef enum
{
    _URC_OK = 0, /* operation completed successfully */
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8,
    _URC_FAILURE = 9 /* unspecified failure of some kind */
} _Unwind_Reason_Code;


/* This will prevent the linking of libgcc unwinder code */
void __aeabi_unwind_cpp_pr0(void);
void __aeabi_unwind_cpp_pr1(void);
void __aeabi_unwind_cpp_pr2(void);

void __aeabi_unwind_cpp_pr0(void)
{
    longjmp(0,0);
}

void __aeabi_unwind_cpp_pr1(void)
{
}

void __aeabi_unwind_cpp_pr2(void)
{
}


static inline __attribute__((always_inline))
uint32_t
btexidx_prel31_to_addr(const uint32_t *prel31)
{
    uint32_t offset = *prel31;
    /* Sign extend to 32 bits.  */
    if (offset & (1 << 30))
        offset |= 1u << 31;
    else
        offset &= ~(1u << 31);

    return offset + (uint32_t)prel31;
}


/* Perform a binary search for RETURN_ADDRESS in TABLE.
 * The table contains NREC entries.  */
static const struct eit *
btexidx_eit_search(
        const eit_t *idxtbl_start
        , const eit_t *idxtbl_end
        , uint32_t needle_fn)
{
    int middle;
    uint32_t middle_fn;
    uint32_t next_fn;

    while (1)
    {
        middle = (idxtbl_end - idxtbl_start) / 2;
        middle_fn = btexidx_prel31_to_addr(&idxtbl_start[middle].fnoffset);
        next_fn = btexidx_prel31_to_addr(&idxtbl_start[middle+1].fnoffset) - 1;
        if (idxtbl_start > idxtbl_end)
            return NULL;
        if (needle_fn < middle_fn)
        {
            idxtbl_end = idxtbl_end - middle - 1;
        }
        else if (needle_fn <= next_fn)
        {
            return &idxtbl_start[middle];
        }
        else
        {
            idxtbl_start = idxtbl_start + middle + 1;
        }
    }
    return NULL;
}


// gcc-flag required:  -mpoke-function-name
static const char *
btexidx_get_function_name(uint32_t *address)
{
    uint32_t flag_word = *(uint32_t *)(address - 4);
    if ((flag_word & 0xff000000) == 0xff000000) {
        return (const char *)(address - 4 - (flag_word & 0x00ffffff));
    }
    return "unknown";
}


static _Unwind_Reason_Code
btexidx_get_next_byte(unwind_control_block_t *ucb, uint8_t *next_byte)
{
    uint32_t instruction;

    if (ucb->remaining == 0)
    {
        return _URC_OK;
    }

    /* Extract the current instruction */
    instruction = ((*ucb->current) >> (ucb->byte << 3)) & 0xff;

    /* Move the next byte */
    --ucb->byte;
    if (ucb->byte < 0) {
        ++ucb->current;
        ucb->byte = 3;
    }
    --ucb->remaining;

    *next_byte = instruction;
    return _URC_CONTINUE_UNWIND;
}


static int
unwind_control_block_init(unwind_control_block_t *ucb
        , const uint32_t *instructions
        , const backtrace_frame_regs_t *frame
        )
{
    /* Initialize control block */
    memset(ucb, 0, sizeof(unwind_control_block_t));
    ucb->current = instructions;

    /* Is the a short unwind description */
    if ((*instructions & 0xff000000) == 0x80000000) {
        ucb->remaining = 3;
        ucb->byte = 2;
        /* Is the a long unwind description */
    } else if ((*instructions & 0xff000000) == 0x81000000) {
        ucb->remaining = ((*instructions & 0x00ff0000) >> 14) + 2;
        ucb->byte = 1;
    } else
        return -1;

    /* Initialize the virtual register set */
    if (frame) {
        ucb->vrs[REG_FP] = frame->fp;
        ucb->vrs[REG_SP] = frame->sp;
        ucb->vrs[REG_LR] = frame->lr;
        ucb->vrs[REG_PC] = 0;
    }

    return 0;
}


/* 9.3 Frame unwinding instructions */
static _Unwind_Reason_Code
personality_routine_exec(unwind_control_block_t *ucb)
{
    _Unwind_Reason_Code rc;
    uint8_t byte1, byte2;
    uint32_t mask;
    uint32_t reg;
    uint32_t *vsp;

    /* Consume all instruction bytes */
    while (1) {
        rc = btexidx_get_next_byte(ucb, &byte1);
        if (rc == _URC_OK)
            return rc;

        if ((byte1 & 0xc0) == 0x00) {
            /* 00xxxxxx: vsp = vsp + (xxxxxx << 2) + 4 */
            ucb->vrs[REG_SP] += ((byte1 & 0x3f) << 2) + 4;

        } else if ((byte1 & 0xc0) == 0x40) {
            /* 01xxxxxx: vsp = vsp - (xxxxxx << 2) - 4 */
            ucb->vrs[REG_SP] -= ((byte1 & 0x3f) << 2) - 4;

        } else if (byte1 == 0x80) {
            /* 10000000 00000000: Refuse to unwind */
            rc = btexidx_get_next_byte(ucb, &byte2);
            if (rc != _URC_CONTINUE_UNWIND)
                return rc;
            if (byte2 == 0x00)
                return _URC_FAILURE;

        } else if ((byte1 & 0xf0) == 0x80) {
            /* 1000iiii iiiiiiii (i not all 0)
             * Pop up to 12 integer registers under masks {r15-r12}, {r11-r4} */
            uint8_t popped_ps = 0;
            rc = btexidx_get_next_byte(ucb, &byte2);
            if (rc != _URC_CONTINUE_UNWIND)
                return rc;

            /* Pop registers using mask */
            vsp = (uint32_t *)ucb->vrs[REG_SP];
            mask = (byte1 << 8 | byte2) & 0x0fff;

            if ((mask & (1 << (13 - 4)) != 0)) {
                popped_ps = 1;
            }

            reg = 4;
            while (mask != 0) {
                if ((mask & 0x001) != 0)
                    ucb->vrs[reg] = *vsp++;
                mask = mask >> 1;
                ++reg;
            }

            /*
             * 10.3 Frame unwinding instructions (Remark b) for Pop
             * The sole exception to this rule is popping r13,
             * when the writeback of the loaded value to vsp is
             * delayed until after the whole instruction has completed.
             * 
             * Update VSP only if not popped.
             */
            if (!popped_ps)
                ucb->vrs[REG_SP] = (uint32_t)vsp;

        } else if ((byte1 & 0xf0) == 0x90
                && byte1 != 0x9d
                && byte1 != 0x9f
                ) {
            /* 1001nnnn (nnnn != 13,15)
             * vsp = r[nnnn] */
            ucb->vrs[REG_SP] = ucb->vrs[byte1 & 0x0f];

        } else if ((byte1 & 0xf0) == 0xa0) {
            /* 10100nnn: pop r4-r[4+nnn] */
            vsp = (uint32_t *)ucb->vrs[REG_SP];

            for (reg = 4; reg <= (byte1 & 0x07) + 4; ++reg)
                ucb->vrs[reg] = *vsp++;

            /* 10101nnn: pop r4-r[4+nnn], r14 */
            if (byte1 & 0x08)
                ucb->vrs[REG_LR] = *vsp++;

            ucb->vrs[REG_SP] = (uint32_t)vsp;

        } else if (byte1 == 0xb0) {
            /* 10110000: Finish */
            if (ucb->vrs[REG_PC] == 0)
                ucb->vrs[REG_PC] = ucb->vrs[REG_LR];

            /* All done unwinding */
            continue;//return _URC_OK;

        } else if (byte1 == 0xb1) {
            /* 10110001: Spare */
            rc = btexidx_get_next_byte(ucb, &byte2);
            if (rc != _URC_CONTINUE_UNWIND)
                return rc;

            /* 10110001 00000000: Spare */
            /* 10110001 xxxxyyyy: Spare (xxxx != 0000) */
            if (byte2 == 0
                    || (byte2 & 0xF0)
               )
                return _URC_FAILURE;

            /* 10110001 0000iiii (i not all 0)
             * Pop integer registers under mask {r3, r2, r1, r0} */
            vsp = (uint32_t *)ucb->vrs[REG_SP];
            reg = 0;
            while (byte2 != 0) {
                if ((byte2 & 0x01) != 0)
                    ucb->vrs[reg] = *vsp++;
                byte2 = byte2 >> 1;
                ++reg;
            }
            ucb->vrs[REG_SP] = (uint32_t)vsp;

        } else if (byte1 == 0xb2) {
            /* 10110010 uleb128: vsp = vsp + 0x204 + (uleb128 << 2) */
            rc = btexidx_get_next_byte(ucb, &byte2);
            if (rc != _URC_CONTINUE_UNWIND)
                return rc;

            ucb->vrs[REG_SP] += 0x204 + (byte2 << 2);

        } else if (byte1 == 0xb3
                || byte1 == 0xc8
                || byte1 == 0xc9
                ) {
            /* pop VFP double-precision registers */
            vsp = (uint32_t *)ucb->vrs[REG_SP];

            /* D[ssss]-D[ssss+cccc] */
            ucb->vrs[REG_LR] = *vsp++;

            if (byte1 == 0xc8) {
                /* D[16+sssss]-D[16+ssss+cccc] */
                ucb->vrs[REG_LR] |= 1 << 16;
            }

            if (byte1 != 0xb3) {
                /* D[sssss]-D[ssss+cccc] */
                ucb->vrs[REG_LR] |= 1 << 17;
            }

            ucb->vrs[REG_SP] = (uint32_t)vsp;


        } else if ((byte1 & 0xfc) == 0xb4) {
            /* 101101nn: Spare (was Pop FPA) */
            return _URC_FAILURE;

        } else if (byte1 == 0xc7) {
            /* 11000111 00000000: Spare */
            /* 11000111 xxxxyyyy: Spare (xxxx != 0000) */
            rc = btexidx_get_next_byte(ucb, &byte2);
            if (rc != _URC_CONTINUE_UNWIND)
                return rc;

            if (byte2 == 0x00
                    || (byte2 & 0xF0)
               )
                return _URC_FAILURE;

        } else if ((byte1 & 0xf8) == 0xb8 /* FSTMFDX */
                || (byte1 & 0xf8) == 0xd0 /* VPUSH */
                ) {
            /* 10111nnn: Pop VFP double-precision registers D[8]-D[8+nnn] (FSTMFDX) */
            /* 11010nnn: Pop VFP double-precision registers D[8]-D[8+nnn] (VPUSH) */
            ucb->vrs[REG_LR] = 0x80 | (byte1 & 0x07);

            if ((byte1 & 0xf8) == 0xd0) {
                ucb->vrs[REG_LR] = 1 << 17;
            }

        } else {
            return _URC_FAILURE;
        }
    }

    return _URC_OK;
}


static inline __attribute__((always_inline))
uint32_t *
read_psp(void)
{
    /* Read the current PSP and return its value as a pointer */
    uint32_t psp;

    __asm volatile (
            "   mrs %0, psp \n"
            : "=r" (psp) : :
            );

    return (uint32_t*)psp;
}


static _Unwind_Reason_Code
btexidx_next_frame(backtrace_frame_regs_t *frame)
{
    unwind_control_block_t ucb;
    const eit_t *eit_idx;
    const uint32_t *instructions;
    _Unwind_Reason_Code rc;

    /* The index table is searched for the entry E that
     * matches the return address (in VRS[r15]).
     * If no matching entry is found */
    eit_idx = btexidx_eit_search(btexidx_start, btexidx_end, frame->pc);
    if (eit_idx == NULL) {
        gcoOS_Print("btexidx_eit_search: no matching entry is found\n");
        return _URC_FAILURE;
    }

    /* or if the entry contains the special bitpattern EXIDX_CANTUNWIND (see §5),
     * the unwinder returns to its caller with _URC_FAILURE */
    if (eit_idx->insn == EXIDX_CANTUNWIND) {
        //gcoOS_Print("EXIDX_CANTUNWIND\n");
        return _URC_FAILURE;
    }

    /* Get the pointer to the first unwind instruction */
    if (eit_idx->insn & 0x80000000)
        instructions = &eit_idx->insn;
    else
        instructions = (uint32_t *)btexidx_prel31_to_addr(&eit_idx->insn);

    if (unwind_control_block_init(&ucb, instructions, frame) < 0) {
        gcoOS_Print("unwind_control_block_init\n");
        return _URC_FAILURE;
    }

    /* Execute the unwind instructions. */
    //while ((rc = personality_routine_exec(&ucb)) == _URC_OK)
    //	;
    rc = personality_routine_exec(&ucb);
    if (rc != _URC_OK) {
        gcoOS_Print("personality_routine_exec\n");
        return rc;
    }

    /* Set the virtual pc to the virtual lr if this is the first unwind */
    if (ucb.vrs[REG_PC] == 0)
        ucb.vrs[REG_PC] = ucb.vrs[REG_LR];

    /* Check for exception return */
    /* TODO Test with other ARM processors to verify this method. */
    if ((ucb.vrs[REG_PC] & 0xf0000000) == 0xf0000000) {
        /* According to the Cortex Programming Manual (p.44), the stack address is always 8-byte aligned (Cortex-M7).
           Depending on where the exception came from (MSP or PSP), we need the right SP value to work with.

           ucb.vrs[REG_FP] contains the right value, so take it and align it by 8 bytes, store it as the current
           SP to work with (ucb.vrs[REG_SP]) which is then saved as the current (virtual) frame's SP.
           */
        uint32_t *stack;
        ucb.vrs[REG_SP] = (ucb.vrs[REG_FP] & ~7);

        /* If we need to start from the MSP, we need to go down X words to find the PC, where:
           X=2  if it was a non-floating-point exception
           X=20 if it was a floating-point (VFP) exception

           If we need to start from the PSP, we need to go up exactly 6 words to find the PC.
           See the ARMv7-M Architecture Reference Manual p.594 and Cortex-M7 Processor Programming Manual p.44/p.45 for details.
           */
        if ((ucb.vrs[REG_PC] & 0xc) == 0) {
            /* Return to Handler Mode: MSP (0xffffff-1) */
            stack = (uint32_t*)(ucb.vrs[REG_SP]);

            /* The PC is always 2 words down from the MSP, if it was a non-floating-point exception */
            stack -= 2;

            /* If there was a VFP exception (0xffffffe1), the PC is located another 18 words down */
            if ((ucb.vrs[REG_PC] & 0xf0) == 0xe0)
            {
                stack -= 18;
            }
        }
        else {
            /* Return to Thread Mode: PSP (0xffffff-d) */
            stack = read_psp();

            /* The PC is always 6 words up from the PSP */
            stack += 6;
        }

        /* Store the PC */
        ucb.vrs[REG_PC] = *stack--;

        /* Store the LR */
        ucb.vrs[REG_LR] = *stack--;
    }

    /* We are done if current frame->pc is equal to the virtual pc */
    if (frame->pc == ucb.vrs[REG_PC])
        return _URC_OK;

    /* Update the frame */
    frame->pc = ucb.vrs[REG_PC];
    frame->lr = ucb.vrs[REG_LR];
    frame->sp = ucb.vrs[REG_SP];
    frame->fp = ucb.vrs[REG_FP];

    return _URC_OK;
}


static int
btexidx_unwind_frame(uint32_t functions[], uint32_t addresses[], unsigned nb_elem, backtrace_frame_regs_t *frame)
{
    int count;

    /* Initialize the backtrace_frame frame buffer */
    //memset(functions, 0, nb_elem);
    //memset(addresses, 0, nb_elem);

    for (count = 0; count < nb_elem; ++count) {
        if (frame->pc == 0) {
            /* Reached __exidx_end. */
            //buffer[count++].name = "<reached end of unwind table>";
            break;
        }

        if (frame->pc == EXIDX_CANTUNWIND) {
            /* Reached .cantunwind instruction. */
            //buffer[count++].name = "<reached .cantunwind>";
            break;
        }

        /* Find the unwind index of the current frame pc */
        const eit_t *eit_idx = btexidx_eit_search(btexidx_start, btexidx_end, frame->pc);
        if (eit_idx == NULL)
            break;

        /* Clear last bit (Thumb indicator) */
        frame->pc &= 0xfffffffeU;

        /* Generate the backtrace_frame information */
        if (addresses)
            addresses[count] = (uint32_t)frame->pc;
        if (functions)
            functions[count] = (uint32_t)btexidx_prel31_to_addr(&eit_idx->fnoffset);
        //buffer[count].name = btexidx_get_function_name(buffer[count].function);

        if (btexidx_next_frame(frame) != _URC_OK) {
            ++count;
            if (addresses)
                addresses[count] = (uint32_t)0x02;
            if (functions)
                functions[count] = (uint32_t)0x02;
            break;
        }
    }

    return count;
}


const char *
btexidx_function_name(uint32_t pc)
{
    const eit_t *eit_idx = btexidx_eit_search(btexidx_start, btexidx_end, pc);
    if (eit_idx == NULL)
        return NULL;

    return btexidx_get_function_name((uint32_t*)btexidx_prel31_to_addr(&eit_idx->fnoffset));
}


int
btexidx_unwind(uint32_t functions[], uint32_t addresses[], unsigned nb_elem)
{
    int rv;
    backtrace_frame_regs_t frame;

    getPC(frame.pc);
    getLR(frame.lr);
    getSP(frame.sp);
    getFP(frame.fp);

    // tail optimization will result in a cantunwind
    rv = btexidx_unwind_frame(functions, addresses, nb_elem, &frame);
    return rv;
}
