/*
 * Copyright (C) 2019, Alex Bennée <alex.bennee@linaro.org>
 *
 * How vectorised is this code?
 *
 * Attempt to measure the amount of vectorisation that has been done
 * on some code by counting classes of instruction.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef enum {
    COUNT_CLASS,
    COUNT_INDIVIDUAL,
    COUNT_NONE
} CountType;

static int limit = INT32_MAX;
static bool do_inline;
static bool verbose;

static GMutex lock;
static GHashTable *insns;
static GHashTable *tbs;

typedef struct {
    const char *class;
    const char *opt;
    uint32_t mask;
    uint32_t pattern;
    CountType what;
    uint64_t count;
} InsnClassExecCount;

typedef struct {
    char *insn;
    uint32_t opcode;
    uint64_t count;
    InsnClassExecCount *class;
} InsnExecCount;


typedef struct 
{
    /* data */
    uint64_t pc;
    uint64_t cnt;
    uint64_t *fusion;
    uint64_t *total_fusion;
}TbExecCount;

typedef enum {
    LuiAddiPair,
    AuipcAddiPair,
    AuipcLoadPair,
    ShaddLoadPair,
    AddLoadPair,
    ShiftAddPair,
    SlliSrliPair,
    LoadPair, 
    StorePair, 
    FusionMax
}Fusion;

typedef enum {
    nop, 
    lb,
    lh, 
    lw, 
    ld, 
    lbu, 
    lhu, 
    lwu, 
    sb,  
    sh, 
    sw, 
    sd, 
    lui, 
    auipc, 
    addi, 
    addiw, 
    slli, 
    srli, 
    add, 
    sh1add, 
    sh1add_uw, 
    sh2add, 
    sh2add_uw, 
    sh3add, 
    sh3add_uw, 
}RISCV;

typedef struct {
    uint8_t rd;
    uint8_t rs1;
    uint8_t rs2;
    uint8_t opcode;
    int imm;
}inst;

int decode_insn(inst *new_inst, uint32_t opcode) {

    int ret = -1;

    if ((opcode & 0x7f) == 0x03) { 
        switch ((opcode >> 12) & 0x7)
        {
        case 0x0:
            new_inst->opcode = lb;
            break;
        case 0x1:
            new_inst->opcode = lh;
            break;
        case 0x2:
            new_inst->opcode = lw;
            break;
        case 0x3:
            new_inst->opcode = ld;
            break;
        case 0x4:
            new_inst->opcode = lbu;
            break;
        case 0x5:
            new_inst->opcode = lhu;
            break;
        case 0x6:
            new_inst->opcode = lwu;
            break;
        default:
            break;
        }

        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->imm = ((int) opcode) >> 20;

        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x23) {
        switch ((opcode >> 12) & 0x7)
        {
        case 0x0:
            new_inst->opcode = sb;
            break;
        case 0x1:
            new_inst->opcode = sh;
            break;
        case 0x2:
            new_inst->opcode = sw;
            break;
        case 0x3:
            new_inst->opcode = sd;
            break;
        default:
            break;
        }

        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->rs2 = (opcode >> 20) & 0x1f;
        new_inst->imm = ((opcode >> 7) & 0x1f) | ((((int) opcode) >> 25) << 5);
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x37) {
        new_inst->opcode = lui;
        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->imm = ((int) opcode) >> 12;
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x17) {
        new_inst->opcode = auipc;
        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->imm = ((int) opcode) >> 12;
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x13) {
        switch ((opcode >> 12) & 0x7)
        {
        case 0x0:
            new_inst->opcode = addi;
            break;
        case 0x1:
            new_inst->opcode = slli;
            break;
        case 0x5:
            new_inst->opcode = srli;
            break;
        default:
            break;
        }
        
        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->imm = ((int) opcode) >> 20;
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x1b) {
        switch ((opcode >> 12) & 0x7)
        {
        case 0x0:
            new_inst->opcode = addiw;
            break;
        }
        
        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->imm = ((int) opcode) >> 20;
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x33) {

        switch ((opcode >> 12) & 0x7)
        {

        case 0x0:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x0:
                new_inst->opcode = add;
                break;
            default:
                break;
            }
            break;

        case 0x2:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh1add;
                break;
            default:
                break;
            }
            break;

        case 0x4:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh2add;
                break;
            default:
                break;
            }
            break;

        case 0x6:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh3add;
                break;
            default:
                break;
            }
            break;
            
        default:
            break;
        }


        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->rs2 = (opcode >> 20) & 0x1f;
        ret = 0;
    }
    else if ((opcode & 0x7f) == 0x3b) {

        switch ((opcode >> 12) & 0x7)
        {

        case 0x2:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh1add_uw;
                break;
            default:
                break;
            }
            break;

        case 0x4:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh2add_uw;
                break;
            default:
                break;
            }
            break;

        case 0x6:
            switch ((opcode >> 25) & 0x7f)
            {
            case 0x10:
                new_inst->opcode = sh3add_uw;
                break;
            default:
                break;
            }
            break;
            
        default:
            break;
        }


        new_inst->rd = (opcode >> 7) & 0x1f;
        new_inst->rs1 = (opcode >> 15) & 0x1f;
        new_inst->rs2 = (opcode >> 20) & 0x1f;
        ret = 0;
    }

    return ret;
}

int checkSameDest(inst* inst1, inst* inst2) {
    return inst1->rd == inst2->rd;
}

int checkDataDependency(inst* inst1, inst* inst2) {
    return (inst1->rd == inst2->rs1) || (inst1->rd == inst2->rs2);
}

int check_fusion(inst* inst1, inst* inst2) {

    if ((inst1->opcode == lui && inst2->opcode == addi) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)) {
            return LuiAddiPair;
    }
    if ((inst1->opcode == auipc && inst2->opcode == addi) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)){
            return AuipcAddiPair;
    }
    if ((inst1->opcode == auipc && inst2->opcode == ld) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)){
            return AuipcLoadPair;
    }
    if ((inst1->opcode == slli && inst2->opcode == add) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)){
            return ShiftAddPair;
    }
    if ((inst1->opcode == slli && inst2->opcode == srli) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)){
            return SlliSrliPair;
    }
    if ((inst1->opcode == add && 
        (inst2->opcode == ld || 
        inst2->opcode == lw || 
        inst2->opcode == lh || 
        inst2->opcode == lb ||
        inst2->opcode == lwu || 
        inst2->opcode == lhu || 
        inst2->opcode == lbu)) && (inst2->imm == 0) && 
        checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)){
            return AddLoadPair;
    }
    if (((inst1->opcode == sh1add || inst1->opcode == sh1add_uw) && (inst2->opcode == lh || inst2->opcode == lhu)) && checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)) {
        return ShaddLoadPair;
    }
    if (((inst1->opcode == sh2add || inst1->opcode == sh2add_uw) && (inst2->opcode == lw || inst2->opcode == lwu)) && checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)) {
        return ShaddLoadPair;
    }
    if (((inst1->opcode == sh1add || inst1->opcode == sh1add_uw) && (inst2->opcode == ld)) && checkSameDest(inst1, inst2) && checkDataDependency(inst1, inst2)) {
        return ShaddLoadPair;
    }
    if (inst1->opcode == inst2->opcode) {
        if ((inst1->opcode == lb || inst1->opcode == lbu) && abs(inst1->imm - inst2->imm) == 1) {
            return LoadPair;
        }
        if ((inst1->opcode == lh || inst1->opcode == lhu) && abs(inst1->imm - inst2->imm) == 2) {
            return LoadPair;
        }
        if ((inst1->opcode == lw || inst1->opcode == lwu) && abs(inst1->imm - inst2->imm) == 4) {
            return LoadPair;
        }
        if ((inst1->opcode == ld) && abs(inst1->imm - inst2->imm) == 8) {
            return LoadPair;
        }
        if ((inst1->opcode == sb) && abs(inst1->imm - inst2->imm) == 1) {
            return StorePair;
        }
        if ((inst1->opcode == sh) && abs(inst1->imm - inst2->imm) == 2) {
            return StorePair;
        }
        if ((inst1->opcode == sw) && abs(inst1->imm - inst2->imm) == 4) {
            return StorePair;
        }
        if ((inst1->opcode == sd) && abs(inst1->imm - inst2->imm) == 8) {
            return StorePair;
        }
    }
    
    return -1;
}


/*
 * Matchers for classes of instructions, order is important.
 *
 * Your most precise match must be before looser matches. If no match
 * is found in the table we can create an individual entry.
 *
 * 31..28 27..24 23..20 19..16 15..12 11..8 7..4 3..0
 */
static InsnClassExecCount aarch64_insn_classes[] = {
    /* "Reserved"" */
    { "  UDEF",              "udef",   0xffff0000, 0x00000000, COUNT_NONE},
    { "  SVE",               "sve",    0x1e000000, 0x04000000, COUNT_CLASS},
    { "Reserved",            "res",    0x1e000000, 0x00000000, COUNT_CLASS},
    /* Data Processing Immediate */
    { "  PCrel addr",        "pcrel",  0x1f000000, 0x10000000, COUNT_CLASS},
    { "  Add/Sub (imm,tags)", "asit",   0x1f800000, 0x11800000, COUNT_CLASS},
    { "  Add/Sub (imm)",     "asi",    0x1f000000, 0x11000000, COUNT_CLASS},
    { "  Logical (imm)",     "logi",   0x1f800000, 0x12000000, COUNT_CLASS},
    { "  Move Wide (imm)",   "movwi",  0x1f800000, 0x12800000, COUNT_CLASS},
    { "  Bitfield",          "bitf",   0x1f800000, 0x13000000, COUNT_CLASS},
    { "  Extract",           "extr",   0x1f800000, 0x13800000, COUNT_CLASS},
    { "Data Proc Imm",       "dpri",   0x1c000000, 0x10000000, COUNT_CLASS},
    /* Branches */
    { "  Cond Branch (imm)", "cndb",   0xfe000000, 0x54000000, COUNT_CLASS},
    { "  Exception Gen",     "excp",   0xff000000, 0xd4000000, COUNT_CLASS},
    { "    NOP",             "nop",    0xffffffff, 0xd503201f, COUNT_NONE},
    { "  Hints",             "hint",   0xfffff000, 0xd5032000, COUNT_CLASS},
    { "  Barriers",          "barr",   0xfffff000, 0xd5033000, COUNT_CLASS},
    { "  PSTATE",            "psta",   0xfff8f000, 0xd5004000, COUNT_CLASS},
    { "  System Insn",       "sins",   0xffd80000, 0xd5080000, COUNT_CLASS},
    { "  System Reg",        "sreg",   0xffd00000, 0xd5100000, COUNT_CLASS},
    { "  Branch (reg)",      "breg",   0xfe000000, 0xd6000000, COUNT_CLASS},
    { "  Branch (imm)",      "bimm",   0x7c000000, 0x14000000, COUNT_CLASS},
    { "  Cmp & Branch",      "cmpb",   0x7e000000, 0x34000000, COUNT_CLASS},
    { "  Tst & Branch",      "tstb",   0x7e000000, 0x36000000, COUNT_CLASS},
    { "Branches",            "branch", 0x1c000000, 0x14000000, COUNT_CLASS},
    /* Loads and Stores */
    { "  AdvSimd ldstmult",  "advlsm", 0xbfbf0000, 0x0c000000, COUNT_CLASS},
    { "  AdvSimd ldstmult++", "advlsmp", 0xbfb00000, 0x0c800000, COUNT_CLASS},
    { "  AdvSimd ldst",      "advlss", 0xbf9f0000, 0x0d000000, COUNT_CLASS},
    { "  AdvSimd ldst++",    "advlssp", 0xbf800000, 0x0d800000, COUNT_CLASS},
    { "  ldst excl",         "ldstx",  0x3f000000, 0x08000000, COUNT_CLASS},
    { "    Prefetch",        "prfm",   0xff000000, 0xd8000000, COUNT_CLASS},
    { "  Load Reg (lit)",    "ldlit",  0x1b000000, 0x18000000, COUNT_CLASS},
    { "  ldst noalloc pair", "ldstnap", 0x3b800000, 0x28000000, COUNT_CLASS},
    { "  ldst pair",         "ldstp",  0x38000000, 0x28000000, COUNT_CLASS},
    { "  ldst reg",          "ldstr",  0x3b200000, 0x38000000, COUNT_CLASS},
    { "  Atomic ldst",       "atomic", 0x3b200c00, 0x38200000, COUNT_CLASS},
    { "  ldst reg (reg off)", "ldstro", 0x3b200b00, 0x38200800, COUNT_CLASS},
    { "  ldst reg (pac)",    "ldstpa", 0x3b200200, 0x38200800, COUNT_CLASS},
    { "  ldst reg (imm)",    "ldsti",  0x3b000000, 0x39000000, COUNT_CLASS},
    { "Loads & Stores",      "ldst",   0x0a000000, 0x08000000, COUNT_CLASS},
    /* Data Processing Register */
    { "Data Proc Reg",       "dprr",   0x0e000000, 0x0a000000, COUNT_CLASS},
    /* Scalar FP */
    { "Scalar FP ",          "fpsimd", 0x0e000000, 0x0e000000, COUNT_CLASS},
    /* Unclassified */
    { "Unclassified",        "unclas", 0x00000000, 0x00000000, COUNT_CLASS},
};

static InsnClassExecCount riscv64_insn_classes[] = {
    // { "flw/fld",                            "addi",  0x0000007f, 0x00000007, COUNT_CLASS},
    // { "fsw/fsd",                            "addi",  0x0000007f, 0x00000027, COUNT_CLASS},
    // { "branch",                             "addi",  0x00000073, 0x00000063, COUNT_CLASS},
    // { "Fence",                              "addi",  0x0000007f, 0x0000000f, COUNT_CLASS},
    // { "Csr",                                "addi",  0x0000007f, 0x00000073, COUNT_CLASS},
    // { "lb",                                 "addi",  0x0000707f, 0x00000003, COUNT_CLASS},
    // { "lh",                                 "addi",  0x0000707f, 0x00001003, COUNT_CLASS},
    // { "lw",                                 "addi",  0x0000707f, 0x00002003, COUNT_CLASS},
    // { "ld",                                 "addi",  0x0000707f, 0x00003003, COUNT_CLASS},
    // { "lbu",                                "addi",  0x0000707f, 0x00004003, COUNT_CLASS},
    // { "lhu",                                "addi",  0x0000707f, 0x00005003, COUNT_CLASS},
    // { "lwu",                                "addi",  0x0000707f, 0x00006003, COUNT_CLASS},
    // { "sb",                                 "addi",  0x0000707f, 0x00000023, COUNT_CLASS},
    // { "sh",                                 "addi",  0x0000707f, 0x00001023, COUNT_CLASS},
    // { "sw",                                 "addi",  0x0000707f, 0x00002023, COUNT_CLASS},
    // { "sd",                                 "addi",  0x0000707f, 0x00003023, COUNT_CLASS},
    // { "th.ldd",                             "addi",  0xf800707f, 0xf800400b, COUNT_CLASS},
    // { "th.lwd",                             "addi",  0xf800707f, 0xe000400b, COUNT_CLASS},
    // { "th.lwud",                            "addi",  0xf800707f, 0xf000400b, COUNT_CLASS},
    // { "th.sdd",                             "addi",  0xf800707f, 0xf800500b, COUNT_CLASS},
    // { "th.swd",                             "addi",  0xf800707f, 0xe000500b, COUNT_CLASS},
    { "sh1add",                             "addi",  0xfe00707f, 0x20002033, COUNT_CLASS},
    { "sh1add.uw",                          "addi",  0xfe00707f, 0x2000203b, COUNT_CLASS},
    { "sh2add",                             "addi",  0xfe00707f, 0x20004033, COUNT_CLASS},
    { "sh2add.uw",                          "addi",  0xfe00707f, 0x2000403b, COUNT_CLASS},
    { "sh3add",                             "addi",  0xfe00707f, 0x20006033, COUNT_CLASS},
    { "sh3add.uw",                          "addi",  0xfe00707f, 0x2000603b, COUNT_CLASS},
    /* Unclassified */
    { "Unclassified",                       "unclas", 0x00000000, 0x00000000, COUNT_CLASS},
};

static InsnClassExecCount sparc32_insn_classes[] = {
    { "Call",                "call",   0xc0000000, 0x40000000, COUNT_CLASS},
    { "Branch ICond",        "bcc",    0xc1c00000, 0x00800000, COUNT_CLASS},
    { "Branch Fcond",        "fbcc",   0xc1c00000, 0x01800000, COUNT_CLASS},
    { "SetHi",               "sethi",  0xc1c00000, 0x01000000, COUNT_CLASS},
    { "FPU ALU",             "fpu",    0xc1f00000, 0x81a00000, COUNT_CLASS},
    { "ALU",                 "alu",    0xc0000000, 0x80000000, COUNT_CLASS},
    { "Load/Store",          "ldst",   0xc0000000, 0xc0000000, COUNT_CLASS},
    /* Unclassified */
    { "Unclassified",        "unclas", 0x00000000, 0x00000000, COUNT_INDIVIDUAL},
};

static InsnClassExecCount sparc64_insn_classes[] = {
    { "SetHi & Branches",     "op0",   0xc0000000, 0x00000000, COUNT_CLASS},
    { "Call",                 "op1",   0xc0000000, 0x40000000, COUNT_CLASS},
    { "Arith/Logical/Move",   "op2",   0xc0000000, 0x80000000, COUNT_CLASS},
    { "Arith/Logical/Move",   "op3",   0xc0000000, 0xc0000000, COUNT_CLASS},
    /* Unclassified */
    { "Unclassified",        "unclas", 0x00000000, 0x00000000, COUNT_INDIVIDUAL},
};

/* Default matcher for currently unclassified architectures */
static InsnClassExecCount default_insn_classes[] = {
    { "Unclassified",        "unclas", 0x00000000, 0x00000000, COUNT_INDIVIDUAL},
};

typedef struct {
    const char *qemu_target;
    InsnClassExecCount *table;
    int table_sz;
} ClassSelector;

static ClassSelector class_tables[] = {
    { "aarch64", aarch64_insn_classes, ARRAY_SIZE(aarch64_insn_classes) },
    { "riscv64", riscv64_insn_classes, ARRAY_SIZE(riscv64_insn_classes) },
    { "sparc",   sparc32_insn_classes, ARRAY_SIZE(sparc32_insn_classes) },
    { "sparc64", sparc64_insn_classes, ARRAY_SIZE(sparc64_insn_classes) },
    { NULL, default_insn_classes, ARRAY_SIZE(default_insn_classes) },
};

static InsnClassExecCount *class_table;
static int class_table_sz;

static gint cmp_exec_count(gconstpointer a, gconstpointer b)
{
    InsnExecCount *ea = (InsnExecCount *) a;
    InsnExecCount *eb = (InsnExecCount *) b;
    return ea->count > eb->count ? -1 : 1;
}

static void free_record(gpointer data)
{
    InsnExecCount *rec = (InsnExecCount *) data;
    g_free(rec->insn);
    g_free(rec);
}

static void free_record_tb(gpointer data)
{
    // TbExecCount *rec = (TbExecCount *) data;
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autoptr(GString) report = g_string_new("");
    int i;
    GList *counts;
    InsnClassExecCount *class = NULL;

    long long sum = 0;
    long long shadd = 0;

    for (i = 0; i < class_table_sz; i++) {
        class = &class_table[i];
        switch (class->what) {
        case COUNT_CLASS:
            if (class->count || verbose) {
                // g_string_append_printf(report,
                //                        "%d, %d, Class: %-24s\t(%" PRId64 " hits)\n",
                //                        i, class_table_sz, 
                //                        class->class,
                //                        class->count);

                if (i == class_table_sz - 1) {
                    shadd = sum;
                }

                sum += class->count;
            }
            break;
        case COUNT_INDIVIDUAL:
            g_string_append_printf(report, "Class: %-24s\tcounted individually\n",
                                   class->class);
            break;
        case COUNT_NONE:
            g_string_append_printf(report, "Class: %-24s\tnot counted\n",
                                   class->class);
            break;
        default:
            break;
        }
    }

    // counts = g_hash_table_get_values(insns);
    // if (counts && g_list_next(counts)) {
    //     g_string_append_printf(report, "Individual Instructions:\n");
    //     counts = g_list_sort(counts, cmp_exec_count);

    //     for (i = 0; i < limit && g_list_next(counts);
    //          i++, counts = g_list_next(counts)) {
    //         InsnExecCount *rec = (InsnExecCount *) counts->data;
    //         g_string_append_printf(report,
    //                                "Instr: %-24s\t(%" PRId64 " hits)"
    //                                "\t(op=0x%08x/%s)\n",
    //                                rec->insn,
    //                                rec->count,
    //                                rec->opcode,
    //                                rec->class ?
    //                                rec->class->class : "un-categorised");
    //     }
    //     g_list_free(counts);
    // }


    uint64_t *total = calloc(sizeof(uint64_t), FusionMax);

    counts = g_hash_table_get_values(tbs);
    if (counts && g_list_next(counts)) {

        for (i = 0; i < limit && g_list_next(counts);
             i++, counts = g_list_next(counts)) {
            TbExecCount *rec = (TbExecCount *) counts->data;

            for(int j=0 ; j < FusionMax ; j++) {
                total[j] += rec->total_fusion[j];
            }

            // if (rec->total_fusion[AddLoadPair])
            //     g_string_append_printf(report, "Tb pc: %x, AddLoadPair: %20ld, Total: %20ld \n", rec->pc, rec->total_fusion[AddLoadPair], total[AddLoadPair]);
    
        }
        g_list_free(counts);
    }

    g_string_append_printf(report, "Insts Sum:      \t%20lld hits  \t\n", sum);
    g_string_append_printf(report, "LuiAddi:    \t%20ld hits  \t%lf\n", total[LuiAddiPair],   (double) total[LuiAddiPair] / sum * 100);
    g_string_append_printf(report, "ShiftAdd:   \t%20ld hits  \t%lf\n", total[ShiftAddPair],  (double) total[ShiftAddPair] / sum * 100);
    g_string_append_printf(report, "ShaddLoad:  \t%20ld hits  \t%lf\n", total[ShaddLoadPair],  (double) total[ShaddLoadPair] / sum * 100);
    g_string_append_printf(report, "AuipcAddi:  \t%20ld hits  \t%lf\n", total[AuipcAddiPair], (double) total[AuipcAddiPair] / sum * 100);
    g_string_append_printf(report, "SlliSrli:   \t%20ld hits  \t%lf\n", total[SlliSrliPair],  (double) total[SlliSrliPair] / sum * 100);
    g_string_append_printf(report, "AuipcLoad:  \t%20ld hits  \t%lf\n", total[AuipcLoadPair], (double) total[AuipcLoadPair] / sum * 100);
    g_string_append_printf(report, "AddLoad:    \t%20ld hits  \t%lf\n", total[AddLoadPair],   (double) total[AddLoadPair] / sum * 100);
    g_string_append_printf(report, "Load:       \t%20ld hits  \t%lf\n", total[LoadPair],      (double) total[LoadPair] / sum * 100);
    g_string_append_printf(report, "Store:      \t%20ld hits  \t%lf\n", total[StorePair],     (double) total[StorePair] / sum * 100);
    // g_string_append_printf(report, "Shadd:      \t%20ld hits  \t%lf\n", shadd,                  (double) shadd / sum * 100);

    
    // g_string_append_printf(report, "ShiftAddPair:   \t%20ld hits  \t%lf\n", total[ShiftAddPair],  (double) total[ShiftAddPair] / sum * 100);
    // g_string_append_printf(report, "AddLoadPair:    \t%20ld hits  \t%lf\n", total[AddLoadPair],   (double) total[AddLoadPair] / sum * 100);
    // g_string_append_printf(report, "ShaddLoadPair:  \t%20ld hits  \t%lf\n", total[ShaddLoadPair],  (double) total[ShaddLoadPair] / sum * 100);

    g_hash_table_destroy(insns);
    g_hash_table_destroy(tbs);

    qemu_plugin_outs(report->str);
}

static void plugin_init(void)
{
    insns = g_hash_table_new_full(NULL, g_direct_equal, NULL, &free_record);
    tbs = g_hash_table_new_full(NULL, g_direct_equal, NULL, &free_record_tb);
}

static void vcpu_insn_exec_before(unsigned int cpu_index, void *udata)
{
    uint64_t *count = (uint64_t *) udata;
    (*count)++;
}

static void vcpu_tb_exec_before(unsigned int cpu_index, void *udata) {
    TbExecCount *rec = (TbExecCount *) udata;
    rec->cnt++;
    for(int i=0;i<FusionMax;i++) {
        rec->total_fusion[i] += rec->fusion[i];
    }

}

static TbExecCount* find_counter_tb(struct qemu_plugin_tb* tb) {
    g_mutex_lock(&lock);

    
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t insns = qemu_plugin_tb_n_insns(tb);
    uint64_t hash = pc ^ insns;

    TbExecCount* icount = (TbExecCount*) g_hash_table_lookup(tbs, (gconstpointer) hash);

    if (!icount) {
        icount = g_new0(TbExecCount, 1);
        icount->pc = pc;
        icount->cnt = 0;
        icount->fusion = calloc(FusionMax, sizeof(uint64_t));
        icount->total_fusion = calloc(FusionMax, sizeof(uint64_t));
        
        g_hash_table_insert(tbs, (gpointer) hash, (gpointer) icount);

        // fprintf(stderr, "insert hash: %llu, pc: %x to icount: %x\n", hash, pc, icount);
    }

    size_t n = qemu_plugin_tb_n_insns(tb);

    inst* prev = calloc(1, sizeof(inst));
    inst* next = calloc(1, sizeof(inst));
    inst* tmp;

    for(int i=0;i<n;i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint32_t _insn = *((uint32_t *)qemu_plugin_insn_data(insn));
        decode_insn(next, _insn);

        if (i >= 1) {
            int fusion_type = check_fusion(prev, next);
            if (fusion_type != -1) {
                icount->fusion[fusion_type] += 1;
                i++;
            }

            if (i < n) {
                struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
                uint32_t _insn = *((uint32_t *)qemu_plugin_insn_data(insn));
                decode_insn(prev, _insn);
            }

            continue;
        }

        tmp = next;
        next = prev;
        prev = tmp;
    }


    g_mutex_unlock(&lock);

    return icount;
}

static uint64_t *find_counter(struct qemu_plugin_insn *insn)
{
    int i;
    uint64_t *cnt = NULL;
    uint32_t opcode;
    InsnClassExecCount *class = NULL;

    /*
     * We only match the first 32 bits of the instruction which is
     * fine for most RISCs but a bit limiting for CISC architectures.
     * They would probably benefit from a more tailored plugin.
     * However we can fall back to individual instruction counting.
     */
    opcode = *((uint32_t *)qemu_plugin_insn_data(insn));

    for (i = 0; !cnt && i < class_table_sz; i++) {
        class = &class_table[i];
        uint32_t masked_bits = opcode & class->mask;
        if (masked_bits == class->pattern) {
            break;
        }
    }

    g_assert(class);

    switch (class->what) {
    case COUNT_NONE:
        return NULL;
    case COUNT_CLASS:
        return &class->count;
    case COUNT_INDIVIDUAL:
    {
        InsnExecCount *icount;

        g_mutex_lock(&lock);
        icount = (InsnExecCount *) g_hash_table_lookup(insns,
                                                       GUINT_TO_POINTER(opcode));

        if (!icount) {
            icount = g_new0(InsnExecCount, 1);
            icount->opcode = opcode;
            icount->insn = qemu_plugin_insn_disas(insn);
            icount->class = class;

            g_hash_table_insert(insns, GUINT_TO_POINTER(opcode),
                                (gpointer) icount);
        }
        g_mutex_unlock(&lock);

        return &icount->count;
    }
    default:
        g_assert_not_reached();
    }

    return NULL;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    for (i = 0; i < n; i++) {
        uint64_t *cnt;
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        cnt = find_counter(insn);

        if (cnt) {
            if (do_inline) {
                qemu_plugin_register_vcpu_insn_exec_inline(
                    insn, QEMU_PLUGIN_INLINE_ADD_U64, cnt, 1);
            } else {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_insn_exec_before, QEMU_PLUGIN_CB_NO_REGS, cnt);
            }
        }
    }

    TbExecCount* icount = find_counter_tb(tb);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec_before, QEMU_PLUGIN_CB_NO_REGS, icount);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    /* Select a class table appropriate to the guest architecture */
    for (i = 0; i < ARRAY_SIZE(class_tables); i++) {
        ClassSelector *entry = &class_tables[i];
        if (!entry->qemu_target ||
            strcmp(entry->qemu_target, info->target_name) == 0) {
            class_table = entry->table;
            class_table_sz = entry->table_sz;
            break;
        }
    }

    for (i = 0; i < argc; i++) {
        char *p = argv[i];
        g_auto(GStrv) tokens = g_strsplit(p, "=", -1);
        if (g_strcmp0(tokens[0], "inline") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &do_inline)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", p);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "verbose") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &verbose)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", p);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "count") == 0) {
            char *value = tokens[1];
            int j;
            CountType type = COUNT_INDIVIDUAL;
            if (*value == '!') {
                type = COUNT_NONE;
                value++;
            }
            for (j = 0; j < class_table_sz; j++) {
                if (strcmp(value, class_table[j].opt) == 0) {
                    class_table[j].what = type;
                    break;
                }
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", p);
            return -1;
        }
    }

    plugin_init();

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
