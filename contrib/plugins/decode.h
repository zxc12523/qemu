/*
 * Copyright (C) 2024, Jerry Shen <b09902112@ntu.edu.tw>

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
