#pragma once
#define DEBUG
//In fact that the size should not longer than 16, however, some of them can be 17
//However we convert one instructions into multiple ones, so we duplicat the size here.
#define MAX_RAW_INSN_SIZE 256
#define BUFFER_STRING_LEN 1024
#define MAX_NUM_PREFIXS 13
#define REX_DEFAULT_PATTERN 0x40
