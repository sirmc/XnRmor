INC_DIR = -I$(DYNINST_ROOT)/proccontrol/h \
		  -I$(DYNINST_ROOT)/dataflowAPI/h \
		  -I$(DYNINST_ROOT)/dyninstAPI/h \
		  -I$(DYNINST_ROOT)/instructionAPI/h \
          -I$(DYNINST_ROOT)/symtabAPI/h \
          -I$(DYNINST_ROOT)/dynutil/h \
          -I$(DYNINST_ROOT)/parseAPI/h \
          -I$(DYNINST_ROOT)/patchAPI/h \
          -I$(DYNINST_ROOT)/dyninst \
          -I$(DYNINST_ROOT)/dyninstAPI/src \
          -I$(DYNINST_ROOT)/patchAPI/src \
          -I$(DYNINST_ROOT)/patchAPI/src/dyninst \
          -I$(DYNINST_ROOT)/dyninstAPI/src/Relocation \
          -I$(DYNINST_ROOT) \
		  -I$(DYNAMORIO_ROOT)/include \
		  -I../headers\
		  -I./h

SRC_DIR = ./src
OBJ_DIR = ./obj
TEST_DIR = ./test
		

CPP	    = /usr/bin/g++ -g
CC	    = /usr/bin/gcc -g
CFLAGS	= -Wall -Dos_linux
LDFLAGS = -L$(DYNINST_LIB) -ldyninstAPI -lsymtabAPI -lpatchAPI -linstructionAPI -lparseAPI -lcommon -ldynamorio
DEFINES = -DLINUX -DX86_64
DEFINES += $(DYNINST_CFLAGS)
DEBUG_FLAGS = -O2

# modules to build for analysis library
LIB_MODULES = CADecoderDynamoRIO CAinst

# executable modules

# make rules

TARGETS = $(OBJ_DIR)/libarmorconvert.so $(OBJ_DIR)/XnRArmor
EXAMPLE = $(OBJ_DIR)/pie
LIB_MODULE_FILES = $(foreach module, $(LIB_MODULES), $(OBJ_DIR)/$(module).o)
EXTERN_LIBS = 

all: $(TARGETS)
example : $(EXAMPLE)

$(OBJ_DIR)/libarmorconvert.so: src/libarmorconvert.c
#	$(CC) $(DEBUG_FLAGS) $? -o $@ -I./h -fomit-frame-pointer -fPIC -DPIC -shared -L/usr/local/lib -lurcu-qsbr -lpthread
	$(CC) $(DEBUG_FLAGS) $? -o $@ -I./h -fomit-frame-pointer -fPIC -DPIC -shared -Bsymbolic -static-libgcc -L/usr/local/lib -l:/usr/local/lib/liburcu-qsbr.a -lpthread
#	strip ./obj/libarmorconvert.so

$(OBJ_DIR)/XnRArmor: $(LIB_MODULE_FILES)
	$(CPP) -O0 $(CFLAGS) $? -o $@ $(LDFLAGS) -L$(OBJ_DIR) -larmorconvert

$(LIB_MODULE_FILES): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CPP) -O0 $(CFLAGS) $(INC_DIR) -c -o $@ $? $(DEFINES) 


#Build Example
$(OBJ_DIR)/pie: $(OBJ_DIR)/pie.o
	$(CC) $(CFLAGS) -O0 -finline-functions $? -o $@
#	$(CC) $(CFLAGS) -fpic -pie $? -o $@
#	$(CC) $(CFLAGS) -fno-pic -mcmodel=large $? -o $@

$(OBJ_DIR)/pie.o: $(TEST_DIR)/pie.c
	$(CC) $(CFLAGS) -O0 -finline-functions -c $? -o $@
#	$(CC) $(CFLAGS) -fpic -pie -c $? -o $@
#	$(CC) $(CFLAGS) -fno-pic -mcmodel=large -c $? -o $@


clean:
	@rm -f $(OBJ_DIR)/XnRArmor
	@rm -f $(OBJ_DIR)/libarmorconvert.so
	@rm -f $(OBJ_DIR)/*.o


