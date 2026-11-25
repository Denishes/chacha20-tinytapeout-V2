SIM ?= icarus
TOPLEVEL_LANG = verilog
PROJECT_SOURCES = tt_um_dinis_chacha20_V2.v chacha20_core.v
TOPLEVEL = tb
MODULE = test
COMPILE_ARGS += -g2012
ifeq ($(GATES),yes)
COMPILE_ARGS += -DGL_TEST -DFUNCTIONAL -DUSE_POWER_PINS -DSIM
VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/primitives.v
VERILOG_SOURCES += $(PDK_ROOT)/sky130A/libs.ref/sky130_fd_sc_hd/verilog/sky130_fd_sc_hd.v
VERILOG_SOURCES += $(PWD)/gate_level_netlist.v
else
VERILOG_SOURCES += $(addprefix $(PWD)/../src/,$(PROJECT_SOURCES))
endif
VERILOG_SOURCES += $(PWD)/tb.v
include $(shell cocotb-config --makefiles)/Makefile.sim
