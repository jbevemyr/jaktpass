.PHONY: all compile clean

EBIN_DIR := ebin
SRC_DIR  := src

ERLC ?= erlc
ERLC_FLAGS := -W +debug_info -I $(SRC_DIR)

SOURCES := $(wildcard $(SRC_DIR)/*.erl)
BEAMS   := $(patsubst $(SRC_DIR)/%.erl,$(EBIN_DIR)/%.beam,$(SOURCES))

all: compile

compile: $(EBIN_DIR) $(BEAMS)

$(EBIN_DIR):
	@mkdir -p $(EBIN_DIR)

$(EBIN_DIR)/%.beam: $(SRC_DIR)/%.erl
	$(ERLC) $(ERLC_FLAGS) -o $(EBIN_DIR) $<

clean:
	@rm -rf $(EBIN_DIR)


