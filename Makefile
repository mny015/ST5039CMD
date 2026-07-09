CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic

TASK1_DIR := task1-auth
TASK1_BUILD := $(TASK1_DIR)/build

TASK2_DIR := task2-sandbox
TASK2_BUILD := $(TASK2_DIR)/build
TASK2_TEST_DIR := $(TASK2_DIR)/test

.PHONY: task1 task2 clean evidence

task1: $(TASK1_BUILD)/Frontend $(TASK1_BUILD)/Backend

$(TASK1_BUILD):
	mkdir -p $@

$(TASK1_BUILD)/Frontend: $(TASK1_DIR)/Frontend.c $(TASK1_DIR)/auth_protocol.h $(TASK1_DIR)/secure_memory.c $(TASK1_DIR)/secure_memory.h | $(TASK1_BUILD)
	$(CC) $(CFLAGS) -o $@ $(TASK1_DIR)/Frontend.c $(TASK1_DIR)/secure_memory.c

$(TASK1_BUILD)/Backend: $(TASK1_DIR)/Backend.c $(TASK1_DIR)/auth_protocol.h $(TASK1_DIR)/secure_memory.c $(TASK1_DIR)/secure_memory.h | $(TASK1_BUILD)
	$(CC) $(CFLAGS) -o $@ $(TASK1_DIR)/Backend.c $(TASK1_DIR)/secure_memory.c

task2: $(TASK2_BUILD)/Sandbox \
	$(TASK2_BUILD)/normal_exit \
	$(TASK2_BUILD)/infinite_loop \
	$(TASK2_BUILD)/memory_hog \
	$(TASK2_BUILD)/sleep_long \
	$(TASK2_BUILD)/ignore_sigterm

$(TASK2_BUILD):
	mkdir -p $@

$(TASK2_BUILD)/Sandbox: $(TASK2_DIR)/Sandbox.c $(TASK2_DIR)/monitor.c $(TASK2_DIR)/monitor.h $(TASK2_DIR)/logger.c $(TASK2_DIR)/logger.h | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $(TASK2_DIR)/Sandbox.c $(TASK2_DIR)/monitor.c $(TASK2_DIR)/logger.c

$(TASK2_BUILD)/normal_exit: $(TASK2_TEST_DIR)/normal_exit.c | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(TASK2_BUILD)/infinite_loop: $(TASK2_TEST_DIR)/infinite_loop.c | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(TASK2_BUILD)/memory_hog: $(TASK2_TEST_DIR)/memory_hog.c | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(TASK2_BUILD)/sleep_long: $(TASK2_TEST_DIR)/sleep_long.c | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(TASK2_BUILD)/ignore_sigterm: $(TASK2_TEST_DIR)/ignore_sigterm.c | $(TASK2_BUILD)
	$(CC) $(CFLAGS) -o $@ $<

evidence:
	@echo "Evidence is collected by the task run scripts."

clean:
	$(RM) -r $(TASK1_BUILD) $(TASK2_BUILD)
