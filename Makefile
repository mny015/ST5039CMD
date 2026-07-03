.PHONY: task1 task2 clean evidence

task1:
	@if [ -f task1/Makefile ]; then \
		$(MAKE) -C task1; \
	else \
		echo "Task 1 build not implemented yet. Add sources under task1/src."; \
	fi

task2:
	@if [ -f task2/Makefile ]; then \
		$(MAKE) -C task2; \
	else \
		echo "Task 2 build not implemented yet. Add sources under task2/src."; \
	fi

evidence:
	@mkdir -p task1/evidence task2/evidence
	@echo "Evidence directories are ready."

clean:
	@if [ -f task1/Makefile ]; then \
		$(MAKE) -C task1 clean; \
	fi
	@if [ -f task2/Makefile ]; then \
		$(MAKE) -C task2 clean; \
	fi
	$(RM) -r build task1/build task2/build
