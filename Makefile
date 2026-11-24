# SAML HUD - tiny helper targets (no build step: the tool is a single file)

TOOL := saml-hud.sh

.PHONY: help test demo lint install samples clean

help:            ## show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  \033[38;5;51m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test:            ## run the regression suite
	@./tests/run_tests.sh

demo:            ## run the built-in demo
	@./$(TOOL) --demo

lint:            ## syntax checks only
	@bash -n $(TOOL)
	@sed -n '/^#__PY_START__$$/,/^#__PY_END__$$/p' $(TOOL) | sed '1d;$$d' > /tmp/hud-engine.py
	@python3 -m py_compile /tmp/hud-engine.py
	@echo "  syntax OK"

install:         ## install as ~/.local/bin/saml-hud
	@mkdir -p $(HOME)/.local/bin
	@install -m 0755 $(TOOL) $(HOME)/.local/bin/saml-hud
	@echo "  installed: $(HOME)/.local/bin/saml-hud"

samples:         ## regenerate the sample corpus (needs the optional samlx helper)
	@python3 tools/make_samples.py

clean:           ## remove caches
	@rm -rf __pycache__ tests/__pycache__ tools/__pycache__ /tmp/hud-engine.py
	@echo "  clean"
