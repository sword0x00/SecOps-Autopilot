.PHONY: install test doctor inventory demo kri-demo report clean

install:
	python3 -m pip install -e .

test:
	python3 -m unittest discover -s tests -v

doctor:
	python3 -m secops_autopilot doctor

inventory:
	python3 -m secops_autopilot inventory

demo:
	./scripts/demo.sh

kri-demo:
	python3 scripts/kri_demo.py

report:
	@python3 -m secops_autopilot runs

clean:
	rm -rf runs .state .cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
