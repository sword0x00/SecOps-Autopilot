.PHONY: install test doctor inventory stages report clean

install:
	python3 -m pip install -e .

test:
	python3 -m unittest discover -s tests -v

doctor:
	python3 -m secops_autopilot doctor

inventory:
	python3 -m secops_autopilot inventory

stages:
	python3 -m secops_autopilot stages

report:
	@python3 -m secops_autopilot runs

clean:
	rm -rf runs .state .cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
