.DEFAULT_GOAL := help

PYTHON ?= python
VENV ?= .venv
COMPOSE ?= podman compose
ENV_FILE ?= .env
TEST_ARGS ?= -q

ifeq ($(OS),Windows_NT)
VENV_PYTHON := $(VENV)/Scripts/python.exe
else
VENV_PYTHON := $(VENV)/bin/python
endif

COMPOSE_CMD = $(COMPOSE) -f deploy/compose.yaml --env-file "$(ENV_FILE)"

.PHONY: help venv setup setup-nlp install test policy-build policy-verify build up down restart status logs smoke test-policy check-containers

help:
	@echo "  make setup-nlp        Set up development dependencies and pinned spaCy model"
	@echo "Run these commands from the repository root:"
	@echo "  make setup            Create .venv and install development dependencies"
	@echo "  make install          Install development dependencies into existing .venv"
	@echo "  make test             Run Python tests (TEST_ARGS defaults to -q)"
	@echo "  make policy-build     Generate and archive an active policy snapshot"
	@echo "  make policy-verify    Verify active and archived policy snapshots"
	@echo "  make build            Build default Compose images"
	@echo "  make up               Build and start the default stack"
	@echo "  make down             Stop the stack, preserving the audit volume"
	@echo "  make restart          Recreate default services without rebuilding"
	@echo "  make status           Show Compose service status"
	@echo "  make logs             Follow control-plane logs"
	@echo "  make smoke            Run real NLP smoke checks in the running stack"
	@echo "  make test-policy      Run Rego tests against the active policy snapshot"
	@echo "  make check-containers Run NLP smoke checks and Rego tests"
	@echo "Overrides: PYTHON=python COMPOSE=\"docker compose\" ENV_FILE=.env"

venv:
	$(PYTHON) -m venv "$(VENV)"

setup: venv
	$(MAKE) install

setup-nlp: setup
	"$(VENV_PYTHON)" -m pip install "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"

install:
	"$(VENV_PYTHON)" -m pip install -e ".[dev]"

test:
	"$(VENV_PYTHON)" -m pytest $(TEST_ARGS)

policy-build:
	"$(VENV_PYTHON)" -m tools.build_policy_snapshot

policy-verify:
	"$(VENV_PYTHON)" -m tools.verify_policy_snapshot

build:
	$(COMPOSE_CMD) build

up:
	$(COMPOSE_CMD) up --build --force-recreate -d

down:
	$(COMPOSE_CMD) down

restart:
	$(COMPOSE_CMD) up --force-recreate -d

status:
	$(COMPOSE_CMD) ps

logs:
	$(COMPOSE_CMD) logs --follow control-plane

smoke:
	$(COMPOSE_CMD) exec control-plane python -m tools.smoke_detection

test-policy:
	$(COMPOSE_CMD) run --rm opa test /policies /policy-tests

check-containers:
	$(MAKE) smoke
	$(MAKE) test-policy
