# VectorAI Refactoring Plan: Architectural Split

This document outlines the step-by-step plan to refactor the monolithic `vectorai_server.py` into a modular Python package.

**Objective:** Improve maintainability, scalability, and organization by splitting the codebase into logical modules.

**Rules:**
- Execute tasks one by one.
- Verify functionality after each significant change.
- Mark tasks as `[X]` only when fully completed and verified.
- Do not proceed to the next task until the previous one is marked done.

## Phase 1: Preparation and Infrastructure

- [X] **1.1. Create Directory Structure**
    - Create `vectorai_app/` root folder.
    - Create subpackages: `config/`, `core/`, `tools/`, `workflows/`, `api/`.
    - Create `__init__.py` files for each.
- [X] **1.2. Backup Original Code**
    - Create a backup of `vectorai_server.py` to `vectorai_server.py.bak`.

## Phase 2: Core Logic Extraction

- [X] **2.1. Extract Configuration**
    - Identify global constants, environment variable loading, and Flask config.
    - Move to `vectorai_app/config/settings.py`.
- [X] **2.2. Extract Logging**
    - Identify logging setup and configuration.
    - Move to `vectorai_app/core/logging.py`.
- [X] **2.3. Extract Data Models**
    - Identify `dataclass` definitions (e.g., `TargetProfile`, `AttackStep`, `CTFChallenge`).
    - Move to `vectorai_app/core/models.py`.

## Phase 3: Tooling and Engines

- [X] **3.1. Extract Tool Manager**
    - Identify `CTFToolManager` class.
    - Move to `vectorai_app/tools/manager.py`.
- [X] **3.2. Extract Decision Engine**
    - Identify `IntelligentDecisionEngine` class.
    - Move to `vectorai_app/core/engine.py`.
- [X] **3.3. Extract File Manager**
    - Identify `FileOperationsManager` class.
    - Move to `vectorai_app/core/files.py`.

## Phase 4: Workflows and Automation

- [X] **4.1. Extract Challenge Automator**
    - Identify `CTFChallengeAutomator` class.
    - Move to `vectorai_app/workflows/automator.py`.
- [X] **4.2. Extract Workflow Definitions**
    - Identify hardcoded workflow dictionaries/lists.
    - Move to `vectorai_app/workflows/definitions.py`.
    - (Note: Extracted `BugBountyWorkflowManager` to `vectorai_app/workflows/bug_bounty.py` and `FileUploadTestingFramework` to `vectorai_app/workflows/file_upload.py`)

## Phase 4.5: Extract Remaining Core Components

- [X] **4.5.1. Extract Reconnaissance Components**
    - Identify `TechnologyDetector`.
    - Move to `vectorai_app/core/recon.py`.
- [ ] **4.5.2. Extract Network & Optimization Components**
    - Identify `RateLimitDetector`, `ParameterOptimizer`.
    - Move to `vectorai_app/core/optimization.py`.
- [ ] **4.5.3. Extract Monitoring & Recovery Components**
    - Identify `PerformanceMonitor`, `FailureRecoverySystem`, `GracefulDegradation`.
    - Move to `vectorai_app/core/monitoring.py` and `vectorai_app/core/recovery.py`.

## Phase 5: API Refactoring

- [ ] **5.1. Setup Flask Application Factory**
    - Create `vectorai_app/__init__.py` (or `app.py`) to initialize Flask.
- [ ] **5.2. Extract Routes (Blueprints)**
    - Group routes by functionality (e.g., `health`, `jobs`, `sessions`, `tools`).
    - Create blueprints in `vectorai_app/api/`.
    - Move route logic to respective blueprint files.

## Phase 6: Integration and Deployment

- [ ] **6.1. Create Entry Point**
    - Create `run.py` (or `main.py`) in the root to start the app.
- [ ] **6.2. Update Docker Configuration**
    - Update `Dockerfile` to copy the new folder structure.
    - Update `CMD` to run the new entry point.
- [ ] **6.3. Final Verification**
    - Build the new container.
    - Run health checks.
    - Run a test workflow.
