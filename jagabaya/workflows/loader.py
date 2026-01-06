"""
Workflow loader for Jagabaya.

Loads and validates workflow definitions from YAML files.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class WorkflowStep(BaseModel):
    """A single step in a workflow."""
    
    name: str = Field(description="Step name")
    tool: str = Field(description="Tool to run")
    description: str = Field(default="", description="Step description")
    
    # Target configuration
    target: str = Field(default="{target}", description="Target (supports variables)")
    target_type: str = Field(default="primary", description="Target type: primary, discovered, all")
    
    # Tool configuration
    parameters: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")
    timeout: int = Field(default=300, description="Step timeout in seconds")
    
    # Conditions
    condition: str | None = Field(default=None, description="Condition to run this step")
    requires: list[str] = Field(default_factory=list, description="Required previous steps")
    on_failure: str = Field(default="continue", description="Action on failure: continue, skip, abort")
    
    # Parallel execution
    parallel: bool = Field(default=False, description="Can run in parallel with other steps")


class WorkflowPhase(BaseModel):
    """A phase containing multiple steps."""
    
    name: str = Field(description="Phase name")
    description: str = Field(default="", description="Phase description")
    steps: list[WorkflowStep] = Field(default_factory=list, description="Steps in this phase")
    
    # Phase conditions
    skip_if: str | None = Field(default=None, description="Condition to skip this phase")
    continue_on_error: bool = Field(default=True, description="Continue if a step fails")


class Workflow(BaseModel):
    """A complete workflow definition."""
    
    name: str = Field(description="Workflow name")
    version: str = Field(default="1.0", description="Workflow version")
    description: str = Field(default="", description="Workflow description")
    author: str = Field(default="", description="Workflow author")
    
    # Phases
    phases: list[WorkflowPhase] = Field(default_factory=list, description="Workflow phases")
    
    # Configuration
    safe_mode: bool = Field(default=True, description="Run in safe mode")
    max_parallel: int = Field(default=3, description="Maximum parallel steps")
    default_timeout: int = Field(default=300, description="Default step timeout")
    
    # Variables
    variables: dict[str, Any] = Field(default_factory=dict, description="Workflow variables")
    
    @field_validator("phases", mode="before")
    @classmethod
    def convert_phases(cls, v: Any) -> list[WorkflowPhase]:
        """Convert phase dicts to WorkflowPhase objects."""
        if not v:
            return []
        result = []
        for phase in v:
            if isinstance(phase, dict):
                # Convert steps
                if "steps" in phase:
                    phase["steps"] = [
                        WorkflowStep(**s) if isinstance(s, dict) else s
                        for s in phase["steps"]
                    ]
                result.append(WorkflowPhase(**phase))
            else:
                result.append(phase)
        return result
    
    def get_all_steps(self) -> list[WorkflowStep]:
        """Get all steps from all phases."""
        steps = []
        for phase in self.phases:
            steps.extend(phase.steps)
        return steps
    
    def get_tools_used(self) -> set[str]:
        """Get set of all tools used in this workflow."""
        return {step.tool for step in self.get_all_steps()}


class WorkflowLoader:
    """
    Loads workflow definitions from YAML files.
    
    Example:
        >>> loader = WorkflowLoader()
        >>> workflow = loader.load("recon")
        >>> print(workflow.name)
    """
    
    def __init__(self, workflow_dirs: list[Path] | None = None):
        """
        Initialize the loader.
        
        Args:
            workflow_dirs: Directories to search for workflows
        """
        # Default workflow directories
        builtin_dir = Path(__file__).parent / "builtin"
        self.workflow_dirs = [builtin_dir]
        
        if workflow_dirs:
            self.workflow_dirs.extend(workflow_dirs)
    
    def load(self, name: str) -> Workflow:
        """
        Load a workflow by name.
        
        Args:
            name: Workflow name (without .yaml extension)
        
        Returns:
            Loaded workflow
        
        Raises:
            FileNotFoundError: If workflow not found
        """
        # Try to find the workflow file
        for dir_path in self.workflow_dirs:
            yaml_path = dir_path / f"{name}.yaml"
            if yaml_path.exists():
                return self.load_file(yaml_path)
            
            yml_path = dir_path / f"{name}.yml"
            if yml_path.exists():
                return self.load_file(yml_path)
        
        raise FileNotFoundError(f"Workflow not found: {name}")
    
    def load_file(self, path: Path) -> Workflow:
        """
        Load a workflow from a file path.
        
        Args:
            path: Path to YAML file
        
        Returns:
            Loaded workflow
        """
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        return Workflow.model_validate(data)
    
    def load_from_string(self, content: str) -> Workflow:
        """
        Load a workflow from a YAML string.
        
        Args:
            content: YAML content
        
        Returns:
            Loaded workflow
        """
        data = yaml.safe_load(content)
        return Workflow.model_validate(data)
    
    def list_available(self) -> list[str]:
        """
        List all available workflow names.
        
        Returns:
            List of workflow names
        """
        workflows = set()
        
        for dir_path in self.workflow_dirs:
            if not dir_path.exists():
                continue
            
            for file_path in dir_path.glob("*.yaml"):
                workflows.add(file_path.stem)
            
            for file_path in dir_path.glob("*.yml"):
                workflows.add(file_path.stem)
        
        return sorted(workflows)
    
    def validate(self, workflow: Workflow, available_tools: set[str]) -> list[str]:
        """
        Validate a workflow.
        
        Args:
            workflow: Workflow to validate
            available_tools: Set of available tool names
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Check required fields
        if not workflow.name:
            errors.append("Workflow name is required")
        
        if not workflow.phases:
            errors.append("Workflow must have at least one phase")
        
        # Validate tools
        for step in workflow.get_all_steps():
            if step.tool not in available_tools:
                errors.append(f"Unknown tool in step '{step.name}': {step.tool}")
        
        # Validate step dependencies
        defined_steps = {step.name for step in workflow.get_all_steps()}
        for step in workflow.get_all_steps():
            for req in step.requires:
                if req not in defined_steps:
                    errors.append(f"Step '{step.name}' requires undefined step: {req}")
        
        return errors
