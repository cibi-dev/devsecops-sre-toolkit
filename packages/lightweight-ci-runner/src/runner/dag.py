"""
Directed Acyclic Graph (DAG) dependency resolver for CI pipelines.
Includes cycle detection, topological sorting, and parallel execution layering.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, List, Set, Optional

from runner.parser import JobDefinition, PipelineDefinition


class DependencyError(Exception):
    """Raised when an explicit dependency refers to a non-existent job."""
    pass


class CircularDependencyError(Exception):
    """Raised when a circular dependency loop is detected in the pipeline graph."""
    pass


class DAG:
    """
    Manages job nodes and directed dependency edges for pipeline orchestration.
    """

    def __init__(self) -> None:
        self.jobs: Dict[str, JobDefinition] = {}
        # dependencies[job] = set of jobs that must complete BEFORE 'job' runs (upstream)
        self.dependencies: Dict[str, Set[str]] = defaultdict(set)
        # dependents[job] = set of jobs that depend on 'job' (downstream)
        self.dependents: Dict[str, Set[str]] = defaultdict(set)

    @classmethod
    def from_pipeline(cls, pipeline: PipelineDefinition) -> DAG:
        """Constructs a DAG from a parsed PipelineDefinition."""
        dag = cls()
        for job_name, job_def in pipeline.jobs.items():
            dag.add_job(job_def)

        for job_name, job_def in pipeline.jobs.items():
            for dep in job_def.needs:
                dag.add_dependency(job_name, dep)

        dag.validate()
        return dag

    def add_job(self, job: JobDefinition) -> None:
        """Registers a job node in the DAG."""
        self.jobs[job.name] = job
        if job.name not in self.dependencies:
            self.dependencies[job.name] = set()
        if job.name not in self.dependents:
            self.dependents[job.name] = set()

    def add_dependency(self, job_name: str, depends_on: str) -> None:
        """
        Adds a directed dependency edge: 'depends_on' -> 'job_name'.
        'depends_on' must execute before 'job_name'.
        """
        self.dependencies[job_name].add(depends_on)
        self.dependents[depends_on].add(job_name)

    def validate(self) -> None:
        """
        Validates DAG integrity:
        1. Ensures all dependencies exist in the declared jobs.
        2. Detects any cycle using DFS and raises CircularDependencyError with cycle path.
        """
        # 1. Verify existence of all dependencies
        for job_name, deps in self.dependencies.items():
            for dep in deps:
                if dep not in self.jobs:
                    raise DependencyError(
                        f"Job '{job_name}' depends on non-existent job '{dep}'"
                    )

        # 2. Cycle detection via 3-color DFS (0 = White/unvisited, 1 = Gray/visiting, 2 = Black/visited)
        visited: Dict[str, int] = {name: 0 for name in self.jobs}
        path: List[str] = []

        def dfs_detect_cycle(node: str) -> None:
            visited[node] = 1  # Gray
            path.append(node)

            # Node depends on upstream nodes (deps).
            # If we traverse from node to its dependencies or node to its dependents:
            # Let's traverse edge: dependency -> dependent (execution flow)
            for neighbor in self.dependents[node]:
                if neighbor not in visited:
                    continue
                if visited[neighbor] == 1:  # Cycle found
                    cycle_start = path.index(neighbor)
                    cycle_path = path[cycle_start:] + [neighbor]
                    raise CircularDependencyError(
                        f"Circular dependency detected: {' -> '.join(cycle_path)}"
                    )
                elif visited[neighbor] == 0:
                    dfs_detect_cycle(neighbor)

            path.pop()
            visited[node] = 2  # Black

        for node in list(self.jobs.keys()):
            if visited[node] == 0:
                dfs_detect_cycle(node)

    def topological_sort(self) -> List[str]:
        """
        Returns a linear topological order of job names where each job appears after its dependencies.
        Uses Kahn's algorithm.
        """
        self.validate()

        in_degree: Dict[str, int] = {name: len(self.dependencies[name]) for name in self.jobs}
        queue: deque[str] = deque([name for name, deg in in_degree.items() if deg == 0])
        sorted_jobs: List[str] = []

        while queue:
            node = queue.popleft()
            sorted_jobs.append(node)

            for dependent in sorted(self.dependents[node]):
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(sorted_jobs) != len(self.jobs):
            raise CircularDependencyError("Graph has circular dependencies that prevent complete topological ordering")

        return sorted_jobs

    def get_execution_layers(self) -> List[List[JobDefinition]]:
        """
        Groups jobs into parallel execution layers.
        Jobs in layer 0 have no dependencies.
        Jobs in layer k only depend on jobs in layers < k.
        All jobs in layer k can be safely scheduled to run concurrently.
        """
        self.validate()

        in_degree: Dict[str, int] = {name: len(self.dependencies[name]) for name in self.jobs}
        current_layer_names = [name for name, deg in in_degree.items() if deg == 0]
        layers: List[List[JobDefinition]] = []
        processed_count = 0

        while current_layer_names:
            current_layer_names.sort()  # deterministic ordering
            layer_jobs = [self.jobs[name] for name in current_layer_names]
            layers.append(layer_jobs)
            processed_count += len(current_layer_names)

            next_layer_names: List[str] = []
            for name in current_layer_names:
                for dependent in self.dependents[name]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        next_layer_names.append(dependent)

            current_layer_names = next_layer_names

        if processed_count != len(self.jobs):
            raise CircularDependencyError("Unable to resolve execution layers due to cyclic dependencies")

        return layers

    def get_independent_stages(self) -> Dict[str, List[JobDefinition]]:
        """Groups jobs by their pipeline stage."""
        stage_map: Dict[str, List[JobDefinition]] = defaultdict(list)
        for job in self.jobs.values():
            stage_map[job.stage].append(job)
        return dict(stage_map)

    def get_transitive_dependencies(self, job_name: str) -> Set[str]:
        """Returns all transitive upstream dependencies for a job."""
        if job_name not in self.jobs:
            raise KeyError(f"Job '{job_name}' does not exist in DAG")
        visited: Set[str] = set()
        queue = deque(self.dependencies[job_name])
        while queue:
            curr = queue.popleft()
            if curr not in visited:
                visited.add(curr)
                queue.extend(self.dependencies[curr])
        return visited

    def to_ascii(self) -> str:
        """Renders the DAG as an ASCII execution plan."""
        layers = self.get_execution_layers()
        lines: List[str] = [
            "============================================================",
            "                   PIPELINE EXECUTION DAG                   ",
            "============================================================",
        ]
        for idx, layer in enumerate(layers):
            lines.append(f"Layer {idx} (Parallel Batch - {len(layer)} job{'s' if len(layer) > 1 else ''}):")
            for job in layer:
                deps_str = f" [needs: {', '.join(sorted(job.needs))}]" if job.needs else " [root]"
                lines.append(f"  └── 📦 {job.name} (stage: {job.stage}){deps_str}")
            if idx < len(layers) - 1:
                lines.append("        │ (awaits completion)")
                lines.append("        ▼")
        lines.append("============================================================")
        return "\n".join(lines)

    def to_dot(self) -> str:
        """Renders the DAG in Graphviz DOT format."""
        lines = [
            "digraph PipelineDAG {",
            '  rankdir="LR";',
            '  node [shape="box", style="rounded,filled", fillcolor="#eef2f7", fontname="Helvetica"];',
            '  edge [color="#64748b", arrowhead="vee"];',
        ]
        for job_name, job_def in self.jobs.items():
            lines.append(f'  "{job_name}" [label="{job_name}\\n(stage: {job_def.stage})"];')

        for job_name, deps in self.dependencies.items():
            for dep in deps:
                lines.append(f'  "{dep}" -> "{job_name}";')

        lines.append("}")
        return "\n".join(lines)
