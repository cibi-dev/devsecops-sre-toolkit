"""
Unit tests for DAG dependency graph resolution, cycle detection, and topological sorting.
"""

import pytest

from runner.dag import (
    DAG,
    CircularDependencyError,
    DependencyError,
)
from runner.parser import JobDefinition, PipelineDefinition


def _create_dummy_job(name: str, stage: str = "default", needs: list[str] | None = None) -> JobDefinition:
    return JobDefinition(
        name=name,
        original_name=name,
        stage=stage,
        needs=needs or [],
        script=["echo test"],
    )


def test_dag_linear_chain():
    dag = DAG()
    dag.add_job(_create_dummy_job("job_a"))
    dag.add_job(_create_dummy_job("job_b", needs=["job_a"]))
    dag.add_job(_create_dummy_job("job_c", needs=["job_b"]))

    dag.add_dependency("job_b", "job_a")
    dag.add_dependency("job_c", "job_b")

    sorted_jobs = dag.topological_sort()
    assert sorted_jobs == ["job_a", "job_b", "job_c"]

    layers = dag.get_execution_layers()
    assert len(layers) == 3
    assert [j.name for j in layers[0]] == ["job_a"]
    assert [j.name for j in layers[1]] == ["job_b"]
    assert [j.name for j in layers[2]] == ["job_c"]


def test_dag_diamond_parallel_layers():
    # A -> B, A -> C, B -> D, C -> D
    dag = DAG()
    dag.add_job(_create_dummy_job("A"))
    dag.add_job(_create_dummy_job("B", needs=["A"]))
    dag.add_job(_create_dummy_job("C", needs=["A"]))
    dag.add_job(_create_dummy_job("D", needs=["B", "C"]))

    dag.add_dependency("B", "A")
    dag.add_dependency("C", "A")
    dag.add_dependency("D", "B")
    dag.add_dependency("D", "C")

    layers = dag.get_execution_layers()
    assert len(layers) == 3
    assert [j.name for j in layers[0]] == ["A"]
    assert sorted([j.name for j in layers[1]]) == ["B", "C"]
    assert [j.name for j in layers[2]] == ["D"]


def test_dag_direct_cycle_detection():
    dag = DAG()
    dag.add_job(_create_dummy_job("A", needs=["B"]))
    dag.add_job(_create_dummy_job("B", needs=["A"]))
    dag.add_dependency("A", "B")
    dag.add_dependency("B", "A")

    with pytest.raises(CircularDependencyError, match="Circular dependency detected"):
        dag.validate()


def test_dag_multinode_cycle_detection():
    # A -> B -> C -> A
    dag = DAG()
    dag.add_job(_create_dummy_job("A", needs=["C"]))
    dag.add_job(_create_dummy_job("B", needs=["A"]))
    dag.add_job(_create_dummy_job("C", needs=["B"]))
    dag.add_dependency("B", "A")
    dag.add_dependency("C", "B")
    dag.add_dependency("A", "C")

    with pytest.raises(CircularDependencyError, match="Circular dependency detected"):
        dag.validate()


def test_dag_self_cycle_detection():
    dag = DAG()
    dag.add_job(_create_dummy_job("A", needs=["A"]))
    dag.add_dependency("A", "A")

    with pytest.raises(CircularDependencyError, match="Circular dependency detected"):
        dag.validate()


def test_dag_missing_dependency_rejection():
    dag = DAG()
    dag.add_job(_create_dummy_job("A", needs=["unknown_job"]))
    dag.add_dependency("A", "unknown_job")

    with pytest.raises(DependencyError, match="depends on non-existent job 'unknown_job'"):
        dag.validate()


def test_dag_from_pipeline():
    pipeline = PipelineDefinition(
        name="Test Pipeline",
        stages=["build", "test"],
        jobs={
            "compile": _create_dummy_job("compile", stage="build"),
            "unit_test": _create_dummy_job("unit_test", stage="test", needs=["compile"]),
        },
    )
    dag = DAG.from_pipeline(pipeline)
    assert dag.topological_sort() == ["compile", "unit_test"]


def test_dag_transitive_dependencies():
    dag = DAG()
    dag.add_job(_create_dummy_job("A"))
    dag.add_job(_create_dummy_job("B", needs=["A"]))
    dag.add_job(_create_dummy_job("C", needs=["B"]))

    dag.add_dependency("B", "A")
    dag.add_dependency("C", "B")

    assert dag.get_transitive_dependencies("C") == {"A", "B"}
    assert dag.get_transitive_dependencies("B") == {"A"}
    assert dag.get_transitive_dependencies("A") == set()

    with pytest.raises(KeyError):
        dag.get_transitive_dependencies("non_existent")


def test_dag_ascii_and_dot_export():
    dag = DAG()
    dag.add_job(_create_dummy_job("build", stage="build"))
    dag.add_job(_create_dummy_job("test", stage="test", needs=["build"]))
    dag.add_dependency("test", "build")

    ascii_out = dag.to_ascii()
    assert "PIPELINE EXECUTION DAG" in ascii_out
    assert "build" in ascii_out
    assert "test" in ascii_out

    dot_out = dag.to_dot()
    assert "digraph PipelineDAG" in dot_out
    assert '"build" -> "test";' in dot_out


def test_dag_independent_stages():
    dag = DAG()
    dag.add_job(_create_dummy_job("lint1", stage="lint"))
    dag.add_job(_create_dummy_job("lint2", stage="lint"))
    dag.add_job(_create_dummy_job("test1", stage="test"))

    stages = dag.get_independent_stages()
    assert len(stages["lint"]) == 2
    assert len(stages["test"]) == 1
