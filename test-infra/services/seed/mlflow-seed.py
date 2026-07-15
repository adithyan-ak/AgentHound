#!/usr/bin/env python3
import json
import os
import time

from mlflow import MlflowClient
from mlflow.exceptions import MlflowException


TRACKING_URI = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000")
EXPERIMENT_NAME = "agenthound-offline-qa"
RUN_NAME = "agenthound-fixture-run"
REGISTERED_MODEL_NAME = "agenthound-fixture-model"
FIXTURE_ID = "agenthound-seed-v1"
START_TIME_MS = 1_720_000_000_000


def wait_for_mlflow(client: MlflowClient) -> None:
    for _ in range(60):
        try:
            client.search_experiments(max_results=1)
            return
        except Exception:
            time.sleep(2)
    raise RuntimeError(f"MLflow did not become ready at {TRACKING_URI}")


def ensure_experiment(client: MlflowClient) -> str:
    experiment = client.get_experiment_by_name(EXPERIMENT_NAME)
    if experiment is None:
        experiment_id = client.create_experiment(
            EXPERIMENT_NAME,
            tags={
                "agenthound.fixture_id": FIXTURE_ID,
                "purpose": "deterministic local collector QA",
            },
        )
    else:
        experiment_id = experiment.experiment_id
        client.set_experiment_tag(
            experiment_id, "agenthound.fixture_id", FIXTURE_ID
        )
        client.set_experiment_tag(
            experiment_id, "purpose", "deterministic local collector QA"
        )
    return experiment_id


def ensure_run(client: MlflowClient, experiment_id: str):
    runs = client.search_runs(
        experiment_ids=[experiment_id],
        max_results=100,
        order_by=["attributes.start_time ASC"],
    )
    for run in runs:
        if run.data.tags.get("agenthound.fixture_id") == FIXTURE_ID:
            return run

    run = client.create_run(
        experiment_id=experiment_id,
        start_time=START_TIME_MS,
        tags={
            "mlflow.runName": RUN_NAME,
            "agenthound.fixture_id": FIXTURE_ID,
            "model_role": "offline-security-qa",
        },
    )
    run_id = run.info.run_id
    client.log_param(run_id, "base_model", "Qwen/Qwen2-0.5B-Instruct")
    client.log_param(run_id, "dataset", "agenthound-placeholder-data")
    client.log_metric(
        run_id,
        "validation_score",
        0.875,
        timestamp=START_TIME_MS + 1_000,
        step=1,
    )
    client.set_terminated(
        run_id,
        status="FINISHED",
        end_time=START_TIME_MS + 5_000,
    )
    return client.get_run(run_id)


def ensure_registered_model(client: MlflowClient, run) -> str:
    try:
        client.get_registered_model(REGISTERED_MODEL_NAME)
    except MlflowException:
        client.create_registered_model(REGISTERED_MODEL_NAME)

    client.set_registered_model_tag(
        REGISTERED_MODEL_NAME, "agenthound.fixture_id", FIXTURE_ID
    )
    client.set_registered_model_tag(
        REGISTERED_MODEL_NAME, "purpose", "deterministic local collector QA"
    )

    versions = client.search_model_versions(
        filter_string=f"name = '{REGISTERED_MODEL_NAME}'",
        max_results=100,
    )
    for version in versions:
        if version.tags.get("agenthound.fixture_id") == FIXTURE_ID:
            return version.version

    source = f"runs:/{run.info.run_id}/model"
    version = client.create_model_version(
        name=REGISTERED_MODEL_NAME,
        source=source,
        run_id=run.info.run_id,
        description="Metadata-only model version for AgentHound offline QA.",
    )
    client.set_model_version_tag(
        REGISTERED_MODEL_NAME,
        version.version,
        "agenthound.fixture_id",
        FIXTURE_ID,
    )
    return version.version


def main() -> None:
    client = MlflowClient(tracking_uri=TRACKING_URI)
    wait_for_mlflow(client)
    experiment_id = ensure_experiment(client)
    run = ensure_run(client, experiment_id)
    model_version = ensure_registered_model(client, run)
    print(
        json.dumps(
            {
                "experiment_id": experiment_id,
                "experiment_name": EXPERIMENT_NAME,
                "model_name": REGISTERED_MODEL_NAME,
                "model_version": model_version,
                "run_id": run.info.run_id,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
