"""Extract and select first-repeat corpus records under the frozen sampling protocol."""

from __future__ import annotations

from agentsec_evidence.core.identity import canonical_json_bytes, sha256_bytes

SEED = "sonic-corpus-review-v1-2026-10-22"
CAPS = {
    "tool-execution": 12,
    "network-data": 12,
    "filesystem": 12,
    "memory-state": 12,
    "self-modification": 12,
    "semgrep-research": 10,
    "agent-audit-python": 10,
}


def records(report: dict) -> list[dict]:
    candidate = report["candidate"]
    sources = {e["source"]["path"]: e for e in report["selected_inputs"]}
    result = []

    def add(producer, key, path, rule, native_id, location, claim):
        if path not in sources:
            raise ValueError("Review record has no bound selected source")
        source = sources[path]
        identity = {
            "candidate_id": candidate["candidate_id"],
            "revision": candidate["revision"],
            "producer": producer,
            "rule_id": rule,
            "source_path": path,
            "source_sha256": source["source"]["sha256"],
            "native_record_identity": native_id,
            "location": location,
        }
        identity_bytes = canonical_json_bytes(identity)
        result.append(
            {
                "identity": identity,
                "identity_sha256": sha256_bytes(identity_bytes),
                "rank_sha256": sha256_bytes(
                    canonical_json_bytes({"seed": SEED, "identity": identity})
                ),
                "candidate_role": candidate["role"],
                "path_role": source["path_role"],
                "evidence_key": key,
                "claim_record": claim,
                "review_status": "pending",
                "outcome": None,
                "reviewer": None,
                "context": None,
                "mitigations": None,
                "security_relevance": None,
                "uncertainty": None,
                "overlap": None,
            }
        )

    for row in report["rows"]:
        producer, key = row["producer"], row["key"]
        if row["repetition"] != 1 or producer not in CAPS or row["state"] != "observed":
            continue
        obs = report["observations"][key]
        before = len(result)
        if obs["kind"] == "custom":
            rules = {r["rule_id"]: r for r in obs["native"]["rules"]}
            for file in obs["native"]["files"]:
                if file["source_sha256"] != sources[file["path"]]["source"]["sha256"]:
                    raise ValueError("Custom source binding differs")
                for record in file["findings"] or []:
                    rule_id = record["rule"]["rule_id"] if "rule" in record else record["rule_id"]
                    rule = rules[rule_id]
                    if producer != "tool-execution" and rule["status"] != "active-condition":
                        raise ValueError("Non-condition record entered review population")
                    add(
                        producer,
                        key,
                        file["path"],
                        rule_id,
                        {"record_id": record["record_id"], "blob_sha256": obs["native_sha256"]},
                        record["location"],
                        {"finding": record, "rule": rule},
                    )
        elif obs["kind"] == "semgrep":
            for record in obs["evidence"]["findings"]:
                anchor = record["anchor"]
                add(
                    producer,
                    key,
                    anchor["path"],
                    anchor["rule_id"],
                    {
                        "json_pointer": record["json_pointer"],
                        "blob_sha256": obs["evidence"]["native_json_sha256"],
                    },
                    anchor,
                    record,
                )
        elif obs["kind"] == "agent-audit":
            for record in obs["findings"]:
                if len(record["locations"]) != 1 or len(record["evidence"]) != 1:
                    raise ValueError("Review identity requires explicit multi-location support")
                location = record["locations"][0]
                evidence = record["evidence"][0]
                add(
                    producer,
                    key,
                    location["artifact_path"],
                    record["rule"]["native_id"],
                    {
                        "json_pointer": evidence["json_pointer"],
                        "blob_sha256": evidence["blob_sha256"],
                    },
                    location,
                    record,
                )
        else:
            raise ValueError("Unknown eligible producer observation")
        if len(result) - before != row["finding_records"]:
            raise ValueError("Review population does not reconcile to first-repeat records")
    if len({r["identity_sha256"] for r in result}) != len(result):
        raise ValueError("Duplicate review identities")
    return result


def select(population: list[dict]) -> list[dict]:
    selected = []
    for producer, cap in CAPS.items():
        candidates = [r for r in population if r["identity"]["producer"] == producer]
        candidates.sort(key=lambda r: (r["rank_sha256"], canonical_json_bytes(r["identity"])))
        selected.extend(candidates[:cap])
    return selected
