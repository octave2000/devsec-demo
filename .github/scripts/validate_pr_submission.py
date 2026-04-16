from __future__ import annotations

import json
import os
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from pathlib import Path


REQUIRED_HEADINGS = [
    "Assignment Summary",
    "Related Issue",
    "Target Assignment Branch",
    "Design Note",
    "Security Impact",
    "Changes Made",
    "Validation",
    "AI Assistance Used",
    "What AI Helped With",
    "What I Changed From AI Output",
    "Security Decisions I Made Myself",
    "Authorship Affirmation",
]

REQUIRED_CHECKLIST_LINES = [
    "I linked the related issue",
    "I linked exactly one assignment issue in the Related Issue section",
    "I started from the active assignment branch for this task",
    "My pull request targets the exact assignment branch named in the linked issue",
    "I included a short design note and meaningful validation details",
    "I disclosed any AI assistance used for this submission",
    "I can explain the key code paths, security decisions, and tests in this PR",
    "I tested the change locally",
    "I updated any directly related documentation or configuration, or none was required",
]

ASSIGNMENT_BRANCH_PATTERN = re.compile(
    r"^\s*(?:-\s*)?`?(assignment/[a-z0-9][a-z0-9-]*)`?\s*$",
    flags=re.MULTILINE,
)
ISSUE_REFERENCE_PATTERN = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)\b",
    flags=re.IGNORECASE,
)
REQUIRED_BRANCH_HEADING = "Required submission branch"


def _load_pull_request_body() -> str:
    return _load_event_payload().get("pull_request", {}).get("body") or ""


def _load_event_payload() -> dict[str, Any]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise RuntimeError("GITHUB_EVENT_PATH is not set")

    return json.loads(Path(event_path).read_text())


def _extract_sections(body: str) -> dict[str, str]:
    boundaries = [match for match in re.finditer(r"^## (.+?)\s*$", body, flags=re.MULTILINE)]
    sections: dict[str, str] = {}

    for index, match in enumerate(boundaries):
        heading = match.group(1).strip()
        start = match.end()
        end = boundaries[index + 1].start() if index + 1 < len(boundaries) else len(body)
        sections[heading] = body[start:end].strip()

    return sections


def _find_missing_headings(body: str) -> list[str]:
    missing: list[str] = []
    for heading in REQUIRED_HEADINGS:
        pattern = rf"^## {re.escape(heading)}\s*$"
        if not re.search(pattern, body, flags=re.MULTILINE):
            missing.append(heading)
    return missing


def _find_empty_sections(body: str) -> list[str]:
    empty: list[str] = []
    sections = _extract_sections(body)

    for heading in REQUIRED_HEADINGS:
        content = sections.get(heading, "")
        if not content:
            empty.append(heading)
            continue

        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
        ]
        if all(line in {"- _None_", "- None", "None", "_None_"} for line in lines):
            empty.append(heading)

    return empty


def _find_unchecked_checklist_items(body: str) -> list[str]:
    unchecked: list[str] = []
    for item in REQUIRED_CHECKLIST_LINES:
        if f"- [x] {item}" in body or f"- [X] {item}" in body:
            continue
        unchecked.append(item)
    return unchecked


def _extract_issue_numbers_from_related_section(body: str) -> list[int]:
    related_section = _extract_sections(body).get("Related Issue", "")
    issue_numbers = [int(match.group(1)) for match in ISSUE_REFERENCE_PATTERN.finditer(related_section)]
    return sorted(set(issue_numbers))


def _extract_branch_names(text: str) -> list[str]:
    return sorted({match.group(1) for match in ASSIGNMENT_BRANCH_PATTERN.finditer(text)})


def _is_assignment_submission(body: str, base_ref: str) -> bool:
    if base_ref.startswith("assignment/"):
        return True

    sections = _extract_sections(body)
    related = sections.get("Related Issue", "")
    branch_text = sections.get("Target Assignment Branch", "")
    return bool(_extract_branch_names(branch_text) or ISSUE_REFERENCE_PATTERN.search(related))


def _fetch_issue_body(issue_number: int) -> str:
    payload = _load_event_payload()
    repo = payload.get("repository", {})
    full_name = repo.get("full_name")
    token = os.environ.get("GITHUB_TOKEN")
    api_url_base = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if not full_name:
        raise RuntimeError("Repository full_name is missing from GitHub event payload")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is not set")

    request = Request(
        f"{api_url_base}/repos/{full_name}/issues/{issue_number}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "devsec-demo-pr-validator",
        },
    )

    try:
        with urlopen(request) as response:
            issue = json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f"Failed to fetch issue #{issue_number}: HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Failed to fetch issue #{issue_number}: {exc.reason}") from exc

    return issue.get("body") or ""


def _extract_required_branch_from_issue(issue_body: str) -> str | None:
    pattern = rf"^## {re.escape(REQUIRED_BRANCH_HEADING)}\s*$"
    match = re.search(pattern, issue_body, flags=re.MULTILINE)
    if not match:
        return None

    remaining = issue_body[match.end():]
    next_heading = re.search(r"^## .+?$", remaining, flags=re.MULTILINE)
    section = remaining[: next_heading.start() if next_heading else len(remaining)].strip()
    branches = _extract_branch_names(section)
    if len(branches) != 1:
        return None
    return branches[0]


def _validate_assignment_linking(body: str, base_ref: str) -> list[str]:
    if not _is_assignment_submission(body, base_ref):
        return []

    errors: list[str] = []
    sections = _extract_sections(body)
    target_branch_section = sections.get("Target Assignment Branch", "")
    target_branches = _extract_branch_names(target_branch_section)
    linked_issue_numbers = _extract_issue_numbers_from_related_section(body)

    if len(linked_issue_numbers) != 1:
        errors.append(
            "Student assignment submissions must link exactly one assignment issue in the Related Issue section.",
        )
        return errors

    if len(target_branches) != 1:
        errors.append(
            "Target Assignment Branch must include exactly one branch name like assignment/example-task.",
        )
        return errors

    declared_target_branch = target_branches[0]
    if declared_target_branch != base_ref:
        errors.append(
            f"PR base branch '{base_ref}' does not match the Target Assignment Branch '{declared_target_branch}'.",
        )

    issue_number = linked_issue_numbers[0]
    issue_body = _fetch_issue_body(issue_number)
    required_branch = _extract_required_branch_from_issue(issue_body)

    if not required_branch:
        errors.append(
            f"Linked issue #{issue_number} is missing a valid '{REQUIRED_BRANCH_HEADING}' section for CI to enforce.",
        )
        return errors

    if required_branch != base_ref:
        errors.append(
            f"Linked issue #{issue_number} requires branch '{required_branch}', but this PR targets '{base_ref}'.",
        )

    return errors


def main() -> int:
    payload = _load_event_payload()
    body = payload.get("pull_request", {}).get("body") or ""
    base_ref = payload.get("pull_request", {}).get("base", {}).get("ref") or ""
    if not body.strip():
        print("Pull request body is empty.")
        return 1

    missing_headings = _find_missing_headings(body)
    empty_sections = _find_empty_sections(body)
    unchecked_items = _find_unchecked_checklist_items(body)
    assignment_linking_errors = _validate_assignment_linking(body, base_ref)

    if not (missing_headings or empty_sections or unchecked_items or assignment_linking_errors):
        print("Pull request submission format looks good.")
        return 0

    if missing_headings:
        print("Missing required sections:")
        for heading in missing_headings:
            print(f"- {heading}")

    if empty_sections:
        print("Empty required sections:")
        for heading in empty_sections:
            print(f"- {heading}")

    if unchecked_items:
        print("Unchecked required checklist items:")
        for item in unchecked_items:
            print(f"- {item}")

    if assignment_linking_errors:
        print("Assignment branch validation errors:")
        for error in assignment_linking_errors:
            print(f"- {error}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
