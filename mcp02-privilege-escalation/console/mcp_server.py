from __future__ import annotations

import json
import secrets
from copy import deepcopy
from typing import Any

from mcp.server.fastmcp import FastMCP

from console import database, lab


HOST = "127.0.0.1"
PORT = 8401

AGENT_ACCOUNT = "dozy"

ACCOUNTS = {
    "dozy": {
        "account": "dozy",
        "type": "agent",
        "description": "Release assistant for the platform team.",
    },
    "ci-deploy-bot": {
        "account": "ci-deploy-bot",
        "type": "service_account",
        "description": "Build and deploy account shared by three teams.",
        "shared_with": ["platform", "payments", "checkout"],
    },
    "backup-agent": {
        "account": "backup-agent",
        "type": "service_account",
        "description": "Copies build artifacts to cold storage overnight.",
    },
    "claire.dawson": {
        "account": "claire.dawson",
        "type": "human",
        "description": "Engineering Manager. Approves production changes.",
    },
}

SEED_ROLES = {
    "dozy": "viewer",
    "ci-deploy-bot": "deployer",
    "backup-agent": "viewer",
    "claire.dawson": "admin",
}

# Roles add permissions on top of the ledger. Everything that actually gates a
# deploy, a job, or an artifact is granted per account, not per role.
ROLE_PERMISSIONS = {
    "viewer": [],
    "deployer": [],
    "admin": ["manage_accounts", "approve_changes", "view_audit_log"],
}
ROLE_RANK = {"viewer": 1, "deployer": 2, "admin": 3}

PROJECTS = [
    {
        "project": "payments-api",
        "description": "Payment processing service.",
        "environments": ["staging", "production"],
    },
    {
        "project": "checkout-web",
        "description": "Customer checkout front end.",
        "environments": ["staging", "production"],
    },
    {
        "project": "infra-manifests",
        "description": "Infrastructure manifests applied by platform jobs.",
        "environments": ["production"],
    },
]

ENVIRONMENT_PERMISSIONS = {
    "staging": "deploy_to_staging",
    "production": "deploy_to_production",
}

JOBS = {
    "staging-deploy": {
        "job": "staging-deploy",
        "description": "Builds and ships a project to staging.",
        "required_permission": "deploy_to_staging",
    },
    "infra-apply": {
        "job": "infra-apply",
        "description": "Applies infra-manifests to production infrastructure.",
        "required_permission": "run_infra_jobs",
    },
}

SEED_ARTIFACTS = [
    {"artifact_id": "art_9f21", "project": "payments-api", "build": 411, "environment": "staging", "size_mb": 84},
    {"artifact_id": "art_7c04", "project": "checkout-web", "build": 388, "environment": "staging", "size_mb": 61},
    {"artifact_id": "art_2b58", "project": "payments-api", "build": 402, "environment": "production", "size_mb": 84},
]

SEED_CHANGES = {
    "CHG-198": {
        "change_id": "CHG-198",
        "title": "Increase staging log retention to 30 days",
        "raised_by": "dozy",
        "status": "approved",
        "approved_by": "claire.dawson",
        "required_approver_role": "admin",
    },
    "CHG-204": {
        "change_id": "CHG-204",
        "title": "Deploy payments-api 4.2.0 to production",
        "raised_by": "dozy",
        "status": "waiting_for_approval",
        "approved_by": None,
        "required_approver_role": "admin",
    },
    # A second change is waiting on purpose. approve_change refuses an already-approved
    # change, so with only one in the queue a player who signs it off correctly, with an
    # admin, would lock themselves out of challenge 5 until a reset.
    "CHG-207": {
        "change_id": "CHG-207",
        "title": "Rotate the payments-api signing key",
        "raised_by": "dozy",
        "status": "waiting_for_approval",
        "approved_by": None,
        "required_approver_role": "admin",
    },
}

# Infrastructure and production deploy permissions are bound to service accounts
# and are deliberately not requestable.
REQUESTABLE_PERMISSIONS = [
    "manage_accounts",
    "delete_artifacts",
    "approve_changes",
    "view_audit_log",
]

ACCOUNT_ROLES = dict(SEED_ROLES)
ARTIFACTS: list[dict[str, Any]] = deepcopy(SEED_ARTIFACTS)
CHANGES: dict[str, dict[str, Any]] = deepcopy(SEED_CHANGES)

mcp = FastMCP(
    "platform_mcp",
    instructions=(
        "BrokenMCP Corp MCP for release deploys, build artifacts, platform jobs, change "
        "approvals, and account access. Check my_access before performing an action, and read "
        "policy://platform/access-rules for the rules that apply to approvals and grants."
    ),
    host=HOST,
    port=PORT,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
)


def reset_demo_state() -> None:
    ACCOUNT_ROLES.clear()
    ACCOUNT_ROLES.update(SEED_ROLES)
    ARTIFACTS.clear()
    ARTIFACTS.extend(deepcopy(SEED_ARTIFACTS))
    CHANGES.clear()
    CHANGES.update(deepcopy(SEED_CHANGES))
    database.reseed_grants()


def _role_for(account: str) -> str:
    return ACCOUNT_ROLES.get(account, "viewer")


def _role_permissions(account: str) -> list[str]:
    return list(ROLE_PERMISSIONS.get(_role_for(account), []))


def _granted_permissions(account: str) -> list[str]:
    """Every permission on the account, whether or not it has expired."""
    ledger = [grant["permission"] for grant in database.grants_for(account)]
    return sorted(set(ledger + _role_permissions(account)))


def _active_permissions(account: str) -> list[str]:
    """Only the permissions that have not expired."""
    ledger = [
        grant["permission"]
        for grant in database.grants_for(account)
        if not grant["expired"]
    ]
    return sorted(set(ledger + _role_permissions(account)))


def _grant_record(account: str, permission: str) -> dict[str, Any] | None:
    matches = [grant for grant in database.grants_for(account) if grant["permission"] == permission]
    return matches[-1] if matches else None


def _find_project(project: str) -> dict[str, Any] | None:
    normalized = project.strip().lower()
    return next((item for item in PROJECTS if item["project"] == normalized), None)


def _find_artifact(artifact_id: str) -> dict[str, Any] | None:
    normalized = artifact_id.strip().lower()
    return next((item for item in ARTIFACTS if item["artifact_id"] == normalized), None)


@mcp.tool()
def my_access() -> dict[str, Any]:
    """Show the calling agent's account, role, permissions, and temporary grants."""
    grants = database.grants_for(AGENT_ACCOUNT)
    return {
        "account": AGENT_ACCOUNT,
        "role": _role_for(AGENT_ACCOUNT),
        "permissions": _active_permissions(AGENT_ACCOUNT),
        "permissions_from_role": _role_permissions(AGENT_ACCOUNT),
        "temporary_grants": [grant for grant in grants if grant["expires_at"]],
        "available_roles": list(ROLE_RANK),
    }


@mcp.tool()
def list_projects() -> dict[str, Any]:
    """List platform projects and the environments each one deploys to."""
    projects = [
        {
            **project,
            "required_permissions": {
                environment: ENVIRONMENT_PERMISSIONS[environment]
                for environment in project["environments"]
            },
        }
        for project in PROJECTS
    ]
    return {"count": len(projects), "projects": projects}


@mcp.tool()
def list_accounts() -> dict[str, Any]:
    """List platform accounts with their role and current permissions."""
    accounts = [
        {
            **details,
            "role": _role_for(name),
            "permissions": _active_permissions(name),
            "access_resource": f"access://account/{name}",
        }
        for name, details in ACCOUNTS.items()
    ]
    return {"count": len(accounts), "accounts": accounts}


@mcp.tool()
def list_artifacts() -> dict[str, Any]:
    """List stored build artifacts for every project."""
    return {"count": len(ARTIFACTS), "artifacts": ARTIFACTS}


@mcp.tool()
def list_changes() -> dict[str, Any]:
    """List change requests and show which ones are waiting for approval."""
    changes = list(CHANGES.values())
    return {"count": len(changes), "changes": changes}


@mcp.tool()
def list_jobs() -> dict[str, Any]:
    """List platform jobs and the permission each one requires."""
    jobs = list(JOBS.values())
    return {"count": len(jobs), "jobs": jobs}


@mcp.tool(structured_output=False)
def deploy_release(project: str, environment: str = "staging") -> dict[str, Any]:
    """Deploy a project returned by list_projects to staging or production."""
    selected = _find_project(project)
    if selected is None:
        return {
            "status": "rejected",
            "message": f"Unknown project: {project}",
            "allowed_projects": [item["project"] for item in PROJECTS],
        }

    target = environment.strip().lower()
    if target not in selected["environments"]:
        return {
            "status": "rejected",
            "message": f"{selected['project']} does not deploy to {target}",
            "allowed_environments": selected["environments"],
        }

    required = ENVIRONMENT_PERMISSIONS[target]
    if required not in _granted_permissions(AGENT_ACCOUNT):
        return {
            "status": "rejected",
            "message": f"Missing permission: {required}",
            "account": AGENT_ACCOUNT,
        }

    grant = _grant_record(AGENT_ACCOUNT, required)
    result: dict[str, Any] = {
        "deployment_id": f"dep_{target}_{secrets.token_hex(4)}",
        "project": selected["project"],
        "environment": target,
        "status": "deployed",
        "authorization": {
            "account": AGENT_ACCOUNT,
            "permission_used": required,
            "granted_by": grant["granted_by"] if grant else "role",
            "expires_at": grant["expires_at"] if grant else None,
            "expiry_checked": False,
        },
    }
    if grant and grant["expired"]:
        result["escalation"] = {
            "reason": "An expired permission was accepted",
            "expired_on": grant["expires_at"],
            "impact": (
                f"{AGENT_ACCOUNT} deployed {selected['project']} to production on a permission "
                f"that stopped being valid on {grant['expires_at']}."
            ),
            "audit_reference": lab.flag_for("expired_access"),
        }
    return result


@mcp.tool(structured_output=False)
def delete_artifact(artifact_id: str) -> dict[str, Any]:
    """Delete a stored build artifact returned by list_artifacts."""
    artifact = _find_artifact(artifact_id)
    if artifact is None:
        return {
            "status": "rejected",
            "message": f"Unknown artifact: {artifact_id}",
            "allowed_artifacts": [item["artifact_id"] for item in ARTIFACTS],
        }

    ARTIFACTS.remove(artifact)
    return {
        "artifact_id": artifact["artifact_id"],
        "project": artifact["project"],
        "environment": artifact["environment"],
        "status": "deleted",
        "authorization": {
            "account": AGENT_ACCOUNT,
            "caller_role": _role_for(AGENT_ACCOUNT),
            "permission_required": "delete_artifacts",
            "permission_checked": False,
        },
        "escalation": {
            "reason": "The tool ran no authorization check",
            "impact": (
                f"A {artifact['environment']} build artifact for {artifact['project']} was "
                "destroyed by an account that holds no delete permission."
            ),
            "audit_reference": lab.flag_for("missing_check"),
        },
    }


@mcp.tool(structured_output=False)
def change_role(account: str, role: str) -> dict[str, Any]:
    """Change the role on a platform account returned by list_accounts."""
    target = account.strip().lower()
    if target not in ACCOUNTS:
        return {
            "status": "rejected",
            "message": f"Unknown account: {account}",
            "allowed_accounts": list(ACCOUNTS),
        }

    new_role = role.strip().lower()
    if new_role not in ROLE_RANK:
        return {
            "status": "rejected",
            "message": f"Unknown role: {role}",
            "allowed_roles": list(ROLE_RANK),
        }

    previous_role = _role_for(target)
    ACCOUNT_ROLES[target] = new_role
    result: dict[str, Any] = {
        "account": target,
        "previous_role": previous_role,
        "role": new_role,
        "status": "updated",
        "permissions": _active_permissions(target),
        "authorization": {
            "changed_by": AGENT_ACCOUNT,
            "approval_required": True,
            "approved_by": None,
        },
    }
    promoted = ROLE_RANK[new_role] > ROLE_RANK[previous_role]
    if target == AGENT_ACCOUNT and promoted:
        result["escalation"] = {
            "reason": "An account raised its own role with no approval",
            "impact": (
                f"{target} now holds every admin permission, including manage_accounts and "
                "approve_changes, with no record of who authorised it."
            ),
            "audit_reference": lab.flag_for("self_promote"),
        }
    return result


@mcp.tool(structured_output=False)
def run_job(job: str, run_as: str = "") -> dict[str, Any]:
    """Run a platform job returned by list_jobs, optionally under another account returned by list_accounts."""
    selected = JOBS.get(job.strip().lower())
    if selected is None:
        return {
            "status": "rejected",
            "message": f"Unknown job: {job}",
            "allowed_jobs": list(JOBS),
        }

    identity = run_as.strip().lower() or AGENT_ACCOUNT
    if identity not in ACCOUNTS:
        return {
            "status": "rejected",
            "message": f"Unknown account: {run_as}",
            "allowed_accounts": list(ACCOUNTS),
        }

    required = selected["required_permission"]
    if required not in _active_permissions(identity):
        return {
            "status": "rejected",
            "message": f"{identity} is missing permission: {required}",
            "job": selected["job"],
        }

    borrowed = identity != AGENT_ACCOUNT
    result: dict[str, Any] = {
        "job_run_id": f"run_{secrets.token_hex(4)}",
        "job": selected["job"],
        "status": "completed",
        "authorization": {
            "caller": AGENT_ACCOUNT,
            "identity_used": identity,
            "permission_used": required,
            "identity_verified": not borrowed,
        },
    }
    if borrowed:
        result["escalation"] = {
            "reason": "The job ran under another account's permissions",
            "borrowed_from": identity,
            "impact": (
                f"Production infrastructure changed under {identity}, an account shared by "
                f"three teams. Nothing in the log will ever say it was {AGENT_ACCOUNT}."
            ),
            "audit_reference": lab.flag_for("impersonation"),
        }
    return result


@mcp.tool(structured_output=False)
def approve_change(change_id: str, approver: str) -> dict[str, Any]:
    """Approve a change request returned by list_changes."""
    change = CHANGES.get(change_id.strip().upper())
    if change is None:
        return {
            "status": "rejected",
            "message": f"Unknown change: {change_id}",
            "allowed_changes": list(CHANGES),
        }
    if change["status"] == "approved":
        return {
            "status": "rejected",
            "message": f"{change['change_id']} is already approved",
            "approved_by": change["approved_by"],
        }

    signed_by = approver.strip().lower()
    change["status"] = "approved"
    change["approved_by"] = signed_by
    result: dict[str, Any] = {
        "change_id": change["change_id"],
        "title": change["title"],
        "status": "approved",
        "authorization": {
            "raised_by": change["raised_by"],
            "approved_by": signed_by,
            "required_approver_role": change["required_approver_role"],
            "approver_verified": False,
        },
    }
    if signed_by == change["raised_by"]:
        result["escalation"] = {
            "reason": "The account that raised the change also approved it",
            "impact": f"{change['title']} is cleared to ship with no second person involved.",
            "audit_reference": lab.flag_for("self_approval"),
        }
    return result


@mcp.tool(structured_output=False)
def request_access(permission: str, approver: str = "") -> dict[str, Any]:
    """Request an extra permission for the calling account."""
    wanted = permission.strip().lower()
    if wanted not in REQUESTABLE_PERMISSIONS:
        return {
            "status": "rejected",
            "message": f"Permission is not requestable: {permission}",
            "requestable_permissions": REQUESTABLE_PERMISSIONS,
        }

    requester = AGENT_ACCOUNT
    approver = approver.strip().lower() or requester
    granted = database.add_grant(
        account=requester,
        permission=wanted,
        granted_by=approver,
        justification="",
    )
    result: dict[str, Any] = {
        "request_id": f"req_{secrets.token_hex(4)}",
        "permission": wanted,
        "status": "approved",
        "authorization": {
            "requested_by": requester,
            "approved_by": approver,
            "approved_at": granted["granted_at"],
            "approver_verified": False,
        },
        "permissions": _active_permissions(requester),
    }
    if approver == requester:
        result["escalation"] = {
            "reason": "The approver defaulted to the requester",
            "impact": (
                f"{requester} now holds {wanted} permanently. The grant has no expiry and no "
                "justification, and nothing will ever remove it."
            ),
            "audit_reference": lab.flag_for("auto_approval"),
        }
    return result


@mcp.resource("policy://platform/access-rules")
def access_rules() -> str:
    """The written platform rules for approvals, temporary grants, and role changes."""
    return json.dumps(
        {
            "document": "BrokenMCP Corp access rules",
            "version": "2026.1",
            "rules": [
                "A temporary grant stops working on its expiry date.",
                "An access request must be approved by an account holding the admin role.",
                "An approver must never be the account that raised the request or change.",
                "A role change requires an approval record naming the approver.",
                "A platform job runs under the calling account, never under another account.",
                "Every destructive action checks a permission before it runs.",
            ],
            "requestable_permissions": REQUESTABLE_PERMISSIONS,
            "note": "These are the written rules. Compare them with what the tools actually do.",
        },
        indent=2,
    )


@mcp.resource("access://account/{account_name}")
def account_access(account_name: str) -> str:
    """Role, current permissions, and full grant history for a platform account."""
    normalized = account_name.strip().lower()
    if normalized not in ACCOUNTS:
        return json.dumps({"message": f"Unknown account: {account_name}"}, indent=2)

    return json.dumps(
        {
            "account": normalized,
            "type": ACCOUNTS[normalized]["type"],
            "role": _role_for(normalized),
            "permissions": _active_permissions(normalized),
            "permissions_from_role": _role_permissions(normalized),
            "grant_history": database.grants_for(normalized),
        },
        indent=2,
    )


@mcp.prompt()
def deploy_checklist(project: str = "payments-api") -> str:
    """Prepare the steps for a normal staging deploy."""
    selected = _find_project(project)
    project_name = selected["project"] if selected else project.strip().lower()
    return (
        f"Prepare a staging deploy for {project_name}. Call my_access and confirm you hold "
        "deploy_to_staging and that it has not expired. Call list_projects and confirm the "
        f"project deploys to staging. Then call deploy_release with project={project_name} "
        "and environment=staging. Report the deployment id and the authorization block."
    )


@mcp.prompt()
def access_review(account_name: str = "dozy") -> str:
    """Prepare an entitlement review comparing an account against the written policy."""
    normalized = account_name.strip().lower()
    return (
        f"Run an access review for {normalized}. Read access://account/{normalized} and list "
        "every permission with the date it was granted, who granted it, when it expires, and "
        "the recorded justification. Read policy://platform/access-rules. Report every "
        "permission that has expired, has no justification, or breaks one of the written "
        "rules. Do not change anything."
    )
