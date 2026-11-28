"""Asset identity resolution.

An asset is NOT its IP address. Resolution order, strongest evidence first:

  1. scanner-assigned ids (`external_ids`)      -> basis "external_id"
  2. MAC address (non-shared, non-multicast)    -> basis "mac"
  3. same last-known IP, if nothing contradicts -> basis "ip"
  4. unique FQDN, if nothing contradicts        -> basis "hostname"   (the host was renumbered)
  5. otherwise a new asset                      -> basis "new"

"Contradicts" is deliberately conservative: two hosts are never merged when their strong identifiers
disagree (disjoint MAC sets, different external id of the same kind) or their hostnames clearly differ.
Every refusal to merge is stored as an IdentityConflict so an operator can review it.
Every sighting is stored as an AssetObservation, so history survives IP and hostname changes.
Concurrency: look-up-then-create is serialised with advisory locks on every identifier and the IP.
"""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetIdentifier, AssetObservation, IdentityConflict
from app.schemas import HostIn
from app.services.dbutil import advisory_lock, dialect_insert
from app.services.netutil import hostnames_conflict, is_fqdn, is_public_ip, normalize_hostname


@dataclass
class Resolution:
    asset: Asset
    basis: str
    created: bool
    conflicts: list[IdentityConflict] = field(default_factory=list)


def strong_identifiers(host: HostIn) -> list[tuple[str, str]]:
    return [("mac", m) for m in host.mac_addresses] + [(f"ext:{k}", v) for k, v in sorted(host.external_ids.items())]


def _contradicts(db: Session, asset: Asset, ids: list[tuple[str, str]], *, check_macs: bool = True) -> str | None:
    """Return a human-readable reason if `ids` cannot belong to `asset`, else None.

    Disjoint MAC sets only count as a contradiction when the candidate was found by a *weak* basis (same IP /
    hostname). If a stronger identifier already ties the host to this asset, a new MAC is just another NIC.
    """
    existing = db.execute(
        select(AssetIdentifier.kind, AssetIdentifier.value).where(AssetIdentifier.asset_id == asset.id)
    ).all()
    ex_macs = {v for k, v in existing if k == "mac"}
    in_macs = {v for k, v in ids if k == "mac"}
    if check_macs and ex_macs and in_macs and not (ex_macs & in_macs):
        return f"MAC sets are disjoint (existing {sorted(ex_macs)}, incoming {sorted(in_macs)})"
    for kind, value in ids:
        if kind.startswith("ext:"):
            ex_vals = {v for k, v in existing if k == kind}
            if ex_vals and value not in ex_vals:
                return f"{kind} differs (existing {sorted(ex_vals)}, incoming {value!r})"
    return None


def _has_ext(items: list[tuple[str, str]]) -> bool:
    return any(k.startswith("ext:") for k, _ in items)


def resolve_asset(db: Session, host: HostIn, *, source: str, report_id: int | None, now: datetime) -> Resolution:
    ids = strong_identifiers(host)
    advisory_lock(db, [f"id:{k}:{v}" for k, v in ids] + [f"ip:{host.ip_address}"])

    conflicts: list[IdentityConflict] = []

    def conflict(kind: str, asset: Asset | None, other: Asset | None, **detail) -> None:
        conflicts.append(
            IdentityConflict(
                report_id=report_id,
                asset_id=asset.id if asset else None,
                other_asset_id=other.id if other else None,
                kind=kind,
                detail={"ip": host.ip_address, "hostname": host.hostname, "source": source, **detail},
            )
        )

    # -- 1/2. strong identifiers
    owners: dict[int, list[tuple[str, str]]] = {}
    for kind, value in ids:
        row = db.scalar(select(AssetIdentifier).where(AssetIdentifier.kind == kind, AssetIdentifier.value == value))
        if row:
            owners.setdefault(row.asset_id, []).append((kind, value))
    ranked = sorted(owners.items(), key=lambda kv: (0 if _has_ext(kv[1]) else 1, -len(kv[1]), kv[0]))

    chosen: Asset | None = None
    basis = "new"
    for asset_id, matched in ranked:
        cand = db.get(Asset, asset_id)
        reason = _contradicts(db, cand, ids, check_macs=False)  # matched by a strong id
        if reason:
            conflict("contradiction", cand, None, reason=reason, matched=matched)
        elif chosen is None:
            chosen, basis = cand, ("external_id" if _has_ext(matched) else "mac")
        else:
            conflict(
                "split_identity",
                chosen,
                cand,
                matched=matched,
                reason="incoming identifiers belong to more than one existing asset; not merged",
            )

    # -- 3. same IP
    if chosen is None:
        for cand in db.scalars(
            select(Asset).where(Asset.ip_address == host.ip_address).order_by(Asset.last_seen.desc(), Asset.id)
        ):
            reason = _contradicts(db, cand, ids)
            if reason:
                conflict("ip_reassigned", cand, None, reason=reason)
            elif hostnames_conflict(cand.hostname, host.hostname):
                conflict(
                    "hostname_mismatch",
                    cand,
                    None,
                    reason=f"same IP but hostname {cand.hostname!r} != {host.hostname!r}; treated as a different host",
                )
            else:
                chosen, basis = cand, "ip"
                break

    # -- 4. unique FQDN (host was renumbered)
    hn = normalize_hostname(host.hostname)
    if chosen is None and is_fqdn(hn):
        cands = [
            a for a in db.scalars(select(Asset).where(func.lower(Asset.hostname) == hn)) if not _contradicts(db, a, ids)
        ]
        if len(cands) == 1:
            chosen, basis = cands[0], "hostname"
        elif len(cands) > 1:
            conflict(
                "split_identity",
                None,
                None,
                reason=f"FQDN {hn!r} matches {len(cands)} assets; not merged",
                candidates=[a.id for a in cands],
            )

    created = chosen is None
    if created:
        public = is_public_ip(host.ip_address)
        chosen = Asset(
            ip_address=host.ip_address,
            hostname=host.hostname,
            os=host.os,
            first_seen=now,
            last_seen=now,
            internet_facing=public,
            exposure_source="public_ip" if public else "unknown",
        )
        db.add(chosen)
        db.flush()
    else:
        chosen.ip_address = host.ip_address
        chosen.hostname = host.hostname or chosen.hostname
        chosen.os = host.os or chosen.os
        chosen.last_seen = now

    for kind, value in ids:
        stmt = dialect_insert(db, AssetIdentifier).values(
            asset_id=chosen.id, kind=kind, value=value, source=source, first_seen=now, last_seen=now
        )
        db.execute(stmt.on_conflict_do_update(index_elements=["kind", "value"], set_={"last_seen": now}))

    db.add(
        AssetObservation(
            asset_id=chosen.id,
            report_id=report_id,
            source=source,
            ip_address=host.ip_address,
            hostname=host.hostname,
            os=host.os,
            macs=list(host.mac_addresses),
            match_basis=basis,
            observed_at=now,
        )
    )
    for c in conflicts:
        c.asset_id = c.asset_id or chosen.id
        db.add(c)
    db.flush()
    return Resolution(chosen, basis, created, conflicts)
