#!/usr/bin/env python3
"""
oci_assessment.py - Assessment SOMENTE LEITURA de um tenancy Oracle Cloud (OCI) alinhado ao
OCI Well-Architected Framework (5 pilares):
  Segurança e conformidade · Confiabilidade e resiliência · Desempenho e custos · Eficiência operacional · Cloud distribuído

Levanta o que existe (observabilidade, segurança, backup/DR, custos, conectividade), aponta lacunas por pilar
com recomendação e gera relatório para stakeholders.

Gera: relatorio.html (stakeholders) · dados.json (bruto; checks/scores/scores_pilar/score_global)
      achados.csv (backlog por pilar) · cobertura_recursos.csv (recurso x alarme/log/métrica/tag)
      otimizacao_custos.csv (desperdício e rightsizing por recurso, com custo real 30d e economia estimada)
      custos_por_recurso.csv (top 25 recursos por custo, mês a mês, na janela de --cost-days; padrão 90 dias)
      relatorio_executivo.pdf (liderança) · relatorio_tecnico.pdf (times de engenharia, A4 paisagem)
      apresentacao_stakeholders.pptx (16:9, gráficos nativos editáveis e notas do apresentador)

Requisitos : Python 3.10+, `pip install oci`   (já instalado no OCI Cloud Shell)
             PDF/PPTX (opcionais): `pip install --user reportlab python-pptx`; sem eles, essas saídas são puladas
Autenticação (--auth):
  auto (padrão) · cloudshell (delegation token) · config (~/.oci/config + --profile) · instance_principal
Permissão mínima (somente leitura):
  Allow group <grupo-assessment> to inspect all-resources in tenancy
  Allow group <grupo-assessment> to read all-resources in tenancy
  Allow group <grupo-assessment> to read usage-reports in tenancy        (pilar de custos / Usage API)
Compartments/serviços sem permissão são contados como "negados" no apêndice e o assessment continua.

Garantia de read-only: todo client passa por um proxy que só permite métodos list_/get_/search_/summarize_
(search_resources, list_metrics, summarize_metrics_data e request_summarized_usages são POST de consulta,
sem efeito colateral). Qualquer outro método levanta erro.

Uso:
  python3 oci_assessment.py --customer "Assaí Atacadista" --days 30
  python3 oci_assessment.py --auth config --profile ASSAI --regions sa-saopaulo-1,sa-vinhedo-1
  python3 oci_assessment.py --compartments "Prod,Shared" --threads 12
  python3 oci_assessment.py --render-only ./oci-assessment-20261123-1500/dados.json
  python3 oci_assessment.py --render-only ./oci-assessment-20261123-1500/dados.json --formats pdf   (só PDFs; 'none' desliga)
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import statistics
import sys
import threading
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

try:
    import oci
except ImportError:  # render-only não precisa do SDK
    oci = None

# --------------------------------------------------------------------------- #
# Catálogos
# --------------------------------------------------------------------------- #

TYPE_LABELS = {
    "Instance": "Compute (VMs/BM)", "LoadBalancer": "Load Balancers", "NetworkLoadBalancer": "Network Load Balancers",
    "AutonomousDatabase": "Autonomous Databases", "DbSystem": "DB Systems", "Database": "Databases (DB System)",
    "CloudVmCluster": "Exadata VM Clusters", "VmCluster": "VM Clusters (ExaC@C)", "MysqlDbSystem": "MySQL HeatWave",
    "PostgresqlDbSystem": "PostgreSQL", "Bucket": "Object Storage Buckets", "Volume": "Block Volumes", "BootVolume": "Boot Volumes",
    "ApiGateway": "API Gateways", "ApiDeployment": "API Deployments", "FunctionsApplication": "Functions Applications",
    "FunctionsFunction": "Functions", "ClustersCluster": "OKE Clusters", "IPSecConnection": "VPN IPSec", "VirtualCircuit": "FastConnect",
    "FileSystem": "File Storage", "Stream": "Streaming", "WebAppFirewall": "WAF", "Queue": "Queues", "Vcn": "VCNs", "Subnet": "Subnets",
    "Drg": "DRGs", "NetworkFirewall": "Network Firewalls",
}

# tipo (Resource Search) -> namespace de métricas nativas
NS_BY_TYPE = {
    "Instance": "oci_computeagent", "LoadBalancer": "oci_lbaas", "NetworkLoadBalancer": "oci_nlb",
    "AutonomousDatabase": "oci_autonomous_database", "DbSystem": "oci_database", "Database": "oci_database",
    "CloudVmCluster": "oci_database_cluster", "VmCluster": "oci_database_cluster", "MysqlDbSystem": "oci_mysql_database",
    "PostgresqlDbSystem": "oci_postgresql", "Bucket": "oci_objectstorage", "Volume": "oci_blockstore", "BootVolume": "oci_blockstore",
    "ApiGateway": "oci_apigateway", "FunctionsFunction": "oci_faas", "ClustersCluster": "oci_oke", "IPSecConnection": "oci_vpn",
    "VirtualCircuit": "oci_fastconnect", "FileSystem": "oci_filestorage", "Stream": "oci_streaming", "WebAppFirewall": "oci_waf",
    "Queue": "oci_queue", "NetworkFirewall": "oci_network_firewall",
}
CRITICAL_TYPES = ("Instance", "LoadBalancer", "NetworkLoadBalancer", "AutonomousDatabase", "DbSystem", "CloudVmCluster", "VmCluster",
                  "MysqlDbSystem", "PostgresqlDbSystem", "ClustersCluster", "ApiGateway", "IPSecConnection", "VirtualCircuit")
# tipos que suportam logs de serviço (OCI Logging)
LOG_TYPES = {"LoadBalancer": "access/error", "Subnet": "VCN Flow Logs", "Bucket": "read/write", "ApiDeployment": "access/execution",
             "FunctionsApplication": "invoke", "WebAppFirewall": "WAF", "NetworkFirewall": "traffic/threat"}
TAG_TYPES = set(NS_BY_TYPE) | set(LOG_TYPES) | {"Vcn", "Drg", "FunctionsApplication"}
DB_TYPES = ("AutonomousDatabase", "DbSystem", "CloudVmCluster", "VmCluster", "MysqlDbSystem", "PostgresqlDbSystem")
GLOBAL_TYPES = {"Compartment", "User", "Group", "Policy", "DynamicGroup", "TagNamespace", "TagDefault", "IdentityProvider", "Tenancy",
                "NetworkSource", "AuthenticationPolicy", "Domain", "TagDefinition", "Alarm", "OnsTopic", "OnsSubscription", "EventRule",
                "LogGroup", "Log", "ServiceConnector"}
DEAD = {"TERMINATED", "TERMINATING", "DELETED", "DELETING", "FAILED"}
SYSTEM_TAG_NS = {"oracle-tags", "orcl-cloud", "oracle-recommended-tags"}
ONCALL = {"PAGERDUTY", "SLACK", "HTTPS", "CUSTOM_HTTPS", "ORACLE_FUNCTIONS"}
FILTER_RE = re.compile(r"\{[^}]*\b(resourceId|resourceName|resourceDisplayName|displayName|instanceId|lbName|dbName|resourceID)\b", re.I)
STATE_RE = re.compile(r"\b(?:to|is|now)\s+(FIRING|OK|RESET)\b", re.I)

P_SEC, P_REL, P_PERF, P_OPS, P_DIST = ("Segurança e conformidade", "Confiabilidade e resiliência", "Desempenho e custos",
                                      "Eficiência operacional", "Cloud distribuído")
PILLARS = (P_SEC, P_REL, P_PERF, P_OPS, P_DIST)
D_IAM, D_NET, D_DATA = "Identidade & Acesso", "Rede & Exposição", "Proteção de dados"
D_HA, D_BKP = "Alta disponibilidade", "Backup & DR"
D_COST, D_WASTE, D_RIGHT = "Visibilidade de custos", "Desperdício", "Rightsizing & Elasticidade"
D_HYB = "Conectividade híbrida/multicloud"
SENSITIVE_PORTS = (22, 3389, 1521, 1522, 3306, 5432, 1433, 6379, 9200, 27017)
LEGACY_SHAPE_RE = re.compile(r"^(VM|BM)\.(Standard1|Standard2|Standard\.E2\.\d|Standard\.B1|DenseIO1|DenseIO2|GPU2|GPU3)", re.I)
D_GOV, D_MON, D_RESP, D_LOG = "Inventário & Governança", "Métricas & Alarmes", "Notificações & Resposta", "Logs & Auditoria"
D_APM, D_DB, D_SEC, D_INT = "APM & Experiência Digital", "Bancos & Plataforma", "Segurança (Cloud Guard)", "Integração & Exportação"
DOMAIN_PILLAR = {D_GOV: P_PERF, D_MON: P_OPS, D_RESP: P_OPS, D_LOG: P_OPS, D_APM: P_OPS, D_DB: P_OPS, D_SEC: P_SEC, D_INT: P_OPS,
                 D_IAM: P_SEC, D_NET: P_SEC, D_DATA: P_SEC, D_HA: P_REL, D_BKP: P_REL, D_COST: P_PERF, D_WASTE: P_PERF, D_RIGHT: P_PERF,
                 D_HYB: P_DIST}
SEV_ORDER = {"Alta": 0, "Média": 1, "Baixa": 2}
SEV_W = {"Alta": 3, "Média": 2, "Baixa": 1}

_lock = threading.Lock()


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr)


def pct(a: int | float, b: int | float) -> int:
    return round(100 * a / b) if b else 0


# --------------------------------------------------------------------------- #
# Clientes (read-only)
# --------------------------------------------------------------------------- #

READ_RE = re.compile(r"^(list|get|search|summarize|request_summarized)_")


class ReadOnly:
    """Proxy: só expõe chamadas de leitura do client OCI."""

    def __init__(self, client: Any, stats: Counter):
        self._c, self._s = client, stats

    def __getattr__(self, name: str):
        if not READ_RE.match(name):
            raise PermissionError(f"operação '{name}' bloqueada: assessment somente leitura")
        fn = getattr(self._c, name)

        def call(*a, **kw):
            with _lock:
                self._s["calls"] += 1
            return fn(*a, **kw)

        return call


class Factory:
    def __init__(self, cfg: dict, signer: Any):
        self.cfg, self.signer, self.stats, self.tl = cfg, signer, Counter(), threading.local()

    def __call__(self, cls: type, region: str) -> ReadOnly:
        cache = self.tl.__dict__.setdefault("c", {})
        key = (cls, region)
        if key not in cache:
            kw: dict[str, Any] = {"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY, "timeout": (10, 180)}
            if self.signer:
                kw["signer"] = self.signer
            cache[key] = ReadOnly(cls(dict(self.cfg, region=region), **kw), self.stats)
        return cache[key]


def make_auth(a: argparse.Namespace) -> tuple[dict, Any, str, str]:
    mode = a.auth
    if mode == "auto":
        mode = "cloudshell" if os.getenv("OCI_CLI_CLOUD_SHELL", "").lower() == "true" else "config"
    if mode == "config":
        cfg = oci.config.from_file(a.config_file or oci.config.DEFAULT_LOCATION, a.profile)
        oci.config.validate_config(cfg)
        return cfg, None, cfg["tenancy"], mode
    if mode == "cloudshell":
        cfg = oci.config.from_file(os.getenv("OCI_CLI_CONFIG_FILE", "/etc/oci/config"), os.getenv("OCI_CLI_PROFILE", "DEFAULT"))
        tok = Path(cfg["delegation_token_file"]).read_text().strip()
        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=tok)
        return {"region": cfg["region"], "tenancy": cfg["tenancy"]}, signer, cfg["tenancy"], mode
    signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
    return {"region": signer.region}, signer, signer.tenancy_id, mode


def page_all(fn: Callable, *a, **kw) -> list:
    out, page = [], None
    while True:
        if page:
            kw["page"] = page
        r = fn(*a, **kw)
        data = r.data
        items = data if isinstance(data, list) else (getattr(data, "items", None) or getattr(data, "entries", None) or [])
        out.extend(items)
        page = getattr(r, "next_page", None)
        if not page:
            return out


class Errors:
    """Contabiliza negações/erros por coletor sem derrubar o assessment."""

    def __init__(self):
        self.e: dict[str, Counter] = defaultdict(Counter)

    def run(self, key: str, fn: Callable, default: Any = None) -> Any:
        try:
            return fn()
        except oci.exceptions.ServiceError as exc:
            with _lock:
                self.e[key][f"HTTP {exc.status} {exc.code}"] += 1
        except Exception as exc:  # noqa: BLE001
            with _lock:
                self.e[key][f"erro {type(exc).__name__}"] += 1
        return default

    def status(self, key: str) -> str:
        c = self.e.get(key)
        return "ok" if not c else "parcial: " + ", ".join(f"{k} x{v}" for k, v in c.most_common(3))


def pmap(fn: Callable, items: list, threads: int) -> list:
    with ThreadPoolExecutor(max_workers=threads) as ex:
        return list(ex.map(fn, items))


def g(o: Any, *path: str, default: Any = None) -> Any:
    for p in path:
        if o is None:
            return default
        o = o.get(p) if isinstance(o, dict) else getattr(o, p, None)
    return default if o is None else o


# --------------------------------------------------------------------------- #
# Coletores
# --------------------------------------------------------------------------- #


def collect_identity(F: Factory, E: Errors, home: str, ten: str, only: list[str]) -> dict:
    idc = F(oci.identity.IdentityClient, home)
    tname = E.run("identity", lambda: idc.get_tenancy(ten).data.name, "root")
    comps = E.run("identity", lambda: page_all(idc.list_compartments, ten, compartment_id_in_subtree=True,
                                                access_level="ACCESSIBLE", lifecycle_state="ACTIVE"), []) or []
    allc = [{"id": ten, "name": tname, "parent": None}] + [{"id": c.id, "name": c.name, "parent": c.compartment_id} for c in comps]
    by = {c["id"]: c for c in allc}
    for c in allc:
        path, p = [c["name"]], c["parent"]
        while p and p in by:
            path.insert(0, by[p]["name"])
            p = by[p]["parent"]
        c["path"] = "/".join(path)
    if only:
        keys = {x.strip().lower() for x in only}
        roots = {c["id"] for c in allc if c["id"].lower() in keys or c["name"].lower() in keys}
        anc = ancestors(allc)
        allc = [c for c in allc if c["id"] in roots or roots & anc[c["id"]]]
    regions = E.run("identity", lambda: idc.list_region_subscriptions(ten).data, []) or []
    tagns = E.run("identity", lambda: page_all(idc.list_tag_namespaces, ten, include_subcompartments=True), []) or []
    return {"tenancy_name": tname, "compartments": allc,
            "regions": [{"name": r.region_name, "home": r.is_home_region, "status": r.status} for r in regions],
            "tag_namespaces": [t.name for t in tagns if t.lifecycle_state == "ACTIVE" and t.name.lower() not in SYSTEM_TAG_NS],
            "_tag_ns_ids": [t.id for t in tagns if t.lifecycle_state == "ACTIVE" and t.name.lower() not in SYSTEM_TAG_NS]}


def ancestors(comps: list[dict]) -> dict[str, set]:
    by = {c["id"]: c for c in comps}
    out = {}
    for c in comps:
        s, p = set(), c.get("parent")
        while p:
            s.add(p)
            p = (by.get(p) or {}).get("parent")
        out[c["id"]] = s
    return out


def is_tagged(r: Any) -> bool:
    if r.freeform_tags:
        return True
    return any(ns.lower() not in SYSTEM_TAG_NS and v for ns, v in (r.defined_tags or {}).items())


def collect_inventory(F: Factory, E: Errors, region: str, comp_ids: set) -> list[dict]:
    sc = F(oci.resource_search.ResourceSearchClient, region)
    det = oci.resource_search.models.StructuredSearchDetails(type="Structured", matching_context_type="NONE", query="query all resources")
    items = E.run("inventory", lambda: page_all(sc.search_resources, det, limit=1000), []) or []
    out = []
    for r in items:
        if r.resource_type in GLOBAL_TYPES or (r.lifecycle_state or "").upper() in DEAD or r.compartment_id not in comp_ids:
            continue
        out.append({"id": r.identifier, "type": r.resource_type, "name": r.display_name or "", "comp": r.compartment_id,
                    "region": region, "state": r.lifecycle_state, "tagged": is_tagged(r)})
    return out


def collect_monitoring(F: Factory, E: Errors, region: str, ten: str, comp_ids: set) -> dict:
    mc = F(oci.monitoring.MonitoringClient, region)
    raw = E.run("alarms", lambda: page_all(mc.list_alarms, ten, compartment_id_in_subtree=True), []) or []
    alarms = []
    for x in raw:
        if x.compartment_id not in comp_ids and x.metric_compartment_id not in comp_ids:
            continue
        subtree = False
        if x.metric_compartment_id == ten:
            subtree = bool(E.run("alarms", lambda: mc.get_alarm(x.id).data.metric_compartment_id_in_subtree, False))
        alarms.append({"id": x.id, "name": x.display_name, "region": region, "comp": x.compartment_id, "namespace": x.namespace,
                       "metric_comp": x.metric_compartment_id, "subtree": subtree, "query": x.query, "severity": x.severity,
                       "enabled": bool(x.is_enabled), "destinations": len(x.destinations or []), "state": x.lifecycle_state})
    st = E.run("alarms_status", lambda: page_all(mc.list_alarms_status, ten, compartment_id_in_subtree=True), []) or []
    ids = {a["id"] for a in alarms}
    status = [{"id": s.id, "status": s.status, "severity": s.severity,
               "triggered": s.timestamp_triggered.isoformat() if s.timestamp_triggered else None} for s in st if s.id in ids]
    LMD = oci.monitoring.models.ListMetricsDetails
    ns = E.run("metrics", lambda: page_all(mc.list_metrics, ten, LMD(group_by=["namespace"]), compartment_id_in_subtree=True), []) or []
    cpu = E.run("metrics", lambda: page_all(mc.list_metrics, ten, LMD(namespace="oci_computeagent", name="CpuUtilization", group_by=["resourceId"]),
                                             compartment_id_in_subtree=True), []) or []
    return {"alarms": alarms, "status": status, "namespaces": sorted({m.namespace for m in ns}),
            "compute_emitting": sorted({(m.dimensions or {}).get("resourceId") for m in cpu} - {None})}


def collect_alarm_history(F: Factory, E: Errors, alarm: dict, since: datetime) -> dict:
    mc = F(oci.monitoring.MonitoringClient, alarm["region"])
    ent = E.run("alarm_history", lambda: page_all(mc.get_alarm_history, alarm["id"], alarm_historytype="STATE_TRANSITION_HISTORY",
                                                  timestamp_greater_than_or_equal_to=since), []) or []
    ev = []
    for e in ent:
        m = STATE_RE.search(e.summary or "")
        if m and e.timestamp:
            ev.append((e.timestamp, m.group(1).upper()))
    ev.sort()
    fires, durs, start = 0, [], None
    for ts, s in ev:
        if s == "FIRING":
            fires += 1
            start = start or ts
        elif start:
            durs.append((ts - start).total_seconds() / 60)
            start = None
    return {"id": alarm["id"], "name": alarm["name"], "entries": len(ent), "parsed": len(ev), "firings": fires, "durations": durs}


def collect_per_compartment(F: Factory, E: Errors, region: str, comp: str) -> dict:
    o: dict[str, Any] = {}
    ctl, dp = F(oci.ons.NotificationControlPlaneClient, region), F(oci.ons.NotificationDataPlaneClient, region)
    o["topics"] = len(E.run("notifications", lambda: page_all(ctl.list_topics, comp), []) or [])
    subs = E.run("notifications", lambda: page_all(dp.list_subscriptions, comp), []) or []
    o["subs"] = [(s.protocol, s.lifecycle_state) for s in subs]
    ev = F(oci.events.EventsClient, region)
    rules = E.run("events", lambda: page_all(ev.list_rules, comp), []) or []
    o["rules"] = [(r.display_name, r.is_enabled) for r in rules if r.lifecycle_state != "DELETED"]
    sch = F(oci.sch.ServiceConnectorClient, region)
    cons = E.run("service_connectors", lambda: page_all(sch.list_service_connectors, comp), []) or []
    o["connectors"] = []
    for c in cons:
        full = E.run("service_connectors", lambda: sch.get_service_connector(c.id).data)
        o["connectors"].append({"name": c.display_name, "state": c.lifecycle_state,
                                "source": g(full, "source", "kind", default="?"), "target": g(full, "target", "kind", default="?")})
    apm = F(oci.apm_control_plane.ApmDomainClient, region)
    o["apm_domains"] = [{"id": d.id, "name": d.display_name, "free": d.is_free_tier}
                        for d in (E.run("apm", lambda: page_all(apm.list_apm_domains, comp), []) or []) if d.lifecycle_state == "ACTIVE"]
    smc = F(oci.stack_monitoring.StackMonitoringClient, region)
    o["stack_mon"] = [r.type for r in (E.run("stack_monitoring", lambda: page_all(smc.list_monitored_resources, comp), []) or [])]
    cc = F(oci.core.ComputeClient, region)
    inst = E.run("compute", lambda: page_all(cc.list_instances, comp), []) or []
    o["instances"] = []
    for i in inst:
        if i.lifecycle_state in DEAD:
            continue
        ac = i.agent_config
        plug = {p.name: p.desired_state for p in (g(ac, "plugins_config") or [])}
        sc = i.shape_config
        o["instances"].append({"id": i.id, "name": i.display_name, "shape": i.shape, "fd": i.fault_domain, "state": i.lifecycle_state,
                               "ocpus": g(sc, "ocpus"), "mem_gb": g(sc, "memory_in_gbs"), "comp": comp, "region": region,
                               "monitoring_disabled": bool(g(ac, "is_monitoring_disabled", default=False)),
                               "all_plugins_disabled": bool(g(ac, "are_all_plugins_disabled", default=False)),
                               "monitoring_plugin": plug.get("Compute Instance Monitoring", "N/D"),
                               "custom_logs_plugin": plug.get("Custom Logs Monitoring", "N/D")})
    return o


def collect_logging(F: Factory, E: Errors, region: str, ten: str, comp_ids: set, threads: int) -> dict:
    lc = F(oci.logging.LoggingManagementClient, region)
    groups = [x for x in (E.run("logging", lambda: page_all(lc.list_log_groups, ten, is_compartment_id_in_subtree=True), []) or [])
              if x.compartment_id in comp_ids]

    def logs_of(grp):
        c = F(oci.logging.LoggingManagementClient, region)
        return E.run("logging", lambda: page_all(c.list_logs, grp.id), []) or []

    logs = [x for lst in pmap(logs_of, groups, threads) for x in lst]
    srcs = []
    for lg in logs:
        src = g(lg, "configuration", "source")
        srcs.append({"type": lg.log_type, "enabled": bool(lg.is_enabled), "service": g(src, "service", default="custom"),
                     "resource": g(src, "resource", default=""), "category": g(src, "category", default=""),
                     "retention_d": lg.retention_duration})
    uac = [x for x in (E.run("unified_agent", lambda: page_all(lc.list_unified_agent_configurations, ten, is_compartment_id_in_subtree=True), []) or [])
           if x.compartment_id in comp_ids]
    return {"log_groups": len(groups), "logs": srcs,
            "unified_agent": {"total": len(uac), "ativas": sum(1 for u in uac if u.is_enabled)}}


def collect_regional_services(F: Factory, E: Errors, region: str, ten: str, apm_domains: list[dict]) -> dict:
    o: dict[str, Any] = {}
    la = F(oci.log_analytics.LogAnalyticsClient, region)
    nss = E.run("log_analytics", lambda: page_all(la.list_namespaces, ten), []) or []
    o["log_analytics_onboarded"] = any(n.is_onboarded for n in nss)
    op = F(oci.opsi.OperationsInsightsClient, region)
    o["opsi_db"] = len(E.run("ops_insights", lambda: page_all(op.list_database_insights, compartment_id=ten, compartment_id_in_subtree=True), []) or [])
    o["opsi_host"] = len(E.run("ops_insights", lambda: page_all(op.list_host_insights, compartment_id=ten, compartment_id_in_subtree=True), []) or [])
    syn = F(oci.apm_synthetics.ApmSyntheticClient, region)
    mons = [m for d in apm_domains for m in (E.run("apm_synthetics", lambda d=d: page_all(syn.list_monitors, d["id"]), []) or [])]
    o["synthetics"] = {"total": len(mons), "ativos": sum(1 for m in mons if m.status == "ENABLED"),
                       "tipos": dict(Counter(m.monitor_type for m in mons))}
    return o


def collect_global(F: Factory, E: Errors, home: str, ten: str, comps: list[dict], days: int, threads: int) -> dict:
    o: dict[str, Any] = {}
    au = F(oci.audit.AuditClient, home)
    o["audit_retention_days"] = E.run("audit", lambda: au.get_configuration(ten).data.retention_period_days)
    cg = F(oci.cloud_guard.CloudGuardClient, home)
    cfg = E.run("cloud_guard", lambda: cg.get_configuration(ten).data)
    o["cloud_guard"] = {"status": g(cfg, "status", default="N/D"), "reporting_region": g(cfg, "reporting_region")}
    if g(cfg, "status") == "ENABLED":
        cgr = F(oci.cloud_guard.CloudGuardClient, g(cfg, "reporting_region") or home)
        probs = E.run("cloud_guard", lambda: page_all(cgr.list_problems, ten, compartment_id_in_subtree=True, access_level="ACCESSIBLE",
                                                       lifecycle_detail="OPEN"), []) or []
        now = datetime.now(timezone.utc)
        o["cloud_guard"].update({
            "abertos": len(probs), "risco": dict(Counter(p.risk_level for p in probs)),
            "top_regras": Counter(p.detector_rule_id for p in probs).most_common(10),
            "tipos_recurso": dict(Counter(p.resource_type for p in probs).most_common(10)),
            "abertos_ha_mais_de_30d": sum(1 for p in probs if p.time_first_detected and now - p.time_first_detected > timedelta(days=30))})
    bc = F(oci.budget.BudgetClient, home)
    b = E.run("budgets", lambda: page_all(bc.list_budgets, ten, target_type="ALL"), []) or []
    o["budgets"] = {"total": len(b), "com_alerta": sum(1 for x in b if (x.alert_rule_count or 0) > 0)}
    hc = F(oci.healthchecks.HealthChecksClient, home)

    def hcs(c):
        return (len(E.run("health_checks", lambda: page_all(hc.list_http_monitors, c["id"]), []) or []),
                len(E.run("health_checks", lambda: page_all(hc.list_ping_monitors, c["id"]), []) or []))

    r = pmap(hcs, comps, threads)
    o["health_checks"] = {"http": sum(x[0] for x in r), "ping": sum(x[1] for x in r)}
    idc = F(oci.identity.IdentityClient, home)

    def pols(c):
        return [(p.name, st) for p in (E.run("policies", lambda: page_all(idc.list_policies, c["id"]), []) or []) for st in (p.statements or [])]

    o["_policies"] = [x for lst in pmap(pols, comps, threads) for x in lst]
    o["_groups"] = [x.name for x in (E.run("identity", lambda: page_all(idc.list_groups, ten), []) or [])]
    o["_dyn_groups"] = [(x.name, x.matching_rule or "") for x in (E.run("identity", lambda: page_all(idc.list_dynamic_groups, ten), []) or [])]
    return o


# --------------------------------------------------------------------------- #
# Coletores WAF (segurança, confiabilidade, custos, cloud distribuído)
# --------------------------------------------------------------------------- #


def open_ports(proto: str, src: str, tcp: Any) -> str:
    if src not in ("0.0.0.0/0", "::/0"):
        return ""
    if proto == "all":
        return "todas"
    if proto != "6":
        return ""
    rng = g(tcp, "destination_port_range")
    if not rng:
        return "todas TCP"
    return ",".join(str(p) for p in SENSITIVE_PORTS if rng.min <= p <= rng.max)


def collect_waf_compartment(F: Factory, E: Errors, region: str, comp: str, ns: str | None, ads: list[str]) -> dict:
    o: dict[str, Any] = {}
    bs, cc, vn = F(oci.core.BlockstorageClient, region), F(oci.core.ComputeClient, region), F(oci.core.VirtualNetworkClient, region)
    vols = E.run("block_volumes", lambda: page_all(bs.list_volumes, compartment_id=comp), []) or []
    o["volumes"] = [{"id": v.id, "name": v.display_name, "gb": v.size_in_gbs or 0, "group": v.volume_group_id, "kind": "block",
                     "replicas": len(v.block_volume_replicas or []), "comp": comp, "region": region} for v in vols if v.lifecycle_state not in DEAD]
    boots, batt = [], []
    for ad in ads:
        boots += E.run("block_volumes", lambda ad=ad: page_all(bs.list_boot_volumes, availability_domain=ad, compartment_id=comp), []) or []
        batt += E.run("attachments", lambda ad=ad: page_all(cc.list_boot_volume_attachments, ad, comp), []) or []
    o["volumes"] += [{"id": v.id, "name": v.display_name, "gb": v.size_in_gbs or 0, "group": v.volume_group_id, "kind": "boot",
                      "replicas": len(v.boot_volume_replicas or []), "comp": comp, "region": region} for v in boots if v.lifecycle_state not in DEAD]
    va = E.run("attachments", lambda: page_all(cc.list_volume_attachments, comp), []) or []
    o["attached"] = [x.volume_id for x in va if x.lifecycle_state in ("ATTACHED", "ATTACHING")] + \
                    [x.boot_volume_id for x in batt if x.lifecycle_state in ("ATTACHED", "ATTACHING")]
    # instância -> volumes (para somar o custo real de instâncias paradas, cobradas pelos volumes)
    o["inst_vols"] = [[x.instance_id, x.volume_id] for x in va if x.lifecycle_state in ("ATTACHED", "ATTACHING")] + \
                     [[x.instance_id, x.boot_volume_id] for x in batt if x.lifecycle_state in ("ATTACHED", "ATTACHING")]
    ips = E.run("public_ips", lambda: page_all(vn.list_public_ips, "REGION", comp, lifetime="RESERVED"), []) or []
    o["reserved_ips"] = [{"id": i.id, "name": i.display_name or i.ip_address, "assigned": bool(i.assigned_entity_id), "comp": comp, "region": region}
                         for i in ips if i.lifecycle_state not in ("TERMINATED", "TERMINATING")]
    rules = []
    for sl in E.run("security_lists", lambda: page_all(vn.list_security_lists, comp), []) or []:
        for r in sl.ingress_security_rules or []:
            p = open_ports(r.protocol, r.source, r.tcp_options)
            if p:
                rules.append({"tipo": "Security List", "nome": sl.display_name, "portas": p, "origem": r.source, "comp": comp, "region": region})
    for n in E.run("nsg", lambda: page_all(vn.list_network_security_groups, compartment_id=comp), []) or []:
        for r in E.run("nsg", lambda n=n: page_all(vn.list_network_security_group_security_rules, n.id, direction="INGRESS"), []) or []:
            p = open_ports(r.protocol, r.source, r.tcp_options) if r.source_type == "CIDR_BLOCK" else ""
            if p:
                rules.append({"tipo": "NSG", "nome": n.display_name, "portas": p, "origem": r.source, "comp": comp, "region": region})
    o["open_rules"] = rules
    o["vcs"] = [{"name": v.display_name, "provider": v.provider_name or "", "service": v.provider_service_name or "", "bgp": v.bgp_session_state,
                 "type": v.type, "region": region} for v in (E.run("fastconnect", lambda: page_all(vn.list_virtual_circuits, comp), []) or [])
                if v.lifecycle_state not in DEAD]
    o["ipsec"] = sum(1 for x in (E.run("vpn", lambda: page_all(vn.list_ip_sec_connections, comp), []) or []) if x.lifecycle_state == "AVAILABLE")
    o["rpcs"] = [{"status": r.peering_status, "peer_region": r.peer_region_name, "region": region}
                 for r in (E.run("drg", lambda: page_all(vn.list_remote_peering_connections, comp), []) or []) if r.lifecycle_state == "AVAILABLE"]
    o["drgs"] = len(E.run("drg", lambda: page_all(vn.list_drgs, comp), []) or [])
    kv = F(oci.key_management.KmsVaultClient, region)
    o["vaults"] = sum(1 for v in (E.run("vault", lambda: page_all(kv.list_vaults, comp), []) or []) if v.lifecycle_state == "ACTIVE")
    bc = F(oci.bastion.BastionClient, region)
    o["bastions"] = sum(1 for b in (E.run("bastion", lambda: page_all(bc.list_bastions, comp), []) or []) if b.lifecycle_state == "ACTIVE")
    vss = F(oci.vulnerability_scanning.VulnerabilityScanningClient, region)
    o["vss_targets"] = len(E.run("vulnerability_scanning", lambda: page_all(vss.list_host_scan_targets, comp), []) or [])
    asc = F(oci.autoscaling.AutoScalingClient, region)
    o["autoscaling"] = len(E.run("autoscaling", lambda: page_all(asc.list_auto_scaling_configurations, comp), []) or [])
    db = F(oci.database.DatabaseClient, region)
    o["adbs"] = [{"name": a.db_name, "dg": bool(a.is_data_guard_enabled or a.is_local_data_guard_enabled or a.is_remote_data_guard_enabled),
                  "remote_dg": bool(a.is_remote_data_guard_enabled), "autoscale": bool(a.is_auto_scaling_enabled), "free": bool(a.is_free_tier),
                  "comp": comp, "region": region}
                 for a in (E.run("databases", lambda: page_all(db.list_autonomous_databases, comp), []) or []) if a.lifecycle_state not in DEAD]
    o["dbs"] = []
    for sy in E.run("databases", lambda: page_all(db.list_db_systems, comp), []) or []:
        if sy.lifecycle_state in DEAD:
            continue
        for x in E.run("databases", lambda sy=sy: page_all(db.list_databases, comp, system_id=sy.id), []) or []:
            o["dbs"].append({"name": x.db_name, "system": sy.display_name, "auto_backup": bool(g(x, "db_backup_config", "auto_backup_enabled", default=False)),
                             "dg": bool(x.data_guard_group), "comp": comp, "region": region})
    my = F(oci.mysql.DbSystemClient, region)
    o["mysql"] = [{"name": m.display_name, "ha": bool(m.is_highly_available), "backup": bool(g(m, "backup_policy", "is_enabled", default=False)),
                   "copy": bool(g(m, "backup_policy", "copy_policies")), "comp": comp, "region": region}
                  for m in (E.run("mysql", lambda: page_all(my.list_db_systems, comp), []) or []) if m.lifecycle_state not in DEAD]
    o["buckets"] = []
    if ns:
        osc = F(oci.object_storage.ObjectStorageClient, region)
        for b in E.run("object_storage", lambda: page_all(osc.list_buckets, ns, comp), []) or []:
            x = E.run("object_storage", lambda b=b: osc.get_bucket(ns, b.name, fields=["approximateSize", "autoTiering"]).data)
            if x:
                o["buckets"].append({"id": x.id, "name": x.name, "public": x.public_access_type not in (None, "NoPublicAccess"), "replication": bool(x.replication_enabled),
                                     "versioning": x.versioning == "Enabled", "lifecycle": bool(x.object_lifecycle_policy_etag),
                                     "auto_tiering": (x.auto_tiering or "Disabled") != "Disabled", "tier": x.storage_tier,
                                     "gb": round((x.approximate_size or 0) / 1024 ** 3, 1), "comp": comp, "region": region})
    return o


def collect_backup_policies(F: Factory, E: Errors, vols: list[dict], threads: int) -> dict[str, bool]:
    cache: dict[str, bool] = {}

    def assigned(region: str, asset: str) -> bool:
        if asset in cache:
            return cache[asset]
        bs = F(oci.core.BlockstorageClient, region)
        v = bool(E.run("backup_policy", lambda: bs.get_volume_backup_policy_asset_assignment(asset).data, []))
        with _lock:
            cache[asset] = v
        return v

    def chk(v):
        return v["id"], assigned(v["region"], v["id"]) or (bool(v["group"]) and assigned(v["region"], v["group"]))

    return dict(pmap(chk, vols, threads))


def collect_utilization(F: Factory, E: Errors, region: str, ten: str, days: int = 14) -> dict:
    mc = F(oci.monitoring.MonitoringClient, region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    def q(query: str) -> dict:
        det = oci.monitoring.models.SummarizeMetricsDataDetails(namespace="oci_computeagent", query=query, start_time=start, end_time=end, resolution="1d")
        res = E.run("utilization", lambda: mc.summarize_metrics_data(ten, det, compartment_id_in_subtree=True).data, []) or []
        out = {}
        for m in res:
            rid = (m.dimensions or {}).get("resourceId")
            vals = [p.value for p in (m.aggregated_datapoints or []) if p.value is not None]
            if rid and vals:
                out[rid] = {"media": round(statistics.mean(vals), 1), "max_dia": round(max(vals), 1)}
        return out

    return {"cpu": q("CpuUtilization[1d].mean()"), "mem": q("MemoryUtilization[1d].mean()")}


def month_windows(start: datetime, end: datetime) -> list[tuple[str, datetime, datetime, bool]]:
    """Divide [start, end) em janelas por mês-calendário: (AAAA-MM, início, fim, mês completo?)."""
    out, s = [], start
    while s < end:
        nxt = (s.replace(day=28) + timedelta(days=4)).replace(day=1)
        e = min(nxt, end)
        out.append((s.strftime("%Y-%m"), s, e, s.day == 1 and e == nxt))
        s = e
    return out


def collect_cost(F: Factory, E: Errors, home: str, ten: str, days: int) -> dict:
    """Custos da Usage API em janelas mensais (cada consulta ≤ 31 dias): por mês, serviço, região, compartment e recurso."""
    uc = F(oci.usage_api.UsageapiClient, home)
    M = oci.usage_api.models.RequestSummarizedUsagesDetails
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    def req(start, end, group_by, depth=None):
        kw: dict[str, Any] = {"tenant_id": ten, "time_usage_started": start, "time_usage_ended": end, "granularity": "DAILY",
                              "query_type": "COST", "is_aggregate_by_time": True, "group_by": group_by}
        if depth:
            kw["compartment_depth"] = depth
        return E.run("cost", lambda: page_all(uc.request_summarized_usages, M(**kw)), []) or []

    def add(c: Counter, items, key):
        for i in items:
            c[getattr(i, key, None) or "N/D"] += float(i.computed_amount or 0)

    def top(c: Counter, n=None):
        return [(k, round(v, 2)) for k, v in c.most_common(n) if v > 0.005]

    wins = month_windows(today - timedelta(days=days), today)
    svc, reg, comp = Counter(), Counter(), Counter()
    svc_mes: dict[str, dict] = {}
    res: dict[str, dict] = {}
    cur = ""
    for lab, s, e, _ in wins:
        items = req(s, e, ["service"])
        cur = cur or next((i.currency for i in items if i.currency), "")
        m: Counter = Counter()
        add(m, items, "service")
        svc.update(m)
        svc_mes[lab] = dict(top(m))
        add(reg, req(s, e, ["region"]), "region")
        add(comp, req(s, e, ["compartmentPath"], 2), "compartment_path")
        for i in req(s, e, ["resourceId", "service"]):
            amt = float(i.computed_amount or 0)
            if amt <= 0.005:
                continue
            rid = i.resource_id or ""
            r = res.setdefault(rid or f"sem-recurso:{i.service}", {"id": rid, "servico": i.service or "N/D", "meses": {}})
            r["meses"][lab] = round(r["meses"].get(lab, 0) + amt, 2)
    # custo real dos últimos 30 dias por recurso: base do DE/PARA de economia
    c30: Counter = Counter()
    for i in req(today - timedelta(days=30), today, ["resourceId"]):
        if i.resource_id:
            c30[i.resource_id] += float(i.computed_amount or 0)
    for r in res.values():
        r["total"] = round(sum(r["meses"].values()), 2)
    m0 = today.replace(day=1)
    return {"dias": days, "moeda": cur, "total": round(sum(svc.values()), 2),
            "por_servico": top(svc, 15), "por_compartment": top(comp, 15), "por_regiao": top(reg),
            "por_mes": {lab: round(sum(svc_mes[lab].values()), 2) for lab, *_ in wins},
            "meses_completos": [lab for lab, _, _, full in wins if full],
            "dias_por_mes": {lab: (e - s).days for lab, s, e, _ in wins},
            "servico_por_mes": svc_mes,
            "top_recursos": sorted(res.values(), key=lambda r: -r["total"])[:25],
            "custo_30d_recurso": {k: round(v, 2) for k, v in c30.items() if v > 0.005},
            "dias_no_mes_atual": (today - m0).days}


def collect_global_waf(F: Factory, E: Errors, home: str, ten: str, tag_ns_ids: list[str], cg_region: str | None) -> dict:
    idc = F(oci.identity.IdentityClient, home)
    users = E.run("users", lambda: page_all(idc.list_users, ten), []) or []
    console = [u for u in users if u.lifecycle_state == "ACTIVE" and not u.identity_provider_id
               and g(u, "capabilities", "can_use_console_password", default=True)]
    tags = [t for ns in tag_ns_ids for t in (E.run("cost_tags", lambda ns=ns: page_all(idc.list_tags, ns), []) or [])]
    cg = F(oci.cloud_guard.CloudGuardClient, cg_region or home)
    zones = E.run("security_zones", lambda: page_all(cg.list_security_zones, ten, is_required_security_zones_in_subtree=True), []) or []
    return {"usuarios_console": len(console), "usuarios_sem_mfa": sum(1 for u in console if not u.is_mfa_activated),
            "usuarios_total": len(users), "tags_cost_tracking": sum(1 for t in tags if t.is_cost_tracking and not t.is_retired),
            "security_zones": sum(1 for z in zones if z.lifecycle_state == "ACTIVE")}


# Premissa de redução sobre o custo REAL (Usage API, últimos 30 dias) dos recursos apontados em cada categoria.
# Ajuste aqui conforme a política do cliente. A ordem de aplicação é a da maior redução: um recurso conta uma única vez.
SAVINGS_RULES: dict[str, tuple[float, str]] = {
    "Volume não anexado": (1.00, "Backup final e exclusão do volume"),
    "IP público reservado sem uso": (1.00, "Liberar o IP reservado"),
    "Instância parada": (1.00, "Imagem/backup e terminate (elimina boot/block volumes)"),
    "Instância ociosa": (0.60, "Desligar fora do horário comercial ou consolidar"),
    "Bucket sem lifecycle/auto-tiering": (0.50, "Auto-tiering / Infrequent Access para dados frios"),
    "Instância subutilizada": (0.40, "Rightsizing (reduzir OCPU/memória)"),
    "Shape legado": (0.20, "Migrar para shape Flex de geração atual"),
}


def build_de_para(opp: list[dict], c30: dict[str, float] | None) -> list[dict] | None:
    """DE = custo real dos últimos 30 dias dos recursos apontados; PARA = custo após a ação (premissa em SAVINGS_RULES)."""
    if not c30:
        return None
    rows: dict[str, dict] = {}
    claimed: set[str] = set()
    for o in sorted(opp, key=lambda o: -SAVINGS_RULES.get(o["categoria"], (0, ""))[0]):
        rate, acao = SAVINGS_RULES.get(o["categoria"], (0.0, "—"))
        ids = [i for i in o.get("ids", []) if i not in claimed]
        claimed.update(ids)
        de = sum(c30.get(i, 0.0) for i in ids)
        o["custo_30d"], o["economia_mes"] = round(de, 2), round(de * rate, 2)
        r = rows.setdefault(o["categoria"], {"categoria": o["categoria"], "acao": acao, "premissa_pct": round(rate * 100), "recursos": 0,
                                             "com_custo": 0, "de": 0.0})
        r["recursos"] += 1
        r["com_custo"] += de > 0.005
        r["de"] += de
    out = []
    for r in rows.values():
        eco = r["de"] * r["premissa_pct"] / 100
        out.append({**r, "de": round(r["de"], 2), "para": round(r["de"] - eco, 2), "economia_mes": round(eco, 2), "economia_ano": round(eco * 12, 2)})
    return sorted(out, key=lambda r: -r["economia_mes"])


def build_waf(d: dict, ext: list[dict], backups: dict[str, bool], util: dict, gw: dict, policies: list[tuple], cost: dict) -> None:
    def flat(k):
        return [x for e in ext for x in e.get(k, [])]

    paths = {c["id"]: c["path"] for c in d["identity"]["compartments"]}
    vols, attached = flat("volumes"), set(flat("attached"))
    for v in vols:
        v["attached"], v["backup"] = v["id"] in attached, backups.get(v["id"], False)
    inst = d["_instances"]
    run = [i for i in inst if i["state"] == "RUNNING"]
    broad = []
    for n, st in policies:
        m = re.search(r"allow\s+(?:group\s+(\S+)|any-user)\s+to\s+manage\s+all-resources\s+in\s+tenancy", st, re.I)
        if m and "administrators" not in (m.group(1) or "any-user").lower():
            broad.append(f"{n}: {st[:140]}")
    buckets, adbs, dbs, mysql = flat("buckets"), flat("adbs"), flat("dbs"), flat("mysql")
    d["security"] = {**{k: gw[k] for k in ("usuarios_console", "usuarios_sem_mfa", "security_zones")},
                     "policies_amplas": broad[:20], "regras_abertas": flat("open_rules"),
                     "buckets_publicos": [b["name"] for b in buckets if b["public"]], "buckets": len(buckets),
                     "vaults": sum(e.get("vaults", 0) for e in ext), "bastions": sum(e.get("bastions", 0) for e in ext),
                     "vss_targets": sum(e.get("vss_targets", 0) for e in ext)}
    fds = Counter(i["fd"] for i in run if i["fd"])
    d["reliability"] = {
        "instancias_running": len(run), "fault_domains": dict(fds),
        "block": {"total": sum(1 for v in vols if v["kind"] == "block"), "com_backup": sum(1 for v in vols if v["kind"] == "block" and v["backup"]),
                  "replicados": sum(1 for v in vols if v["kind"] == "block" and v["replicas"])},
        "boot": {"total": sum(1 for v in vols if v["kind"] == "boot" and v["attached"]),
                 "com_backup": sum(1 for v in vols if v["kind"] == "boot" and v["attached"] and v["backup"]),
                 "replicados": sum(1 for v in vols if v["kind"] == "boot" and v["replicas"])},
        "adb": {"total": sum(1 for a in adbs if not a["free"]), "data_guard": sum(1 for a in adbs if a["dg"] and not a["free"]),
                "cross_region": sum(1 for a in adbs if a["remote_dg"])},
        "dbs": {"total": len(dbs), "auto_backup": sum(1 for x in dbs if x["auto_backup"]), "data_guard": sum(1 for x in dbs if x["dg"])},
        "mysql": {"total": len(mysql), "ha": sum(1 for m in mysql if m["ha"]), "backup": sum(1 for m in mysql if m["backup"]),
                  "copia_cross_region": sum(1 for m in mysql if m["copy"])},
        "buckets_replicados": sum(1 for b in buckets if b["replication"]), "buckets_versionados": sum(1 for b in buckets if b["versioning"]),
    }
    opp: list[dict] = []

    def add(cat, tipo, nome, region, comp, det, ids=()):
        opp.append({"categoria": cat, "tipo": tipo, "nome": nome, "regiao": region, "compartment": paths.get(comp, comp), "detalhe": det,
                    "ids": [x for x in ids if x]})

    vols_of: dict[str, list[str]] = defaultdict(list)
    for iid, vid in flat("inst_vols"):
        vols_of[iid].append(vid)
    for v in vols:
        if not v["attached"]:
            add("Volume não anexado", "Boot volume" if v["kind"] == "boot" else "Block volume", v["name"], v["region"], v["comp"], f"{v['gb']} GB",
                [v["id"]])
    for ip in flat("reserved_ips"):
        if not ip["assigned"]:
            add("IP público reservado sem uso", "Public IP", ip["name"], ip["region"], ip["comp"], "reservado e não atribuído", [ip.get("id")])
    cpu, mem = util.get("cpu", {}), util.get("mem", {})
    idle = under = 0
    for i in inst:
        if i["state"] == "STOPPED":
            add("Instância parada", "Compute", i["name"], i["region"], i["comp"], f"{i['shape']} · boot/block volumes continuam cobrados",
                [i["id"], *vols_of.get(i["id"], [])])
            continue
        if i["state"] != "RUNNING":
            continue
        c, m = cpu.get(i["id"]), mem.get(i["id"])
        if c and c["media"] < 5 and c["max_dia"] < 10:
            idle += 1
            add("Instância ociosa", "Compute", i["name"], i["region"], i["comp"], f"{i['shape']} · CPU média {c['media']}% (máx. diária {c['max_dia']}%) em 14d",
                [i["id"]])
        elif c and c["media"] < 20 and (m is None or m["media"] < 40):
            under += 1
            add("Instância subutilizada", "Compute", i["name"], i["region"], i["comp"],
                f"{i['shape']} {i['ocpus'] or '?'} OCPU/{i['mem_gb'] or '?'} GB · CPU {c['media']}%" + (f" · memória {m['media']}%" if m else ""), [i["id"]])
        if LEGACY_SHAPE_RE.match(i["shape"] or ""):
            add("Shape legado", "Compute", i["name"], i["region"], i["comp"], f"{i['shape']} → migrar para E5/E4 Flex ou A1/A2 Flex", [i["id"]])
    for b in buckets:
        if b["gb"] >= 100 and not (b["lifecycle"] or b["auto_tiering"]) and b["tier"] == "Standard":
            add("Bucket sem lifecycle/auto-tiering", "Bucket", b["name"], b["region"], b["comp"], f"{b['gb']} GB em Standard", [b.get("id")])
    # nomes legíveis para os recursos que mais custaram (o faturamento só traz OCID)
    known = {r["id"]: (r["name"], TYPE_LABELS.get(r["type"], r["type"]), paths.get(r["comp"], r["comp"])) for r in d["inventory"]["resources"]}
    known.update({x["id"]: (x["name"], "Compute", paths.get(x["comp"], x["comp"])) for x in inst})
    known.update({x["id"]: (x["name"], "Boot volume" if x["kind"] == "boot" else "Block volume", paths.get(x["comp"], x["comp"])) for x in vols})
    known.update({x["id"]: (x["name"], "Bucket", paths.get(x["comp"], x["comp"])) for x in buckets if x.get("id")})
    for r in cost.get("top_recursos", []):
        nm, tp, cp = known.get(r["id"], (None, None, None))
        r["nome"] = nm or (r["id"][:40] + "…" if r["id"] else f"Sem recurso associado ({r['servico']})")
        r["tipo"], r["compartment"] = tp or r["servico"], cp or "—"
    pm = list(cost.get("por_mes", {}).items())
    if "meses_completos" in cost:
        full = [(k, v) for k, v in pm if k in cost["meses_completos"]]
    else:  # dados.json de versões anteriores
        full = pm[:-1] if cost.get("dias_no_mes_atual") else pm
    mom = pct(full[-1][1] - full[-2][1], full[-2][1]) if len(full) >= 2 and full[-2][1] else None
    mtd = pm[-1][1] if pm and cost.get("dias_no_mes_atual") and pm[-1][0] == datetime.now(timezone.utc).strftime("%Y-%m") else None
    proj = None
    if mtd is not None and cost["dias_no_mes_atual"]:
        now = datetime.now(timezone.utc)
        dim = ((now.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)).day
        proj = round(mtd / cost["dias_no_mes_atual"] * dim, 2)
    d["cost"] = {**cost, "variacao_mes_pct": mom, "mtd": round(mtd, 2) if mtd is not None else None, "projecao_mes": proj,
                 "tags_cost_tracking": gw["tags_cost_tracking"], "oportunidades": opp,
                 "resumo_oportunidades": dict(Counter(o["categoria"] for o in opp)), "ociosas": idle, "subutilizadas": under,
                 "instancias_com_metrica_cpu": sum(1 for i in run if i["id"] in cpu),
                 "autoscaling": sum(e.get("autoscaling", 0) for e in ext), "adb_autoscale": sum(1 for a in adbs if a["autoscale"]), "adb_total": len(adbs),
                 "buckets_lifecycle": sum(1 for b in buckets if b["lifecycle"] or b["auto_tiering"]), "buckets": len(buckets),
                 "gb_volumes_nao_anexados": round(sum(v["gb"] for v in vols if not v["attached"]), 1)}
    d["cost"]["de_para"] = build_de_para(opp, cost.get("custo_30d_recurso"))
    vcs = flat("vcs")
    d["distributed"] = {"fastconnect": len(vcs), "fastconnect_bgp_up": sum(1 for v in vcs if (v["bgp"] or "").upper() == "UP"),
                        "provedores": dict(Counter(v["provider"] or v["type"] for v in vcs)),
                        "azure_interconnect": sum(1 for v in vcs if re.search(r"azure|microsoft", v["provider"] + " " + v["service"], re.I)),
                        "ipsec": sum(e.get("ipsec", 0) for e in ext), "drgs": sum(e.get("drgs", 0) for e in ext),
                        "rpc_peered": sum(1 for r in flat("rpcs") if r["status"] == "PEERED"), "regioes": len(d["meta"]["regioes"])}


# --------------------------------------------------------------------------- #
# Consolidação e cobertura
# --------------------------------------------------------------------------- #


def detect_tools(d: dict, keywords: list[str]) -> dict:
    hits: dict[str, Counter] = {k: Counter() for k in keywords}

    def scan(text: str, where: str):
        t = (text or "").lower()
        for k in keywords:
            if k in t:
                hits[k][where] += 1

    for r in d["inventory"]["resources"]:
        scan(r["name"], f"recurso {r['type']}")
    for c in d["integration"]["connectors"]:
        scan(c["name"], "Service Connector")
    G = d.pop("_identity_scan", {})
    for n, st in G.get("policies", []):
        scan(n + " " + st, "policy IAM")
    for n in G.get("groups", []):
        scan(n, "grupo IAM")
    for n, rule in G.get("dyn_groups", []):
        scan(n + " " + rule, "dynamic group")
    for ns in d["monitoring"]["namespaces"]:
        scan(ns, "namespace de métrica")
    return {k: dict(v) for k, v in hits.items() if v}


def compute_coverage(d: dict) -> None:
    comps = d["identity"]["compartments"]
    anc = ancestors(comps)
    res = d["inventory"]["resources"]
    alarms = [a for a in d["monitoring"]["alarms"] if a["enabled"]]
    by_ns: dict[tuple, list] = defaultdict(list)
    for a in alarms:
        by_ns[(a["region"], a["namespace"])].append(a)
    log_refs = {s["resource"] for s in d["logging"]["logs"] if s["enabled"] and s["type"] == "SERVICE" and s["resource"]}
    emitting = set(d["monitoring"]["compute_emitting"])

    def covered(r: dict) -> bool | None:
        ns = NS_BY_TYPE.get(r["type"])
        if not ns:
            return None
        for a in by_ns.get((r["region"], ns), []):
            mc = a["metric_comp"]
            if not (r["comp"] == mc or (a["subtree"] and mc in anc.get(r["comp"], set()))):
                continue
            q = a["query"] or ""
            if not FILTER_RE.search(q) or r["id"] in q or (r["name"] and r["name"] in q):
                return True
        return False

    for r in res:
        r["alarme"] = covered(r)
        r["log"] = (r["id"] in log_refs or r["name"] in log_refs) if r["type"] in LOG_TYPES else None
        r["metricas"] = (r["id"] in emitting) if r["type"] == "Instance" else None

    agg: dict[str, dict] = {}
    for r in res:
        a = agg.setdefault(r["type"], {"total": 0, "alarme": 0, "log": 0, "metricas": 0, "tag": 0, "regioes": Counter()})
        a["total"] += 1
        a["regioes"][r["region"]] += 1
        for k in ("alarme", "log", "metricas"):
            a[k] += bool(r[k])
        a["tag"] += r["tagged"]
    d["coverage"] = {t: dict(v, regioes=dict(v["regioes"])) for t, v in sorted(agg.items(), key=lambda kv: -kv[1]["total"])}


def summarize_alarms(d: dict, hist: list[dict]) -> None:
    A, S = d["monitoring"]["alarms"], d["monitoring"]["status"]
    now = datetime.now(timezone.utc)
    firing = [s for s in S if s["status"] == "FIRING"]
    stale = sum(1 for s in firing if s["triggered"] and now - datetime.fromisoformat(s["triggered"]) > timedelta(days=7))
    durs = sorted(x for h in hist for x in h["durations"])
    fires = sorted(((h["name"], h["firings"]) for h in hist if h["firings"]), key=lambda kv: -kv[1])
    total_f = sum(n for _, n in fires)
    d["alarms_summary"] = {
        "total": len(A), "habilitados": sum(a["enabled"] for a in A), "sem_destino": sum(1 for a in A if a["enabled"] and not a["destinations"]),
        "severidade": dict(Counter(a["severity"] for a in A)), "namespaces": dict(Counter(a["namespace"] for a in A).most_common(15)),
        "status": dict(Counter(s["status"] for s in S)), "firing": len(firing), "firing_ha_mais_de_7d": stale,
        "historico_analisado": len(hist), "historico_sem_parse": sum(1 for h in hist if h["entries"] and not h["parsed"]),
        "disparos": total_f, "disparos_por_dia": round(total_f / d["meta"]["days"], 1) if d["meta"]["days"] else 0,
        "top_alarmes": fires[:10],
        "mttr_mediana_min": round(statistics.median(durs), 1) if durs else None,
        "mttr_p90_min": round(durs[int(len(durs) * 0.9) - 1], 1) if len(durs) >= 10 else None,
    }


# --------------------------------------------------------------------------- #
# Motor de avaliação
# --------------------------------------------------------------------------- #


@dataclass
class Check:
    domain: str
    severity: str
    title: str
    passed: bool | None
    evidence: str
    impact: str
    recommendation: str
    pillar: str = ""


def evaluate(d: dict) -> list[Check]:
    out: list[Check] = []
    C, AS, LG, NT = d["coverage"], d["alarms_summary"], d["logging"], d["notifications"]
    GL, RS, INTG, CP = d["global"], d["regional"], d["integration"], d["compute"]
    days = d["meta"]["days"]

    def add(dom, sev, title, cond, ev, impact, reco, pillar=None):
        out.append(Check(dom, sev, title, cond, ev, impact, reco, pillar or DOMAIN_PILLAR[dom]))

    def tot(types, k="total"):
        return sum((C.get(t) or {}).get(k, 0) for t in types)

    n_res = tot(TAG_TYPES)
    # Governança
    if n_res:
        tg = tot(TAG_TYPES, "tag")
        add(D_GOV, "Média", "Recursos classificados com tags", pct(n_res - tg, n_res) <= 20,
            f"{n_res - tg} de {n_res} recursos principais sem tag de negócio ({pct(n_res - tg, n_res)}%).",
            "Sem tags não há filtro por ambiente, aplicação, time ou centro de custo; alertas e custos ficam sem dono.",
            "Definir defined tags obrigatórias (Ambiente, Aplicação, Time, Criticidade, CentroCusto) com Tag Defaults por compartment.")
    add(D_GOV, "Baixa", "Tag namespaces (defined tags) padronizados", len(d["identity"]["tag_namespaces"]) > 0,
        f"{len(d['identity']['tag_namespaces'])} tag namespaces de cliente: {', '.join(d['identity']['tag_namespaces'][:6]) or '—'}.",
        "Freeform tags não têm validação; o padrão degrada com o tempo.", "Criar tag namespace corporativo com valores controlados (list).")
    nc = len(d["identity"]["compartments"])
    add(D_GOV, "Média", "Compartments segregando ambientes/workloads", nc > 2, f"{nc} compartments acessíveis (incluindo root).",
        "Sem segregação, políticas de acesso, alarmes e budgets não conseguem ser aplicados por ambiente.",
        "Estruturar compartments por ambiente/workload (padrão Landing Zone OCI CIS).", P_SEC)
    b = GL.get("budgets") or {}
    if b.get("total") is not None:
        add(D_GOV, "Baixa", "Budgets com alertas (FinOps)", b.get("com_alerta", 0) > 0, f"{b.get('total')} budgets, {b.get('com_alerta')} com regra de alerta.",
            "Estouro de custo só é percebido na fatura.", "Criar budgets por compartment/tag com alertas de forecast e real (50/80/100%).")

    # Métricas & Alarmes
    add(D_MON, "Alta", "Alarmes do OCI Monitoring configurados", AS["habilitados"] > 0, f"{AS['total']} alarmes, {AS['habilitados']} habilitados.",
        "Sem alarmes, falhas de infraestrutura e PaaS só são percebidas por usuários.",
        "Criar alarmes padrão por tipo de recurso (CPU, memória, disco, health de LB, ADB storage/CPU, VPN/FastConnect state).")
    crit = [t for t in CRITICAL_TYPES if (C.get(t) or {}).get("total")]
    if crit:
        ct, cc = tot(crit), tot(crit, "alarme")
        worst = sorted(((t, pct(C[t]["alarme"], C[t]["total"])) for t in crit), key=lambda kv: kv[1])[:4]
        add(D_MON, "Alta", "Cobertura de alarmes em recursos críticos", pct(cc, ct) >= 80,
            f"{cc} de {ct} recursos críticos cobertos por alarme ({pct(cc, ct)}%). Menor cobertura: "
            + "; ".join(f"{TYPE_LABELS.get(t, t)} {p}%" for t, p in worst) + " (heurística por namespace/compartment/query).",
            "Recursos críticos sem alarme falham em silêncio: bancos, LBs, VPN/FastConnect e OKE são os de maior impacto no negócio.",
            "Aplicar baseline de alarmes via Terraform (módulo por tipo de recurso) cobrindo todos os compartments de produção.")
    if AS["habilitados"]:
        add(D_MON, "Média", "Alarmes com destino de notificação", AS["sem_destino"] == 0,
            f"{AS['sem_destino']} alarmes habilitados sem tópico de destino.",
            "Alarme sem destino dispara sem ninguém saber.", "Vincular todos os alarmes a tópicos ONS por time/criticidade.")
        add(D_MON, "Média", "Severidade CRITICAL definida", (AS["severidade"].get("CRITICAL") or 0) > 0,
            f"Severidades: {', '.join(f'{k} {v}' for k, v in AS['severidade'].items())}.",
            "Sem priorização, tudo parece urgente (ou nada parece).", "Classificar alarmes em CRITICAL/ERROR/WARNING alinhado ao ITSM.")
        add(D_MON, "Média", "Alarmes em FIRING contínuo", pct(AS["firing"], AS["habilitados"]) <= 10,
            f"{AS['firing']} alarmes em FIRING agora ({pct(AS['firing'], AS['habilitados'])}%), {AS['firing_ha_mais_de_7d']} há mais de 7 dias.",
            "Alarme sempre disparado é ignorado; mascara incidentes reais.", "Revisar limiares/pendingDuration ou suprimir alarmes obsoletos.")
    ni = CP.get("total", 0)
    if ni:
        add(D_MON, "Média", "Compute emitindo métricas (agente Oracle Cloud Agent)", pct(CP["emitindo"], ni) >= 90,
            f"{CP['emitindo']} de {ni} instâncias emitindo oci_computeagent ({pct(CP['emitindo'], ni)}%); {CP['monitoring_desabilitado']} com monitoramento desabilitado.",
            "VMs sem agente não têm CPU/memória/disco no Monitoring: nenhum alarme funciona nelas.",
            "Habilitar o plugin 'Compute Instance Monitoring' e liberar Service Gateway/NAT para o agente.")
    custom = [n for n in d["monitoring"]["namespaces"] if not n.startswith("oci_") and not n.startswith("oracle_")]
    add(D_MON, "Baixa", "Métricas customizadas / de negócio", len(custom) > 0, f"{len(custom)} namespaces customizados: {', '.join(custom[:6]) or '—'}.",
        "Sem métricas de negócio não há correlação entre saúde técnica e impacto (pedidos, PDV, pagamentos).",
        "Publicar KPIs de negócio via PostMetricData/OpenTelemetry e criar alarmes sobre eles.")

    # Notificações & Resposta
    subs = subs_map(NT)
    act = sum(v for (p, s), v in subs.items() if s == "ACTIVE")
    add(D_RESP, "Alta", "Tópicos com assinaturas ativas", act > 0, f"{NT['topicos']} tópicos ONS, {act} assinaturas ativas.",
        "Eventos e alarmes não chegam às equipes, aumentando tempo de detecção.", "Criar tópicos por time/criticidade e assinar o canal de on-call.")
    prot = {p for (p, s) in subs if s == "ACTIVE"}
    add(D_RESP, "Média", "Integração com on-call / ITSM", bool(prot & ONCALL),
        f"Protocolos ativos: {', '.join(sorted(prot)) or 'nenhum'}.",
        "Só e-mail não garante acionamento 24x7 nem abertura de incidente.",
        "Integrar ONS com PagerDuty/ITSM (HTTPS/Functions) e Teams/Slack para alertas críticos.")
    pend = sum(v for (p, s), v in subs.items() if s == "PENDING")
    add(D_RESP, "Baixa", "Assinaturas confirmadas", pend == 0, f"{pend} assinaturas pendentes de confirmação.",
        "Assinatura pendente não recebe nada: falsa sensação de cobertura.", "Confirmar ou remover assinaturas pendentes.")
    ev_on = sum(1 for _, en in NT["regras_eventos"] if en)
    add(D_RESP, "Média", "Event rules (eventos de ciclo de vida)", ev_on > 0, f"{len(NT['regras_eventos'])} regras de eventos, {ev_on} habilitadas.",
        "Mudanças críticas (terminate, alteração de rede/IAM, falha de backup) passam despercebidas.",
        "Criar event rules para eventos críticos (Compute terminate, DB backup failed, alterações IAM/VCN) com destino ONS.")
    if AS["disparos"] >= 20:
        top = AS["top_alarmes"][0]
        add(D_RESP, "Média", "Ruído de alarmes (disparos repetitivos)", pct(top[1], AS["disparos"]) < 20,
            f"{AS['disparos']} disparos em {days}d ({AS['disparos_por_dia']}/dia); o mais frequente (\"{top[0]}\") representa {pct(top[1], AS['disparos'])}%.",
            "Alarmes repetitivos geram fadiga e reduzem a confiança no monitoramento.",
            "Ajustar limiares, pendingDuration e agregações; tratar causa recorrente via problem management.")

    # Logs & Auditoria
    en = [s for s in LG["logs"] if s["enabled"]]
    add(D_LOG, "Alta", "OCI Logging com logs habilitados", len(en) > 0, f"{LG['log_groups']} log groups, {len(en)} logs habilitados.",
        "Sem logs não há trilha para diagnóstico nem evidência pós-incidente.", "Habilitar logs de serviço e custom logs em log groups por ambiente.")
    lt = [t for t in LOG_TYPES if (C.get(t) or {}).get("total")]
    if lt:
        a, b_ = tot(lt), tot(lt, "log")
        add(D_LOG, "Média", "Cobertura de logs de serviço (LB, API GW, Buckets, Functions, WAF, Flow Logs)", pct(b_, a) >= 70,
            f"{b_} de {a} recursos com log de serviço ({pct(b_, a)}%): " + "; ".join(f"{TYPE_LABELS.get(t, t)} {C[t]['log']}/{C[t]['total']}" for t in lt) + ".",
            "Sem access logs e flow logs não se investiga lentidão, erro 5xx ou incidente de rede/segurança.",
            "Habilitar logs de serviço via Terraform (oci_logging_log) priorizando LBs, API Gateways e subnets de produção.")
    if CP.get("total"):
        ua = LG["unified_agent"]["ativas"]
        add(D_LOG, "Média", "Logs de SO/aplicação (Unified Agent)", ua > 0, f"{ua} configurações de Unified Agent ativas para {CP['total']} instâncias.",
            "Logs de sistema e aplicação ficam só na VM e se perdem em falha ou rebuild.", "Criar agent configurations por dynamic group (syslog, app logs).")
    add(D_LOG, "Baixa", "Logging Analytics habilitado", any(r.get("log_analytics_onboarded") for r in RS.values()),
        "Onboarded em: " + (", ".join(k for k, r in RS.items() if r.get("log_analytics_onboarded")) or "nenhuma região") + ".",
        "Sem análise centralizada, a correlação de logs é manual.", "Avaliar Logging Analytics ou exportar logs (Service Connector) para a plataforma de observabilidade.")
    ar = GL.get("audit_retention_days")
    if ar is not None:
        add(D_LOG, "Média", "Retenção do Audit ≥ 365 dias", ar >= 365, f"Retenção configurada: {ar} dias.",
            "Retenção curta impede investigação forense e atende mal requisitos de compliance.", "Ajustar retenção do Audit para 365 dias.", P_SEC)

    # APM & Experiência Digital
    nd = d["apm"]["dominios"]
    add(D_APM, "Média", "APM Domain configurado", nd > 0, f"{nd} APM domains ativos.",
        "Sem APM (ou ferramenta equivalente) não há traces distribuídos das aplicações na OCI.",
        "Confirmar se o APM é feito pelo Dynatrace; senão, criar APM Domain e instrumentar via OpenTelemetry.")
    syn = sum((r.get("synthetics") or {}).get("ativos", 0) for r in RS.values())
    hcn = (GL.get("health_checks") or {})
    hc_t = (hcn.get("http") or 0) + (hcn.get("ping") or 0)
    add(D_APM, "Alta", "Monitoração sintética de disponibilidade", syn + hc_t > 0,
        f"{syn} monitores APM Synthetics ativos e {hc_t} Health Checks (HTTP {hcn.get('http', 0)}, ping {hcn.get('ping', 0)}).",
        "Sem synthetic a indisponibilidade só é percebida via cliente.",
        "Criar monitores REST/Browser para endpoints e jornadas críticas (ou confirmar cobertura no Dynatrace Synthetic).")

    # Bancos & Plataforma
    ndb = tot(DB_TYPES)
    if ndb:
        od = sum(r.get("opsi_db", 0) for r in RS.values())
        add(D_DB, "Média", "Ops Insights para bancos", od > 0, f"{od} database insights para {ndb} bancos/DB systems.",
            "Sem análise de capacidade e SQL, gargalos de banco aparecem só como lentidão de aplicação.",
            "Habilitar Ops Insights/Database Management nos bancos de produção.", P_PERF)
    if ni or ndb:
        sm = d["stack_monitoring"]["total"]
        add(D_DB, "Baixa", "Stack Monitoring (middleware/hosts)", sm > 0, f"{sm} recursos no Stack Monitoring.",
            "Middleware e bancos não-gerenciados ficam sem visão de topologia.", "Avaliar Stack Monitoring ou cobertura equivalente via Dynatrace.")
    if tot(["ClustersCluster"]):
        k = C["ClustersCluster"]
        add(D_DB, "Média", "OKE com alarmes", k["alarme"] == k["total"], f"{k['alarme']} de {k['total']} clusters OKE cobertos por alarme.",
            "Falha de nós ou API server do cluster derruba workloads sem aviso.", "Criar alarmes oci_oke (APIServer, NodeState) e integrar ao Dynatrace Operator.", P_REL)

    # Segurança
    cg = GL.get("cloud_guard") or {}
    if cg.get("status") != "N/D":
        add(D_SEC, "Alta", "Cloud Guard habilitado", cg.get("status") == "ENABLED", f"Status: {cg.get('status')} · região de reporte: {cg.get('reporting_region') or '—'}.",
            "Sem Cloud Guard, configurações inseguras (bucket público, porta aberta) não são detectadas.", "Habilitar Cloud Guard com target no root e recipes padrão.")
    if cg.get("status") == "ENABLED":
        crit_n = (cg.get("risco") or {}).get("CRITICAL", 0) + (cg.get("risco") or {}).get("HIGH", 0)
        add(D_SEC, "Alta", "Problemas Cloud Guard críticos/altos em aberto", crit_n == 0,
            f"{cg.get('abertos', 0)} problemas abertos ({crit_n} CRITICAL/HIGH); {cg.get('abertos_ha_mais_de_30d', 0)} há mais de 30 dias.",
            "Exposição ativa a risco de segurança com impacto em disponibilidade e dados.", "Tratar CRITICAL/HIGH com dono e prazo; automatizar responders onde aplicável.")

    # Integração
    con = [c for c in INTG["connectors"] if c["state"] == "ACTIVE"]
    add(D_INT, "Média", "Service Connector Hub exportando telemetria", len(con) > 0,
        f"{len(con)} connectors ativos: " + (", ".join(f"{k} {v}" for k, v in Counter(f"{c['source']}→{c['target']}" for c in con).items()) or "—") + ".",
        "Logs e métricas da OCI não chegam à plataforma central de observabilidade.",
        "Exportar logs/métricas via Service Connector (Streaming/Functions) para a plataforma central (ex.: Dynatrace).")
    tools = INTG["ferramentas"]
    exp = d["meta"]["expected_tools"]
    for t in exp:
        add(D_INT, "Média", f"Integração OCI ↔ {t.title()} detectada", t in tools,
            ("Indícios: " + ", ".join(f"{w} x{n}" for w, n in tools[t].items()) + ".") if t in tools else "Nenhum recurso, policy, grupo ou connector com referência.",
            f"Recursos OCI fora do {t.title()} ficam sem correlação com o restante do ambiente (Azure/AWS/on-prem).",
            f"Configurar a integração nativa OCI do {t.title()} (policy de leitura de métricas + OneAgent nas VMs/OKE).")
    # ===================== Pilares WAF adicionais ===================== #
    SE, RE_, CO, DI = d.get("security") or {}, d.get("reliability") or {}, d.get("cost") or {}, d.get("distributed") or {}
    cur = CO.get("moeda", "")

    def money(v):
        return "N/D" if v is None else f"{cur} {v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

    # Segurança e conformidade
    if SE:
        uc = SE["usuarios_console"]
        if uc:
            add(D_IAM, "Alta", "MFA para usuários com acesso ao console", SE["usuarios_sem_mfa"] == 0,
                f"{SE['usuarios_sem_mfa']} de {uc} usuários locais com senha de console sem MFA (usuários federados excluídos).",
                "Credencial vazada dá acesso direto ao console da cloud.", "Exigir MFA via Sign-On Policy do Identity Domain para todos os usuários locais.")
        add(D_IAM, "Média", "Policies com privilégio amplo (manage all-resources)", not SE["policies_amplas"],
            f"{len(SE['policies_amplas'])} statements 'manage all-resources in tenancy' fora do grupo Administrators.",
            "Privilégio excessivo amplia o raio de impacto de erro humano ou credencial comprometida.",
            "Aplicar menor privilégio: policies por compartment e por família de recurso; revisar any-user.")
        rr = SE["regras_abertas"]
        add(D_NET, "Alta", "Portas administrativas/banco expostas à internet (0.0.0.0/0)", not rr,
            f"{len(rr)} regras de ingresso abertas para 0.0.0.0/0 em portas sensíveis (SSH, RDP, bancos) ou todas as portas.",
            "Superfície de ataque direta para força bruta e exploração de vulnerabilidades.",
            "Restringir origens por CIDR corporativo, usar OCI Bastion/VPN e NSGs; remover regras 0.0.0.0/0 das security lists default.")
        if CP.get("total"):
            add(D_NET, "Baixa", "OCI Bastion para acesso administrativo", SE["bastions"] > 0, f"{SE['bastions']} bastions ativos.",
                "Acesso administrativo sem sessão auditada e com IP público.", "Usar OCI Bastion (sessões temporárias, auditadas) em vez de IP público + SSH.")
            add(D_NET, "Média", "Vulnerability Scanning em hosts", SE["vss_targets"] > 0, f"{SE['vss_targets']} host scan targets.",
                "Vulnerabilidades de SO/pacotes não são identificadas.", "Criar scan recipes e targets por compartment de produção.")
        add(D_DATA, "Alta", "Buckets sem acesso público", not SE["buckets_publicos"],
            f"{len(SE['buckets_publicos'])} de {SE['buckets']} buckets públicos" + (f": {', '.join(SE['buckets_publicos'][:5])}" if SE["buckets_publicos"] else "") + ".",
            "Vazamento de dados por objeto público.", "Definir buckets como NoPublicAccess e usar PARs com expiração quando necessário.")
        add(D_DATA, "Média", "Vault/KMS para chaves gerenciadas pelo cliente", SE["vaults"] > 0, f"{SE['vaults']} vaults ativos.",
            "Sem controle de chaves e secrets centralizado (rotação, revogação, auditoria).", "Criar Vault para chaves (CMK) e secrets das aplicações.")
        add(D_DATA, "Média", "Security Zones aplicadas", SE["security_zones"] > 0, f"{SE['security_zones']} security zones ativas.",
            "Nada impede a criação de recursos fora do padrão de segurança (bucket público, sem criptografia).",
            "Aplicar Security Zones nos compartments de produção (recipe Maximum Security).")
    # Confiabilidade e resiliência
    if RE_:
        fds = RE_["fault_domains"]
        nrun = RE_["instancias_running"]
        if nrun >= 2:
            top = max(fds.values()) if fds else 0
            add(D_HA, "Média", "Compute distribuído entre fault domains", pct(top, nrun) <= 70,
                f"{nrun} instâncias em execução: " + ", ".join(f"{k} {v}" for k, v in sorted(fds.items())) + f" (maior concentração {pct(top, nrun)}%).",
                "Manutenção ou falha de hardware em um fault domain derruba a maior parte do workload.",
                "Distribuir instâncias de cada tier entre FD-1/2/3 (instance pools com placement por FD).")
        b, bt = RE_["block"], RE_["boot"]
        if b["total"]:
            add(D_BKP, "Alta", "Block volumes com política de backup", pct(b["com_backup"], b["total"]) >= 90,
                f"{b['com_backup']} de {b['total']} block volumes com backup policy ({pct(b['com_backup'], b['total'])}%).",
                "Perda de dados sem ponto de restauração.", "Atribuir backup policy (Gold/Silver ou custom) via Terraform em todos os volumes de dados.")
        if bt["total"]:
            add(D_BKP, "Média", "Boot volumes com política de backup", pct(bt["com_backup"], bt["total"]) >= 80,
                f"{bt['com_backup']} de {bt['total']} boot volumes anexados com backup policy ({pct(bt['com_backup'], bt['total'])}%).",
                "Reconstrução manual de servidores aumenta o RTO.", "Atribuir backup policy aos boot volumes ou garantir rebuild por imagem/IaC.")
        if RE_["dbs"]["total"]:
            x = RE_["dbs"]
            add(D_BKP, "Alta", "DB Systems com backup automático", x["auto_backup"] == x["total"],
                f"{x['auto_backup']} de {x['total']} databases com auto backup; {x['data_guard']} com Data Guard.",
                "Banco sem backup automático = risco de perda irreversível.", "Habilitar auto backup (recovery window ≥ 30d) e Data Guard nos bancos críticos.")
        if RE_["adb"]["total"]:
            x = RE_["adb"]
            add(D_HA, "Média", "Autonomous Database com Autonomous Data Guard", pct(x["data_guard"], x["total"]) >= 80,
                f"{x['data_guard']} de {x['total']} ADBs com Data Guard ({x['cross_region']} cross-region).",
                "Falha de infraestrutura ou região sem standby aumenta RTO/RPO.", "Habilitar Autonomous Data Guard (local e/ou cross-region para Vinhedo).")
        if RE_["mysql"]["total"]:
            x = RE_["mysql"]
            add(D_HA, "Média", "MySQL HeatWave com HA e backup", x["ha"] == x["total"] and x["backup"] == x["total"],
                f"{x['ha']} de {x['total']} com alta disponibilidade, {x['backup']} com backup, {x['copia_cross_region']} com cópia cross-region.",
                "Instância única de MySQL é ponto único de falha.", "Habilitar HA (3 instâncias em FDs/ADs) e cópia de backup cross-region.")
        if DI.get("regioes", 1) >= 2:
            dr = b["replicados"] + bt["replicados"] + RE_["adb"]["cross_region"] + RE_["buckets_replicados"] + RE_["mysql"]["copia_cross_region"]
            add(D_BKP, "Alta", "Estratégia de DR cross-region", dr > 0,
                f"Mecanismos de DR detectados: {b['replicados'] + bt['replicados']} volumes replicados, {RE_['adb']['cross_region']} ADB cross-region, "
                f"{RE_['buckets_replicados']} buckets com replicação, {RE_['mysql']['copia_cross_region']} MySQL com cópia; {DI.get('rpc_peered', 0)} RPCs peered.",
                "Indisponibilidade regional (São Paulo) sem plano de recuperação na segunda região.",
                "Definir RTO/RPO por aplicação e implementar DR para Vinhedo (Full Stack DR, replicação de volumes, ADG, replicação de buckets).")
    # Desempenho e custos
    if CO:
        add(D_COST, "Média", "Visibilidade de custos (Usage API)", CO.get("total") is not None and (CO.get("total") or 0) > 0,
            f"Custo dos últimos {CO.get('dias')} dias: {money(CO.get('total'))}; mês atual até hoje {money(CO.get('mtd'))}, projeção {money(CO.get('projecao_mes'))}.",
            "Sem visibilidade, decisões de capacidade e arquitetura ignoram custo.", "Publicar dashboard de custos por compartment/tag e revisão mensal FinOps.")
        if CO.get("variacao_mes_pct") is not None:
            add(D_COST, "Média", "Crescimento de custo mês a mês controlado", CO["variacao_mes_pct"] <= 15,
                f"Variação do último mês fechado: {CO['variacao_mes_pct']:+d}%. Meses: " + ", ".join(f"{k} {money(v)}" for k, v in CO.get("por_mes", {}).items()) + ".",
                "Crescimento não explicado de custo corrói margem.", "Investigar serviços/compartments com maior crescimento e ajustar budgets.")
        add(D_COST, "Média", "Tags de cost-tracking definidas", CO.get("tags_cost_tracking", 0) > 0,
            f"{CO.get('tags_cost_tracking', 0)} tags marcadas como cost-tracking.",
            "Custo não é atribuível a aplicação, time ou centro de custo (showback/chargeback).",
            "Marcar tags CentroCusto/Aplicação/Ambiente como cost-tracking e usar em budgets e relatórios.")
        R_ = CO.get("resumo_oportunidades", {})
        add(D_WASTE, "Média", "Volumes não anexados", R_.get("Volume não anexado", 0) == 0,
            f"{R_.get('Volume não anexado', 0)} volumes não anexados ({CO.get('gb_volumes_nao_anexados', 0)} GB).",
            "Armazenamento pago sem uso.", "Fazer backup final e excluir volumes órfãos; automatizar detecção mensal.")
        add(D_WASTE, "Baixa", "IPs públicos reservados sem uso", R_.get("IP público reservado sem uso", 0) == 0,
            f"{R_.get('IP público reservado sem uso', 0)} IPs reservados não atribuídos.", "Custo recorrente sem uso.", "Liberar IPs reservados não utilizados.")
        if CP.get("total") or CP.get("paradas"):
            add(D_WASTE, "Baixa", "Instâncias paradas há tempo indeterminado", R_.get("Instância parada", 0) == 0,
                f"{R_.get('Instância parada', 0)} instâncias STOPPED (boot e block volumes continuam cobrados).",
                "Custo de storage de servidores sem uso.", "Validar com os donos; criar imagem/backup e terminar as não necessárias.")
        if CO.get("instancias_com_metrica_cpu"):
            n = CO["instancias_com_metrica_cpu"]
            add(D_WASTE, "Média", "Instâncias ociosas", pct(CO["ociosas"], n) <= 5,
                f"{CO['ociosas']} de {n} instâncias com CPU média < 5% e pico diário < 10% em 14 dias.",
                "Capacidade paga sem uso.", "Desligar fora do horário (scheduler), consolidar ou terminar.")
            add(D_RIGHT, "Média", "Instâncias subutilizadas (rightsizing)", pct(CO["subutilizadas"], n) <= 20,
                f"{CO['subutilizadas']} de {n} instâncias com CPU média < 20% e memória < 40% em 14 dias.",
                "Superdimensionamento eleva o custo de compute.", "Reduzir OCPU/memória dos shapes Flex conforme P95 de uso.")
        if CP.get("total"):
            add(D_RIGHT, "Baixa", "Shapes de geração atual (Flex)", R_.get("Shape legado", 0) == 0,
                f"{R_.get('Shape legado', 0)} instâncias em shapes legados (Standard2/E2/DenseIO1-2).",
                "Shapes antigos custam mais por desempenho e perdem flexibilidade.", "Migrar para E5/E4 Flex ou Ampere A1/A2 Flex.")
        if CO.get("buckets"):
            add(D_RIGHT, "Baixa", "Object Storage com lifecycle/auto-tiering", R_.get("Bucket sem lifecycle/auto-tiering", 0) == 0,
                f"{CO['buckets_lifecycle']} de {CO['buckets']} buckets com lifecycle ou auto-tiering; {R_.get('Bucket sem lifecycle/auto-tiering', 0)} buckets ≥100 GB sem.",
                "Dados frios cobrados como Standard.", "Habilitar auto-tiering ou regras de lifecycle (Infrequent Access/Archive).")
        if CO.get("adb_total") or CP.get("total"):
            add(D_RIGHT, "Baixa", "Elasticidade (autoscaling)", CO.get("autoscaling", 0) + CO.get("adb_autoscale", 0) > 0,
                f"{CO.get('autoscaling', 0)} configurações de autoscaling de instance pools; {CO.get('adb_autoscale', 0)} de {CO.get('adb_total', 0)} ADBs com auto scaling.",
                "Capacidade fixa dimensionada para o pico.", "Usar instance pools com autoscaling e ADB auto scaling para cargas variáveis.")
    # Cloud distribuído
    if DI:
        hyb = DI["fastconnect"] + DI["ipsec"]
        if hyb:
            red = DI["fastconnect"] >= 2 or (DI["fastconnect"] >= 1 and DI["ipsec"] >= 1) or DI["ipsec"] >= 2
            add(D_HYB, "Alta", "Conectividade híbrida redundante", red,
                f"{DI['fastconnect']} FastConnect ({DI['fastconnect_bgp_up']} com BGP UP), {DI['ipsec']} VPNs IPSec, {DI['drgs']} DRGs.",
                "Um único link entre OCI e on-premises/outras clouds é ponto único de falha.",
                "Manter dois FastConnect em locais distintos ou FastConnect + VPN IPSec como backup.")
            if DI["fastconnect"]:
                add(D_HYB, "Média", "Sessões BGP do FastConnect ativas", DI["fastconnect_bgp_up"] == DI["fastconnect"],
                    f"{DI['fastconnect_bgp_up']} de {DI['fastconnect']} circuitos com BGP UP.", "Circuito sem BGP ativo não transporta tráfego.",
                    "Investigar circuitos DOWN com o provedor e criar alarme oci_fastconnect ConnectionState.")
        if "azure" in d["meta"].get("expected_clouds", []):
            add(D_HYB, "Baixa", "Interconexão OCI ↔ Azure", DI["azure_interconnect"] > 0,
                f"{DI['azure_interconnect']} circuitos com provedor Microsoft Azure (Oracle Interconnect for Azure).",
                "Tráfego entre OCI e Azure via internet/VPN tem mais latência e custo de egress.",
                "Avaliar Oracle Interconnect for Microsoft Azure (FastConnect + ExpressRoute) para workloads multicloud.")
        if DI["regioes"] >= 2:
            add(D_HYB, "Baixa", "Peering entre regiões (RPC)", DI["rpc_peered"] > 0, f"{DI['rpc_peered']} remote peering connections ativas.",
                "Sem rede entre regiões não há replicação privada nem failover de aplicação.", "Criar RPC entre os DRGs de São Paulo e Vinhedo.")
    return out


def score(checks: list[Check], key: str = "domain") -> tuple[dict[str, int], int]:
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for c in checks:
        if c.passed is None:
            continue
        w = SEV_W[c.severity]
        k = getattr(c, key)
        acc[k][1] += w
        acc[k][0] += w if c.passed else 0
    dom = {k: pct(a, b) for k, (a, b) in acc.items() if b}
    ta, tb = sum(a for a, _ in acc.values()), sum(b for _, b in acc.values())
    return dom, pct(ta, tb)


def score_actions(checks: list[Check], pillar: str) -> list[dict]:
    """Para cada lacuna do pilar: score do pilar e global se só ela fosse resolvida, e o acumulado resolvendo em ordem de ganho."""
    pil0, _ = score(checks, "pillar")
    _, ov0 = score(checks)

    def sim(fixed: set[int]) -> tuple[int, int]:
        cs = [replace(c, passed=True) if i in fixed else c for i, c in enumerate(checks)]
        p, _ = score(cs, "pillar")
        _, o = score(cs)
        return p.get(pillar, 0), o

    gaps = [i for i, c in enumerate(checks) if c.pillar == pillar and c.passed is False]
    rows = []
    for i in gaps:
        p, o = sim({i})
        rows.append({"idx": i, "check": checks[i], "pilar_de": pil0.get(pillar, 0), "pilar_para": p, "global_de": ov0, "global_para": o})
    rows.sort(key=lambda r: (-(r["global_para"] - r["global_de"]), -(r["pilar_para"] - r["pilar_de"]), SEV_ORDER[r["check"].severity]))
    fixed: set[int] = set()
    for r in rows:
        fixed.add(r["idx"])
        r["pilar_acum"], r["global_acum"] = sim(fixed)
    return rows


def level(sc: int) -> str:
    return "Inicial" if sc < 40 else "Em desenvolvimento" if sc < 65 else "Estruturado" if sc < 85 else "Otimizado"


# --------------------------------------------------------------------------- #
# Relatório
# --------------------------------------------------------------------------- #

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#667085;--bd:#e4e7ec;--ok:#12805c;--warn:#b54708;--bad:#c01048;--acc:#c74634}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--tx:#e8eaed;--mut:#9aa3b2;--bd:#262b36;--ok:#3ddc97;--warn:#ffb020;--bad:#ff6b8b;--acc:#ff8a75}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}h1{margin:0 0 4px;font-size:28px}h2{margin:40px 0 14px;font-size:20px}h3{margin:18px 0 8px;font-size:15px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.sub{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.kpi b{display:block;font-size:28px;line-height:1.2}.kpi span{color:var(--mut);font-size:13px}
.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}.ring{--p:0;--c:var(--ok);width:130px;height:130px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*3.6deg),var(--bd) 0);display:grid;place-items:center;flex:none}
.ring i{font-style:normal;width:98px;height:98px;border-radius:50%;background:var(--card);display:grid;place-items:center;font-size:30px;font-weight:700}
.bar{height:8px;background:var(--bd);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.row{display:grid;grid-template-columns:220px 1fr 44px;gap:12px;align-items:center;margin:9px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.Alta,.nao{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}.Média,.parcial{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.Baixa,.nd{background:var(--bd);color:var(--mut)}.sim{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
ul{margin:6px 0;padding-left:20px}.mut{color:var(--mut)}.road{border-left:4px solid var(--bd)}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def esc(x: Any) -> str:
    return html.escape(str(x))


def color(sc: int) -> str:
    return "var(--ok)" if sc >= 75 else "var(--warn)" if sc >= 50 else "var(--bad)"


def table(headers: list[str], rows: list[list[Any]], raw: bool = False) -> str:
    if not rows:
        return '<p class="mut">Sem dados.</p>'
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if raw else esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def badge(txt: str, cls: str | None = None) -> str:
    return f'<span class="badge {cls or txt}">{esc(txt)}</span>'


def dict_rows(d: dict | None) -> list[list[Any]]:
    return [[k, v] for k, v in sorted((d or {}).items(), key=lambda kv: -kv[1] if isinstance(kv[1], int) else 0)]


def subs_map(nt: dict) -> dict[tuple, int]:
    return {tuple(k.split("|", 1)): v for k, v in (nt.get("assinaturas") or {}).items()}


def cov_badge(n: int, t: int) -> str:
    p = pct(n, t)
    return badge(f"{n}/{t} · {p}%", "sim" if p >= 80 else "parcial" if p >= 40 else "nao")


def capability_items(d: dict) -> list[tuple[str, Any]]:
    AS, RS, GL = d["alarms_summary"], d["regional"], d["global"]
    syn = sum((r.get("synthetics") or {}).get("ativos", 0) for r in RS.values())
    hc = (GL.get("health_checks") or {})
    items = [
        ("Alarmes (OCI Monitoring)", AS["habilitados"]), ("Tópicos de notificação (ONS)", d["notifications"]["topicos"]),
        ("Event rules", len(d["notifications"]["regras_eventos"])), ("Logs habilitados (OCI Logging)", sum(1 for s in d["logging"]["logs"] if s["enabled"])),
        ("Unified Agent (logs de SO/app)", d["logging"]["unified_agent"]["ativas"]),
        ("Logging Analytics", sum(1 for r in RS.values() if r.get("log_analytics_onboarded"))),
        ("Service Connector Hub", len(d["integration"]["connectors"])), ("APM Domains", d["apm"]["dominios"]),
        ("APM Synthetics", syn), ("Health Checks", (hc.get("http") or 0) + (hc.get("ping") or 0)),
        ("Stack Monitoring", d["stack_monitoring"]["total"]), ("Ops Insights (DB + hosts)", sum(r.get("opsi_db", 0) + r.get("opsi_host", 0) for r in RS.values())),
        ("Cloud Guard", 1 if (GL.get("cloud_guard") or {}).get("status") == "ENABLED" else 0 if GL.get("cloud_guard") else None),
        ("Budgets com alerta", (GL.get("budgets") or {}).get("com_alerta")), ("Métricas customizadas (namespaces)",
                                                                              sum(1 for n in d["monitoring"]["namespaces"] if not n.startswith(("oci_", "oracle_")))),
        ("Vault / KMS", (d.get("security") or {}).get("vaults")), ("Security Zones", (d.get("security") or {}).get("security_zones")),
        ("OCI Bastion", (d.get("security") or {}).get("bastions")), ("Vulnerability Scanning", (d.get("security") or {}).get("vss_targets")),
        ("Block volumes com backup policy", ((d.get("reliability") or {}).get("block") or {}).get("com_backup")),
        ("FastConnect", (d.get("distributed") or {}).get("fastconnect")),
    ] + [(f"Integração {t.title()}", sum(d["integration"]["ferramentas"].get(t, {}).values())) for t in d["meta"]["expected_tools"]]
    return items


def capability_matrix(d: dict) -> list[list[Any]]:
    rows = []
    for name, n in capability_items(d):
        b = badge("N/D", "nd") if n is None else badge("Em uso", "sim") if n > 0 else badge("Não detectado", "nao")
        rows.append([esc(name), "-" if n is None else n, b])
    return rows


def money_fmt(v: float | None, cur: str, dec: int = 2) -> str:
    if v is None:
        return "N/D"
    return f"{cur} {v:,.{dec}f}".replace(",", "X").replace(".", ",").replace("X", ".").strip()


MESES = ("jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez")


def mes_label(k: str, CO: dict) -> str:
    """'2026-08' -> 'ago/26', com '*' quando o mês está parcial na janela."""
    try:
        y, m = k.split("-")
        lab = f"{MESES[int(m) - 1]}/{y[2:]}"
    except (ValueError, IndexError):
        return k
    return lab + ("*" if "meses_completos" in CO and k not in CO["meses_completos"] else "")


def cost_monthly_avg(CO: dict) -> float | None:
    return round(CO["total"] / CO["dias"] * 30, 2) if CO.get("total") and CO.get("dias") else None


def partial_note(CO: dict) -> str:
    parc = [f"{mes_label(k, {})} ({CO.get('dias_por_mes', {}).get(k, '?')} dias)" for k in CO.get("por_mes", {}) if k not in CO.get("meses_completos", list(CO.get("por_mes", {})))]
    return ("* Mês parcial na janela: " + ", ".join(parc) + ".") if parc else ""


def report_ctx(d: dict, checks: list[Check], pil: dict[str, int], overall: int) -> dict:
    """Dados derivados compartilhados por HTML, PDF e PowerPoint."""
    C, CO, SE = d["coverage"], d.get("cost") or {}, d.get("security") or {}
    porder = {p: i for i, p in enumerate(PILLARS)}
    fails = sorted((c for c in checks if c.passed is False), key=lambda c: (SEV_ORDER[c.severity], porder.get(c.pillar, 9)))
    n_res = sum(v["total"] for t, v in C.items() if t in TAG_TYPES)
    crit = [t for t in CRITICAL_TYPES if t in C]
    ct, cc = sum(C[t]["total"] for t in crit), sum(C[t]["alarme"] for t in crit)
    cur = CO.get("moeda", "")
    kpis = [("Recursos principais", n_res), ("Compute (running)", d["compute"].get("total", 0)), ("Bancos", sum((C.get(t) or {}).get("total", 0) for t in DB_TYPES)),
            ("Cobertura de alarmes (críticos)", f"{pct(cc, ct)}%"), (f"Custo {CO.get('dias', '')}d", money_fmt(CO.get("total"), cur)),
            ("Projeção do mês", money_fmt(CO.get("projecao_mes"), cur)), ("Oportunidades de custo", len(CO.get("oportunidades", []))),
            ("Regras expostas 0.0.0.0/0", len(SE.get("regras_abertas", [])))]
    return {"fails": fails, "oks": [c for c in checks if c.passed], "high": [c for c in fails if c.severity == "Alta"],
            "evaluated": [c for c in checks if c.passed is not None], "n_res": n_res, "ct": ct, "cc": cc, "cur": cur, "co": CO, "se": SE,
            "kpis": kpis, "worst": sorted(pil.items(), key=lambda kv: kv[1])[:2], "best": max(pil.items(), key=lambda kv: kv[1], default=None),
            "overall": overall, "pil": pil}


def exec_summary(d: dict, x: dict, b: Callable[[Any], str] = lambda s: f"<b>{s}</b>", e: Callable[[Any], str] = esc) -> str:
    """Parágrafo do resumo executivo; `b` marca destaque e `e` escapa texto (HTML, PDF ou texto puro)."""
    M, CO, cur, ov = d["meta"], x["co"], x["cur"], x["overall"]
    s = (f"O tenancy {b(e(d['identity']['tenancy_name']))} possui {b(x['n_res'])} recursos principais em {b(len(M['regioes']))} região(ões) "
         f"e {b(len(d['identity']['compartments']))} compartments. A aderência ao {b('OCI Well-Architected Framework')} é "
         + b(f"{ov}/100 ({level(ov)})") + "; os pilares mais frágeis são " + " e ".join(f"{b(e(k))} ({v})" for k, v in x["worst"]) + ". "
         f"Foram identificadas {b(len(x['fails']))} lacunas, {b(len(x['high']))} de prioridade alta"
         + (": " + "; ".join(e(c.title.lower()) for c in x["high"][:4]) if x["high"] else "") + ". ")
    if CO.get("total"):
        s += (f"O custo dos últimos {CO.get('dias')} dias foi {b(e(money_fmt(CO.get('total'), cur)))}"
              + (f", com variação de {b(format(CO['variacao_mes_pct'], '+d') + '%')} no último mês fechado" if CO.get("variacao_mes_pct") is not None else "")
              + f", e há {b(len(CO.get('oportunidades', [])))} oportunidades de otimização mapeadas.")
    return s


ROADMAP = (("Alta", "0 – 30 dias"), ("Média", "30 – 60 dias"), ("Baixa", "60 – 90 dias"))
PNOTE = "Pilares do OCI Well-Architected Framework; pontuação ponderada por criticidade (Alta=3, Média=2, Baixa=1)."


def build_report(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str) -> str:
    C, AS, M = d["coverage"], d["alarms_summary"], d["meta"]
    SE, RE_, CO, DI = d.get("security") or {}, d.get("reliability") or {}, d.get("cost") or {}, d.get("distributed") or {}
    cur = CO.get("moeda", "")
    days = M["days"]
    x = report_ctx(d, checks, pil, overall)
    fails, oks = x["fails"], x["oks"]
    summary = exec_summary(d, x)
    kpi_html = "".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in x["kpis"])

    def bars(items):
        return "".join(f'<div class="row"><span>{esc(k)}</span><div class="bar"><i style="width:{v}%;background:{color(v)}"></i></div><b>{v}</b></div>' for k, v in items)

    pil_rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        pil_rows.append([esc(p), f"<b style='color:{color(pil[p])}'>{pil[p]}</b>" if p in pil else "N/A", sum(1 for c in cs if c.passed),
                         sum(1 for c in cs if not c.passed), sum(1 for c in cs if not c.passed and c.severity == "Alta")])
    dom_by_p = "".join(
        f"<h3>{esc(p)}</h3>" + bars(sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1]))
        for p in PILLARS if any(c.pillar == p for c in checks))
    find_rows = [[badge(c.severity), esc(c.pillar), esc(c.domain), f"<b>{esc(c.title)}</b><br><span class='mut'>{esc(c.evidence)}</span>", esc(c.impact), esc(c.recommendation)] for c in fails]
    road = ""
    for sev, label in ROADMAP:
        items = [c for c in fails if c.severity == sev]
        if items:
            road += f'<div class="card road"><h3>{label} · prioridade {sev}</h3><ul>' + "".join(
                f"<li><span class='badge nd'>{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.recommendation)}</li>" for c in items) + "</ul></div>"

    cov_rows = []
    for t, v in C.items():
        if t not in TAG_TYPES:
            continue
        cov_rows.append([esc(TYPE_LABELS.get(t, t)), v["total"], cov_badge(v["alarme"], v["total"]) if t in NS_BY_TYPE else "—",
                         cov_badge(v["log"], v["total"]) if t in LOG_TYPES else "—", cov_badge(v["metricas"], v["total"]) if t == "Instance" else "—",
                         cov_badge(v["tag"], v["total"]), esc(", ".join(f"{r} {n}" for r, n in v["regioes"].items()))])
    other = sorted(((t, v["total"]) for t, v in C.items() if t not in TAG_TYPES), key=lambda kv: -kv[1])[:30]

    al_html = (f'<div class="grid g2"><div class="card"><h3>Por severidade</h3>{table(["Severidade", "Qtde"], dict_rows(AS["severidade"]))}</div>'
               f'<div class="card"><h3>Por namespace</h3>{table(["Namespace", "Alarmes"], dict_rows(AS["namespaces"]))}</div>'
               f'<div class="card"><h3>Status atual</h3>{table(["Status", "Qtde"], dict_rows(AS["status"]))}</div>'
               f'<div class="card"><h3>Alarmes que mais dispararam ({days}d)</h3>{table(["Alarme", "Disparos"], AS["top_alarmes"])}</div></div>'
               f'<p class="mut">Sem destino: {AS["sem_destino"]} · FIRING há mais de 7 dias: {AS["firing_ha_mais_de_7d"]} · '
               f'Mediana de resolução: {AS["mttr_mediana_min"] if AS["mttr_mediana_min"] is not None else "N/D"} min · P90: {AS["mttr_p90_min"] if AS["mttr_p90_min"] is not None else "N/D"} min · '
               f'históricos analisados: {AS["historico_analisado"]} (sem parse: {AS["historico_sem_parse"]})</p>')
    NT, LG, GL = d["notifications"], d["logging"], d["global"]
    cg = GL.get("cloud_guard") or {}
    flows = dict(Counter(c["source"] + " → " + c["target"] for c in d["integration"]["connectors"]))
    resp_html = (f'<div class="grid g2"><div class="card"><h3>Assinaturas ONS (protocolo · estado)</h3>{table(["Protocolo", "Estado", "Qtde"], [[p, s, n] for (p, s), n in sorted(subs_map(NT).items(), key=lambda kv: -kv[1])])}</div>'
                 f'<div class="card"><h3>Logs por serviço de origem</h3>{table(["Serviço", "Logs habilitados"], dict_rows(dict(Counter(s["service"] for s in LG["logs"] if s["enabled"]))))}</div>'
                 f'<div class="card"><h3>Service Connectors</h3>{table(["Fluxo", "Qtde"], dict_rows(flows))}</div>'
                 f'<div class="card"><h3>Integração com ferramentas externas</h3>'
                 + (table(["Ferramenta", "Onde foi encontrada"], [[k.title(), ", ".join(f"{w} x{n}" for w, n in v.items())] for k, v in d["integration"]["ferramentas"].items()])
                    if d["integration"]["ferramentas"] else '<p class="mut">Nenhuma referência às ferramentas pesquisadas.</p>') + "</div></div>")

    # Segurança
    rr = SE.get("regras_abertas", [])
    sec_html = (f'<div class="grid g2"><div class="card"><h3>Postura</h3>{table(["Item", "Valor"], [["Usuários de console sem MFA", f"{SE.get('usuarios_sem_mfa', 0)} de {SE.get('usuarios_console', 0)}"], ["Policies amplas (manage all-resources)", len(SE.get("policies_amplas", []))], ["Buckets públicos", f"{len(SE.get('buckets_publicos', []))} de {SE.get('buckets', 0)}"], ["Vaults", SE.get("vaults", 0)], ["Security Zones", SE.get("security_zones", 0)], ["Bastions", SE.get("bastions", 0)], ["Vulnerability Scanning targets", SE.get("vss_targets", 0)], ["Cloud Guard", cg.get("status", "N/D")], ["Problemas Cloud Guard abertos", cg.get("abertos", "N/D")], ["Retenção do Audit (dias)", GL.get("audit_retention_days", "N/D")]])}</div>'
                f'<div class="card"><h3>Regras expostas a 0.0.0.0/0 (top 15)</h3>{table(["Tipo", "Nome", "Portas", "Região"], [[r["tipo"], r["nome"], r["portas"], r["region"]] for r in rr[:15]])}</div></div>'
                + ('<div class="card" style="margin-top:14px"><h3>Policies amplas</h3><ul>' + "".join(f"<li>{esc(x)}</li>" for x in SE["policies_amplas"]) + "</ul></div>" if SE.get("policies_amplas") else ""))
    # Confiabilidade
    rel_rows = []
    if RE_:
        b, bt, ad, db, my = RE_["block"], RE_["boot"], RE_["adb"], RE_["dbs"], RE_["mysql"]
        rel_rows = [["Block volumes com backup policy", cov_badge(b["com_backup"], b["total"]) if b["total"] else "—", f"{b['replicados']} replicados cross-region"],
                    ["Boot volumes com backup policy", cov_badge(bt["com_backup"], bt["total"]) if bt["total"] else "—", f"{bt['replicados']} replicados"],
                    ["Autonomous DB com Data Guard", cov_badge(ad["data_guard"], ad["total"]) if ad["total"] else "—", f"{ad['cross_region']} cross-region"],
                    ["DB Systems com auto backup", cov_badge(db["auto_backup"], db["total"]) if db["total"] else "—", f"{db['data_guard']} com Data Guard"],
                    ["MySQL com HA", cov_badge(my["ha"], my["total"]) if my["total"] else "—", f"{my['backup']} com backup · {my['copia_cross_region']} cópia cross-region"],
                    ["Buckets", f"{RE_['buckets_replicados']} replicados", f"{RE_['buckets_versionados']} com versionamento"],
                    ["Fault domains (instâncias running)", esc(", ".join(f"{k}: {v}" for k, v in sorted(RE_["fault_domains"].items())) or "—"), ""]]
    rel_html = table(["Controle", "Cobertura", "Detalhe"], rel_rows, raw=True)
    dist_html = table(["Item", "Valor"], [["FastConnect", f"{DI.get('fastconnect', 0)} ({DI.get('fastconnect_bgp_up', 0)} BGP UP)"], ["Provedores", ", ".join(f"{k} {v}" for k, v in (DI.get("provedores") or {}).items()) or "—"],
                                          ["Oracle Interconnect for Azure", DI.get("azure_interconnect", 0)], ["VPN IPSec", DI.get("ipsec", 0)], ["DRGs", DI.get("drgs", 0)],
                                          ["Remote peering (entre regiões) ativos", DI.get("rpc_peered", 0)]]) if DI else ""
    # Custos
    opp = CO.get("oportunidades", [])
    cost_html = ""
    if CO:
        cost_html = ('<div class="grid g4">' + "".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in [
            (f"Custo últimos {CO.get('dias')}d", money_fmt(CO.get("total"), cur)), ("Mês atual até hoje", money_fmt(CO.get("mtd"), cur)),
            ("Projeção do mês", money_fmt(CO.get("projecao_mes"), cur)), ("Variação último mês", f"{CO['variacao_mes_pct']:+d}%" if CO.get("variacao_mes_pct") is not None else "N/D")]) + "</div>"
            f'<div class="grid g2" style="margin-top:14px"><div class="card"><h3>Por serviço (top 15)</h3>{table(["Serviço", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_servico", [])])}</div>'
            f'<div class="card"><h3>Por compartment (top 15)</h3>{table(["Compartment", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_compartment", [])])}</div>'
            f'<div class="card"><h3>Por mês</h3>{table(["Mês", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_mes", {}).items()])}<p class="mut">Mês corrente parcial ({CO.get("dias_no_mes_atual")} dias).</p></div>'
            f'<div class="card"><h3>Por região</h3>{table(["Região", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_regiao", [])])}</div>'
            f'<div class="card"><h3>Oportunidades de otimização</h3>{table(["Categoria", "Qtde"], dict_rows(CO.get("resumo_oportunidades")))}'
            f'<p class="mut">{CO.get("gb_volumes_nao_anexados", 0)} GB em volumes não anexados · detalhe por recurso em otimizacao_custos.csv.</p></div>'
            f'<div class="card"><h3>Maiores oportunidades (amostra)</h3>{table(["Categoria", "Recurso", "Detalhe"], [[o["categoria"], o["nome"], o["detalhe"]] for o in opp[:15]])}</div></div>')
    app_rows = [[k, v] for k, v in M["coleta"].items()]
    pnote = PNOTE

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assessment OCI Well-Architected · {esc(customer)}</title><style>{CSS}</style></head><body><main>
<h1>Assessment OCI · Well-Architected Framework</h1>
<p class="sub">{esc(customer)} · Tenancy {esc(d['identity']['tenancy_name'])} · Regiões: {esc(', '.join(M['regioes']))} · Gerado em {M['gerado_em']} · Janela: {days} dias · Coleta somente leitura</p>

<h2>1. Resumo executivo</h2>
<div class="card hero"><div class="ring" style="--p:{overall};--c:{color(overall)}"><i>{overall}</i></div><div style="flex:1;min-width:280px"><h3 style="margin-top:0">Aderência ao WAF · {level(overall)}</h3><p style="margin:0">{summary}</p></div></div>
<div class="grid g4" style="margin-top:14px">{kpi_html}</div>

<h2>2. Maturidade por pilar (OCI Well-Architected)</h2><div class="card">{bars([(p, pil[p]) for p in PILLARS if p in pil])}
{table(["Pilar", "Score", "Atende", "Lacunas", "Lacunas Alta"], pil_rows, raw=True)}<p class="mut" style="margin-bottom:0">{pnote}</p></div>

<h2>3. Maturidade por domínio</h2><div class="card">{dom_by_p}</div>

<h2>4. Lacunas priorizadas e recomendações</h2><div class="card">{table(["Prioridade", "Pilar", "Domínio", "Lacuna", "Impacto no negócio", "Recomendação"], find_rows, raw=True) if fails else '<p>Nenhuma lacuna identificada.</p>'}</div>

<h2>5. Roadmap sugerido</h2><div class="grid">{road}</div>

<h2>6. Pontos fortes</h2><div class="card"><ul>{''.join(f'<li><span class="badge sim">{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.evidence)}</li>' for c in oks) or '<li>—</li>'}</ul></div>

<h2>7. Desempenho e custos</h2>{cost_html or '<p class="mut">Custos não coletados (verifique a policy read usage-reports).</p>'}

<h2>8. Segurança e conformidade</h2>{sec_html}

<h2>9. Confiabilidade e resiliência</h2><div class="card">{rel_html}</div>

<h2>10. Cloud distribuído (híbrido/multicloud)</h2><div class="card">{dist_html}</div>

<h2>11. Eficiência operacional · observabilidade</h2>
<div class="card">{table(["Capacidade", "Itens detectados", "Situação"], capability_matrix(d), raw=True)}</div>
<h3>Cobertura por tipo de recurso</h3><div class="card">{table(["Tipo", "Total", "Com alarme", "Com log de serviço", "Emitindo métricas", "Com tag", "Regiões"], cov_rows, raw=True)}
<p class="mut">Alarme: heurística por namespace + compartment + filtro da query (resourceId/nome). Detalhe por recurso em cobertura_recursos.csv.</p></div>
<h3>Alarmes e resposta</h3>{al_html}{resp_html}

<h2>12. Inventário (demais tipos)</h2><div class="card">{table(["Tipo", "Qtde"], [[t, n] for t, n in other])}</div>

<h2>Apêndice A · Status da coleta</h2><div class="card">{table(["Coletor", "Status"], app_rows)}<p class="mut">"parcial" indica compartments/serviços sem permissão de leitura (404 NotAuthorizedOrNotFound) ou serviço não habilitado na região; os controles dependentes podem estar subestimados.</p></div>
</main></body></html>"""


# --------------------------------------------------------------------------- #
# Relatórios PDF (executivo e técnico) · reportlab  —  imports lazy: opcionais
# --------------------------------------------------------------------------- #

HEX_OK, HEX_WARN, HEX_BAD, HEX_ACC = "#12805C", "#B54708", "#C01048", "#C74634"
HEX_TX, HEX_MUT, HEX_BD, HEX_BG, HEX_SOFT = "#1B1F24", "#667085", "#E4E7EC", "#F6F7F9", "#C9CED6"
SEV_HEX = {"Alta": HEX_BAD, "Média": HEX_WARN, "Baixa": HEX_MUT}
_PDF_FONT = ["Helvetica", "Helvetica-Bold", False]  # (regular, bold, unicode completo?)
_ASCII_MAP = str.maketrans({"→": "->", "↔": "<->", "≥": ">=", "≤": "<=", "✓": "v", "✗": "x", "×": "x"})


def hex_score(sc: int) -> str:
    return HEX_OK if sc >= 75 else HEX_WARN if sc >= 50 else HEX_BAD


def clip(s: Any, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def next_level(sc: int) -> tuple[str, int] | None:
    for lim in (40, 65, 85):
        if sc < lim:
            return level(lim), lim
    return None


def _pdf_fonts() -> list:
    """Registra uma fonte TrueType com acentuação/símbolos (DejaVu no Cloud Shell, Arial no Windows/macOS)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if _PDF_FONT[2]:
        return _PDF_FONT
    win = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    pairs = [(Path(p) / "DejaVuSans.ttf", Path(p) / "DejaVuSans-Bold.ttf") for p in
             ("/usr/share/fonts/dejavu", "/usr/share/fonts/dejavu-sans-fonts", "/usr/share/fonts/truetype/dejavu")]
    pairs += [(win / "arial.ttf", win / "arialbd.ttf"), (win / "segoeui.ttf", win / "segoeuib.ttf"),
              (Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf"))]
    pairs += [(Path(p) / "LiberationSans-Regular.ttf", Path(p) / "LiberationSans-Bold.ttf") for p in
              ("/usr/share/fonts/liberation-sans", "/usr/share/fonts/truetype/liberation")]
    for reg, bold in pairs:
        if reg.is_file() and bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont("WAF", str(reg)))
                pdfmetrics.registerFont(TTFont("WAF-Bold", str(bold)))
                pdfmetrics.registerFontFamily("WAF", normal="WAF", bold="WAF-Bold", italic="WAF", boldItalic="WAF-Bold")
                _PDF_FONT[:] = ["WAF", "WAF-Bold", True]
                break
            except Exception:  # fonte corrompida/sem permissão: tenta a próxima
                continue
    return _PDF_FONT


def _plain(s: Any) -> str:
    s = str(s)
    return s if _PDF_FONT[2] else s.translate(_ASCII_MAP)


def _xe(s: Any) -> str:
    return _plain(html.escape(str(s), quote=False))


def _pdf_styles(font: str, bold: str) -> dict:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    c = colors.HexColor
    base = ParagraphStyle("base", fontName=font, fontSize=9.5, leading=13.5, textColor=c(HEX_TX))
    return {
        "base": base,
        "h2": ParagraphStyle("h2", parent=base, fontName=bold, fontSize=14, leading=18, spaceBefore=12, spaceAfter=8, textColor=c(HEX_ACC)),
        "h3": ParagraphStyle("h3", parent=base, fontName=bold, fontSize=10, leading=13, spaceBefore=8, spaceAfter=4, textColor=c(HEX_MUT)),
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=10, textColor=c(HEX_MUT)),
        "td": ParagraphStyle("td", parent=base, fontSize=7.8, leading=10),
        "th": ParagraphStyle("th", parent=base, fontName=bold, fontSize=7.5, leading=9.5, textColor=colors.white),
        "kpi": ParagraphStyle("kpi", parent=base, fontName=bold, fontSize=14, leading=17),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3),
    }


def _pdf_table(S: dict, headers: list[str], rows: list[list[Any]], width: float, fr: list[float] | None = None) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Flowable, Paragraph, Table, TableStyle
    if not rows:
        return Paragraph("Sem dados.", S["small"])
    fr = fr or [1] * len(headers)
    data = [[Paragraph(_xe(h), S["th"]) for h in headers]]
    data += [[v if isinstance(v, (Flowable, list)) else Paragraph(_xe("-" if v is None else v), S["td"]) for v in r] for r in rows]
    t = Table(data, colWidths=[width * f / sum(fr) for f in fr], repeatRows=1, hAlign="LEFT")
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(HEX_TX)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(HEX_BD)), ("TOPPADDING", (0, 0), (-1, -1), 3.5),
          ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    st += [("BACKGROUND", (0, i), (-1, i), colors.HexColor(HEX_BG)) for i in range(2, len(data), 2)]
    t.setStyle(TableStyle(st))
    return t


def _pdf_side(blocks: list[list[Any]], width: float) -> Any:
    """Blocos lado a lado (cada bloco é uma lista de flowables com largura width/len(blocks) - 10)."""
    from reportlab.platypus import Table, TableStyle
    t = Table([blocks], colWidths=[width / len(blocks)] * len(blocks))
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 10)]))
    return t


def _pdf_kpis(S: dict, kpis: list[tuple[str, Any]], width: float, cols: int = 4) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle
    cells = [[Paragraph(_xe(v), S["kpi"]), Paragraph(_xe(k), S["small"])] for k, v in kpis]
    cells += [""] * (-len(cells) % cols)
    t = Table([cells[i:i + cols] for i in range(0, len(cells), cols)], colWidths=[width / cols] * cols)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(HEX_BG)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEAFTER", (0, 0), (-1, -1), 4, colors.white), ("LINEBELOW", (0, 0), (-1, -1), 4, colors.white),
                           ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(HEX_ACC)),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 9)]))
    return t


def _pdf_bars(items: list[tuple[str, int]], width: float, label_w: float = 165, row_h: float = 17) -> Any:
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    h = row_h * len(items) + 2
    dr = Drawing(width, h)
    bw = width - label_w - 30
    for i, (k, v) in enumerate(items):
        y = h - (i + 1) * row_h + 3
        dr.add(String(0, y + 1.5, _plain(clip(k, 38)), fontName=font, fontSize=8.5, fillColor=colors.HexColor(HEX_TX)))
        dr.add(Rect(label_w, y + 1, bw, 8, rx=4, ry=4, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
        if v:
            dr.add(Rect(label_w, y + 1, max(8, bw * v / 100), 8, rx=4, ry=4, fillColor=colors.HexColor(hex_score(v)), strokeColor=None))
        dr.add(String(width, y + 1.5, str(v), fontName=bold, fontSize=9, textAnchor="end", fillColor=colors.HexColor(hex_score(v))))
    return dr


def _pdf_gauge(sc: int, size: float) -> Any:
    from reportlab.graphics.shapes import Circle, Drawing, String, Wedge
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    dr, c, r = Drawing(size, size), size / 2, size / 2
    col = colors.HexColor(hex_score(sc))
    dr.add(Circle(c, c, r, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
    if sc >= 100:
        dr.add(Circle(c, c, r, fillColor=col, strokeColor=None))
    elif sc > 0:
        dr.add(Wedge(c, c, r, 90 - 3.6 * sc, 90, fillColor=col, strokeColor=None))
    dr.add(Circle(c, c, r * 0.76, fillColor=colors.white, strokeColor=None))
    dr.add(String(c, c - size * 0.06, str(sc), fontName=bold, fontSize=size * 0.30, textAnchor="middle", fillColor=col))
    dr.add(String(c, c - size * 0.22, "/100", fontName=font, fontSize=size * 0.09, textAnchor="middle", fillColor=colors.HexColor(HEX_MUT)))
    return dr


def _pdf_doc(path: Path, d: dict, customer: str, subtitle: str, x: dict, land: bool) -> tuple:
    """Documento A4 com capa (1ª página) e cabeçalho/rodapé nas demais. Retorna (doc, styles, story inicial, largura útil)."""
    from reportlab.graphics import renderPDF
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import Flowable, PageBreak, SimpleDocTemplate
    font, bold, _ = _pdf_fonts()
    S = _pdf_styles(font, bold)
    ps = landscape(A4) if land else A4
    M, hx, ten = d["meta"], colors.HexColor, d["identity"]["tenancy_name"]
    doc = SimpleDocTemplate(str(path), pagesize=ps, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=18 * mm, bottomMargin=16 * mm,
                            title=f"Assessment OCI Well-Architected - {subtitle} - {customer}", author="oci_assessment.py",
                            subject="OCI Well-Architected Framework")

    def later(cv, dc):
        w, h = ps
        cv.saveState()
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, h - 5, w, 5, fill=1, stroke=0)
        cv.setFont(font, 7.5)
        cv.setFillColor(hx(HEX_MUT))
        cv.drawString(dc.leftMargin, h - 11 * mm, _plain(f"Assessment OCI Well-Architected · {subtitle} · {customer}"))
        cv.drawRightString(w - dc.rightMargin, h - 11 * mm, "Confidencial")
        cv.drawString(dc.leftMargin, 8 * mm, _plain(f"Tenancy {ten} · gerado em {M['gerado_em']} · coleta somente leitura"))
        cv.drawRightString(w - dc.rightMargin, 8 * mm, f"Página {dc.page}")
        cv.restoreState()

    def first(cv, dc):
        w, h = ps
        by, L, gs, ov = h * (0.46 if land else 0.57), 22 * mm, 130, x["overall"]
        cv.saveState()
        cv.setFillColor(hx(HEX_TX))
        cv.rect(0, by, w, h - by, fill=1, stroke=0)
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, by - 6, w, 6, fill=1, stroke=0)
        cv.setFont(bold, 9.5)
        cv.drawString(L, h - 70, "OCI WELL-ARCHITECTED FRAMEWORK")
        cv.setFillColor(colors.white)
        cv.setFont(bold, 30)
        cv.drawString(L, h - 115, "Assessment de arquitetura")
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 17)
        cv.drawString(L, h - 142, _plain(subtitle))
        cv.setFillColor(colors.white)
        cv.setFont(bold, 16)
        cv.drawString(L, h - 192, _plain(clip(customer, 70)))
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 10)
        for i, ln in enumerate([f"Tenancy {ten} · home region {M.get('home_region', '-')}", f"Regiões: {', '.join(M['regioes'])}",
                                f"Gerado em {M['gerado_em']} · janela de {M['days']} dias · coleta somente leitura"]):
            cv.drawString(L, h - 214 - i * 15, _plain(clip(ln, 120)))
        gy = by / 2 - gs / 2 + 12
        renderPDF.draw(_pdf_gauge(ov, gs), cv, L, gy)
        tx = L + gs + 32
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(bold, 9)
        cv.drawString(tx, gy + gs - 8, "ADERÊNCIA AO WELL-ARCHITECTED FRAMEWORK")
        cv.setFillColor(hx(hex_score(ov)))
        cv.setFont(bold, 20)
        cv.drawString(tx, gy + gs - 34, level(ov))
        bars = _pdf_bars([(p, x["pil"][p]) for p in PILLARS if p in x["pil"]], min(w - tx - L, 340), label_w=140)
        renderPDF.draw(bars, cv, tx, gy + gs - 46 - bars.height)
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(font, 7.5)
        cv.drawString(L, 12 * mm, "Confidencial · gerado automaticamente por oci_assessment.py a partir de APIs somente leitura da OCI")
        cv.restoreState()

    class _CoverFill(Flowable):  # ocupa a 1ª página; a capa é desenhada direto no canvas
        def wrap(self, aw, ah):
            return aw, ah - 1

        def draw(self):
            pass

    doc._waf_pages = (first, later)
    return doc, S, [_CoverFill(), PageBreak()], doc.width


def _pdf_sev(S: dict, sev: str) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph(f'<font color="{SEV_HEX.get(sev, HEX_MUT)}"><b>{_xe(sev)}</b></font>', S["td"])


def _pdf_score(S: dict, v: int | None) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph("N/A" if v is None else f'<font color="{hex_score(v)}"><b>{v}</b></font>', S["td"])


def _pdf_cov(S: dict, n: int, t: int) -> Any:
    from reportlab.platypus import Paragraph
    if not t:
        return Paragraph("—", S["td"])
    p = pct(n, t)
    col = HEX_OK if p >= 80 else HEX_WARN if p >= 40 else HEX_BAD
    return Paragraph(f'<font color="{col}"><b>{n}/{t}</b> · {p}%</font>', S["td"])


def _pdf_pillar_rows(S: dict, checks: list[Check], pil: dict[str, int], with_counts: bool) -> list[list[Any]]:
    rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        if not cs:
            continue
        sc = pil.get(p)
        fs = [c for c in cs if not c.passed]
        base = [p, _pdf_score(S, sc), level(sc) if sc is not None else "—"]
        if with_counts:
            rows.append(base + [sum(1 for c in cs if c.passed), len(fs), sum(1 for c in fs if c.severity == "Alta")])
        else:
            rows.append(base + [sum(1 for c in fs if c.severity == s) for s in SEV_ORDER])
    return rows


def build_pdf_exec(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import KeepTogether, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório executivo", x, land=False)
    CO, cur = x["co"], x["cur"]
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731

    story += [P("1. Resumo executivo", "h2"), P(exec_summary(d, x, e=_xe)), Spacer(1, 10), _pdf_kpis(S, x["kpis"], W),
              KeepTogether([P("Maturidade por pilar", "h3"), _pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], W),
                            Spacer(1, 6), _pdf_table(S, ["Pilar", "Score", "Nível", "Lacunas Alta", "Média", "Baixa"],
                                                     _pdf_pillar_rows(S, checks, pil, False), W, [3, 1, 2, 1.2, 1, 1]),
                            P(PNOTE, "small")])]

    story.append(P("2. Principais riscos para o negócio", "h2"))
    top = x["high"] or x["fails"]
    if top:
        story.append(P(f"{len(x['high'])} lacunas de prioridade alta exigem ação nos próximos 30 dias. "
                       + ("Os itens abaixo concentram o maior risco operacional, de segurança ou financeiro." if x["high"] else
                          "Não há lacunas de prioridade alta; abaixo, as mais relevantes."), "base"))
        story.append(Spacer(1, 6))
        story.append(_pdf_table(S, ["Prioridade", "Pilar", "Risco identificado", "Impacto no negócio", "Ação recomendada"],
                                [[_pdf_sev(S, c.severity), c.pillar, P(f"<b>{_xe(c.title)}</b>", "td"), c.impact, c.recommendation] for c in top[:12]],
                                W, [1, 1.4, 1.9, 2.4, 2.6]))
        if len(top) > 12:
            story.append(P(f"+{len(top) - 12} itens no relatório técnico.", "small"))
    else:
        story.append(P("Nenhuma lacuna identificada nos controles avaliados."))

    if CO.get("total"):
        opp = CO.get("resumo_oportunidades") or {}
        dp = CO.get("de_para")
        eco = sum(r["economia_mes"] for r in dp) if dp else None
        story += [P("3. Custos e oportunidades de otimização", "h2"),
                  _pdf_kpis(S, [(f"Custo últimos {CO.get('dias')}d", money_fmt(CO.get("total"), cur)), ("Média mensal", money_fmt(cost_monthly_avg(CO), cur)),
                                ("Variação último mês", f"{CO['variacao_mes_pct']:+d}%" if CO.get("variacao_mes_pct") is not None else "N/D"),
                                ("Economia estimada/mês", money_fmt(eco, cur)) if dp else ("Projeção do mês", money_fmt(CO.get("projecao_mes"), cur))], W),
                  Spacer(1, 8),
                  _pdf_side([[P("Maiores serviços", "h3"), _pdf_table(S, ["Serviço", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_servico", [])[:6]], W / 2 - 10, [2, 1])],
                             [P("Oportunidades mapeadas", "h3"), _pdf_table(S, ["Categoria", "Qtde"], dict_rows(opp)[:6], W / 2 - 10, [3, 1]),
                              P(f"{len(CO.get('oportunidades', []))} oportunidades por recurso · {CO.get('gb_volumes_nao_anexados', 0)} GB em volumes não anexados.", "small")]], W)]
        if dp:
            de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
            story += [KeepTogether([P("DE/PARA de economia", "h3"),
                                    _pdf_table(S, ["Categoria", "DE (mês)", "PARA (mês)", "Economia/mês", "Economia/ano"],
                                               [[r["categoria"], money_fmt(r["de"], cur), money_fmt(r["para"], cur),
                                                 P(f'<font color="{HEX_OK}"><b>{_xe(money_fmt(r["economia_mes"], cur))}</b></font>', "td"), money_fmt(r["economia_ano"], cur)]
                                                for r in dp] + [[P("<b>Total</b>", "td"), money_fmt(de, cur), money_fmt(para, cur),
                                                                 P(f'<font color="{HEX_OK}"><b>{_xe(money_fmt(de - para, cur))}</b></font>', "td"),
                                                                 money_fmt((de - para) * 12, cur)]], W, [2.4, 1, 1, 1, 1]),
                                    P("DE = custo real dos últimos 30 dias dos recursos apontados; PARA = após a ação recomendada. "
                                      "Detalhe por recurso no relatório técnico.", "small")])]
    n = 4 if CO.get("total") else 3

    story.append(P(f"{n}. Roadmap sugerido (30 · 60 · 90 dias)", "h2"))
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story.append(KeepTogether([P(f"{label} · prioridade {sev} ({len(items)})", "h3")]
                                      + [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="•")
                                         for c in items]))

    story.append(P(f"{n + 1}. Pontos fortes", "h2"))
    story += [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="✓" if _PDF_FONT[2] else "•")
              for c in x["oks"][:14]] or [P("—")]

    nl = next_level(overall)
    steps = ["Validar os achados com os times de plataforma, segurança, operações e FinOps e confirmar a priorização.",
             f"Designar responsáveis e datas para as {len(x['high'])} lacunas de prioridade alta (janela de 0 a 30 dias).",
             "Aprovar o roadmap 30/60/90 e o modelo de execução (baseline via Terraform / OCI Landing Zone)."]
    if CO.get("oportunidades"):
        steps.append(f"Tratar as {len(CO['oportunidades'])} oportunidades de otimização de custo (detalhe em otimizacao_custos.csv).")
    steps.append("Reexecutar o assessment em 90 dias para medir a evolução"
                 + (f" (meta: nível {nl[0]}, score ≥ {nl[1]})." if nl else " e manter o nível Otimizado."))
    story.append(KeepTogether([P(f"{n + 2}. Próximos passos e decisões", "h2")]
                              + [Paragraph(_xe(s), S["bullet"], bulletText=f"{i}.") for i, s in enumerate(steps, 1)]
                              + [Spacer(1, 8), P("Detalhamento técnico, evidências por controle e inventário: relatorio_tecnico.pdf · backlog: achados.csv.", "small")]))
    first, later = doc._waf_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


def build_pdf_tech(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório técnico", x, land=True)
    C, AS, M, NT, LG, GL = d["coverage"], d["alarms_summary"], d["meta"], d["notifications"], d["logging"], d["global"]
    SE, RE_, CO, DI, cur = x["se"], d.get("reliability") or {}, x["co"], d.get("distributed") or {}, x["cur"]
    cg, days, H = GL.get("cloud_guard") or {}, M["days"], W / 2 - 10
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731
    T = lambda h, r, w=W, fr=None: _pdf_table(S, h, r, w, fr)  # noqa: E731

    def h2(t):
        story.extend([CondPageBreak(150), P(t, "h2")])

    h2("1. Escopo e metodologia")
    story.append(_pdf_side([[T(["Item", "Valor"], [
        ["Cliente", customer], ["Tenancy", d["identity"]["tenancy_name"]], ["Home region", M.get("home_region", "-")],
        ["Regiões avaliadas", ", ".join(M["regioes"])], ["Compartments", len(d["identity"]["compartments"])],
        ["Recursos principais", x["n_res"]], ["Janela de alarmes / custos", f"{days} dias / {CO.get('dias', '-')} dias"],
        ["Autenticação", M.get("auth", "-")], ["Chamadas de API (leitura)", M.get("chamadas_api", "-")], ["Gerado em", M["gerado_em"]]], H, [1, 2])],
        [P("<b>Abordagem.</b> Coleta 100% somente leitura via SDK OCI: todo client passa por um proxy que só permite métodos "
           "list_/get_/search_/summarize_. Os dados são avaliados contra controles dos cinco pilares do OCI Well-Architected Framework."),
         Spacer(1, 6), P(f"<b>Pontuação.</b> {_xe(PNOTE)} Controles sem dados (N/A) não entram no cálculo. "
                         f"Foram avaliados {len(x['evaluated'])} controles: {len(x['oks'])} atendidos e {len(x['fails'])} lacunas."),
         Spacer(1, 6), P("<b>Níveis.</b> Inicial (&lt;40) · Em desenvolvimento (40–64) · Estruturado (65–84) · Otimizado (≥85)."),
         Spacer(1, 6), P("<b>Limitações.</b> Cobertura de alarmes é heurística (namespace + compartment + filtro da query). "
                         "Coletores com status 'parcial' (Apêndice A) indicam permissões ausentes e podem subestimar controles.")]], W))

    h2("2. Maturidade por pilar")
    story += [P(exec_summary(d, x, e=_xe)), Spacer(1, 8),
              _pdf_side([[_pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], H)],
                         [T(["Pilar", "Score", "Nível", "Atende", "Lacunas", "Alta"], _pdf_pillar_rows(S, checks, pil, True), H, [3, 1, 2, 1, 1, 1])]], W)]

    h2("3. Maturidade por domínio")
    blocks = []
    for p in PILLARS:
        items = sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1])
        if items:
            blocks.append([P(p, "h3"), _pdf_bars(items, H)])
    for i in range(0, len(blocks), 2):
        pair = blocks[i:i + 2]
        story.append(_pdf_side(pair + [[]] * (2 - len(pair)), W))

    h2("4. Lacunas priorizadas e recomendações")
    story.append(T(["Prioridade", "Pilar", "Domínio", "Lacuna e evidência", "Impacto no negócio", "Recomendação"],
                   [[_pdf_sev(S, c.severity), c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b><br/><font color='{HEX_MUT}'>{_xe(c.evidence)}</font>", "td"),
                     c.impact, c.recommendation] for c in x["fails"]], W, [0.8, 1.2, 1.2, 3.2, 2.2, 2.6]) if x["fails"] else P("Nenhuma lacuna identificada."))

    h2("5. Roadmap sugerido")
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story += [P(f"{label} · prioridade {sev} ({len(items)} itens)", "h3"),
                      T(["Pilar", "Domínio", "Ação", "Recomendação"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.recommendation] for c in items],
                        W, [1.2, 1.2, 2.2, 4.5])]

    h2("6. Pontos fortes")
    story.append(T(["Pilar", "Domínio", "Controle atendido", "Evidência"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.evidence] for c in x["oks"]],
                   W, [1.2, 1.2, 2.2, 4.5]))

    h2("7. Desempenho e custos")
    if CO:
        opp = CO.get("oportunidades", [])
        story += [_pdf_kpis(S, [(f"Custo últimos {CO.get('dias')}d", money_fmt(CO.get("total"), cur)), ("Mês atual até hoje", money_fmt(CO.get("mtd"), cur)),
                                ("Projeção do mês", money_fmt(CO.get("projecao_mes"), cur)),
                                ("Variação último mês", f"{CO['variacao_mes_pct']:+d}%" if CO.get("variacao_mes_pct") is not None else "N/D"),
                                ("Instâncias ociosas", CO.get("ociosas", "-")), ("Subutilizadas", CO.get("subutilizadas", "-")),
                                ("Buckets com lifecycle", f"{CO.get('buckets_lifecycle', 0)} de {CO.get('buckets', 0)}"),
                                ("Tags de cost tracking", CO.get("tags_cost_tracking", "-"))], W), Spacer(1, 8),
                  _pdf_side([[P("Por serviço (top 15)", "h3"), T(["Serviço", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_servico", [])[:15]], H, [2, 1])],
                             [P("Por compartment (top 15)", "h3"), T(["Compartment", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_compartment", [])[:15]], H, [2, 1])]], W),
                  _pdf_side([[P("Por região", "h3"), T(["Região", "Custo"], [[k, money_fmt(v, cur)] for k, v in CO.get("por_regiao", [])], H, [2, 1])],
                             [P("Por mês", "h3"), T(["Mês", "Custo"], [[mes_label(k, CO), money_fmt(v, cur)] for k, v in (CO.get("por_mes") or {}).items()], H, [2, 1]),
                              P(partial_note(CO) or f"Mês corrente parcial ({CO.get('dias_no_mes_atual')} dias).", "small")]], W),
                  P("Oportunidades de otimização", "h3"), T(["Categoria", "Qtde"], dict_rows(CO.get("resumo_oportunidades")), H, [3, 1])]
        top_r = CO.get("top_recursos") or []
        if top_r:
            meses = list(CO.get("por_mes") or {})
            story += [CondPageBreak(150), P(f"Recursos que mais consumiram ({CO.get('dias')} dias)", "h3"),
                      T(["Recurso", "Tipo", "Compartment"] + [mes_label(m, CO) for m in meses] + ["Total", "% total"],
                        [[P(f"<b>{_xe(r.get('nome', r['id']))}</b>", "td"), r.get("tipo", r["servico"]), r.get("compartment", "—")]
                         + [money_fmt(r["meses"].get(m), cur, 0) if r["meses"].get(m) else "—" for m in meses]
                         + [P(f"<b>{_xe(money_fmt(r['total'], cur, 0))}</b>", "td"), f"{pct(r['total'], CO['total'])}%"] for r in top_r],
                        W, [2.4, 1.2, 2.2] + [1] * len(meses) + [1.1, 0.6]),
                      P((partial_note(CO) + " " if partial_note(CO) else "") + "Lista completa em custos_por_recurso.csv.", "small")]
        dp = CO.get("de_para")
        if dp:
            de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
            story += [CondPageBreak(150), P("DE/PARA de economia (base: custo real dos últimos 30 dias)", "h3"),
                      T(["Categoria", "Ação", "Recursos", "Redução", "DE (mês)", "PARA (mês)", "Economia/mês", "Economia/ano"],
                        [[r["categoria"], r["acao"], r["recursos"], f"{r['premissa_pct']}%", money_fmt(r["de"], cur), money_fmt(r["para"], cur),
                          P(f'<font color="{HEX_OK}"><b>{_xe(money_fmt(r["economia_mes"], cur))}</b></font>', "td"), money_fmt(r["economia_ano"], cur)] for r in dp]
                        + [[P("<b>Total</b>", "td"), "", sum(r["recursos"] for r in dp), "", money_fmt(de, cur), money_fmt(para, cur),
                            P(f'<font color="{HEX_OK}"><b>{_xe(money_fmt(de - para, cur))}</b></font>', "td"), money_fmt((de - para) * 12, cur)]],
                        W, [1.8, 2.4, 0.7, 0.7, 1.2, 1.2, 1.2, 1.2]),
                      P("DE = custo real (Usage API) dos últimos 30 dias dos recursos apontados. PARA = custo após a ação, aplicando a redução indicada "
                        "(premissa ajustável em SAVINGS_RULES no script). Cada recurso é contado uma única vez, na categoria de maior redução.", "small")]
        story += [P(f"Oportunidades por recurso ({min(len(opp), 40)} de {len(opp)}; lista completa em otimizacao_custos.csv)", "h3"),
                  T(["Categoria", "Tipo", "Recurso", "Região", "Compartment", "Detalhe"] + (["Custo 30d", "Economia/mês"] if dp else []),
                    [[o["categoria"], o["tipo"], o["nome"], o["regiao"], o["compartment"], o["detalhe"]]
                     + ([money_fmt(o.get("custo_30d"), cur), money_fmt(o.get("economia_mes"), cur)] if dp else []) for o in opp[:40]],
                    W, [1.4, 1, 1.8, 1, 1.4, 3] + ([1, 1] if dp else []))]
    else:
        story.append(P("Custos não coletados (verifique a policy read usage-reports).", "small"))

    h2("8. Segurança e conformidade")
    rr = SE.get("regras_abertas", [])
    story.append(_pdf_side([[P("Postura", "h3"), T(["Item", "Valor"], [
        ["Usuários de console sem MFA", f"{SE.get('usuarios_sem_mfa', 0)} de {SE.get('usuarios_console', 0)}"],
        ["Policies amplas (manage all-resources)", len(SE.get("policies_amplas", []))], ["Buckets públicos", f"{len(SE.get('buckets_publicos', []))} de {SE.get('buckets', 0)}"],
        ["Vaults", SE.get("vaults", 0)], ["Security Zones", SE.get("security_zones", 0)], ["Bastions", SE.get("bastions", 0)],
        ["Vulnerability Scanning targets", SE.get("vss_targets", 0)], ["Cloud Guard", cg.get("status", "N/D")],
        ["Problemas Cloud Guard abertos", cg.get("abertos", "N/D")], ["Retenção do Audit (dias)", GL.get("audit_retention_days", "N/D")]], H, [2, 1])],
        [P(f"Regras expostas a 0.0.0.0/0 ({min(len(rr), 15)} de {len(rr)})", "h3"),
         T(["Tipo", "Nome", "Portas", "Região"], [[r["tipo"], r["nome"], r["portas"], r["region"]] for r in rr[:15]], H, [1, 2, 1, 1])]], W))
    if len(rr) > 15:
        story += [P("Demais regras expostas", "h3"), T(["Tipo", "Nome", "Portas", "Região"], [[r["tipo"], r["nome"], r["portas"], r["region"]] for r in rr[15:200]], W, [1, 3, 1.5, 1])]
    acts = score_actions(checks, P_SEC)
    if acts:
        g = lambda a, b: P(f'<font color="{HEX_OK if b > a else HEX_MUT}"><b>{a} → {b}</b>' + (f" (+{b - a})" if b > a else "") + "</font>", "td")  # noqa: E731
        story += [P("Ações para elevar o score de segurança", "h3"),
                  T(["#", "Ação", "Prioridade", "Recomendação", "Score segurança", "Score global", "Global acumulado"],
                    [[i, P(f"<b>{_xe(a['check'].title)}</b>", "td"), _pdf_sev(S, a["check"].severity), a["check"].recommendation,
                      g(a["pilar_de"], a["pilar_para"]), g(a["global_de"], a["global_para"]), _pdf_score(S, a["global_acum"])] for i, a in enumerate(acts, 1)],
                    W, [0.3, 2.4, 0.8, 3.6, 1.1, 1.1, 1]),
                  P("Score se apenas a ação da linha for resolvida; 'Global acumulado' resolve as ações na ordem da tabela. "
                    "Mesma pontuação ponderada do relatório (Alta=3, Média=2, Baixa=1).", "small")]
    if SE.get("policies_amplas"):
        story += [P("Policies amplas", "h3")] + [Paragraph(_xe(p), S["bullet"], bulletText="•") for p in SE["policies_amplas"]]
    if SE.get("buckets_publicos"):
        story += [P("Buckets públicos", "h3"), P(_xe(", ".join(map(str, SE["buckets_publicos"]))), "td")]

    h2("9. Confiabilidade e resiliência")
    if RE_:
        b, bt, ad, db, my = RE_["block"], RE_["boot"], RE_["adb"], RE_["dbs"], RE_["mysql"]
        story.append(T(["Controle", "Cobertura", "Detalhe"], [
            ["Block volumes com backup policy", _pdf_cov(S, b["com_backup"], b["total"]), f"{b['replicados']} replicados cross-region"],
            ["Boot volumes com backup policy", _pdf_cov(S, bt["com_backup"], bt["total"]), f"{bt['replicados']} replicados"],
            ["Autonomous DB com Data Guard", _pdf_cov(S, ad["data_guard"], ad["total"]), f"{ad['cross_region']} cross-region"],
            ["DB Systems com auto backup", _pdf_cov(S, db["auto_backup"], db["total"]), f"{db['data_guard']} com Data Guard"],
            ["MySQL com HA", _pdf_cov(S, my["ha"], my["total"]), f"{my['backup']} com backup · {my['copia_cross_region']} cópia cross-region"],
            ["Buckets", f"{RE_['buckets_replicados']} replicados", f"{RE_['buckets_versionados']} com versionamento"],
            ["Fault domains (instâncias running)", ", ".join(f"{k}: {v}" for k, v in sorted(RE_["fault_domains"].items())) or "—", ""]], W, [2, 1.2, 3]))
    else:
        story.append(P("Sem dados.", "small"))

    h2("10. Cloud distribuído (híbrido/multicloud)")
    story.append(T(["Item", "Valor"], [["FastConnect", f"{DI.get('fastconnect', 0)} ({DI.get('fastconnect_bgp_up', 0)} BGP UP)"],
                                       ["Provedores", ", ".join(f"{k} {v}" for k, v in (DI.get("provedores") or {}).items()) or "—"],
                                       ["Oracle Interconnect for Azure", DI.get("azure_interconnect", 0)], ["VPN IPSec", DI.get("ipsec", 0)],
                                       ["DRGs", DI.get("drgs", 0)], ["Remote peering (entre regiões) ativos", DI.get("rpc_peered", 0)]], H, [2, 1]) if DI else P("Sem dados.", "small"))

    h2("11. Eficiência operacional · observabilidade")
    cap = [[n, "-" if v is None else v, P(f'<font color="{HEX_MUT if v is None else HEX_OK if v > 0 else HEX_BAD}"><b>'
                                         + ("N/D" if v is None else "Em uso" if v > 0 else "Não detectado") + "</b></font>", "td")] for n, v in capability_items(d)]
    half = (len(cap) + 1) // 2
    story.append(_pdf_side([[T(["Capacidade", "Itens", "Situação"], cap[:half], H, [3, 1, 1.3])],
                            [T(["Capacidade", "Itens", "Situação"], cap[half:], H, [3, 1, 1.3])]], W))
    cov = [[TYPE_LABELS.get(t, t), v["total"], _pdf_cov(S, v["alarme"], v["total"]) if t in NS_BY_TYPE else "—",
            _pdf_cov(S, v["log"], v["total"]) if t in LOG_TYPES else "—", _pdf_cov(S, v["metricas"], v["total"]) if t == "Instance" else "—",
            _pdf_cov(S, v["tag"], v["total"]), ", ".join(f"{r} {n}" for r, n in v["regioes"].items())] for t, v in C.items() if t in TAG_TYPES]
    story += [P("Cobertura por tipo de recurso", "h3"),
              T(["Tipo", "Total", "Com alarme", "Com log de serviço", "Emitindo métricas", "Com tag", "Regiões"], cov, W, [2, 0.7, 1.1, 1.1, 1.1, 1.1, 2.2]),
              P("Alarme: heurística por namespace + compartment + filtro da query (resourceId/nome). Detalhe por recurso em cobertura_recursos.csv.", "small")]
    mttr = lambda k: AS[k] if AS[k] is not None else "N/D"  # noqa: E731
    story += [CondPageBreak(160), P("Alarmes e resposta", "h3"),
              _pdf_kpis(S, [("Alarmes", AS["total"]), ("Habilitados", AS["habilitados"]), ("Sem destino", AS["sem_destino"]),
                            ("FIRING há mais de 7 dias", AS["firing_ha_mais_de_7d"]), ("Mediana de resolução (min)", mttr("mttr_mediana_min")),
                            ("P90 de resolução (min)", mttr("mttr_p90_min")), ("Históricos analisados", AS["historico_analisado"]),
                            ("Históricos sem parse", AS["historico_sem_parse"])], W), Spacer(1, 6),
              _pdf_side([[P("Por severidade", "h3"), T(["Severidade", "Qtde"], dict_rows(AS["severidade"])[:15], H, [3, 1])],
                         [P("Status atual", "h3"), T(["Status", "Qtde"], dict_rows(AS["status"])[:15], H, [3, 1])]], W),
              _pdf_side([[P("Por namespace (top 15)", "h3"), T(["Namespace", "Alarmes"], dict_rows(AS["namespaces"])[:15], H, [3, 1])],
                         [P(f"Alarmes que mais dispararam ({days}d)", "h3"), T(["Alarme", "Disparos"], list(AS["top_alarmes"])[:15], H, [3, 1])]], W)]
    flows = dict(Counter(c["source"] + " → " + c["target"] for c in d["integration"]["connectors"]))
    tools = d["integration"]["ferramentas"]
    story += [_pdf_side([[P("Assinaturas ONS (protocolo · estado)", "h3"),
                          T(["Protocolo", "Estado", "Qtde"], [[p, s, n] for (p, s), n in sorted(subs_map(NT).items(), key=lambda kv: -kv[1])][:15], H, [2, 2, 1])],
                         [P("Logs por serviço de origem", "h3"),
                          T(["Serviço", "Logs habilitados"], dict_rows(dict(Counter(s["service"] for s in LG["logs"] if s["enabled"])))[:15], H, [3, 1])]], W),
              _pdf_side([[P("Service Connectors", "h3"), T(["Fluxo", "Qtde"], dict_rows(flows)[:15], H, [3, 1])],
                         [P("Integração com ferramentas externas", "h3"),
                          T(["Ferramenta", "Onde foi encontrada"], [[k.title(), ", ".join(f"{w} x{n}" for w, n in v.items())] for k, v in tools.items()][:15], H, [1, 3])
                          if tools else P("Nenhuma referência às ferramentas pesquisadas.", "small")]], W)]

    h2("12. Inventário (demais tipos)")
    other = [[t, n] for t, n in sorted(((t, v["total"]) for t, v in C.items() if t not in TAG_TYPES), key=lambda kv: -kv[1])[:40]]
    half = (len(other) + 1) // 2
    story.append(_pdf_side([[T(["Tipo", "Qtde"], other[:half], H, [3, 1])], [T(["Tipo", "Qtde"], other[half:], H, [3, 1]) if other[half:] else []]], W))

    st = list(M["coleta"].items())
    half = (len(st) + 1) // 2
    story += [PageBreak() if len(st) > 30 else CondPageBreak(150),
              KeepTogether([P("Apêndice A · Status da coleta", "h2"),
                            _pdf_side([[T(["Coletor", "Status"], [[k, v] for k, v in st[:half]], H, [2, 1])],
                                       [T(["Coletor", "Status"], [[k, v] for k, v in st[half:]], H, [2, 1])]], W),
                            P("'parcial' indica compartments/serviços sem permissão de leitura (404 NotAuthorizedOrNotFound) ou serviço não "
                              "habilitado na região; os controles dependentes podem estar subestimados.", "small")])]
    first, later = doc._waf_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


# --------------------------------------------------------------------------- #
# Apresentação PowerPoint para stakeholders · python-pptx (16:9, gráficos nativos editáveis)
# --------------------------------------------------------------------------- #


def build_pptx(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from pptx import Presentation
    from pptx.chart.data import CategoryChartData
    from pptx.dml.color import RGBColor
    from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION, XL_TICK_MARK
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
    from pptx.oxml.ns import qn
    from pptx.util import Inches, Pt

    x = report_ctx(d, checks, pil, overall)
    M, CO, SE, cur = d["meta"], x["co"], x["se"], x["cur"]
    cg = (d["global"].get("cloud_guard") or {})
    W, FONT = 13.333, "Calibri"
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(W), Inches(7.5)
    blank = prs.slide_layouts[6]
    rgb = lambda h: RGBColor.from_string(h.lstrip("#"))  # noqa: E731
    state = {"n": 0}

    def text(sl, l, t, w, h, paras, size=14, bold=False, color=HEX_TX, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, space=0):
        """paras: str | list[str | list[(texto, size, bold, cor)]]"""
        tb = sl.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))
        tf = tb.text_frame
        tf.word_wrap, tf.vertical_anchor = True, anchor
        tf.margin_left = tf.margin_right = Inches(0.04)
        tf.margin_top = tf.margin_bottom = Inches(0.02)
        for i, para in enumerate(paras if isinstance(paras, list) else [paras]):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            p.alignment = align
            if space:
                p.space_after = Pt(space)
            for seg in (para if isinstance(para, list) else [(para, size, bold, color)]):
                r = p.add_run()
                r.text = str(seg[0])
                f = r.font
                f.name, f.size, f.bold = FONT, Pt(seg[1]), seg[2]
                f.color.rgb = rgb(seg[3])
        return tb

    def box(sl, l, t, w, h, fill, line=None, rounded=False):
        s = sl.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if rounded else MSO_SHAPE.RECTANGLE, Inches(l), Inches(t), Inches(w), Inches(h))
        if rounded:
            s.adjustments[0] = 0.06
        s.fill.solid()
        s.fill.fore_color.rgb = rgb(fill)
        if line:
            s.line.color.rgb, s.line.width = rgb(line), Pt(0.75)
        else:
            s.line.fill.background()
        s.shadow.inherit = False
        return s

    def slide(title, kicker="", notes=""):
        sl = prs.slides.add_slide(blank)
        state["n"] += 1
        box(sl, 0, 0, W, 0.08, HEX_ACC)
        if kicker:
            text(sl, 0.6, 0.32, 11, 0.3, kicker.upper(), 11, True, HEX_ACC)
        text(sl, 0.6, 0.58, 12.1, 0.7, title, 28, True)
        text(sl, 0.6, 7.02, 9, 0.3, f"{customer} · Assessment OCI Well-Architected · Confidencial", 9, color=HEX_MUT)
        text(sl, W - 1.6, 7.02, 1.0, 0.3, str(state["n"]), 9, color=HEX_MUT, align=PP_ALIGN.RIGHT)
        if notes:
            sl.notes_slide.notes_text_frame.text = notes
        return sl

    def tile(sl, l, t, w, h, value, label, accent=HEX_ACC, vsize=26):
        box(sl, l, t, w, h, HEX_BG, rounded=True)
        box(sl, l, t + 0.12, 0.06, h - 0.24, accent)
        text(sl, l + 0.2, t + 0.12, w - 0.3, h * 0.55, str(value), vsize, True, accent if accent != HEX_ACC else HEX_TX, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l + 0.2, t + h * 0.6, w - 0.3, h * 0.38, label, 11, color=HEX_MUT)

    def style_chart(ch, legend=False):
        ch.font.name, ch.font.size = FONT, Pt(12)
        ch.font.color.rgb = rgb(HEX_TX)
        ch.has_title = False
        ch.has_legend = legend
        if legend:
            ch.legend.position, ch.legend.include_in_layout = XL_LEGEND_POSITION.BOTTOM, False

    def bar_chart(sl, l, t, w, h, cats, series, colors_=None, maxv=None, fmt="0", stacked=False):
        cd = CategoryChartData()
        cd.categories = cats
        for name, vals in series:
            cd.add_series(name, vals)
        ch = sl.shapes.add_chart(XL_CHART_TYPE.BAR_STACKED if stacked else XL_CHART_TYPE.BAR_CLUSTERED,
                                 Inches(l), Inches(t), Inches(w), Inches(h), cd).chart
        style_chart(ch, legend=stacked)
        plot = ch.plots[0]
        plot.gap_width = 55
        if stacked:
            plot.overlap = 100
        plot.has_data_labels = True
        dl = plot.data_labels
        dl.font.size, dl.font.bold = Pt(12), True
        dl.number_format, dl.number_format_is_linked = fmt, False
        if not stacked:
            dl.position = XL_LABEL_POSITION.OUTSIDE_END
        va = ch.value_axis
        va.minimum_scale = 0
        if maxv:
            va.maximum_scale = maxv
        va.has_major_gridlines, va.visible = False, False
        ca = ch.category_axis
        ca.reverse_order = True
        ca.major_tick_mark = XL_TICK_MARK.NONE
        ca.format.line.color.rgb = rgb(HEX_BD)
        ca.tick_labels.font.size = Pt(12)
        if stacked:
            for s, c in zip(plot.series, colors_ or []):
                s.format.fill.solid()
                s.format.fill.fore_color.rgb = rgb(c)
        else:
            for i, c in enumerate(colors_ or []):
                pt = plot.series[0].points[i]
                pt.format.fill.solid()
                pt.format.fill.fore_color.rgb = rgb(c)
        return ch

    def table(sl, l, t, w, h, headers, rows, widths, size=11, aligns=None, total_row=False):
        """Células: str | (texto, cor, negrito) | [(texto, tamanho, negrito, cor), ...] (um parágrafo por item)."""
        tb = sl.shapes.add_table(len(rows) + 1, len(headers), Inches(l), Inches(t), Inches(w), Inches(h)).table
        aligns = aligns or [PP_ALIGN.LEFT] * len(headers)
        for j, wd in enumerate(widths):
            tb.columns[j].width = Inches(w * wd / sum(widths))
        for i in range(len(rows) + 1):
            tb.rows[i].height = Inches(h / (len(rows) + 1))
        for i, r in enumerate([[(hd, "#FFFFFF", True) for hd in headers]] + rows):
            last = total_row and i == len(rows)
            for j, v in enumerate(r):
                c = tb.cell(i, j)
                c.fill.solid()
                c.fill.fore_color.rgb = rgb(HEX_TX if i == 0 else HEX_SOFT if last else HEX_BG if i % 2 == 0 else "#FFFFFF")
                c.margin_left = c.margin_right = Inches(0.07)
                c.margin_top = c.margin_bottom = Inches(0.03)
                c.vertical_anchor = MSO_ANCHOR.MIDDLE
                c.text_frame.word_wrap = True
                paras = v if isinstance(v, list) else [(v[0], size, v[2], v[1]) if isinstance(v, tuple) else (v, size, last, HEX_TX)]
                for k, (txt, sz, b, col) in enumerate(paras):
                    p = c.text_frame.paragraphs[0] if k == 0 else c.text_frame.add_paragraph()
                    p.alignment = aligns[j]
                    run = p.add_run()
                    run.text = str(txt)
                    run.font.name, run.font.size, run.font.bold = FONT, Pt(sz if i else size - 1), b
                    run.font.color.rgb = rgb(col)
        return tb

    def column_stacked(sl, l, t, w, h, cats, series, colors_, fmt="#,##0"):
        cd = CategoryChartData()
        cd.categories = cats
        for name, vals in series:
            cd.add_series(name, vals)
        ch = sl.shapes.add_chart(XL_CHART_TYPE.COLUMN_STACKED, Inches(l), Inches(t), Inches(w), Inches(h), cd).chart
        style_chart(ch, legend=True)
        ch.font.size = Pt(11)
        plot = ch.plots[0]
        plot.gap_width, plot.overlap = 60, 100
        va = ch.value_axis
        va.has_major_gridlines = True
        va.major_gridlines.format.line.color.rgb = rgb(HEX_BD)
        va.tick_labels.number_format, va.tick_labels.number_format_is_linked = fmt, False
        va.format.line.fill.background()
        ch.category_axis.major_tick_mark = XL_TICK_MARK.NONE
        ch.category_axis.format.line.color.rgb = rgb(HEX_BD)
        for s, c in zip(plot.series, colors_):
            s.format.fill.solid()
            s.format.fill.fore_color.rgb = rgb(c)
        return ch

    def doughnut(sl, l, t, size, sc):
        cd = CategoryChartData()
        cd.categories = ["Score", ""]
        cd.add_series("WAF", (sc, 100 - sc))
        ch = sl.shapes.add_chart(XL_CHART_TYPE.DOUGHNUT, Inches(l), Inches(t), Inches(size), Inches(size), cd).chart
        style_chart(ch)
        plot = ch.plots[0]
        plot.has_data_labels = False
        for i, c in enumerate((hex_score(sc), HEX_BD)):
            pt = plot.series[0].points[i]
            pt.format.fill.solid()
            pt.format.fill.fore_color.rgb = rgb(c)
            pt.format.line.fill.background()
        hs = plot._element.find(qn("c:holeSize"))
        if hs is not None:
            hs.set("val", "72")
        text(sl, l, t + size * 0.30, size, size * 0.28, str(sc), 54, True, hex_score(sc), align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l, t + size * 0.58, size, size * 0.12, "/100", 14, color=HEX_MUT, align=PP_ALIGN.CENTER)

    pils = [p for p in PILLARS if p in pil]
    ten = d["identity"]["tenancy_name"]
    plain_summary = exec_summary(d, x, b=str, e=str)

    # 1 · Capa
    sl = prs.slides.add_slide(blank)
    state["n"] += 1
    box(sl, 0, 0, W, 7.5, HEX_TX)
    box(sl, 0.8, 2.15, 1.4, 0.08, HEX_ACC)
    text(sl, 0.8, 1.6, 11, 0.4, "OCI WELL-ARCHITECTED FRAMEWORK", 14, True, HEX_ACC)
    text(sl, 0.8, 2.45, 11.5, 1.2, "Assessment de arquitetura e operação", 44, True, "#FFFFFF")
    text(sl, 0.8, 3.65, 11.5, 0.6, customer, 26, False, "#FFFFFF")
    text(sl, 0.8, 4.35, 11.5, 0.9, [f"Tenancy {ten} · Regiões: {', '.join(M['regioes'])}", f"Gerado em {M['gerado_em']} · coleta somente leitura"],
         14, color=HEX_SOFT, space=4)
    text(sl, 0.8, 6.6, 11.5, 0.4, "Apresentação para stakeholders · Confidencial", 12, color=HEX_MUT)
    sl.notes_slide.notes_text_frame.text = (f"Objetivo: apresentar o resultado do assessment do tenancy {ten} frente ao OCI Well-Architected Framework, "
                                            "os principais riscos e o plano de ação proposto, e obter as decisões necessárias.")

    # 2 · Escopo e abordagem
    sl = slide("Escopo e abordagem", "Contexto", "A coleta foi feita apenas com APIs de leitura; nenhum recurso foi alterado. "
               "Cada controle tem peso por criticidade (Alta=3, Média=2, Baixa=1).")
    text(sl, 0.6, 1.55, 6.6, 5.2, [
        [("Tenancy  ", 16, True, HEX_TX), (f"{ten} (home region {M.get('home_region', '-')})", 16, False, HEX_TX)],
        [("Regiões  ", 16, True, HEX_TX), (", ".join(M["regioes"]), 16, False, HEX_TX)],
        [("Escala  ", 16, True, HEX_TX), (f"{len(d['identity']['compartments'])} compartments · {x['n_res']} recursos principais", 16, False, HEX_TX)],
        [("Janela  ", 16, True, HEX_TX), (f"{M['days']} dias de alarmes · {CO.get('dias', '-')} dias de custos", 16, False, HEX_TX)],
        [("Coleta  ", 16, True, HEX_TX), (f"100% somente leitura via APIs OCI ({M.get('chamadas_api', '-')} chamadas)", 16, False, HEX_TX)],
        [("Método  ", 16, True, HEX_TX), (f"{len(x['evaluated'])} controles avaliados nos 5 pilares, ponderados por criticidade", 16, False, HEX_TX)],
    ], space=14)
    for i, p in enumerate(PILLARS):
        n = sum(1 for c in x["evaluated"] if c.pillar == p)
        y = 1.55 + i * 1.0
        box(sl, 7.7, y, 5.0, 0.82, HEX_BG, rounded=True)
        box(sl, 7.7, y + 0.12, 0.06, 0.58, HEX_ACC)
        text(sl, 7.95, y + 0.08, 3.6, 0.66, p, 16, True, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 11.3, y + 0.08, 1.25, 0.66, f"{n} controles", 12, color=HEX_MUT, align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)

    # 3 · Resultado geral
    sl = slide("Resultado geral", "Resumo executivo", plain_summary)
    doughnut(sl, 0.6, 1.5, 3.9, overall)
    text(sl, 0.6, 5.45, 3.9, 0.5, level(overall), 22, True, hex_score(overall), align=PP_ALIGN.CENTER)
    text(sl, 0.6, 5.95, 3.9, 0.4, "Aderência ao Well-Architected", 12, color=HEX_MUT, align=PP_ALIGN.CENTER)
    text(sl, 5.0, 1.55, 7.7, 3.2, clip(plain_summary, 720), 15, space=6)
    for i, (k, v, c) in enumerate([("Recursos principais", x["n_res"], HEX_ACC), ("Cobertura de alarmes (críticos)", f"{pct(x['cc'], x['ct'])}%", hex_score(pct(x["cc"], x["ct"]))),
                                    ("Lacunas identificadas", len(x["fails"]), HEX_ACC), ("Prioridade alta", len(x["high"]), HEX_BAD if x["high"] else HEX_OK)]):
        tile(sl, 5.0 + i * 1.97, 5.0, 1.82, 1.45, v, k, c, 24)

    # 4 · Maturidade por pilar
    worst = x["worst"][0] if x["worst"] else None
    sl = slide("Maturidade por pilar", "OCI Well-Architected Framework",
               "Score de 0 a 100 por pilar, ponderado pela criticidade dos controles. " + " · ".join(f"{p}: {pil[p]}" for p in pils))
    if pils:
        bar_chart(sl, 0.4, 1.45, 8.4, 5.3, pils, [("Score", [pil[p] for p in pils])], [hex_score(pil[p]) for p in pils], maxv=110)
    if x["best"]:
        tile(sl, 9.2, 1.6, 3.5, 1.5, f"{x['best'][1]}", f"Pilar mais forte · {x['best'][0]}", hex_score(x["best"][1]), 30)
    if worst:
        tile(sl, 9.2, 3.3, 3.5, 1.5, f"{worst[1]}", f"Pilar mais frágil · {worst[0]}", hex_score(worst[1]), 30)
    text(sl, 9.2, 5.05, 3.5, 1.7, ["Níveis de maturidade", "Inicial < 40", "Em desenvolvimento 40–64", "Estruturado 65–84", "Otimizado ≥ 85"],
         12, color=HEX_MUT, space=2)

    # 5 · Lacunas por pilar e prioridade
    sl = slide("Onde estão as lacunas", "Lacunas por pilar e prioridade",
               f"{len(x['fails'])} lacunas no total: " + ", ".join(f"{sum(1 for c in x['fails'] if c.severity == s)} {s.lower()}" for s in SEV_ORDER) + ".")
    gp = [p for p in PILLARS if any(c.pillar == p for c in x["evaluated"])]
    if gp:
        bar_chart(sl, 0.4, 1.45, 8.6, 5.4, gp, [(s, [sum(1 for c in x["fails"] if c.pillar == p and c.severity == s) for p in gp]) for s in SEV_ORDER],
                  [SEV_HEX[s] for s in SEV_ORDER], fmt="0;;;", stacked=True)
    tile(sl, 9.4, 1.6, 3.3, 1.5, len(x["fails"]), "Lacunas identificadas", HEX_ACC, 32)
    for i, s in enumerate(SEV_ORDER):
        n = sum(1 for c in x["fails"] if c.severity == s)
        tile(sl, 9.4, 3.3 + i * 1.18, 3.3, 1.05, n, f"Prioridade {s.lower()}", SEV_HEX[s], 20)

    # 6 · Principais riscos
    top = x["high"] or x["fails"]
    sl = slide("Principais riscos para o negócio", f"{len(x['high'])} lacunas de prioridade alta",
               "\n".join(f"- {c.title}: {c.impact} Recomendação: {c.recommendation}" for c in top[:6]))
    for i, c in enumerate(top[:6]):
        col, row = i % 2, i // 2
        l, t = 0.6 + col * 6.15, 1.45 + row * 1.74
        box(sl, l, t, 5.95, 1.62, HEX_BG, rounded=True)
        box(sl, l, t + 0.15, 0.06, 1.32, SEV_HEX[c.severity])
        text(sl, l + 0.22, t + 0.08, 5.6, 1.5, [[(c.pillar.upper(), 10, True, SEV_HEX[c.severity])], [(clip(c.title, 75), 15, True, HEX_TX)],
                                                 [(clip(c.impact, 130), 11, False, HEX_MUT)],
                                                 [("Ação: ", 11, True, HEX_TX), (clip(c.recommendation, 150), 11, False, HEX_TX)]], space=2)
    if len(top) > 6:
        rest = len(top) - 6
        text(sl, 0.6, 6.68, 12, 0.3, f"+{rest} {'item' if rest == 1 else 'itens'} no relatório técnico e no backlog (achados.csv).", 11, color=HEX_MUT)
    if not top:
        text(sl, 0.6, 1.6, 12, 1, "Nenhuma lacuna identificada nos controles avaliados.", 18)

    # 7 · Custos: tendência mensal na janela (padrão 90 dias)
    if CO.get("total"):
        dias, avg, var = CO.get("dias"), cost_monthly_avg(CO), CO.get("variacao_mes_pct")
        pm = CO.get("por_mes") or {}
        sm = CO.get("servico_por_mes") or {}
        sl = slide(f"Custos dos últimos {dias} dias", "Desempenho e custos",
                   f"Custo total de {money_fmt(CO['total'], cur)} em {dias} dias (média de {money_fmt(avg, cur)} por mês). "
                   + ("Por mês: " + "; ".join(f"{mes_label(k, CO)} {money_fmt(v, cur, 0)}" for k, v in pm.items()) + ". " if pm else "")
                   + "Principais serviços: " + ", ".join(f"{k} ({money_fmt(v, cur, 0)})" for k, v in CO.get("por_servico", [])[:5]) + ".")
        full = [k for k in pm if k in CO.get("meses_completos", list(pm))]
        tiles_ = [(money_fmt(CO["total"], cur, 0), f"Custo total · {dias} dias", HEX_ACC), (money_fmt(avg, cur, 0), "Média mensal", HEX_ACC),
                  ("N/D" if var is None else f"{var:+d}%", f"Variação {mes_label(full[-1], CO)} vs {mes_label(full[-2], CO)}" if len(full) >= 2 else "Variação mês a mês",
                   HEX_MUT if var is None else HEX_BAD if var > 0 else HEX_OK),
                  (money_fmt(CO.get("projecao_mes"), cur, 0), "Projeção do mês atual", HEX_ACC)]
        for i, (v, k, c) in enumerate(tiles_):
            tile(sl, 0.6, 1.45 + i * 1.33, 3.6, 1.2, v, k, c, 22)
        if sm:
            top_s = [k for k, _ in CO.get("por_servico", [])[:5]]
            ser = [(s, [round((sm.get(m) or {}).get(s, 0)) for m in pm]) for s in top_s]
            ser.append(("Outros", [round(sum(v for k, v in (sm.get(m) or {}).items() if k not in top_s)) for m in pm]))
            text(sl, 4.6, 1.4, 8, 0.35, f"Custo por mês e serviço ({cur})", 13, True, HEX_MUT)
            column_stacked(sl, 4.5, 1.75, 8.3, 4.75, [mes_label(k, CO) for k in pm], ser,
                           [HEX_ACC, "#1F6FB2", "#12805C", "#B54708", "#6E56CF", HEX_SOFT])
        else:  # dados.json de versões anteriores (sem quebra mensal)
            svc = CO.get("por_servico", [])[:8]
            text(sl, 4.6, 1.4, 8, 0.35, f"Maiores serviços ({cur})", 13, True, HEX_MUT)
            bar_chart(sl, 4.5, 1.75, 8.3, 4.75, [clip(k, 30) for k, _ in svc], [("Custo", [round(v or 0) for _, v in svc])], [HEX_ACC] * len(svc), fmt="#,##0")
        if partial_note(CO):
            text(sl, 4.6, 6.6, 8.2, 0.3, partial_note(CO), 10, color=HEX_MUT)

    # 7b · Recursos que mais consumiram
    top_r = [r for r in CO.get("top_recursos", []) if r.get("total")][:10]
    if top_r:
        meses = list(CO.get("por_mes") or {})
        soma = sum(r["total"] for r in top_r)
        sl = slide("Recursos que mais consumiram", f"Top 10 · {CO.get('dias')} dias",
                   f"Os 10 recursos de maior custo somam {money_fmt(soma, cur)} ({pct(soma, CO['total'])}% do total do período). "
                   + "; ".join(f"{r.get('nome')}: {money_fmt(r['total'], cur, 0)}" for r in top_r))
        rows = [[[(clip(r.get("nome", r["id"]), 44), 11, True, HEX_TX), (clip(f"{r.get('tipo', r['servico'])} · {r.get('compartment', '—')}", 60), 9, False, HEX_MUT)],
                 clip(r["servico"], 22)] + [money_fmt(r["meses"].get(m), cur, 0) if r["meses"].get(m) else "—" for m in meses]
                + [(money_fmt(r["total"], cur, 0), HEX_TX, True), f"{pct(r['total'], CO['total'])}%"] for r in top_r]
        R = PP_ALIGN.RIGHT
        table(sl, 0.6, 1.45, 12.1, 5.0, ["Recurso", "Serviço"] + [mes_label(m, CO) for m in meses] + ["Total", "% do total"], rows,
              [4.2, 1.8] + [1.25] * len(meses) + [1.4, 0.9], 11, [PP_ALIGN.LEFT, PP_ALIGN.LEFT] + [R] * (len(meses) + 2))
        text(sl, 0.6, 6.6, 12, 0.3, (partial_note(CO) + "  " if partial_note(CO) else "") + "Lista completa em custos_por_recurso.csv.", 10, color=HEX_MUT)

    # 7c · DE/PARA de economia (custo real dos recursos apontados x custo após a ação)
    dp = CO.get("de_para")
    if dp:
        de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
        eco, avg = de - para, cost_monthly_avg(CO)
        sl = slide("DE/PARA de economia", "Oportunidades de otimização",
                   f"Base: custo real faturado nos últimos 30 dias dos recursos apontados. Economia estimada de {money_fmt(eco, cur)} por mês "
                   f"({money_fmt(eco * 12, cur)} por ano). " + "; ".join(f"{r['categoria']}: {money_fmt(r['economia_mes'], cur)}/mês" for r in dp))
        for i, (v, k, c) in enumerate([(money_fmt(de, cur, 0), "DE · custo atual/mês dos recursos apontados", HEX_TX),
                                       (money_fmt(para, cur, 0), "PARA · custo/mês após as ações", HEX_ACC),
                                       (money_fmt(eco, cur, 0), "Economia mensal" + (f" · {pct(eco, avg)}% da fatura" if avg else ""), HEX_OK),
                                       (money_fmt(eco * 12, cur, 0), "Economia anual estimada", HEX_OK)]):
            tile(sl, 0.6 + i * 3.06, 1.4, 2.9, 1.15, v, k, c, 20)
        R = PP_ALIGN.RIGHT
        rows = [[[(r["categoria"], 11, True, HEX_TX), (r["acao"], 9, False, HEX_MUT)], f"{r['recursos']}", f"{r['premissa_pct']}%",
                 money_fmt(r["de"], cur, 0), money_fmt(r["para"], cur, 0), (money_fmt(r["economia_mes"], cur, 0), HEX_OK, True),
                 money_fmt(r["economia_ano"], cur, 0)] for r in dp]
        rows.append(["Total", f"{sum(r['recursos'] for r in dp)}", "", money_fmt(de, cur, 0), money_fmt(para, cur, 0),
                     (money_fmt(eco, cur, 0), HEX_OK, True), money_fmt(eco * 12, cur, 0)])
        table(sl, 0.6, 2.75, 12.1, min(3.7, 0.45 * (len(rows) + 1)), ["Categoria · ação", "Recursos", "Redução", "DE (mês)", "PARA (mês)", "Economia/mês", "Economia/ano"],
              rows, [4.0, 1.0, 1.0, 1.5, 1.5, 1.55, 1.55], 11, [PP_ALIGN.LEFT, R, R, R, R, R, R], total_row=True)
        sem = sum(r["recursos"] - r["com_custo"] for r in dp)
        text(sl, 0.6, 6.5, 12.1, 0.45, "DE = custo real (Usage API) dos últimos 30 dias dos recursos apontados. PARA = custo após a ação, com a redução "
             "indicada por categoria (premissa ajustável em SAVINGS_RULES). Cada recurso é contado uma vez."
             + (f" {sem} recurso(s) sem custo no faturamento (ex.: IPs, itens gratuitos)." if sem else ""), 9, color=HEX_MUT)
    elif CO.get("oportunidades"):
        log("DE/PARA de economia omitido: dados.json sem custo por recurso (gerado por versão anterior); rode uma nova coleta")

    # 8 · Segurança: indicadores + ações com ganho de score
    acts = score_actions(checks, P_SEC)
    pil_sec = pil.get(P_SEC)
    sl = slide("Postura de segurança", P_SEC,
               "Ações ordenadas pelo ganho no score global: " + "; ".join(
                   f"{a['check'].title}: segurança {a['pilar_de']}→{a['pilar_para']}, global {a['global_de']}→{a['global_para']}" for a in acts)
               if acts else "Sem lacunas no pilar.")
    if pil_sec is not None:
        text(sl, 9.0, 0.62, 3.7, 0.6, f"Score do pilar: {pil_sec}", 18, True, hex_score(pil_sec), align=PP_ALIGN.RIGHT)
    nomfa, rr, pub, pol = SE.get("usuarios_sem_mfa", 0), len(SE.get("regras_abertas", [])), len(SE.get("buckets_publicos", [])), len(SE.get("policies_amplas", []))
    cgs = cg.get("status", "N/D")
    tiles_ = [(f"{nomfa} de {SE.get('usuarios_console', 0)}", "Console sem MFA", HEX_BAD if nomfa else HEX_OK),
              (rr, "Regras 0.0.0.0/0", HEX_BAD if rr else HEX_OK), (pub, "Buckets públicos", HEX_BAD if pub else HEX_OK),
              (pol, "Policies amplas", HEX_WARN if pol else HEX_OK), (cgs, "Cloud Guard", HEX_OK if cgs == "ENABLED" else HEX_BAD if cg else HEX_MUT),
              (SE.get("security_zones", 0), "Security Zones", HEX_OK if SE.get("security_zones") else HEX_WARN)]
    for i, (v, k, c) in enumerate(tiles_):
        tile(sl, 0.6 + i * 2.03, 1.4, 1.93, 1.0, v, k, c, 18)
    if acts:
        def gain(a, b):
            return (f"{a} → {b}" + (f"  (+{b - a})" if b > a else ""), HEX_OK if b > a else HEX_MUT, b > a)
        shown = acts[:5]
        rows = [[f"{i}", [(clip(a["check"].title, 70), 12, True, HEX_TX), (clip(a["check"].recommendation, 115), 10, False, HEX_MUT)],
                 (a["check"].severity, SEV_HEX[a["check"].severity], True), gain(a["pilar_de"], a["pilar_para"]), gain(a["global_de"], a["global_para"]),
                 (f"{a['global_acum']}", hex_score(a["global_acum"]), True)] for i, a in enumerate(shown, 1)]
        C_ = PP_ALIGN.CENTER
        text(sl, 0.6, 2.55, 12, 0.35, "Ações para elevar o score (ganho se apenas esta ação for resolvida)", 13, True, HEX_MUT)
        table(sl, 0.6, 2.92, 12.1, min(3.45, 0.62 * (len(rows) + 1)), ["#", "Ação recomendada", "Prioridade", "Score segurança", "Score global", "Global acumulado"],
              rows, [0.35, 6.1, 1.1, 1.55, 1.55, 1.45], 11, [C_, PP_ALIGN.LEFT, C_, C_, C_, C_])
        last = acts[-1]
        text(sl, 0.6, 6.45, 12.1, 0.45, [[("Resolvendo as " + str(len(acts)) + " lacunas de segurança: ", 12, True, HEX_TX),
                                          (f"pilar {acts[0]['pilar_de']} → {last['pilar_acum']} · score global {acts[0]['global_de']} → {last['global_acum']}", 12, True, HEX_OK),
                                          (("   ·  +" + str(len(acts) - len(shown)) + " ações no relatório técnico") if len(acts) > len(shown) else "", 10, False, HEX_MUT)]])
    else:
        text(sl, 0.6, 2.7, 12, 0.6, "Nenhuma lacuna no pilar de segurança nos controles avaliados.", 16)

    # 9 · Roadmap
    sl = slide("Roadmap sugerido", "Plano 30 · 60 · 90 dias",
               " | ".join(f"{label}: {sum(1 for c in x['fails'] if c.severity == s)} itens de prioridade {s.lower()}" for s, label in ROADMAP))
    for i, (sev, label) in enumerate(ROADMAP):
        items = [c for c in x["fails"] if c.severity == sev]
        l = 0.6 + i * 4.1
        box(sl, l, 1.5, 3.9, 0.75, SEV_HEX[sev], rounded=True)
        text(sl, l + 0.15, 1.53, 3.6, 0.7, [[(label, 18, True, "#FFFFFF")], [(f"Prioridade {sev.lower()} · {len(items)} itens", 11, False, "#FFFFFF")]],
             anchor=MSO_ANCHOR.MIDDLE)
        box(sl, l, 2.35, 3.9, 4.45, HEX_BG, rounded=True)
        lines = [[("•  ", 12, True, SEV_HEX[sev]), (clip(c.title, 52), 12, False, HEX_TX)] for c in items[:11]]
        if len(items) > 11:
            lines.append([(f"+{len(items) - 11} {'item' if len(items) == 12 else 'itens'} no relatório técnico", 11, True, HEX_MUT)])
        text(sl, l + 0.15, 2.5, 3.6, 4.2, lines or "Nenhum item.", 12, color=HEX_MUT, space=5)

    # 10 · Pontos fortes
    sl = slide("Pontos fortes", f"{len(x['oks'])} controles atendidos", "\n".join(f"- {c.title}: {c.evidence}" for c in x["oks"][:12]))
    oks = x["oks"][:12]
    for i, c in enumerate(oks):
        l, t = 0.6 + (i // 6) * 6.15, 1.5 + (i % 6) * 0.86
        text(sl, l, t, 0.4, 0.4, "✓", 18, True, HEX_OK)
        text(sl, l + 0.42, t, 5.5, 0.8, [[(clip(c.title, 62), 15, True, HEX_TX)], [(f"{c.pillar} · {clip(c.evidence, 70)}", 11, False, HEX_MUT)]])
    if len(x["oks"]) > 12:
        text(sl, 0.6, 6.68, 12, 0.3, f"+{len(x['oks']) - 12} controles atendidos no relatório técnico.", 11, color=HEX_MUT)
    if not oks:
        text(sl, 0.6, 1.6, 12, 1, "Nenhum controle atendido integralmente.", 18)

    # 11 · Próximos passos
    nl = next_level(overall)
    steps = [("Validar achados", "Confirmar evidências e priorização com plataforma, segurança, operações e FinOps."),
             ("Designar responsáveis", f"Owners e datas para as {len(x['high'])} lacunas de prioridade alta (0–30 dias)."),
             ("Aprovar o roadmap", "Patrocínio e capacidade para o plano 30/60/90 (baseline Terraform / OCI Landing Zone).")]
    if CO.get("oportunidades"):
        steps.append(("Capturar economia", f"Tratar as {len(CO['oportunidades'])} oportunidades de custo mapeadas."))
    steps.append(("Medir a evolução", "Reexecutar o assessment em 90 dias" + (f" · meta: {nl[0]} (score ≥ {nl[1]})." if nl else " · manter o nível Otimizado.")))
    sl = slide("Próximos passos e decisões", "Encaminhamentos", "Decisões solicitadas: aprovação do roadmap, designação de responsáveis e cadência de acompanhamento.")
    for i, (h, t_) in enumerate(steps):
        y = 1.5 + i * 1.05
        box(sl, 0.6, y, 0.75, 0.75, HEX_ACC, rounded=True)
        text(sl, 0.6, y, 0.75, 0.75, str(i + 1), 22, True, "#FFFFFF", align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 1.6, y - 0.02, 6.6, 0.85, [[(h, 17, True, HEX_TX)], [(t_, 13, False, HEX_MUT)]], anchor=MSO_ANCHOR.MIDDLE)
    box(sl, 8.7, 1.5, 4.0, 4.95, HEX_TX, rounded=True)
    text(sl, 8.95, 1.7, 3.5, 4.6, [[("Decisões solicitadas", 18, True, "#FFFFFF")], [("", 8, False, HEX_SOFT)],
                                   [("•  Aprovar o roadmap 30/60/90", 14, False, HEX_SOFT)], [("•  Nomear responsáveis por pilar", 14, False, HEX_SOFT)],
                                   [("•  Definir cadência de acompanhamento (quinzenal)", 14, False, HEX_SOFT)],
                                   [("•  Agendar reavaliação em 90 dias", 14, False, HEX_SOFT)]], space=8)

    prs.core_properties.title = f"Assessment OCI Well-Architected - {customer}"
    prs.core_properties.author = "oci_assessment.py"
    prs.save(str(path))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


EXTRA_OUTPUTS = {"pdf": [("relatorio_executivo.pdf", build_pdf_exec), ("relatorio_tecnico.pdf", build_pdf_tech)],
                 "pptx": [("apresentacao_stakeholders.pptx", build_pptx)]}


def render_extras(d: dict, checks: list[Check], dom: dict, pil: dict, overall: int, out: Path, customer: str, formats: list[str]) -> None:
    """PDF/PPTX são opcionais: falta de biblioteca ou erro de render não interrompe as demais saídas."""
    for fmt in formats:
        for name, fn in EXTRA_OUTPUTS.get(fmt, []):
            try:
                fn(d, checks, dom, pil, overall, customer, out / name)
                log(f"gerado {name}")
            except ImportError as e:
                log(f"{name} não gerado: módulo '{e.name}' ausente; instale com: pip install --user reportlab python-pptx")
            except Exception as e:  # noqa: BLE001
                log(f"falha ao gerar {name}: {e!r}")


def finalize(d: dict, out: Path, customer: str, formats: list[str] | None = None) -> int:
    checks = evaluate(d)
    dom, overall = score(checks)
    pil, _ = score(checks, "pillar")
    pil = {p: pil[p] for p in PILLARS if p in pil}
    d["checks"], d["scores"], d["scores_pilar"], d["score_global"] = [asdict(x) for x in checks], dom, pil, overall
    out.mkdir(parents=True, exist_ok=True)
    (out / "dados.json").write_text(json.dumps(d, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (out / "relatorio.html").write_text(build_report(d, checks, dom, pil, overall, customer), encoding="utf-8")
    with (out / "achados.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Prioridade", "Pilar WAF", "Domínio", "Lacuna", "Evidência", "Impacto", "Recomendação"])
        for x in sorted((x for x in checks if x.passed is False), key=lambda x: SEV_ORDER[x.severity]):
            w.writerow([x.severity, x.pillar, x.domain, x.title, x.evidence, x.impact, x.recommendation])
    paths = {c["id"]: c["path"] for c in d["identity"]["compartments"]}
    yn = {True: "sim", False: "NÃO", None: "n/a"}
    with (out / "cobertura_recursos.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Região", "Compartment", "Tipo", "Nome", "OCID", "Alarme", "Log de serviço", "Emitindo métricas", "Tag"])
        for r in sorted(d["inventory"]["resources"], key=lambda r: (r["type"] not in CRITICAL_TYPES, r["type"], r["region"])):
            if r["type"] in TAG_TYPES:
                w.writerow([r["region"], paths.get(r["comp"], r["comp"]), TYPE_LABELS.get(r["type"], r["type"]), r["name"], r["id"],
                            yn[r["alarme"]], yn[r["log"]], yn[r["metricas"]], yn[r["tagged"]]])
    with (out / "otimizacao_custos.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Categoria", "Tipo", "Recurso", "Região", "Compartment", "Detalhe", "Custo real 30d", "Economia estimada/mês", "OCIDs"])
        for o in (d.get("cost") or {}).get("oportunidades", []):
            w.writerow([o["categoria"], o["tipo"], o["nome"], o["regiao"], o["compartment"], o["detalhe"], o.get("custo_30d", ""),
                        o.get("economia_mes", ""), " ".join(o.get("ids", []))])
    CO = d.get("cost") or {}
    if CO.get("top_recursos"):
        meses = list(CO.get("por_mes") or {})
        with (out / "custos_por_recurso.csv").open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["Recurso", "Tipo", "Serviço", "Compartment", "OCID"] + [mes_label(m, CO) for m in meses] + [f"Total {CO.get('dias')}d", "Moeda"])
            for r in CO["top_recursos"]:
                w.writerow([r.get("nome", ""), r.get("tipo", ""), r["servico"], r.get("compartment", ""), r["id"]]
                           + [r["meses"].get(m, 0) for m in meses] + [r["total"], CO.get("moeda", "")])
    render_extras(d, checks, dom, pil, overall, out, customer, list(EXTRA_OUTPUTS) if formats is None else formats)
    log("Pilares: " + " · ".join(f"{k} {v}" for k, v in pil.items()))
    log(f"Concluído: score {overall}/100 · {d['meta'].get('chamadas_api', 0)} chamadas de leitura · saída em {out.resolve()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Assessment read-only de observabilidade OCI")
    ap.add_argument("--auth", choices=["auto", "cloudshell", "config", "instance_principal"], default="auto")
    ap.add_argument("--config-file", default=None)
    ap.add_argument("--profile", default=os.getenv("OCI_CLI_PROFILE", "DEFAULT"))
    ap.add_argument("--customer", default="Assaí Atacadista")
    ap.add_argument("--regions", default=None, help="Regiões separadas por vírgula (padrão: todas as subscritas)")
    ap.add_argument("--compartments", default=None, help="Nomes/OCIDs de compartments (inclui subárvore). Padrão: todos")
    ap.add_argument("--days", type=int, default=30, help="Janela do histórico de alarmes (máx. 90)")
    ap.add_argument("--max-alarm-history", type=int, default=500, help="Máximo de alarmes com histórico analisado")
    ap.add_argument("--expected-tools", default="dynatrace", help="Ferramentas externas esperadas (ex.: dynatrace,grafana)")
    ap.add_argument("--scan-keywords", default="dynatrace,grafana,zabbix,datadog,splunk,newrelic,elastic,prometheus")
    ap.add_argument("--cost-days", type=int, default=90, help="Janela de custos em dias (Usage API, consultada mês a mês)")
    ap.add_argument("--max-backup-checks", type=int, default=3000, help="Máximo de volumes com política de backup verificada")
    ap.add_argument("--expected-clouds", default="azure", help="Clouds com interconexão esperada (ex.: azure)")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--out", default=None)
    ap.add_argument("--render-only", default=None, help="Regera relatório/achados a partir de um dados.json existente")
    ap.add_argument("--formats", default="pdf,pptx",
                    help="Saídas adicionais ao HTML/CSV/JSON: pdf (executivo + técnico), pptx (stakeholders). Use 'none' para nenhuma")
    a = ap.parse_args()
    formats = [f.strip().lower() for f in a.formats.split(",") if f.strip() and f.strip().lower() != "none"]
    if bad := [f for f in formats if f not in EXTRA_OUTPUTS]:
        ap.error(f"--formats inválido: {', '.join(bad)} (opções: {', '.join(EXTRA_OUTPUTS)}, none)")

    if a.render_only:
        jf = Path(a.render_only)
        d = json.loads(jf.read_text(encoding="utf-8"))
        return finalize(d, Path(a.out) if a.out else jf.parent, a.customer, formats)

    if oci is None:
        ap.error("instale o SDK: pip install oci")
    days = max(1, min(a.days, 90))
    cfg, signer, ten, mode = make_auth(a)
    F, E = Factory(cfg, signer), Errors()
    home_guess = cfg.get("region")
    log(f"auth={mode} · tenancy={ten[:30]}…")

    idc = F(oci.identity.IdentityClient, home_guess)
    subs = idc.list_region_subscriptions(ten).data  # falha aqui = sem acesso; aborta
    home = next((r.region_name for r in subs if r.is_home_region), home_guess)
    log("coletando identity/compartments...")
    ident = collect_identity(F, E, home, ten, [x for x in (a.compartments or "").split(",") if x.strip()])
    ready = [r["name"] for r in ident["regions"] if r["status"] == "READY"]
    regions = [r.strip() for r in a.regions.split(",")] if a.regions else ready
    comps = ident["compartments"]
    comp_ids = {c["id"] for c in comps}
    log(f"{len(comps)} compartments · regiões: {', '.join(regions)}")

    d: dict[str, Any] = {"meta": {"days": days, "coleta": {}, "gerado_em": datetime.now().strftime("%d/%m/%Y %H:%M"), "regioes": regions,
                                  "home_region": home, "auth": mode, "expected_clouds": [x.strip().lower() for x in a.expected_clouds.split(",") if x.strip()],
                                  "expected_tools": [x.strip().lower() for x in a.expected_tools.split(",") if x.strip()]},
                         "identity": ident}
    res, alarms, status, nss, emitting, hist_targets = [], [], [], set(), set(), []
    logs = {"log_groups": 0, "logs": [], "unified_agent": {"total": 0, "ativas": 0}}
    per: list[dict] = []
    ext: list[dict] = []
    util: dict[str, dict] = {"cpu": {}, "mem": {}}
    regional: dict[str, dict] = {}
    for rg in regions:
        log(f"[{rg}] inventário (Resource Search)...")
        res += collect_inventory(F, E, rg, comp_ids)
        log(f"[{rg}] alarmes e métricas...")
        m = collect_monitoring(F, E, rg, ten, comp_ids)
        alarms += m["alarms"]
        status += m["status"]
        nss |= set(m["namespaces"])
        emitting |= set(m["compute_emitting"])
        log(f"[{rg}] logging...")
        lg = collect_logging(F, E, rg, ten, comp_ids, a.threads)
        logs["log_groups"] += lg["log_groups"]
        logs["logs"] += lg["logs"]
        for k in ("total", "ativas"):
            logs["unified_agent"][k] += lg["unified_agent"][k]
        log(f"[{rg}] notificações, eventos, connectors, APM, compute ({len(comps)} compartments)...")
        pr = pmap(lambda c, rg=rg: collect_per_compartment(F, E, rg, c["id"]), comps, a.threads)
        per += pr
        apm_d = [x for p in pr for x in p["apm_domains"]]
        log(f"[{rg}] WAF: volumes, rede, bancos, buckets, vault, conectividade...")
        idr = F(oci.identity.IdentityClient, rg)
        ads = [x.name for x in (E.run("identity", lambda: idr.list_availability_domains(ten).data, []) or [])]
        osn = E.run("object_storage", lambda: F(oci.object_storage.ObjectStorageClient, rg).get_namespace().data)
        ext += pmap(lambda c, rg=rg: collect_waf_compartment(F, E, rg, c["id"], osn, ads), comps, a.threads)
        log(f"[{rg}] utilização de compute (14d)...")
        u = collect_utilization(F, E, rg, ten)
        util["cpu"].update(u["cpu"])
        util["mem"].update(u["mem"])
        log(f"[{rg}] Log Analytics, Ops Insights, Synthetics...")
        regional[rg] = collect_regional_services(F, E, rg, ten, apm_d)
        regional[rg]["apm_domains"] = len(apm_d)

    since = datetime.now(timezone.utc) - timedelta(days=days)
    hist_targets = [x for x in alarms if x["enabled"]][: a.max_alarm_history]
    log(f"histórico de {len(hist_targets)} alarmes ({days}d)...")
    hist = pmap(lambda x: collect_alarm_history(F, E, x, since), hist_targets, a.threads)
    log("serviços globais (Audit, Cloud Guard, Budgets, Health Checks, IAM)...")
    gl = collect_global(F, E, home, ten, comps, days, a.threads)
    gw = collect_global_waf(F, E, home, ten, ident.pop("_tag_ns_ids", []), (gl.get("cloud_guard") or {}).get("reporting_region"))
    vols = [v for e in ext for v in e.get("volumes", [])][: a.max_backup_checks]
    log(f"política de backup de {len(vols)} volumes...")
    backups = collect_backup_policies(F, E, vols, a.threads)
    log(f"custos ({a.cost_days}d por mês, serviço e recurso, Usage API)...")
    cost = collect_cost(F, E, home, ten, a.cost_days)

    subs_c = Counter(s for p in per for s in p["subs"])
    inst = [i for p in per for i in p["instances"]]
    d.update({
        "inventory": {"resources": res, "por_tipo": dict(Counter(r["type"] for r in res).most_common())},
        "monitoring": {"alarms": alarms, "status": status, "namespaces": sorted(nss), "compute_emitting": sorted(emitting)},
        "logging": logs,
        "notifications": {"topicos": sum(p["topics"] for p in per), "assinaturas": {f"{k[0]}|{k[1]}": v for k, v in subs_c.items()},
                          "regras_eventos": [r for p in per for r in p["rules"]]},
        "integration": {"connectors": [c for p in per for c in p["connectors"]]},
        "apm": {"dominios": sum(len(p["apm_domains"]) for p in per)},
        "stack_monitoring": {"total": sum(len(p["stack_mon"]) for p in per), "tipos": dict(Counter(t for p in per for t in p["stack_mon"]))},
        "_instances": inst,
        "compute": {"total": sum(1 for i in inst if i["state"] == "RUNNING"), "paradas": sum(1 for i in inst if i["state"] == "STOPPED"),
                    "emitindo": sum(1 for i in inst if i["state"] == "RUNNING" and i["id"] in emitting),
                    "monitoring_desabilitado": sum(1 for i in inst if i["state"] == "RUNNING" and (i["monitoring_disabled"] or i["all_plugins_disabled"] or i["monitoring_plugin"] == "DISABLED")),
                    "custom_logs_plugin_ativo": sum(1 for i in inst if i["custom_logs_plugin"] == "ENABLED")},
        "regional": regional,
        "global": {k: v for k, v in gl.items() if not k.startswith("_")},
        "_identity_scan": {"policies": gl["_policies"], "groups": gl["_groups"], "dyn_groups": gl["_dyn_groups"]},
    })
    d["integration"]["ferramentas"] = detect_tools(d, [k.strip().lower() for k in a.scan_keywords.split(",") if k.strip()])
    compute_coverage(d)
    summarize_alarms(d, hist)
    build_waf(d, ext, backups, util, gw, gl["_policies"], cost)
    d.pop("_instances", None)
    keys = ["identity", "inventory", "alarms", "alarms_status", "metrics", "alarm_history", "logging", "unified_agent", "notifications", "events",
            "service_connectors", "apm", "apm_synthetics", "stack_monitoring", "compute", "log_analytics", "ops_insights", "audit", "cloud_guard",
            "budgets", "health_checks", "policies", "users", "security_zones", "cost_tags", "block_volumes", "attachments", "backup_policy",
            "public_ips", "security_lists", "nsg", "fastconnect", "vpn", "drg", "vault", "bastion", "vulnerability_scanning", "autoscaling",
            "databases", "mysql", "object_storage", "utilization", "cost"]
    d["meta"]["coleta"] = {k: E.status(k) for k in keys}
    d["meta"]["chamadas_api"] = F.stats["calls"]
    out = Path(a.out or f"oci-assessment-{datetime.now():%Y%m%d-%H%M}")
    return finalize(d, out, a.customer, formats)


if __name__ == "__main__":
    sys.exit(main())