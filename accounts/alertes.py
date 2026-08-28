"""Moteur alertes, décisions & règles métier (Sprint 6, S 6-02 → S 6-04).

RM-22 — Informer → Avertir → Décider → Tracer :
    1. Une opération (sortie) est évaluée contre les règles actives du
       business (RM-07). Chaque règle déclenchée émet une ALERTE persistée
       (« Avertir ») : le problème reste visible après toute décision.
    2. Une règle BLOCAGE est obligatoire : la demande est refusée, aucun
       contournement possible (S 6-05 « blocage obligatoire »).
    3. Une règle AVERTISSEMENT peut être dépassée (« Décider ») par un
       utilisateur autorisé (permission stock.exception, RM-19) — la
       décision est tracée (« Tracer », RM-06) : qui, quand, quoi, combien,
       pourquoi (motif obligatoire).

RM-05 : l'entretien n'interdit pas automatiquement l'utilisation : chaque
business choisit le mode de ses règles (avertir ou bloquer).
"""

from .activite import Act, log_activity, notify_members
from .fiabilite import a_verifier
from .maintenance import etat_entretien
from .models import Alert, BusinessRule, DecisionLog
from .rbac import Perm


DEFAULT_RULES = {
    BusinessRule.Code.ARTICLE_EN_ENTRETIEN: BusinessRule.Mode.AVERTISSEMENT,
    BusinessRule.Code.ENTRETIEN_PARTIEL: BusinessRule.Mode.AVERTISSEMENT,
    BusinessRule.Code.ARTICLE_A_VERIFIER: BusinessRule.Mode.AVERTISSEMENT,
}

RULES_LIBELLES = {
    BusinessRule.Code.ARTICLE_EN_ENTRETIEN: "Sortir un article en entretien",
    BusinessRule.Code.ENTRETIEN_PARTIEL: "Sortir un article à l'entretien partiel",
    BusinessRule.Code.ARTICLE_A_VERIFIER: "Sortir un article à vérifier",
}

RULES_MESSAGES = {
    BusinessRule.Code.ARTICLE_EN_ENTRETIEN: "L'article est en entretien.",
    BusinessRule.Code.ENTRETIEN_PARTIEL: "L'article a un entretien partiel.",
    BusinessRule.Code.ARTICLE_A_VERIFIER: (
        "Les données de stock de l'article sont à vérifier (dernier comptage non certain)."
    ),
}


def seed_business_rules(business):
    """Crée les règles par défaut (RM-07) — appelé à la création du business."""
    for code, mode in DEFAULT_RULES.items():
        BusinessRule.objects.get_or_create(
            business=business, code=code, defaults={"mode": mode, "est_actif": True}
        )
    return list(business.rules.all())


def get_default_rule_payloads():
    """Règles par défaut pour la migration de re-seed des business existants."""
    return [
        {
            "code": code.value,
            "mode": mode.value,
            "libelle": RULES_LIBELLES[code].capitalize(),
            "message": RULES_MESSAGES[code],
        }
        for code, mode in DEFAULT_RULES.items()
    ]


def _triggered(item, rule, etat):
    if rule.code == BusinessRule.Code.ARTICLE_EN_ENTRETIEN:
        return etat["code"] == "EN_ENTRETIEN"
    if rule.code == BusinessRule.Code.ENTRETIEN_PARTIEL:
        return etat["code"] == "PARTIEL"
    if rule.code == BusinessRule.Code.ARTICLE_A_VERIFIER:
        return a_verifier(item)
    return False


def check_rules(*, business, item, acteur, quantite=None, mouvement=None):
    """Évalue les règles actives du business pour une opération (RM-22).

    Chaque règle déclenchée est persistée comme alerte et renvoyée avec son
    mode : AVERTISSEMENT (contournable avec permission + décision) ou
    BLOCAGE (obligatoire — la demande sera refusée par l'appelant).
    """
    etat = etat_entretien(item)
    violations = []
    for rule in business.rules.filter(est_actif=True).order_by("code"):
        if not _triggered(item, rule, etat):
            continue
        alert = Alert.objects.create(
            business=business,
            item=item,
            rule=rule,
            code=rule.code,
            mode=rule.mode,
            message=RULES_MESSAGES[rule.code],
            quantite=quantite,
            mouvement=mouvement,
            acteur=acteur,
        )
        violations.append(
            {
                "code": alert.code,
                "mode": alert.mode,
                "message": alert.message,
                "alert_id": alert.id,
            }
        )
    return violations


def record_decision(
    *, business, item, rule, acteur, motif, quantite=None, mouvement=None, code=None
):
    """Trace une décision exceptionnelle (RM-06) : qui, quand, quoi, combien, pourquoi."""
    if motif is None or not str(motif).strip():
        raise ValueError("Un motif est obligatoire pour tracer une décision.")
    decision = DecisionLog.objects.create(
        business=business,
        item=item,
        rule=rule,
        code=code or rule.code,
        motif=str(motif).strip(),
        quantite=quantite,
        mouvement=mouvement,
        acteur=acteur,
    )
    log_activity(
        business=business,
        acteur=acteur,
        action=Act.DECISION_EXCEPTION,
        item=item,
        cible=RULES_LIBELLES.get(rule.code, rule.code),
        detail={"motif": decision.motif, "quantite": quantite, "code": decision.code},
    )
    notify_members(
        business=business,
        code="DECISION.EXCEPTION",
        message=(
            f"Décision exceptionnelle : « {item.nom} » utilisé malgré "
            f"l'avertissement ({RULES_LIBELLES.get(rule.code, rule.code)}) "
            f"par {acteur.email}."
        ),
        item=item,
        permission_codename=Perm.STOCK_EXCEPTION,
        ignore_user=acteur,
    )
    return decision