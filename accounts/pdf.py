from django.conf import settings
from django.template.loader import render_to_string

from io import BytesIO


def _absolute_url(request, field_file):
    if not field_file:
        return None
    url = getattr(field_file, "url", None)
    if not url:
        return None
    if request is not None:
        return request.build_absolute_uri(url)
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return url


def render_invoice_pdf(invoice, request) -> bytes:
    business = invoice.business
    line_rows = list(invoice.invoice_lines.all())
    if line_rows:
        lines = [
            {
                "description": line.description,
                "type_ligne": line.type_ligne,
                "quantite": line.quantite,
                "prix_unitaire": line.prix_unitaire,
                "total": line.total,
                "image_url": _absolute_url(request, line.image),
                "ordre": line.ordre,
            }
            for line in line_rows
        ]
    else:
        lines = [
            {
                "description": line.get("description", ""),
                "type_ligne": line.get("type_ligne", "article"),
                "quantite": line.get("quantite"),
                "prix_unitaire": line.get("prix_unitaire"),
                "total": line.get("total", 0),
                "image_url": None,
                "ordre": index,
            }
            for index, line in enumerate(invoice.lignes or [])
        ]

    invoice.calculer_montants()
    invoice.save(update_fields=[
        "sous_total",
        "tva_montant",
        "total_ttc",
    ])

    html = render_to_string(
        "invoices/invoice.html",
        {
            "invoice": invoice,
            "business": business,
            "lines": lines,
            "logo_url": _absolute_url(request, business.logo),
            "cachet_url": _absolute_url(request, business.cachet),
            "watermark_url": _absolute_url(request, business.logo),
            "signature_title": business.signature_titre or "Le Responsable",
        },
        request=request,
    )

    try:
        from weasyprint import HTML

        return HTML(
            string=html,
            base_url=str(settings.BASE_DIR),
        ).write_pdf(presentational_hints=True)
    except (ImportError, OSError):
        return _render_reportlab_fallback(invoice, business, lines)


def _render_reportlab_fallback(invoice, business, lines) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_RIGHT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=invoice.numero,
    )
    styles = getSampleStyleSheet()
    story = [
        Paragraph(str(business.nom), styles["Title"]),
        Paragraph(
            "LOCATION, VENTE DES ACCESSOIRES DE DECORATION",
            styles["Normal"],
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            f"{invoice.numero} - {invoice.generee_le.strftime('%d/%m/%Y')}",
            styles["Normal"],
        ),
        Spacer(1, 4 * mm),
    ]

    table_data = [["Qté", "Désignations", "Illustrations", "P. Unit.", "P. Total"]]
    for line in lines:
        if line["type_ligne"] == "forfait":
            table_data.append([
                "",
                line["description"],
                "",
                "",
                f"{int(line['total'] or 0):,}".replace(",", " ") + " Fr",
            ])
        else:
            table_data.append([
                str(line["quantite"] or ""),
                line["description"],
                "",
                f"{int(line['prix_unitaire'] or 0):,}".replace(",", " ") + " Fr",
                f"{int(line['total'] or 0):,}".replace(",", " ") + " Fr",
            ])
    table_data.append(["", "", "", "TOTAL", f"{int(invoice.total_ttc or 0):,}".replace(",", " ") + " Fr"])

    table = Table(table_data, repeatRows=1, colWidths=[12 * mm, 70 * mm, 28 * mm, 28 * mm, 28 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D7E1F1")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.black),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "Times-Roman"),
        ("FONTNAME", (0, -1), (-1, -1), "Times-Bold"),
    ]))
    story.append(table)
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(
        f"<b>TOTAL TTC : {int(invoice.total_ttc or 0):,}".replace(",", " ") + " Fr</b>",
        styles["Normal"],
    ))
    story.append(Spacer(1, 12 * mm))
    story.append(Paragraph(
        f"<i>Fait à {invoice.reservation.lieu_nom or business.adresse}, le {invoice.generee_le.strftime('%d/%m/%Y')}</i>",
        styles["Normal"],
    ))
    story.append(Paragraph("<u>Le Responsable</u>", styles["Normal"]))
    if business.signature_nom:
        story.append(Paragraph(
            f"<b>{business.signature_nom}</b>",
            styles["Normal"],
        ))

    document.build(story)
    return buffer.getvalue()
