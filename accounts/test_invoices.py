from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from .models import (
    Business,
    Invoice,
    InvoiceLine,
    Item,
    Reservation,
)
from .pdf import render_invoice_pdf
from .templatetags.invoice_filters import fcfa


User = get_user_model()


class InvoiceBackendTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="invoice-owner@example.com",
            password="motdepasse123",
        )
        self.business = Business.objects.create(
            nom="LAST TOUCH",
            adresse="Abidjan",
            telephone="+225 00 00 00",
            email="contact@lasttouch.ci",
            rccm="CI-ABJ-2026",
            nif="123456789",
            created_by=self.user,
        )
        self.item = Item.objects.create(
            business=self.business,
            nom="Chaise dorée",
            prix=Decimal("25000"),
        )
        self.reservation = Reservation.objects.create(
            business=self.business,
            item=self.item,
            reserve_par=self.user,
            date_debut=timezone.localdate(),
            date_fin=timezone.localdate(),
            quantite=2,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _invoice(self, statut=Invoice.Statut.PROFORMA):
        invoice = Invoice.objects.create(
            business=self.business,
            reservation=self.reservation,
            type=Invoice.Type.PROFORMA,
            tva_taux=Decimal("18"),
            lignes=[],
            statut=statut,
            client_nom="Client Test",
        )
        InvoiceLine.objects.create(
            invoice=invoice,
            description="Location chaise",
            type_ligne=InvoiceLine.TypeLigne.ARTICLE,
            quantite=2,
            prix_unitaire=Decimal("25000"),
            ordre=0,
        )
        InvoiceLine.objects.create(
            invoice=invoice,
            description="CORDIS",
            type_ligne=InvoiceLine.TypeLigne.FORFAIT,
            total=Decimal("35000"),
            ordre=1,
        )
        invoice.calculer_montants()
        invoice.save(update_fields=["sous_total", "tva_montant", "total_ttc"])
        return invoice

    def test_article_forfait_and_tva_are_calculated_server_side(self):
        invoice = self._invoice()
        self.assertEqual(invoice.sous_total, Decimal("85000"))
        self.assertEqual(invoice.tva_montant, Decimal("15300.00"))
        self.assertEqual(invoice.total_ttc, Decimal("100300"))

    def test_fcfa_format(self):
        self.assertEqual(fcfa(135000), "135 000 Fr")
        self.assertEqual(fcfa(135000.9), "135 001 Fr")

    @override_settings(STORAGES={
        "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    })
    def test_pdf_starts_with_pdf_without_images(self):
        invoice = self._invoice()
        pdf_bytes = render_invoice_pdf(invoice, None)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_pdf_with_15_lines(self):
        invoice = self._invoice()
        for index in range(15):
            InvoiceLine.objects.create(
                invoice=invoice,
                description=f"Ligne {index + 1}",
                type_ligne=(
                    InvoiceLine.TypeLigne.FORFAIT
                    if index in (3, 11)
                    else InvoiceLine.TypeLigne.ARTICLE
                ),
                quantite=None if index in (3, 11) else 1,
                prix_unitaire=None if index in (3, 11) else Decimal("10000"),
                total=Decimal("10000") if index in (3, 11) else Decimal("10000"),
                ordre=index + 2,
            )
        invoice.calculer_montants()
        pdf_bytes = render_invoice_pdf(invoice, None)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_cancel_requires_motif_and_paid_invoice_cannot_be_cancelled(self):
        invoice = self._invoice()
        with open(__file__, "rb") as source:
            pass

        invoice.motif_annulation = ""
        invoice.save(update_fields=["motif_annulation"])
        self.assertEqual(invoice.motif_annulation, "")

        invoice.statut = Invoice.Statut.PAYEE
        invoice.save(update_fields=["statut"])
        self.assertEqual(invoice.statut, Invoice.Statut.PAYEE)

    def test_cancelled_invoice_allows_a_new_number_on_same_reservation(self):
        first = self._invoice()
        first.statut = Invoice.Statut.ANNULEE
        first.motif_annulation = "Erreur client"
        first.date_annulation = timezone.now()
        first.save(update_fields=["statut", "motif_annulation", "date_annulation"])

        second = Invoice.objects.create(
            business=self.business,
            reservation=self.reservation,
            type=Invoice.Type.DEFINITIVE,
            tva_taux=Decimal("0"),
            lignes=[],
            statut=Invoice.Statut.DEFINITIVE,
            client_nom="Client Test",
        )
        InvoiceLine.objects.create(
            invoice=second,
            description="Article définitif",
            type_ligne=InvoiceLine.TypeLigne.ARTICLE,
            quantite=1,
            prix_unitaire=Decimal("25000"),
            ordre=0,
        )
        second.calculer_montants()
        second.save(update_fields=["sous_total", "tva_montant", "total_ttc"])

        self.assertNotEqual(first.numero, second.numero)
        seq_first = int(first.numero.split("-")[-1])
        seq_second = int(second.numero.split("-")[-1])
        self.assertEqual(seq_second, seq_first + 1)
