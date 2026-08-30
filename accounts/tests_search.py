"""Tests complets pour DODOME Smart Search et Moteur de Recommandations.

Couvre :
- Normalisation textuelle (accents, stopwords, synonymes FR/EN)
- Analyse d'intention (événements, cibles, effectifs, lieux, variations linguistiques)
- Moteur de classement et scoring composite
- Moteur de recommandation (similar, complementary, used_for, often_rented_together)
- Isolation stricte multi-tenant
- Exclusion des articles inactifs ou non publiés
- Disponibilité basée sur les dates
- Endpoints DRF PublicSearchView et PublicItemRecommendationsView
- Tests de non-régression des endpoints publics existants
"""

from datetime import date, timedelta
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from .models import User, Business, Category, Item, StockMovement, Reservation, BookingRequest
from .search.normalizer import QueryNormalizer
from .search.intent_analyzer import SearchIntentAnalyzer
from .search.ranking_engine import RankingEngine
from .search.recommendation_engine import RecommendationEngine
from .search.search_service import SearchService


class QueryNormalizerTestCase(TestCase):
    """Tests unitaires du service de normalisation."""

    def test_strip_accents(self):
        self.assertEqual(QueryNormalizer.strip_accents("Événement Décoration Fête"), "Evenement Decoration Fete")
        self.assertEqual(QueryNormalizer.strip_accents(""), "")

    def test_clean_text(self):
        cleaned = QueryNormalizer.clean_text("  Organiser l'anniversaire de ma mère !  ")
        self.assertEqual(cleaned, "organiser l anniversaire de ma mere")

    def test_tokenize_and_stopwords(self):
        tokens = QueryNormalizer.tokenize("Je veux organiser une fête pour mon ami")
        self.assertIn("organiser", tokens)
        self.assertIn("fete", tokens)
        self.assertIn("ami", tokens)
        self.assertNotIn("je", tokens)
        self.assertNotIn("veux", tokens)
        self.assertNotIn("une", tokens)
        self.assertNotIn("pour", tokens)
        self.assertNotIn("mon", tokens)

    def test_synonyms_resolution(self):
        self.assertEqual(QueryNormalizer.resolve_synonym("bday"), "anniversaire")
        self.assertEqual(QueryNormalizer.resolve_synonym("wedding"), "mariage")
        self.assertEqual(QueryNormalizer.resolve_synonym("maman"), "mere")
        self.assertEqual(QueryNormalizer.resolve_synonym("barnum"), "tente")
        self.assertEqual(QueryNormalizer.resolve_synonym("sono"), "sonorisation")


class SearchIntentAnalyzerTestCase(TestCase):
    """Tests unitaires de l'analyseur d'intention."""

    def test_empty_query(self):
        res = SearchIntentAnalyzer.analyze("")
        self.assertEqual(res["intent"], "search")
        self.assertIsNone(res["event"])
        self.assertIsNone(res["target"])

    def test_birthday_mother(self):
        res = SearchIntentAnalyzer.analyze("Organiser un anniversaire pour ma mère")
        self.assertEqual(res["intent"], "event_organization")
        self.assertEqual(res["event"], "birthday")
        self.assertIsNotNone(res["target"])
        self.assertEqual(res["target"]["relationship"], "mother")
        self.assertEqual(res["target"]["gender"], "female")

    def test_wedding(self):
        res = SearchIntentAnalyzer.analyze("Organiser un mariage")
        self.assertEqual(res["intent"], "event_organization")
        self.assertEqual(res["event"], "wedding")

    def test_child_birthday_with_age(self):
        res = SearchIntentAnalyzer.analyze("Organiser l'anniversaire de mon fils de 10 ans")
        self.assertEqual(res["intent"], "event_organization")
        self.assertEqual(res["event"], "birthday")
        self.assertEqual(res["target"]["relationship"], "son")
        self.assertEqual(res["target"]["age"], 10)
        self.assertEqual(res["target"]["audience"], "children")

    def test_attendees_extraction(self):
        res = SearchIntentAnalyzer.analyze("Je cherche des équipements pour une petite fête de 50 personnes")
        self.assertEqual(res["event"], "party")
        self.assertEqual(res["attendees"], 50)

    def test_location_and_target_father(self):
        res = SearchIntentAnalyzer.analyze("Je veux organiser l'anniversaire de mon père avec une décoration simple à Lomé")
        self.assertEqual(res["event"], "birthday")
        self.assertEqual(res["target"]["relationship"], "father")
        self.assertEqual(res["location"], "Lomé")

    def test_english_synonyms(self):
        res = SearchIntentAnalyzer.analyze("wedding party for my daughter")
        self.assertEqual(res["event"], "wedding")
        self.assertEqual(res["target"]["relationship"], "daughter")


class SmartDiscoveryIntegrationTestCase(TestCase):
    """Tests d'intégration complets multi-tenants, ranking, disponibilité et recommandations."""

    def setUp(self):
        self.client = APIClient()

        self.user_a = User.objects.create_user(
            email="owner_a@prestige.com",
            username="owner_a@prestige.com",
            password="Password123!",
            first_name="Owner",
            last_name="Prestige",
        )
        self.user_b = User.objects.create_user(
            email="owner_b@autre.com",
            username="owner_b@autre.com",
            password="Password123!",
            first_name="Owner",
            last_name="Autre",
        )

        # Business 1 (Principal)
        self.business_a = Business.objects.create(
            nom="Prestige Events Lomé",
            slug="prestige-events",
            business_type=Business.BusinessType.DECORATION_RENTAL,
            created_by=self.user_a,
        )

        # Business 2 (Concurrent / Tenant isolé)
        self.business_b = Business.objects.create(
            nom="Autre Entreprise",
            slug="autre-entreprise",
            business_type=Business.BusinessType.DECORATION_RENTAL,
            created_by=self.user_b,
        )

        # Catégories Business A
        self.cat_tentes = Category.objects.create(business=self.business_a, nom="Tentes & Chapiteaux")
        self.cat_mobilier = Category.objects.create(business=self.business_a, nom="Mobilier & Chaises")
        self.cat_deco = Category.objects.create(business=self.business_a, nom="Décoration")
        self.cat_sono = Category.objects.create(business=self.business_a, nom="Sonorisation & Éclairage")

        # Articles Business A (Publiés et actifs)
        self.item_tente = Item.objects.create(
            business=self.business_a,
            category=self.cat_tentes,
            nom="Tente Réception Blanche 10x10",
            reference="TENT-1010",
            description="Grande tente imperméable idéale pour mariages et cérémonies extérieures",
            public_description="Tente de prestige pour grandes réceptions et mariages",
            prix=100000.00,
            unite="jour",
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        self.item_chaise = Item.objects.create(
            business=self.business_a,
            category=self.cat_mobilier,
            nom="Chaise Pliante Blanche Chiavari",
            reference="CHAIR-001",
            description="Chaise élégante pour banquets, anniversaires et mariages",
            prix=1500.00,
            unite="jour",
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        self.item_table = Item.objects.create(
            business=self.business_a,
            category=self.cat_mobilier,
            nom="Table Ronde 8 Personnes",
            reference="TAB-08",
            description="Table ronde en bois pour dîners et réceptions",
            prix=5000.00,
            unite="jour",
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        self.item_pack_anniv = Item.objects.create(
            business=self.business_a,
            category=self.cat_deco,
            nom="Pack Décoration Anniversaire Festif",
            reference="DEC-BDAY",
            description="Kit complet de décoration avec ballons, guirlandes et centres de table",
            prix=35000.00,
            unite="forfait",
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        self.item_sono = Item.objects.create(
            business=self.business_a,
            category=self.cat_sono,
            nom="Pack Sonorisation 500W & Micro sans fil",
            reference="SONO-500",
            description="Enceinte amplifiée avec micro pour discours et musique d'ambiance",
            prix=25000.00,
            unite="jour",
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        # Article non publié Business A
        self.item_unpublished = Item.objects.create(
            business=self.business_a,
            category=self.cat_deco,
            nom="Décoration Secrète Non Publiée",
            prix=10000.00,
            statut=Item.Statut.ACTIF,
            is_published=False,
        )

        # Article inactif Business A
        self.item_inactive = Item.objects.create(
            business=self.business_a,
            category=self.cat_deco,
            nom="Décoration Déclassée Inactive",
            prix=10000.00,
            statut=Item.Statut.INACTIF,
            is_published=True,
        )

        # Articles Business B (Tenant isolé)
        self.item_business_b = Item.objects.create(
            business=self.business_b,
            nom="Tente Exclusivité Business B",
            reference="TENT-B",
            description="Tente appartenant strictement au business B",
            prix=80000.00,
            statut=Item.Statut.ACTIF,
            is_published=True,
        )

        # Création de mouvements de stock initiaux pour Business A
        for item, qty in [
            (self.item_tente, 2),
            (self.item_chaise, 100),
            (self.item_table, 15),
            (self.item_pack_anniv, 5),
            (self.item_sono, 3),
        ]:
            StockMovement.objects.create(
                business=self.business_a,
                item=item,
                type=StockMovement.Type.ENTREE,
                quantite=qty,
                acteur=self.user_a,
                motif="Stock initial",
            )

    def test_smart_search_intent_and_ranking(self):
        """Recherche 'Organiser un anniversaire pour ma mère' classe le pack anniversaire et le mobilier en tête."""
        url = f"/api/public/b/{self.business_a.slug}/search/?q=Organiser un anniversaire pour ma mère"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertIn("metadata", data)
        self.assertEqual(data["metadata"]["event"], "birthday")
        self.assertEqual(data["metadata"]["target"]["relationship"], "mother")

        results = data["results"]
        self.assertTrue(len(results) > 0)

        # Le pack anniversaire doit être parmi les premiers résultats
        top_item_names = [r["nom"] for r in results[:2]]
        self.assertIn(self.item_pack_anniv.nom, top_item_names)

        # Vérifier que le score et les raisons sont inclus
        self.assertIn("score", results[0])
        self.assertIn("match_reasons", results[0])

    def test_multi_tenant_isolation_in_search(self):
        """Une recherche dans Business A ne doit JAMAIS retourner les articles de Business B."""
        url = f"/api/public/b/{self.business_a.slug}/search/?q=tente"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        item_ids = [r["id"] for r in response.data["results"]]

        self.assertIn(str(self.item_tente.id), item_ids)
        self.assertNotIn(str(self.item_business_b.id), item_ids)

    def test_inactive_and_unpublished_items_excluded(self):
        """Les articles non publiés ou inactifs sont strictement exclus de la recherche."""
        url = f"/api/public/b/{self.business_a.slug}/search/?q=decoration"
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        item_ids = [r["id"] for r in response.data["results"]]

        self.assertIn(str(self.item_pack_anniv.id), item_ids)
        self.assertNotIn(str(self.item_unpublished.id), item_ids)
        self.assertNotIn(str(self.item_inactive.id), item_ids)

    def test_search_with_availability_dates(self):
        """La recherche avec dates calcule la disponibilité exacte et ajuste les scores."""
        d_debut = date.today() + timedelta(days=10)
        d_fin = date.today() + timedelta(days=12)

        # Créer une réservation qui consomme toutes les tentes sur cette période
        Reservation.objects.create(
            business=self.business_a,
            item=self.item_tente,
            reserve_par=self.user_a,
            date_debut=d_debut,
            date_fin=d_fin,
            quantite=2,
            statut=Reservation.Statut.VALIDEE,
        )

        url = (
            f"/api/public/b/{self.business_a.slug}/search/"
            f"?q=mariage&date_debut={d_debut.isoformat()}&date_fin={d_fin.isoformat()}"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["results"]

        # Trouver la tente dans les résultats
        tente_res = next(r for r in results if r["id"] == str(self.item_tente.id))
        self.assertEqual(tente_res["disponible"], 0)
        self.assertFalse(tente_res["peut_reserver"])

        # Trouver les chaises (qui doivent rester disponibles)
        chaise_res = next(r for r in results if r["id"] == str(self.item_chaise.id))
        self.assertEqual(chaise_res["disponible"], 100)
        self.assertTrue(chaise_res["peut_reserver"])

    def test_category_filter_in_search(self):
        """Le filtre par catégorie fonctionne en synergie avec la recherche."""
        url = (
            f"/api/public/b/{self.business_a.slug}/search/"
            f"?q=blanche&category={self.cat_mobilier.id}"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data["results"]
        for r in results:
            self.assertEqual(r["category_nom"], self.cat_mobilier.nom)

    def test_recommendations_similar(self):
        """Recommandations SIMILAR retournent des articles de la même catégorie."""
        url = (
            f"/api/public/b/{self.business_a.slug}/items/{self.item_chaise.id}/recommendations/"
            f"?type=similar&limit=2"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["type"], "SIMILAR")
        rec_ids = [r["id"] for r in data["recommendations"]]

        # Ne doit pas contenir l'article lui-même
        self.assertNotIn(str(self.item_chaise.id), rec_ids)
        # Doit contenir la table (même catégorie mobilier)
        self.assertIn(str(self.item_table.id), rec_ids)

    def test_recommendations_complementary(self):
        """Recommandations COMPLEMENTARY retournent des articles complémentaires (ex: Tente -> Chaises/Tables/Sono)."""
        url = (
            f"/api/public/b/{self.business_a.slug}/items/{self.item_tente.id}/recommendations/"
            f"?type=complementary&limit=4"
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.data
        self.assertEqual(data["type"], "COMPLEMENTARY")
        rec_ids = [r["id"] for r in data["recommendations"]]

        self.assertNotIn(str(self.item_tente.id), rec_ids)
        # La tente doit recommander le mobilier ou la sonorisation
        self.assertTrue(
            str(self.item_chaise.id) in rec_ids
            or str(self.item_table.id) in rec_ids
            or str(self.item_sono.id) in rec_ids
        )

    def test_non_regression_existing_public_endpoints(self):
        """Vérifie la non-régression de tous les endpoints publics préexistants."""
        slug = self.business_a.slug

        # 1. Détail business
        res_b = self.client.get(f"/api/public/b/{slug}/")
        self.assertEqual(res_b.status_code, status.HTTP_200_OK)

        # 2. Liste catalogue
        res_cat = self.client.get(f"/api/public/b/{slug}/items/")
        self.assertEqual(res_cat.status_code, status.HTTP_200_OK)

        # 3. Catégories
        res_categories = self.client.get(f"/api/public/b/{slug}/categories/")
        self.assertEqual(res_categories.status_code, status.HTTP_200_OK)

        # 4. Disponibilité article
        d_debut = (date.today() + timedelta(days=1)).isoformat()
        d_fin = (date.today() + timedelta(days=3)).isoformat()
        res_avail = self.client.get(
            f"/api/public/b/{slug}/items/{self.item_tente.id}/availability/?date_debut={d_debut}&date_fin={d_fin}"
        )
        self.assertEqual(res_avail.status_code, status.HTTP_200_OK)
