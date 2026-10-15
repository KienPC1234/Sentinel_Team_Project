from django.test import TestCase
from django.core.management import call_command
from django.contrib.auth import get_user_model
from api.core.data.scam_iq_bank import get_balanced_exam_questions, SCAM_IQ_BANK
from api.core.models import Report, Domain, BankAccount, ForumPost, LearnLesson, TrendDaily

User = get_user_model()


class ScamIQBankTestCase(TestCase):
    def test_bank_integrity(self):
        """Validate all items in the curated bank have required keys and non-empty values."""
        self.assertGreaterEqual(len(SCAM_IQ_BANK), 60)
        valid_difficulties = {'easy', 'medium', 'hard', 'extreme'}
        valid_types = {
            'single_choice', 'multi_select', 'true_false',
            'simulation_sms', 'simulation_email', 'incident_response'
        }

        for q in SCAM_IQ_BANK:
            self.assertTrue(q.get('id'))
            self.assertIn(q.get('difficulty'), valid_difficulties)
            self.assertIn(q.get('type'), valid_types)
            self.assertTrue(q.get('question'))
            self.assertTrue(q.get('explanation'))
            if q.get('type') in {'single_choice', 'multi_select', 'true_false'}:
                self.assertGreaterEqual(len(q.get('options', [])), 2)
                self.assertTrue(len(q.get('correct_option_ids', [])) >= 1)

    def test_balanced_exam_contract(self):
        """Verify the balanced exam meets the 30-question educational contract."""
        exam = get_balanced_exam_questions(seed=42)
        self.assertEqual(len(exam), 30)

        # 1. Strictly ascending difficulty: 6 easy -> 10 medium -> 10 hard -> 4 extreme
        diffs = [q['difficulty'] for q in exam]
        self.assertEqual(diffs[:6], ['easy'] * 6)
        self.assertEqual(diffs[6:16], ['medium'] * 10)
        self.assertEqual(diffs[16:26], ['hard'] * 10)
        self.assertEqual(diffs[26:30], ['extreme'] * 4)

        # 2. Multi-select count >= 7
        multi_count = sum(1 for q in exam if q.get('type') == 'multi_select')
        self.assertGreaterEqual(multi_count, 7)

        # 3. Simulation count >= 8
        sim_types = {'simulation_sms', 'simulation_email', 'incident_response'}
        sim_count = sum(1 for q in exam if q.get('type') in sim_types)
        self.assertGreaterEqual(sim_count, 8)

        # 4. Clean Q1..Q30 numbering
        self.assertEqual([q['id'] for q in exam], [f"Q{i}" for i in range(1, 31)])


class SeedDataCommandTestCase(TestCase):
    def test_seed_data_execution(self):
        """Verify the seed_data management command runs cleanly and populates database."""
        call_command('seed_data', '--clear')

        self.assertGreaterEqual(User.objects.count(), 5)
        self.assertGreaterEqual(Report.objects.count(), 10)
        self.assertGreaterEqual(Domain.objects.count(), 5)
        self.assertGreaterEqual(BankAccount.objects.count(), 5)
        self.assertGreaterEqual(ForumPost.objects.count(), 4)
        self.assertGreaterEqual(LearnLesson.objects.count(), 2)
        self.assertGreaterEqual(TrendDaily.objects.count(), 14)

