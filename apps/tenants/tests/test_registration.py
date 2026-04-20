import pytest
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestRegisterView:
    def setup_method(self):
        self.client = APIClient()
        self.url = reverse('register')
        self.valid_payload = {
            'organization_name': 'Test Corp',
            'email': 'admin@testcorp.com',
            'password': 'StrongPass123!',
            'confirm_password': 'StrongPass123!',
        }

    def test_successful_registration_returns_tokens(self):
        res = self.client.post(self.url, self.valid_payload)
        assert res.status_code == 201
        assert 'access' in res.data
        assert 'refresh' in res.data
        assert res.data['user']['role'] == 'owner'
        assert res.data['user']['organization']['name'] == 'Test Corp'

    def test_duplicate_email_rejected(self):
        self.client.post(self.url, self.valid_payload)
        res = self.client.post(self.url, self.valid_payload)
        assert res.status_code == 400
        assert 'email' in res.data

    def test_duplicate_org_name_rejected(self):
        self.client.post(self.url, self.valid_payload)
        payload2 = {**self.valid_payload, 'email': 'other@testcorp.com'}
        res = self.client.post(self.url, payload2)
        assert res.status_code == 400
        assert 'organization_name' in res.data

    def test_password_mismatch_rejected(self):
        payload = {**self.valid_payload, 'confirm_password': 'WrongPassword!'}
        res = self.client.post(self.url, payload)
        assert res.status_code == 400

    def test_short_password_rejected(self):
        payload = {**self.valid_payload, 'password': 'short', 'confirm_password': 'short'}
        res = self.client.post(self.url, payload)
        assert res.status_code == 400

    def test_first_user_is_org_owner(self):
        res = self.client.post(self.url, self.valid_payload)
        assert res.data['user']['role'] == 'owner'

    def test_org_and_user_created_atomically(self):
        """If user creation fails, the org must not exist either."""
        from unittest.mock import patch
        from apps.tenants.models import Organization

        with patch('apps.tenants.models.User.objects.create_user', side_effect=Exception('DB error')):
            try:
                self.client.post(self.url, self.valid_payload)
            except Exception:
                pass

        assert not Organization.objects.filter(name='Test Corp').exists()
