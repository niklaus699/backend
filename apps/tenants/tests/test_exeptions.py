import pytest
@pytest.mark.django_db
def test_exception_handler_masking(api_client, tenant_a_user):
    api_client.force_authenticate(user=tenant_a_user)
    
    # Trigger a 404 on a non-existent endpoint or cross-tenant resource
    url = "/api/v1/assets/999-invalid-uuid/"
    response = api_client.get(url)
    assert response.status_code == 404

    content = str(response.content).lower()
    assert "not found" in content
