import pytest
@pytest.mark.django_db
def test_exception_handler_masking(authenticated_client):
    response = authenticated_client.get(
        "/api/assets/00000000-0000-0000-0000-000000000000/"
    )

    assert response.status_code == 404

    content = str(response.content).lower()
    assert "not found" in content
