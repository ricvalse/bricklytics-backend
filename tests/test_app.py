import pytest
from app import app
import json
from unittest.mock import patch, MagicMock

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_bigquery():
    with patch('app.client') as mock_client:
        # Mock query results
        mock_query_job = MagicMock()
        mock_query_job.result.return_value = [
            {'property_id': '1', 'address': '123 Test St', 'price': 100000},
            {'property_id': '2', 'address': '456 Mock Ave', 'price': 200000}
        ]
        mock_client.query.return_value = mock_query_job
        yield mock_client

def test_get_properties(client, mock_bigquery):
    """Test getting properties endpoint"""
    response = client.get('/api/properties')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) > 0

def test_get_market_trends(client, mock_bigquery):
    """Test getting market trends endpoint"""
    response = client.get('/api/market-trends')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_get_investment_scores(client, mock_bigquery):
    """Test getting investment scores endpoint"""
    response = client.get('/api/investment-scores')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_signup_missing_data(client):
    """Test signup with missing data"""
    response = client.post('/api/signup', 
                         data=json.dumps({}),
                         content_type='application/json')
    assert response.status_code == 400
    assert b'error' in response.data

def test_login_missing_data(client):
    """Test login with missing data"""
    response = client.post('/api/login', 
                         data=json.dumps({}),
                         content_type='application/json')
    assert response.status_code == 400
    assert b'error' in response.data

@patch('app.client')
def test_property_details(mock_client, client):
    """Test getting specific property details"""
    # Mock the query result
    mock_query_job = MagicMock()
    mock_query_job.result.return_value = [{
        'property_id': '1',
        'address': '123 Test St',
        'price': 100000,
        'ai_score': 0.8,
        'roi_estimate': 0.1,
        'rental_yield': 0.05
    }]
    mock_client.query.return_value = mock_query_job

    response = client.get('/api/properties/1')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) > 0
    assert 'property_id' in data[0]