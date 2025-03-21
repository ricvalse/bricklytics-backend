import pytest
import os
from app import app
import json
from unittest.mock import patch

# Set testing environment
os.environ['TESTING'] = 'True'

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with patch('app.query_bigquery') as mock_query:
            # Mock data for different queries
            mock_query.return_value = [
                {'property_id': '1', 'address': '123 Test St', 'price': 100000},
                {'property_id': '2', 'address': '456 Mock Ave', 'price': 200000}
            ]
            yield client

def test_get_properties(client):
    """Test getting properties endpoint"""
    response = client.get('/api/properties')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) > 0

def test_get_market_trends(client):
    """Test getting market trends endpoint"""
    response = client.get('/api/market-trends')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_get_investment_scores(client):
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

def test_login_missing_data(client):
    """Test login with missing data"""
    response = client.post('/api/login', 
                         data=json.dumps({}),
                         content_type='application/json')
    assert response.status_code == 400