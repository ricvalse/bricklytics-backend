import pytest
from unittest.mock import patch, MagicMock
import os
import sys

# Create mock before any imports
mock_client = MagicMock()
mock_client.project = "capstone-riccardo"
mock_query_job = MagicMock()
mock_query_job.result.return_value = [
    {'property_id': '1', 'address': '123 Test St', 'price': 100000},
    {'property_id': '2', 'address': '456 Mock Ave', 'price': 200000}
]
mock_client.query.return_value = mock_query_job

# Mock the bigquery.Client before importing app
with patch('google.cloud.bigquery.Client') as mock_bigquery:
    mock_bigquery.return_value = mock_client
    # Force the mock to be used when importing app
    from google.cloud import bigquery
    bigquery.Client = lambda project=None: mock_client

# Now we can import app
import app

@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    with app.app.test_client() as client:
        yield client 