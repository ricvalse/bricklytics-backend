import pytest
from unittest.mock import patch, MagicMock
import os

# Set up mock before any imports
mock_client = MagicMock()
mock_client.project = "capstone-riccardo"
mock_query_job = MagicMock()
mock_query_job.result.return_value = [
    {'property_id': '1', 'address': '123 Test St', 'price': 100000},
    {'property_id': '2', 'address': '456 Mock Ave', 'price': 200000}
]
mock_client.query.return_value = mock_query_job

# Apply mock to google.cloud.bigquery.Client
patch('google.cloud.bigquery.Client', return_value=mock_client).start() 