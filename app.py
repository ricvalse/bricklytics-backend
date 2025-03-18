import pandas as pd
from google.cloud import bigquery
from flask import Flask, jsonify, request, session, make_response
from flask_cors import CORS
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import uuid  # Add this import
import traceback
from functools import wraps

app = Flask(__name__)

# Updated CORS configuration
CORS(app, 
    resources={
        r"/api/*": {
            "origins": ["https://bricklytics-frontend-382735415092.europe-southwest1.run.app"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Accept"],
            "supports_credentials": True
        }
    })

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'https://bricklytics-frontend-382735415092.europe-southwest1.run.app')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Accept')
    response.headers.add('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS')
    return response

app.secret_key = 'mysecretkey'

# Configure session settings
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Correct for HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='None',  # Change from 'Lax' to 'None' for cross-site requests
    SESSION_COOKIE_PATH='/',
    SESSION_COOKIE_DOMAIN=None,  # Let Flask determine the domain automatically
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_PERMANENT=True
)

# Initialize BigQuery client
client = bigquery.Client(project="capstone-riccardo")
DATASET_ID = "capstonedataset"

# Function to execute queries in BigQuery
def query_bigquery(query):
    job = client.query(query)
    return [dict(row) for row in job.result()]

# Function to insert row-by-row into BigQuery
# def insert_into_bigquery(table_name, data):
#     table_ref = f"{client.project}.{DATASET_ID}.{table_name}"
#     errors = client.insert_rows_json(table_ref, data)
#     return "Success" if not errors else f"Errors: {errors}"

# Add after client initialization
def verify_users_table():
    table_id = f"{client.project}.{DATASET_ID}.users"
    try:
        table = client.get_table(table_id)
        print("Current table schema:", [field.name for field in table.schema])
        return table
    except Exception as e:
        print(f"Error getting users table: {e}")
        return None

# Call this after client initialization
verify_users_table()

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized access'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Property Endpoints
@app.route("/api/properties", methods=["GET"])
def get_properties():
    query = f"""
        SELECT * FROM `{client.project}.{DATASET_ID}.properties`
        WHERE on_sale = TRUE
    """
    return jsonify(query_bigquery(query))

@app.route("/api/properties/<property_id>", methods=["GET"])
def get_property(property_id):
    """Get detailed property information including investment scores and market trends."""
    query = f"""
        SELECT p.*, i.ai_score, i.roi_estimate, i.risk_level, m.rental_yield
        FROM `{client.project}.{DATASET_ID}.properties` p
        LEFT JOIN `{client.project}.{DATASET_ID}.investment_scores` i
        ON p.property_id = i.property_id
        LEFT JOIN `{client.project}.{DATASET_ID}.market_trends` m
        ON p.property_id = m.property_id
        WHERE p.property_id = '{property_id}'
    """
    try:
        result = query_bigquery(query)
        if not result:
            return jsonify({'error': 'Property not found'}), 404
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching property: {e}")
        return jsonify({'error': 'Failed to fetch property details'}), 500

# Market Trends Endpoints
@app.route("/api/market-trends", methods=["GET"])
def get_market_trends():
    query = f"SELECT * FROM `{client.project}.{DATASET_ID}.market_trends`"
    return jsonify(query_bigquery(query))

@app.route("/api/market-trends/<property_id>", methods=["GET"])
def get_market_trend(property_id):
    query = f"SELECT * FROM `{client.project}.{DATASET_ID}.market_trends` WHERE property_id = '{property_id}'"
    return jsonify(query_bigquery(query))

# Investment Scores Endpoints
@app.route("/api/investment-scores", methods=["GET"])
def get_investment_scores():
    query = f"SELECT * FROM `{client.project}.{DATASET_ID}.investment_scores`"
    return jsonify(query_bigquery(query))

@app.route("/api/investment-scores/<property_id>", methods=["GET"])
def get_investment_score(property_id):
    query = f"SELECT * FROM `{client.project}.{DATASET_ID}.investment_scores` WHERE property_id = '{property_id}'"
    return jsonify(query_bigquery(query))

# User Endpoints
@app.route("/api/users/<user_id>/saved-properties", methods=["GET"])
@require_auth
def get_saved_properties(user_id):
    # Verify the logged-in user is accessing their own data
    if str(session['user_id']) != str(user_id):
        return jsonify({'error': 'Unauthorized access'}), 403
        
    """Get saved properties with full property details for a user."""
    query = f"""
        SELECT p.*, sp.saved_at
        FROM `{client.project}.{DATASET_ID}.saved_properties` sp
        JOIN `{client.project}.{DATASET_ID}.properties` p
        ON sp.property_id = p.property_id
        WHERE sp.user_id = '{user_id}'
    """
    try:
        properties = query_bigquery(query)
        print("Saved properties query result:", properties)  # Debug print
        return jsonify(properties)
    except Exception as e:
        print(f"Error fetching saved properties: {e}")
        return jsonify({'error': 'Failed to fetch saved properties'}), 500

@app.route("/api/users/<user_id>/save-property/<property_id>", methods=["POST"])
@require_auth
def save_property(user_id, property_id):
    # Verify the logged-in user is accessing their own data
    if str(session['user_id']) != str(user_id):
        return jsonify({'error': 'Unauthorized access'}), 403
    
    try:
        print(f"Attempting to save property {property_id} for user {user_id}")
        
        # Check if already saved
        check_query = f"""
            SELECT * FROM `{client.project}.{DATASET_ID}.saved_properties`
            WHERE user_id = '{user_id}' AND property_id = '{property_id}'
        """
        existing = query_bigquery(check_query)
        
        if existing:
            return jsonify({'message': 'Property already saved'}), 409

        # Create job config for batch load
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
        )
        
        # Prepare saved property data
        saved_data = {
            'saved_id': str(uuid.uuid4()),
            'user_id': user_id,
            'property_id': property_id,
            'saved_at': datetime.now().isoformat()
        }
        
        # Load data using batch load
        saved_table = f"{client.project}.{DATASET_ID}.saved_properties"
        job = client.load_table_from_json(
            [saved_data],
            saved_table,
            job_config=job_config
        )
        job.result()  # Wait for the job to complete
        
        if job.errors:
            return jsonify({'error': f'Failed to save property: {job.errors}'}), 500
            
        return jsonify({'message': 'Property saved successfully'}), 201
        
    except Exception as e:
        print(f"Error saving property: {str(e)}")
        print(f"Full error details: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to save property: {str(e)}'}), 500

@app.route("/api/users/<user_id>/save-property/<property_id>", methods=["DELETE"])
@require_auth
def remove_saved_property(user_id, property_id):
    """Remove a saved property for a user from the `saved_properties` table."""
    try:
        query = f"""
            DELETE FROM `{client.project}.{DATASET_ID}.saved_properties`
            WHERE user_id = '{user_id}'
            AND property_id = '{property_id}'
        """
        job = client.query(query)
        job.result()  # Wait for the job to complete
        return jsonify({'message': 'Property removed successfully'}), 200
    except Exception as e:
        print(f"Error removing property: {e}")
        return jsonify({'error': 'Failed to remove property'}), 500

@app.route("/api/properties/city/<city>", methods=["GET"])
def get_properties_by_city(city):
    query = f"""
        SELECT p.*, i.ai_score, i.roi_estimate
        FROM `{client.project}.{DATASET_ID}.properties` p
        LEFT JOIN `{client.project}.{DATASET_ID}.investment_scores` i
        ON p.property_id = i.property_id
        WHERE p.city = '{city}' AND p.on_sale = TRUE
    """
    return jsonify(query_bigquery(query))

@app.route("/api/analytics/average-price/<city>", methods=["GET"])
def get_average_price_by_city(city):
    query = f"SELECT city, AVG(price) as average_price FROM `{client.project}.{DATASET_ID}.properties` WHERE city = '{city}' GROUP BY city"
    return jsonify(query_bigquery(query))

@app.route("/api/properties/most-expensive", methods=["GET"])
def get_most_expensive_properties():
    """Get the 10 most expensive properties."""
    query = f"""
        SELECT p.*, i.ai_score, i.roi_estimate, m.rental_yield
        FROM `{client.project}.{DATASET_ID}.properties` p
        LEFT JOIN `{client.project}.{DATASET_ID}.investment_scores` i
        ON p.property_id = i.property_id
        LEFT JOIN `{client.project}.{DATASET_ID}.market_trends` m
        ON p.property_id = m.property_id
        WHERE p.on_sale = TRUE
        ORDER BY p.price DESC
        LIMIT 10
    """
    try:
        result = query_bigquery(query)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching most expensive properties: {e}")
        return jsonify({'error': 'Failed to fetch properties'}), 500

# Analytics Endpoints
@app.route("/api/analytics/top-investment-properties", methods=["GET"])
def get_top_investment_properties():
    """Get the 10 properties with the highest AI score."""
    query = f"""
        SELECT p.*, i.ai_score, i.roi_estimate, m.rental_yield
        FROM `{client.project}.{DATASET_ID}.properties` p
        JOIN `{client.project}.{DATASET_ID}.investment_scores` i
        ON p.property_id = i.property_id
        LEFT JOIN `{client.project}.{DATASET_ID}.market_trends` m
        ON p.property_id = m.property_id
        WHERE p.on_sale = TRUE
        ORDER BY i.ai_score DESC
        LIMIT 10
    """
    try:
        result = query_bigquery(query)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching top investment properties: {e}")
        return jsonify({'error': 'Failed to fetch properties'}), 500

@app.route("/api/analytics/highest-rental-yield", methods=["GET"])
def get_highest_rental_yield():
    """Get the 10 properties with the highest rental yield."""
    query = f"""
        SELECT p.*, i.ai_score, i.roi_estimate, m.rental_yield
        FROM `{client.project}.{DATASET_ID}.properties` p
        JOIN `{client.project}.{DATASET_ID}.market_trends` m
        ON p.property_id = m.property_id
        LEFT JOIN `{client.project}.{DATASET_ID}.investment_scores` i
        ON p.property_id = i.property_id
        WHERE p.on_sale = TRUE
        ORDER BY m.rental_yield DESC
        LIMIT 10
    """
    try:
        result = query_bigquery(query)
        return jsonify(result)
    except Exception as e:
        print(f"Error fetching highest rental yield properties: {e}")
        return jsonify({'error': 'Failed to fetch properties'}), 500

@app.route("/upload-data", methods=["GET"])
def upload_data():
    """Uploads CSV data to BigQuery tables."""
    csv_files = {
        "properties": "properties_sample_data.csv",
        "users": "users_sample_data.csv",
        "market_trends": "market_trends_sample_data.csv",
        "investment_scores": "investment_scores_sample_data.csv",
        "saved_properties": "saved_properties_sample_data.csv"
    }
    results = {}
    for table, csv_file in csv_files.items():
        try:
            df = pd.read_csv(csv_file)
            data = df.to_dict(orient="records")
            results[table] = insert_into_bigquery(table, data)
        except Exception as e:
            results[table] = f"Error processing {csv_file}: {e}"
    
    return jsonify(results)

# API routes
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug print
        
        if not data or 'email' not in data or 'password' not in data:
            print("Missing data")  # Debug print
            return jsonify({'error': 'Missing email or password'}), 400
        
        # Check if user already exists
        query = f"""
            SELECT email FROM `{client.project}.{DATASET_ID}.users`
            WHERE email = '{data['email']}'
        """
        print("Executing query:", query)  # Debug print
        existing_user = query_bigquery(query)
        print("Existing user check:", existing_user)  # Debug print
        
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user with UUID
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(data['password'])
        
        user_data = [{
            'user_id': user_id,
            'email': data['email'],
            'password_hash': hashed_password,
            'created_at': datetime.now().isoformat()
        }]
        
        print("Attempting to insert:", user_data)  # Debug print
        table_ref = f"{client.project}.{DATASET_ID}.users"
        errors = client.insert_rows_json(table_ref, user_data)
        
        if errors:
            print("BigQuery errors:", errors)  # Debug print
            return jsonify({'error': f'Registration failed: {str(errors)}'}), 500
        
        return jsonify({'message': 'Registered successfully'}), 201
        
    except Exception as e:
        print("Server error:", str(e))  # Debug print
        return jsonify({'error': f'Server error occurred: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print("Login attempt with data:", data)  # Debug print
        
        if not data or 'email' not in data or 'password' not in data:
            print("Missing email or password")  # Debug print
            return jsonify({'error': 'Missing email or password'}), 400

        query = f"""
            SELECT user_id, email, password_hash 
            FROM `{client.project}.{DATASET_ID}.users`
            WHERE email = '{data['email']}'
        """
        print("Executing query:", query)  # Debug print
        users = query_bigquery(query)
        print("Query result:", users)  # Debug print

        if not users:
            print("No user found")  # Debug print
            return jsonify({'error': 'Invalid credentials'}), 401

        if check_password_hash(users[0]['password_hash'], data['password']):
            print("Password verified, setting up session")  # Debug print
            session.permanent = True
            session['user_id'] = users[0]['user_id']
            
            response = jsonify({
                'message': 'Logged in successfully',
                'user': {
                    'id': users[0]['user_id'],
                    'email': users[0]['email']
                }
            })
            
            print("Session after login:", dict(session))  # Debug print
            return response
        else:
            print("Invalid password")  # Debug print
            return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        print("Login error details:", str(e))  # Debug print
        print("Full traceback:", traceback.format_exc())  # Debug print
        return jsonify({'error': f'An error occurred during login: {str(e)}'}), 500

@app.route('/api/logout')
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    print("Session contents:", dict(session))  # Debug print
    if 'user_id' in session:
        try:
            query = f"""
                SELECT user_id, email
                FROM `{client.project}.{DATASET_ID}.users`
                WHERE user_id = '{session['user_id']}'
            """
            users = query_bigquery(query)
            
            if users:
                return jsonify({
                    'authenticated': True,
                    'user': {
                        'id': users[0]['user_id'],
                        'email': users[0]['email']
                    }
                })
        except Exception as e:
            print("Check auth error:", str(e))
            
    return jsonify({'authenticated': False}), 401

@app.route("/api/users/<user_id>/owned-properties", methods=["GET"])
@require_auth
def get_owned_properties(user_id):
    if str(session['user_id']) != str(user_id):
        return jsonify({'error': 'Unauthorized access'}), 403
    """Get properties owned by a user with their current values."""
    query = f"""
        SELECT 
            p.*,
            op.price_paid,
            op.purchase_date,
            op.rental_income,
            COALESCE(mt.current_value, op.price_paid) as current_value,
            ROUND(((COALESCE(mt.current_value, op.price_paid) - op.price_paid) / op.price_paid) * 100, 2) as return
        FROM `{client.project}.{DATASET_ID}.owned_properties` op
        JOIN `{client.project}.{DATASET_ID}.properties` p
        ON op.property_id = p.property_id
        LEFT JOIN `{client.project}.{DATASET_ID}.market_trends` mt
        ON p.property_id = mt.property_id
        WHERE op.user_id = '{user_id}'
        ORDER BY op.purchase_date DESC
    """
    try:
        properties = query_bigquery(query)
        return jsonify(properties)
    except Exception as e:
        print(f"Error fetching owned properties: {e}")
        return jsonify({'error': 'Failed to fetch owned properties'}), 500

@app.route("/api/users/<user_id>/add-property", methods=["POST"])
@require_auth
def add_owned_property(user_id):
    if str(session['user_id']) != str(user_id):
        return jsonify({'error': 'Unauthorized access'}), 403
    """Add a new property to user's portfolio."""
    try:
        data = request.get_json()
        property_id = str(uuid.uuid4())
        
        # Prepare property data
        property_data = {
            'property_id': property_id,
            'address': data['address'],
            'city': data['city'],
            'country': data['country'],
            'price': float(data['price_paid']),
            'property_type': data['type'],
            'bedrooms': data['bedrooms'],
            'bathrooms': data.get('bathrooms'),
            'size_sqft': data.get('size'),
            'on_sale': False
        }
        
        # Add property using batch load
        batch_load_to_bigquery('properties', property_data)
        
        # Prepare owned property data
        owned_data = {
            'owned_id': str(uuid.uuid4()),
            'user_id': user_id,
            'property_id': property_id,
            'price_paid': float(data['price_paid']),
            'purchase_date': data['purchase_date'],
            'rental_income': float(data['rental_income']) if data.get('rental_income') else None,
            'created_at': datetime.now().isoformat()
        }
        
        # Add owned property using batch load
        batch_load_to_bigquery('owned_properties', owned_data)
        
        return jsonify({'message': 'Property added successfully'}), 201
        
    except Exception as e:
        print(f"Error adding property: {str(e)}")
        print(f"Full error details: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to add property: {str(e)}'}), 500

@app.route("/api/users/<user_id>/property-values", methods=["GET"])
def get_property_values(user_id):
    """Get historical property values for user's portfolio."""
    query = f"""
        WITH yearly_investments AS (
            SELECT 
                DATE_TRUNC(purchase_date, YEAR) as year,
                SUM(price_paid) as year_investment
            FROM `{client.project}.{DATASET_ID}.owned_properties`
            WHERE user_id = '{user_id}'
            GROUP BY DATE_TRUNC(purchase_date, YEAR)
        )
        SELECT 
            year as date,
            SUM(year_investment) OVER (ORDER BY year) as total_investment
        FROM yearly_investments
        ORDER BY date ASC
    """
    try:
        values = query_bigquery(query)
        return jsonify(values)
    except Exception as e:
        print(f"Error fetching property values: {e}")
        return jsonify({'error': 'Failed to fetch property values'}), 500

@app.route("/api/users/<user_id>/owned-property/<property_id>", methods=["DELETE"])
def remove_owned_property(user_id, property_id):
    """Remove a property from user's portfolio."""
    try:
        print(f"Attempting to remove property {property_id} for user {user_id}")
        
        # Delete from owned_properties table
        delete_owned_query = f"""
            DELETE FROM `{client.project}.{DATASET_ID}.owned_properties`
            WHERE user_id = '{user_id}'
            AND property_id = '{property_id}'
        """
        job = client.query(delete_owned_query)
        job.result()

        # Delete the property if it was created for portfolio (on_sale = FALSE)
        # Otherwise, set it back to on_sale = TRUE
        check_property_query = f"""
            SELECT on_sale FROM `{client.project}.{DATASET_ID}.properties`
            WHERE property_id = '{property_id}'
        """
        property_result = query_bigquery(check_property_query)
        
        if property_result and not property_result[0]['on_sale']:
            # Property was created for portfolio, delete it
            delete_property_query = f"""
                DELETE FROM `{client.project}.{DATASET_ID}.properties`
                WHERE property_id = '{property_id}'
            """
            job = client.query(delete_property_query)
            job.result()
        else:
            # Property was from research, set back to on_sale
            update_query = f"""
                UPDATE `{client.project}.{DATASET_ID}.properties`
                SET on_sale = TRUE
                WHERE property_id = '{property_id}'
            """
            job = client.query(update_query)
            job.result()

        print("Property removed successfully")
        return jsonify({'message': 'Property removed successfully'}), 200
    except Exception as e:
        print(f"Error removing owned property: {str(e)}")
        print(f"Full error details: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to remove property: {str(e)}'}), 500

@app.route("/api/users/<user_id>/owned-property/<property_id>", methods=["PUT"])
def update_owned_property(user_id, property_id):
    """Update an existing property in user's portfolio."""
    try:
        data = request.get_json()
        
        # Update the property details
        update_property_query = f"""
            UPDATE `{client.project}.{DATASET_ID}.properties`
            SET 
                address = '{data['address']}',
                city = '{data['city']}',
                country = '{data['country']}',
                property_type = '{data['type']}',
                bedrooms = {data['bedrooms']},
                bathrooms = {data.get('bathrooms', 'NULL')},
                size_sqft = {data.get('size', 'NULL')}
            WHERE property_id = '{property_id}'
        """
        job = client.query(update_property_query)
        job.result()

        # Update the owned_property details
        update_owned_query = f"""
            UPDATE `{client.project}.{DATASET_ID}.owned_properties`
            SET 
                price_paid = {float(data['price_paid'])},
                purchase_date = '{data['purchase_date']}',
                rental_income = {float(data['rental_income']) if data.get('rental_income') else 'NULL'}
            WHERE user_id = '{user_id}'
            AND property_id = '{property_id}'
        """
        job = client.query(update_owned_query)
        job.result()

        return jsonify({'message': 'Property updated successfully'}), 200
    except Exception as e:
        print(f"Error updating property: {str(e)}")
        print(f"Full error details: {traceback.format_exc()}")
        return jsonify({'error': f'Failed to update property: {str(e)}'}), 500

@app.route("/api/users/<user_id>/owned-property/<property_id>", methods=["GET"])
def get_owned_property_details(user_id, property_id):
    """Get detailed property information including ownership details."""
    query = f"""
        SELECT p.*, o.purchase_date, o.price_paid, o.rental_income
        FROM `{client.project}.{DATASET_ID}.properties` p
        JOIN `{client.project}.{DATASET_ID}.owned_properties` o
        ON p.property_id = o.property_id
        WHERE o.user_id = '{user_id}'
        AND p.property_id = '{property_id}'
    """
    try:
        print(f"Executing query for user {user_id} and property {property_id}")
        print("Query:", query)
        result = query_bigquery(query)
        print("Query result:", result)
        
        if not result:
            print("No property found")
            return jsonify({'error': 'Property not found'}), 404
            
        print("Property details being sent:", result[0])
        return jsonify(result[0])
    except Exception as e:
        print(f"Error fetching property details: {e}")
        print(f"Full error details: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch property details'}), 500

def batch_load_to_bigquery(table_name, data):
    """Helper function to perform batch loads to BigQuery."""
    try:
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
        )
        
        table_id = f"{client.project}.{DATASET_ID}.{table_name}"
        job = client.load_table_from_json(
            [data],
            table_id,
            job_config=job_config
        )
        job.result()  # Wait for the job to complete
        
        if job.errors:
            raise Exception(f"Load errors: {job.errors}")
            
        return True
    except Exception as e:
        print(f"Error in batch load: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(debug=True, port=5001)
