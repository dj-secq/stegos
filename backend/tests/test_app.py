from stego_triage.app import app

def test_frontend_index_is_served():
    client = app.test_client()
    response = client.get('/')
    assert response.status_code == 200
    assert b'<title>Stego Triage</title>' in response.data

def test_frontend_javascript_is_served():
    client = app.test_client()
    response = client.get('/app.js')
    assert response.status_code == 200
    assert response.mimetype == 'text/javascript'

def test_health_endpoint_still_responds():
    client = app.test_client()
    response = client.get('/api/health')
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'ok'
    assert body['version'] == '0.2.0'
    assert 'Access-Control-Allow-Origin' not in response.headers
