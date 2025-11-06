#!/usr/bin/env python3
"""
Deep Eye - Web GUI for Configuration Management
Provides a web interface to manage API keys and AI provider settings
"""

import os
import json
from pathlib import Path
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv, set_key, find_dotenv
from utils.secret_manager import encrypt_value, decrypt_value, get_decrypted_env

app = Flask(__name__)
CORS(app)

ENV_FILE = Path('.env')
CONFIG_DIR = Path('config')
CONFIG_DIR.mkdir(exist_ok=True)

load_dotenv()

@app.route('/')
def index():
    """Render the main settings page"""
    return render_template('settings.html')

@app.route('/favicon.ico')
def favicon():
    """Return empty response for favicon to avoid 404 errors"""
    return '', 204

@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get current AI provider settings (without exposing API keys)"""
    settings = {
        'providers': {
            'openai': {
                'enabled': os.getenv('OPENAI_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('OPENAI_API_KEY'))
            },
            'claude': {
                'enabled': os.getenv('CLAUDE_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('ANTHROPIC_API_KEY'))
            },
            'grok': {
                'enabled': os.getenv('GROK_ENABLED', 'false').lower() == 'true',
                'has_key': bool(get_decrypted_env('GROK_API_KEY'))
            },
            'ollama': {
                'enabled': os.getenv('OLLAMA_ENABLED', 'false').lower() == 'true',
                'has_key': bool(os.getenv('OLLAMA_HOST'))
            }
        },
        'ai_enabled': os.getenv('AI_FEATURES_ENABLED', 'false').lower() == 'true'
    }
    return jsonify(settings)

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update AI provider settings and API keys"""
    data = request.json
    
    if not ENV_FILE.exists():
        ENV_FILE.touch()
        os.chmod(ENV_FILE, 0o600)
    
    try:
        if 'ai_enabled' in data:
            set_key(ENV_FILE, 'AI_FEATURES_ENABLED', str(data['ai_enabled']).lower())
        
        providers = data.get('providers', {})
        
        if 'openai' in providers:
            prov = providers['openai']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'OPENAI_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'OPENAI_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'claude' in providers:
            prov = providers['claude']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'ANTHROPIC_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'CLAUDE_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'grok' in providers:
            prov = providers['grok']
            if prov.get('api_key'):
                encrypted_key = encrypt_value(prov['api_key'])
                set_key(ENV_FILE, 'GROK_API_KEY', encrypted_key)
            set_key(ENV_FILE, 'GROK_ENABLED', str(prov.get('enabled', False)).lower())
        
        if 'ollama' in providers:
            prov = providers['ollama']
            if prov.get('host'):
                set_key(ENV_FILE, 'OLLAMA_HOST', prov['host'])
            set_key(ENV_FILE, 'OLLAMA_ENABLED', str(prov.get('enabled', False)).lower())
        
        load_dotenv(override=True)
        
        return jsonify({'success': True, 'message': 'Settings updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/test-connection/<provider>', methods=['POST'])
def test_connection(provider):
    """Test API connection for a specific provider"""
    try:
        if provider == 'openai':
            api_key = get_decrypted_env('OPENAI_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import openai
            client = openai.OpenAI(api_key=api_key)
            client.models.list()
            return jsonify({'success': True, 'message': 'OpenAI connection successful'})
        
        elif provider == 'claude':
            api_key = get_decrypted_env('ANTHROPIC_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            return jsonify({'success': True, 'message': 'Claude connection successful'})
        
        elif provider == 'grok':
            api_key = get_decrypted_env('GROK_API_KEY')
            if not api_key:
                return jsonify({'success': False, 'message': 'API key not configured'})
            
            import openai
            client = openai.OpenAI(
                api_key=api_key,
                base_url='https://api.x.ai/v1'
            )
            client.models.list()
            return jsonify({'success': True, 'message': 'Grok connection successful'})
        
        elif provider == 'ollama':
            import ollama
            ollama.list()
            return jsonify({'success': True, 'message': 'Ollama connection successful'})
        
        else:
            return jsonify({'success': False, 'message': 'Unknown provider'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Connection failed: {str(e)}'}), 500

if __name__ == '__main__':
    print("\n🌐 Starting Deep Eye Web GUI...")
    print("📡 Access the interface at: http://0.0.0.0:5000")
    print("🔐 Manage your AI provider settings securely\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
