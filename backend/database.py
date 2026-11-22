"""
SentinelAI - Storage Repository Layer
Provides seamless integration with MongoDB Atlas with automatic fallback
to local persistent JSON storage when MongoDB credentials are not configured.
"""

import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

DB_FALLBACK_FILE = os.path.join(os.path.dirname(__file__), 'data', 'incidents.json')

class IncidentRepository:
    def __init__(self):
        self.lock = threading.Lock()
        self.provider = 'local_json_fallback'
        self.client = None
        self.collection = None
        self.local_cache: List[Dict[str, Any]] = []
        self._init_storage()

    def _init_storage(self):
        mongo_uri = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI')
        if mongo_uri:
            try:
                import pymongo
                self.client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
                # Verify connection
                self.client.admin.command('ping')
                db_name = os.getenv('MONGODB_DB', 'sentinel_db')
                self.collection = self.client[db_name]['incidents']
                self.collection.create_index('id', unique=True)
                self.collection.create_index([('timestamp', -1)])
                self.provider = 'mongodb_atlas'
                print(f"[SentinelAI Storage] Successfully connected to MongoDB Atlas ({db_name}.incidents)")
                return
            except Exception as e:
                print(f"[SentinelAI Storage] MongoDB Atlas connection error ({e}). Falling back to local storage.")
                self.client = None
                self.collection = None

        # Fallback to local persistent JSON
        self.provider = 'local_json_fallback'
        os.makedirs(os.path.dirname(DB_FALLBACK_FILE), exist_ok=True)
        if os.path.exists(DB_FALLBACK_FILE):
            try:
                with open(DB_FALLBACK_FILE, 'r', encoding='utf-8') as f:
                    self.local_cache = json.load(f)
                print(f"[SentinelAI Storage] Loaded {len(self.local_cache)} incidents from local store ({DB_FALLBACK_FILE})")
            except Exception as e:
                print(f"[SentinelAI Storage] Could not read local incidents file: {e}")
                self.local_cache = []
        else:
            self.local_cache = []
            self._save_local_file()
            print(f"[SentinelAI Storage] Initialized clean local store at {DB_FALLBACK_FILE}")

    def _save_local_file(self):
        try:
            with open(DB_FALLBACK_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.local_cache, f, indent=2)
        except Exception as e:
            print(f"[SentinelAI Storage] Error persisting to local file: {e}")

    def save_incident(self, incident: Dict[str, Any]):
        return self.save_incidents([incident])

    def save_incidents(self, incidents: List[Dict[str, Any]]):
        if not incidents:
            return
            
        with self.lock:
            if self.provider == 'mongodb_atlas' and self.collection is not None:
                try:
                    # Clean copy without _id conflicts if any
                    to_insert = []
                    for inc in incidents:
                        c = dict(inc)
                        c.pop('_id', None)
                        to_insert.append(c)
                    self.collection.insert_many(to_insert)
                    return
                except Exception as e:
                    print(f"[SentinelAI Storage] Error writing to MongoDB: {e}. Falling back to local cache.")
            
            # Local fallback save
            existing_ids = {item['id'] for item in self.local_cache}
            for inc in incidents:
                if inc['id'] in existing_ids:
                    # Update existing
                    self.local_cache = [inc if x['id'] == inc['id'] else x for x in self.local_cache]
                else:
                    self.local_cache.append(inc)
                    existing_ids.add(inc['id'])
            self._save_local_file()

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if self.provider == 'mongodb_atlas' and self.collection is not None:
                try:
                    doc = self.collection.find_one({'id': incident_id}, {'_id': 0})
                    if doc:
                        return doc
                except Exception as e:
                    print(f"[SentinelAI Storage] MongoDB find error: {e}")
            
            for item in reversed(self.local_cache):
                if item.get('id') == incident_id:
                    return dict(item)
            return None

    def list_incidents(
        self,
        label: Optional[str] = None,
        severity: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 200,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        with self.lock:
            if self.provider == 'mongodb_atlas' and self.collection is not None:
                try:
                    query = {}
                    if label and label != 'all':
                        query['label'] = label
                    if severity and severity != 'all':
                        query['severity'] = severity
                    if search:
                        query['$or'] = [
                            {'id': {'$regex': search, '$options': 'i'}},
                            {'threat_vector': {'$regex': search, '$options': 'i'}},
                            {'mitre_technique': {'$regex': search, '$options': 'i'}}
                        ]
                    cursor = self.collection.find(query, {'_id': 0}).sort('timestamp', -1).skip(offset).limit(limit)
                    return list(cursor)
                except Exception as e:
                    print(f"[SentinelAI Storage] MongoDB list error: {e}")

            # Local fallback query
            res = list(reversed(self.local_cache))
            if label and label != 'all':
                res = [x for x in res if x.get('label') == label]
            if severity and severity != 'all':
                res = [x for x in res if x.get('severity', '').lower() == severity.lower()]
            if search:
                s = search.lower()
                res = [
                    x for x in res
                    if s in x.get('id', '').lower()
                    or s in x.get('threat_vector', '').lower()
                    or s in x.get('mitre_technique', '').lower()
                    or any(s in str(v).lower() for v in x.get('features', {}).values())
                ]
            return res[offset : offset + limit]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self.lock:
            all_items = []
            if self.provider == 'mongodb_atlas' and self.collection is not None:
                try:
                    all_items = list(self.collection.find({}, {'_id': 0}).sort('timestamp', -1).limit(500))
                except Exception as e:
                    print(f"[SentinelAI Storage] MongoDB stats error: {e}")
                    all_items = list(reversed(self.local_cache))
            else:
                all_items = list(reversed(self.local_cache))

            total = len(all_items)
            suspicious = sum(1 for i in all_items if i.get('label') == 'suspicious')
            normal = sum(1 for i in all_items if i.get('label') == 'normal')
            
            severities = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            vectors = {}
            for i in all_items:
                sev = i.get('severity', 'Low')
                severities[sev] = severities.get(sev, 0) + 1
                vec = i.get('threat_vector', 'Unknown')
                vectors[vec] = vectors.get(vec, 0) + 1

            # Recent 10 for dashboard preview
            recent = all_items[:10]
            
            return {
                'total': total,
                'suspicious': suspicious,
                'normal': normal,
                'severities': severities,
                'vectors': vectors,
                'recent': recent,
                'storage_provider': self.provider
            }

    def clear_all(self):
        with self.lock:
            if self.provider == 'mongodb_atlas' and self.collection is not None:
                try:
                    self.collection.delete_many({})
                except Exception as e:
                    print(f"[SentinelAI Storage] Error clearing MongoDB: {e}")
            self.local_cache = []
            self._save_local_file()

    def get_status(self) -> Dict[str, Any]:
        return {
            'provider': self.provider,
            'is_mongo': self.provider == 'mongodb_atlas',
            'record_count': len(self.local_cache) if self.provider == 'local_json_fallback' else (self.collection.count_documents({}) if self.collection is not None else 0),
            'fallback_path': DB_FALLBACK_FILE if self.provider == 'local_json_fallback' else None
        }

# Global singleton repository
repository = IncidentRepository()
