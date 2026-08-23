/**
 * PhishGuard AI - SQLite Database Layer
 * Handles persistent storage for user accounts, scan history, threat intel cache, model versions
 */

import sqlite3 from 'better-sqlite3';
import path from 'path';

// Database schema
export interface DBSchema {
  // User accounts table
  users: {
    id: string;
    email: string;
    name: string;
    createdAt: string;
    lastLoginAt: string | null;
    settings: any;
  };
  
  // Scan history table
  scans: {
    id: string;
    userId: string;
    type: 'URL' | 'EMAIL' | 'TEXT' | 'PAGE';
    input: string;
    prediction: 'Phishing' | 'Suspicious' | 'Safe';
    confidence: number;
    riskScore: number;
    threatLevel: 'High' | 'Medium' | 'Low';
    reasons: string[];
    recommendations: string[];
    sources: {
      local: boolean;
      backend: boolean;
      threatIntel: boolean;
    };
    analyzedAt: string;
    url?: string;
  };
  
  // Threat intelligence cache table
  threatCache: {
    id: number;
    userId: string | null;
    url: string;
    result: any;
    timestamp: number;
    expiresAt: number;
  };
  
  // Model versions table
  modelVersions: {
    id: number;
    version: string;
    type: 'heuristic' | 'ml' | 'ensemble';
    accuracy: number;
    trainedAt: string;
    active: boolean;
  };
}

// Database path - use Chrome/Firefox profile directory
const getDBPath = (): string => {
  // Try to get from chrome.runtime.getDirectory() equivalent
  const baseDir = process.env['PG_DB_PATH'] || '/tmp/phishguard';
  return path.join(baseDir, 'phishguard.db');
};

// Initialize database connection
let db: sqlite3.Database | null = null;

export function initDB(): void {
  try {
    const dbPath = getDBPath();
    
    // Create directory if it doesn't exist (simplified for now)
    // In production, use chrome.fileSystem.createEntry() or similar
    
    db = sqlite3(dbPath);
    
    // Enable foreign keys
    db.pragma('foreign_keys = ON');
    
    // Create tables
    createTables();
    
  } catch (error: any) {
    console.error('Database initialization error:', error.message);
    // Fall back to localStorage if DB fails
    db = null;
  }
}

function createTables(): void {
  const dbPath = getDBPath();
  
  // Users table
  db!.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL DEFAULT 'Anonymous',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login_at TEXT,
      settings TEXT DEFAULT '{}'
    )
  `).run();
  
  // Scans table
  db!.prepare(`
    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      type TEXT NOT NULL CHECK(type IN ('URL', 'EMAIL', 'TEXT', 'PAGE')),
      input TEXT NOT NULL,
      prediction TEXT NOT NULL CHECK(prediction IN ('Phishing', 'Suspicious', 'Safe')),
      confidence REAL NOT NULL DEFAULT 0.5,
      risk_score REAL NOT NULL DEFAULT 0.5,
      threat_level TEXT NOT NULL CHECK(threat_level IN ('High', 'Medium', 'Low')),
      reasons TEXT DEFAULT '[]' NOT NULL,
      recommendations TEXT DEFAULT '[]' NOT NULL,
      sources TEXT DEFAULT '{"local":true,"backend":false,"threatIntel":false}' NOT NULL,
      analyzed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      url TEXT
    )
  `).run();
  
  // Threat cache table
  db!.prepare(`
    CREATE TABLE IF NOT EXISTS threat_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      url TEXT NOT NULL,
      result TEXT DEFAULT '{}' NOT NULL,
      timestamp INTEGER NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at INTEGER NOT NULL DEFAULT 0
    )
  `).run();
  
  // Model versions table
  db!.prepare(`
    CREATE TABLE IF NOT EXISTS model_versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('heuristic', 'ml', 'ensemble')),
      accuracy REAL DEFAULT 0.5,
      trained_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      active BOOLEAN DEFAULT TRUE
    )
  `).run();
  
  console.log('Database initialized successfully');
}

export function getDB(): sqlite3.Database | null {
  return db;
}

// Initialize on module load (will use localStorage fallback if needed)
initDB();
