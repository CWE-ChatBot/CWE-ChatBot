-- Initialize CWE ChatBot database with pgvector extension
-- This script runs automatically when the PostgreSQL container starts

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create CWE embeddings table
CREATE TABLE IF NOT EXISTS cwe_embeddings (
    id SERIAL PRIMARY KEY,
    cwe_id VARCHAR(20) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    abstraction VARCHAR(50),
    status VARCHAR(50),
    description TEXT,
    extended_description TEXT,
    full_text TEXT NOT NULL,  -- Combined text for embedding
    embedding vector(1536),   -- OpenAI text-embedding-3-small dimensions
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_embeddings(cwe_id);
CREATE INDEX IF NOT EXISTS idx_embedding_cosine ON cwe_embeddings USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS idx_full_text_gin ON cwe_embeddings USING gin(to_tsvector('english', full_text));

-- Create users table (for future application data)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create messages table
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    message_type VARCHAR(20) NOT NULL CHECK (message_type IN ('user', 'assistant')),
    content TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data (small subset of CWEs for initial testing)
INSERT INTO cwe_embeddings (cwe_id, name, abstraction, status, description, extended_description, full_text, embedding) VALUES
    ('CWE-79', 'Improper Neutralization of Input During Web Page Generation (''Cross-site Scripting'')', 'Base', 'Stable', 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.', 'Cross-site scripting (XSS) vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping.', 'CWE-79 Cross-site Scripting XSS web application security input validation output encoding HTML JavaScript injection attack vector user-controllable data', NULL),
    ('CWE-89', 'Improper Neutralization of Special Elements used in an SQL Command (''SQL Injection'')', 'Base', 'Stable', 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component.', 'SQL injection attacks involve inserting or injecting malicious SQL queries into application input fields.', 'CWE-89 SQL injection database query parameter validation prepared statements input sanitization code injection attack', NULL),
    ('CWE-120', 'Buffer Copy without Checking Size of Input (''Classic Buffer Overflow'')', 'Base', 'Stable', 'The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.', 'Buffer overflow vulnerabilities are among the most common and dangerous security issues in software applications.', 'CWE-120 buffer overflow memory corruption bounds checking input validation C C++ memory safety stack heap', NULL),
    ('CWE-20', 'Improper Input Validation', 'Class', 'Stable', 'The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program.', 'Input validation is a critical security control that prevents many types of attacks.', 'CWE-20 input validation sanitization filtering whitelist blacklist data validation security control', NULL),
    ('CWE-787', 'Out-of-bounds Write', 'Base', 'Stable', 'The software writes data past the end, or before the beginning, of the intended buffer.', 'Out-of-bounds write vulnerabilities can lead to memory corruption and potential code execution.', 'CWE-787 out-of-bounds write memory corruption buffer overflow array bounds checking memory safety', NULL)
ON CONFLICT (cwe_id) DO NOTHING;

-- Create helper functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers
CREATE TRIGGER update_cwe_embeddings_updated_at BEFORE UPDATE ON cwe_embeddings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_conversations_updated_at BEFORE UPDATE ON conversations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Verify setup
SELECT 'Database initialized successfully' as status;
SELECT COUNT(*) as test_cwe_count FROM cwe_embeddings;