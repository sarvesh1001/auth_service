CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    company_id UUID,
    role VARCHAR(20) NOT NULL,
    content TEXT,
    tool_name VARCHAR(100),
    tool_success BOOLEAN,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_user_time 
    ON chat_messages (user_id, created_at DESC);