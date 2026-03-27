-- init-db/init.sql
-- Этот скрипт выполнится ТОЛЬКО при первом старте пустой БД
-- Файлы в /docker-entrypoint-initdb.d/ игнорируются, если БД уже инициализирована

-- ============================================
-- Таблица для сбора трафика (партиционированная)
-- ============================================
CREATE TABLE IF NOT EXISTS traffic (
    id BIGSERIAL,
    user_name TEXT NOT NULL,
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at)  -- Важно: PK должен включать ключ партиционирования
) PARTITION BY RANGE (created_at);

-- Индексы для ускорения запросов
CREATE INDEX IF NOT EXISTS idx_traffic_user_created 
    ON traffic (user_name, created_at);

CREATE INDEX IF NOT EXISTS idx_traffic_created 
    ON traffic (created_at);

-- ============================================
-- Таблица для хранения последних значений счётчиков
-- ============================================
CREATE TABLE IF NOT EXISTS last_stats (
    public_key TEXT PRIMARY KEY,
    rx BIGINT NOT NULL DEFAULT 0,
    tx BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_last_stats_updated 
    ON last_stats (updated_at);

-- ============================================
-- Комментарий к таблицам (для документации)
-- ============================================
COMMENT ON TABLE traffic IS 'Партиционированная таблица статистики трафика WireGuard';
COMMENT ON TABLE last_stats IS 'Последние известные значения счётчиков WireGuard';

-- ============================================
-- Права доступа (опционально, если используете не суперпользователя)
-- ============================================
-- GRANT SELECT, INSERT, UPDATE ON traffic TO your_app_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON last_stats TO your_app_user;
-- GRANT USAGE, SELECT ON SEQUENCE traffic_id_seq TO your_app_user;