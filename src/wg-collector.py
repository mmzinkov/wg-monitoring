#!/usr/bin/env python3
"""
Сборщик статистики трафика WireGuard

Собирает статистику трафика из контейнеров WireGuard и сохраняет её в PostgreSQL
с поддержкой месячного партиционирования.
"""

import logging
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, NamedTuple

import psycopg2
from apscheduler.schedulers.blocking import BlockingScheduler
from psycopg2 import sql
from psycopg2.extras import execute_batch, RealDictCursor

# =============================================================================
# КОНСТАНТЫ И АЛИАСЫ ТИПОВ
# =============================================================================

WG_SUPPORTED_TYPES: Final[frozenset[str]] = frozenset({"wireguard", "amnezia"})
WG_CONFIG_PATH_WIREGUARD: Final[str] = "/etc/wireguard/wg0.conf"
WG_CONFIG_PATH_AMNEZIA: Final[str] = "/opt/amnezia/awg/clientsTable"
WG_INTERFACE: Final[str] = "wg0"
DB_HOST: Final[str] = "127.0.0.1"
DB_PORT: Final[int] = 5432
MIN_INTERVAL_SECONDS: Final[int] = 10
DEFAULT_INTERVAL_SECONDS: Final[int] = 60

PublicKey = str
UserName = str
BytesCount = int
TrafficTuple = tuple[BytesCount, BytesCount]

logger = logging.getLogger(__name__)


# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================

@dataclass(frozen=True)
class Config:
    """Конфигурация приложения из переменных окружения."""
    
    wg_container: str
    wg_type:str
    postgres_db: str
    postgres_user: str
    postgres_password: str
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    
    @classmethod
    def from_env(cls) -> "Config":
        """Создать конфигурацию из переменных окружения с валидацией."""
        wg_container = os.getenv("WG_CONTAINER")
        wg_type = os.getenv("WG_TYPE", "").lower()
        
        if not wg_container:
            raise ValueError("Переменная окружения WG_CONTAINER обязательна")
        if wg_type not in WG_SUPPORTED_TYPES:
            raise ValueError(
                f"WG_TYPE должен быть одним из {WG_SUPPORTED_TYPES}, получено: {wg_type!r}"
            )

        required_vars = ["POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD"]
        missing = [var for var in required_vars if not os.getenv(var)]
        if missing:
            raise ValueError(f"Отсутствуют обязательные переменные окружения: {missing}")
        
        interval = int(os.getenv("INTERVAL", DEFAULT_INTERVAL_SECONDS))
        if interval < MIN_INTERVAL_SECONDS:
            logger.warning(
                f"Интервал {interval}с ниже минимального {MIN_INTERVAL_SECONDS}с, "
                f"используется {MIN_INTERVAL_SECONDS}с"
            )
            interval = MIN_INTERVAL_SECONDS
        
        return cls(
            wg_container=wg_container,
            wg_type=wg_type,
            postgres_db=os.getenv("POSTGRES_DB", ""),
            postgres_user=os.getenv("POSTGRES_USER", ""),
            postgres_password=os.getenv("POSTGRES_PASSWORD", ""),
            interval_seconds=interval,
        )

    def get_config_path(self) -> str:
        """Вернуть путь к конфигурационному файлу в зависимости от типа WG."""
        if self.wg_type == "amnezia":
            return WG_CONFIG_PATH_AMNEZIA
        return WG_CONFIG_PATH_WIREGUARD


class UserStats(NamedTuple):
    """Статистика трафика для одного пользователя."""
    user_name: UserName
    rx_bytes: BytesCount
    tx_bytes: BytesCount
    public_key: PublicKey


# =============================================================================
# УТИЛИТЫ ДЛЯ РАБОТЫ С БАЗОЙ ДАННЫХ
# =============================================================================

@contextmanager
def get_db_connection(config: Config) -> Iterator[psycopg2.extensions.connection]:
    """Контекстный менеджер для соединений с БД с корректной очисткой ресурсов."""
    conn = None
    try:
        conn = psycopg2.connect(
            dbname=config.postgres_db,
            user=config.postgres_user,
            password=config.postgres_password,
            host=DB_HOST,
            port=DB_PORT,
            connect_timeout=10,
        )
        yield conn
    except psycopg2.Error as e:
        logger.error(f"Ошибка подключения к базе данных: {e}")
        raise
    finally:
        if conn and not conn.closed:
            conn.close()


# =============================================================================
# УТИЛИТЫ ДЛЯ DOCKER И ПАРСИНГА
# =============================================================================

def _execute_docker_command(
    container: str, 
    *args: str,
    timeout: int = 30
) -> str:
    """Выполнить команду в Docker-контейнере и вернуть декодированный вывод."""
    try:
        result = subprocess.run(
            ["docker", "exec", container, *args],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Команда не выполнена: {' '.join(args)}, ошибка: {e.stderr.strip()}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"Таймаут команды: {' '.join(args)}")
        raise


def parse_wireguard_config(config_text: str) -> dict[PublicKey, UserName]:
    """
    Распарсить конфигурационный файл WireGuard и извлечь сопоставление 
    публичного ключа и имени пользователя.
    
    Ожидаемый формат:
        # Client: username (comment)
        PublicKey = xxx...
    """
    users: dict[PublicKey, UserName] = {}
    current_name: UserName | None = None
    
    for line in config_text.splitlines():
        line = line.strip()
        
        if line.startswith("# Client:"):
            raw = line.removeprefix("# Client:").strip()
            current_name = raw.split("(")[0].strip()
            
        elif line.startswith("PublicKey") and current_name:
            try:
                key = line.split("=", 1)[1].strip()
                if key:
                    users[key] = current_name
            except IndexError:
                logger.warning(f"Не удалось распарсить строку PublicKey: {line}")
            finally:
                current_name = None
    
    return users


def parse_amnezia_config(config_text: str) -> dict[PublicKey, UserName]:
    """
    Распарсить конфигурационный файл Amnezia WireGuard (JSON формат).
    
    Ожидаемый формат JSON:
    [
        {
            "clientId": "публичный_ключ",
            "userData": {
                "clientName": "имя_пользователя",
                ...
            }
        },
        ...
    ]
    """
    users: dict[PublicKey, UserName] = {}
    
    try:
        clients = json.loads(config_text)
        
        if not isinstance(clients, list):
            logger.warning("Amnezia config: ожидается список клиентов")
            return users
        
        for idx, client in enumerate(clients):
            if not isinstance(client, dict):
                logger.warning(f"Amnezia config: клиент {idx} не является объектом")
                continue
            
            client_id = client.get("clientId")
            user_data = client.get("userData", {})
            
            if not client_id:
                logger.warning(f"Amnezia config: клиент {idx} не имеет clientId")
                continue
            
            if not isinstance(user_data, dict):
                logger.warning(f"Amnezia config: клиент {idx} не имеет userData")
                continue
            
            client_name = user_data.get("clientName")
            
            if not client_name:
                logger.warning(f"Amnezia config: клиент {idx} не имеет clientName")
                continue
            
            users[client_id] = client_name
        
        logger.info(f"Amnezia config: найдено {len(users)} пользователей")
        
    except json.JSONDecodeError as e:
        logger.error(f"Amnezia config: ошибка парсинга JSON: {e}")
    
    return users


def get_users(config: Config) -> dict[PublicKey, UserName]:
    """Получить и распарсить конфигурацию WireGuard для получения сопоставления пользователей."""
    config_path = config.get_config_path()
    
    try:
        output = _execute_docker_command(
            config.wg_container, "cat", config_path
        )
        
        if config.wg_type == "amnezia":
            return parse_amnezia_config(output)
        else:
            return parse_wireguard_config(output)
    except subprocess.SubprocessError as e:
        logger.error(f"Не удалось получить конфигурацию WireGuard: {e}")
        return {}


def parse_wg_dump(dump_text: str) -> dict[PublicKey, TrafficTuple]:
    """
    Распарсить вывод команды 'wg show <interface> dump'.
    
    Формат: public_key, pre-shared-key, endpoint, allowed-ips, 
            latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
    """
    stats: dict[PublicKey, TrafficTuple] = {}
    
    for line_num, line in enumerate(dump_text.splitlines(), 1):
        parts = line.strip().split()
        
        if len(parts) < 7 or parts[0] == WG_INTERFACE:
            continue
            
        try:
            public_key = parts[0]
            rx_bytes = int(parts[5])
            tx_bytes = int(parts[6])
            stats[public_key] = (rx_bytes, tx_bytes)
        except (ValueError, IndexError) as e:
            logger.warning(
                f"Не удалось распарсить строку статистики {line_num}: '{line}', ошибка: {e}"
            )
            continue
    
    return stats


def get_stats(config: Config) -> dict[PublicKey, TrafficTuple]:
    """Получить текущую статистику трафика WireGuard."""
    try:
        output = _execute_docker_command(
            config.wg_container, "wg", "show", WG_INTERFACE, "dump"
        )
        return parse_wg_dump(output)
    except subprocess.SubprocessError as e:
        logger.error(f"Не удалось получить статистику WireGuard: {e}")
        return {}


# =============================================================================
# УПРАВЛЕНИЕ ПАРТИЦИЯМИ
# =============================================================================

def get_month_boundaries(dt: datetime) -> tuple[datetime, datetime]:
    """Вернуть начало (включительно) и конец (исключительно) месяца, содержащего dt."""
    start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


def _validate_table_identifier(name: str) -> bool:
    """Проверить, что строка безопасна для использования как идентификатор PostgreSQL."""
    if not name or len(name) > 63:
        return False
    if not (name[0].isalpha() or name[0] == "_"):
        return False
    return all(c.isalnum() or c == "_" for c in name)


def ensure_partitions(conn: psycopg2.extensions.connection, reference_dt: datetime) -> None:
    """Гарантировать существование партиций таблицы traffic для текущего и следующего месяца."""
    partitions = [
        get_month_boundaries(reference_dt),
        get_month_boundaries(reference_dt + timedelta(days=31)),
    ]
    
    with conn.cursor() as cur:
        for start, end in partitions:
            table_name = f"traffic_{start.year}_{start.month:02d}"
            
            if not _validate_table_identifier(table_name):
                logger.error(f"Невалидное имя таблицы партиции: {table_name}")
                continue
            
            query = sql.SQL("""
                CREATE TABLE IF NOT EXISTS {table}
                PARTITION OF traffic
                FOR VALUES FROM (%s) TO (%s)
            """).format(table=sql.Identifier(table_name))
            
            try:
                cur.execute(query, (start, end))
                logger.debug(f"Гарантировано существование партиции {table_name}")
            except psycopg2.Error as e:
                if "already exists" not in str(e):
                    logger.error(f"Не удалось создать партицию {table_name}: {e}")
                    raise


# =============================================================================
# ЛОГИКА СБОРА ТРАФИКА
# =============================================================================

def _calculate_delta(current: int, previous: int) -> int:
    """Рассчитать дельту трафика с обработкой сброса счётчиков."""
    return current - previous if current >= previous else current


def collect_traffic(config: Config) -> None:
    """Основная логика сбора: получить статистику, рассчитать дельты, сохранить в БД."""
    now = datetime.now(UTC)
    
    with get_db_connection(config) as conn:
        ensure_partitions(conn, now)
        
        users = get_users(config)
        stats = get_stats(config)
        
        if not users:
            logger.warning("Не найдено пользователей в конфигурации WireGuard")
        if not stats:
            logger.warning("Не получена статистика трафика от WireGuard")
        
        # Загрузить предыдущие значения для расчёта дельт
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT public_key, rx, tx FROM last_stats")
            last_stats: dict[PublicKey, TrafficTuple] = {
                row["public_key"]: (row["rx"], row["tx"]) 
                for row in cur.fetchall()
            }
        
        # Подготовить данные для пакетных операций
        traffic_records: list[UserStats] = []
        last_stats_updates: list[tuple[PublicKey, int, int]] = []
        
        for public_key, (rx, tx) in stats.items():
            if public_key not in users:
                logger.debug(f"Пропущен неизвестный публичный ключ: {public_key}")
                continue
            
            user_name = users[public_key]
            prev_rx, prev_tx = last_stats.get(public_key, (0, 0))
            
            delta_rx = _calculate_delta(rx, prev_rx)
            delta_tx = _calculate_delta(tx, prev_tx)
            
            if delta_rx > 0 or delta_tx > 0:
                traffic_records.append(
                    UserStats(user_name, delta_rx, delta_tx, public_key)
                )
            
            last_stats_updates.append((public_key, rx, tx))
        
        # Пакетная вставка записей о трафике
        if traffic_records:
            with conn.cursor() as cur:
                execute_batch(
                    cur,
                    """
                    INSERT INTO traffic (user_name, rx_bytes, tx_bytes)
                    VALUES (%s, %s, %s)
                    """,
                    [
                        (rec.user_name, rec.rx_bytes, rec.tx_bytes)
                        for rec in traffic_records
                    ],
                )
                logger.info(f"Вставлено {len(traffic_records)} записей о трафике")
        
        # Пакетное обновление last_stats (upsert)
        if last_stats_updates:
            with conn.cursor() as cur:
                execute_batch(
                    cur,
                    """
                    INSERT INTO last_stats (public_key, rx, tx)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (public_key)
                    DO UPDATE SET
                        rx = EXCLUDED.rx,
                        tx = EXCLUDED.tx,
                        updated_at = NOW()
                    """,
                    last_stats_updates,
                )
        
        conn.commit()
        logger.info(
            f"Сбор завершён в {now.isoformat()}: "
            f"записано {len(traffic_records)} записей"
        )


# =============================================================================
# ТОЧКА ВХОДА ПРИЛОЖЕНИЯ
# =============================================================================

def _setup_logging(level: int = logging.INFO) -> None:
    """Настроить структурированное логирование."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        force=True,
    )


def main() -> int:
    """Точка входа приложения."""
    _setup_logging()
    
    try:
        config = Config.from_env()
    except ValueError as e:
        logger.critical(f"Ошибка конфигурации: {e}")
        return 1
    
    logger.info(
        f"Запуск сборщика статистики WireGuard (интервал: {config.interval_seconds}с)"
    )
    
    scheduler = BlockingScheduler(timezone=UTC)
    
    try:
        scheduler.add_job(
            collect_traffic,
            trigger="interval",
            seconds=config.interval_seconds,
            max_instances=1,
            coalesce=True,
            kwargs={"config": config},
        )
        scheduler.start()
    except KeyboardInterrupt:
        logger.info("Получен сигнал завершения, остановка планировщика...")
        scheduler.shutdown(wait=True)
    except Exception as e:
        logger.exception(f"Неожиданная ошибка: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())